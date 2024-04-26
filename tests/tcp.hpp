#include <gnutls/gnutls.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/gnutls_crypto.hpp>

extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
}

#include <future>
#include <thread>

#include "utils.hpp"

namespace oxen::quic
{
    struct TCPConnection;
    class TCPHandle;

    inline const auto LOCALHOST = "127.0.0.1"s;
    inline const auto TUNNEL_SEED = oxenc::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
    inline const auto TUNNEL_PUBKEY = oxenc::from_hex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");

    struct TCPQUIC
    {
        std::shared_ptr<connection_interface> _ci;

        // keyed against backend tcp address
        std::unordered_map<Address, std::shared_ptr<TCPConnection>> _tcp_conns;
    };

    // held in a map keyed against the remote address
    struct tunneled_connection
    {
        std::shared_ptr<TCPHandle> h;

        // keyed against the remote port (for tunnel_client) or local port (for tunnel_server)
        std::unordered_map<uint16_t, TCPQUIC> conns;
    };

    inline constexpr auto evconnlistener_deleter = [](::evconnlistener* e) {
        log::trace(test_cat, "Invoking evconnlistener deleter!");
        if (e)
            evconnlistener_free(e);
    };

    void tcp_read_cb(struct bufferevent* bev, void* user_arg);
    void tcp_event_cb(struct bufferevent* bev, short what, void* user_arg);
    void tcp_listen_cb(
            struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* src, int socklen, void* user_arg);
    void tcp_err_cb(struct evconnlistener* listener, void* user_arg);

    struct TCPConnection
    {
        TCPConnection(struct bufferevent* _bev, evutil_socket_t _fd, std::shared_ptr<Stream> _s) :
                bev{_bev}, fd{_fd}, stream{std::move(_s)}
        {}

        TCPConnection() = delete;

        /// Non-copyable and non-moveable
        TCPConnection(const TCPConnection& s) = delete;
        TCPConnection& operator=(const TCPConnection& s) = delete;
        TCPConnection(TCPConnection&& s) = delete;
        TCPConnection& operator=(TCPConnection&& s) = delete;

        ~TCPConnection() = default;

        struct bufferevent* bev;
        evutil_socket_t fd;

        std::shared_ptr<Stream> stream;
    };

    using tcpconn_hook = std::function<TCPConnection*(struct bufferevent*, evutil_socket_t, oxen::quic::Address src)>;

    class TCPHandle
    {
        using socket_t =
#ifndef _WIN32
                int
#else
                SOCKET
#endif
                ;

        std::shared_ptr<Loop> _ev;
        std::shared_ptr<::evconnlistener> _tcp_listener;

        // The OutboundSession will set up an evconnlistener and set the listening socket address inside ::_bound
        std::optional<Address> _bound = std::nullopt;

        // The InboundSession will set this address to the lokinet-primary-ip to connect to
        std::optional<Address> _connect = std::nullopt;

        socket_t _sock;

        explicit TCPHandle(const std::shared_ptr<Loop>& ev, tcpconn_hook cb, uint16_t p) :
                _ev{ev}, _conn_maker{std::move(cb)}
        {
            assert(_ev);

            if (!_conn_maker)
                throw std::logic_error{"TCPSocket construction requires a non-empty receive callback"};

            _init_server(p);
        }

        explicit TCPHandle(const std::shared_ptr<Loop>& ev) : _ev{ev} { assert(_ev); }

      public:
        TCPHandle() = delete;

        tcpconn_hook _conn_maker;

        // The OutboundSession object will hold a server listening on some localhost:port, returning that port to the
        // application for it to make a TCP connection
        static std::shared_ptr<TCPHandle> make_server(const std::shared_ptr<Loop>& ev, tcpconn_hook cb, uint16_t port = 0)
        {
            std::shared_ptr<TCPHandle> h{new TCPHandle(ev, std::move(cb), port)};
            return h;
        }

        // The InboundSession object will hold a client that connects to some application configured
        // lokinet-primary-ip:port every time the OutboundSession opens a new stream over the tunneled connection
        static std::shared_ptr<TCPHandle> make_client(const std::shared_ptr<Loop>& ev)
        {
            std::shared_ptr<TCPHandle> h{new TCPHandle{ev}};
            return h;
        }

        ~TCPHandle()
        {
            _tcp_listener.reset();
            log::info(test_cat, "TCPHandle shut down!");
        }

        uint16_t port() const { return _bound.has_value() ? _bound->port() : 0; }

        // checks _bound has been set by ::make_server(...)
        bool is_bound() const { return _bound.has_value(); }

        // checks _connect has been set by ::connect_to_backend(...)
        bool is_connected() const { return _connect.has_value(); }

        // returns the bind address of the TCP listener
        std::optional<Address> bind() const { return _bound; }

        // returns the socket address of the TCP connection
        std::optional<Address> connect() const { return _connect; }

        std::shared_ptr<TCPConnection> connect_to_backend(std::shared_ptr<Stream> s, Address addr)
        {
            if (addr.port() == 0)
                throw std::runtime_error{"TCP backend must have valid port on localhost!"};

            log::critical(test_cat, "Attempting TCP connection to backend at: {}", addr);
            sockaddr_in _addr = addr.in4();

            struct bufferevent* _bev =
                    bufferevent_socket_new(_ev->loop().get(), -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

            s->set_stream_data_cb([_bev](oxen::quic::Stream& s, bstring_view data) {
                auto rv = _bev ? bufferevent_write(_bev, data.data(), data.size()) : -1;
                log::info(
                        test_cat,
                        "Stream (id: {}) {} {}B to TCP buffer",
                        s.stream_id(),
                        rv < 0 ? "failed to write" : "successfully wrote",
                        data.size());
            });

            s->set_stream_close_cb([_bev](Stream&, uint64_t) {
                log::critical(
                        test_cat,
                        "Stream closed cb fired, {}...",
                        _bev ? "freeing bufferevent" : "bufferevent already freed");
                if (_bev)
                    bufferevent_free(_bev);
            });

            auto tcp_conn = std::make_shared<TCPConnection>(_bev, -1, std::move(s));

            bufferevent_setcb(_bev, tcp_read_cb, nullptr, tcp_event_cb, tcp_conn.get());
            bufferevent_enable(_bev, EV_READ | EV_WRITE);

            if (bufferevent_socket_connect(_bev, (struct sockaddr*)&_addr, sizeof(_addr)) < 0)
            {
                log::warning(test_cat, "Failed to make bufferevent-based TCP connection!");
                return nullptr;
            }

            // fd is only set after a call to bufferevent_socket_connect
            tcp_conn->fd = bufferevent_getfd(_bev);
            _sock = tcp_conn->fd;

            log::debug(test_cat, "TCP bufferevent has fd: {}", tcp_conn->fd);

            Address temp{};
            if (getsockname(tcp_conn->fd, temp, temp.socklen_ptr()) < 0)
                throw std::runtime_error{
                        "Failed to bind bufferevent: {}"_format(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};

            _connect = temp;

            log::info(test_cat, "TCP bufferevent sock on addr: {}", *_connect);

            return tcp_conn;
        }

      private:
        void _init_client() {}

        void _init_server(uint16_t port)
        {
            sockaddr_in _tcp{};
            _tcp.sin_family = AF_INET;
            _tcp.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            _tcp.sin_port = htons(port);

            _tcp_listener = _ev->shared_ptr<struct evconnlistener>(
                    evconnlistener_new_bind(
                            _ev->loop().get(),
                            tcp_listen_cb,
                            this,
                            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE | LEV_OPT_REUSEABLE,
                            -1,
                            reinterpret_cast<sockaddr*>(&_tcp),
                            sizeof(sockaddr)),
                    evconnlistener_deleter);

            if (not _tcp_listener)
                throw std::runtime_error{
                        "TCP listener construction failed: {}"_format(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};

            _sock = evconnlistener_get_fd(_tcp_listener.get());

            log::info(test_cat, "TCP server has fd: {}", _sock);

            Address temp{};
            if (getsockname(_sock, temp, temp.socklen_ptr()) < 0)
                throw std::runtime_error{
                        "Failed to bind listener: {}"_format(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};

            _bound = temp;

            evconnlistener_set_error_cb(_tcp_listener.get(), tcp_err_cb);

            log::critical(test_cat, "TCPHandle set up listener on: {}", *_bound);
        }
    };

    inline void tcp_read_cb(struct bufferevent* bev, void* user_arg)
    {
        std::array<uint8_t, 2048> buf{};

        // Load data from input buffer to local buffer
        auto nwrite = bufferevent_read(bev, buf.data(), buf.size());

        log::info(test_cat, "TCP socket received {}B", nwrite);

        if (nwrite > 0)
        {
            auto* conn = reinterpret_cast<TCPConnection*>(user_arg);
            assert(conn);

            conn->stream->send(ustring{(buf.data()), nwrite});
        }
    }

    inline void tcp_event_cb([[maybe_unused]] struct bufferevent* bev, short what, void* user_arg)
    {
        // this is where the InboundSession confirms it established a TCP connection to the backend app
        if (what & BEV_EVENT_CONNECTED)
        {
            log::info(test_cat, "TCP connect operation succeeded!");
        }
        if (what & BEV_EVENT_EOF)
        {
            log::critical(test_cat, "TCP Connection EOF!");
        }
        if (what & BEV_EVENT_ERROR)
        {
            log::critical(
                    test_cat,
                    "TCP Connection encountered bufferevent error (msg: {})!",
                    evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        }
        if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF))
        {
            // if (bev)
            // {
            //     log::critical(test_cat, "Freeing bufferevent socket...");
            //     bufferevent_free(bev);
            // }

            auto* conn = reinterpret_cast<TCPConnection*>(user_arg);
            assert(conn);

            log::critical(test_cat, "Closing stream...");
            conn->stream->close();
            // auto& str = conn->stream;
            // if (str and not str->is_closing())
            // {
            //     return str->close();
            // }
            // log::critical(test_cat, "Stream for tcp connection already destroyed...");
        }
    }

    inline void tcp_listen_cb(
            struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* src, int socklen, void* user_arg)
    {
        oxen::quic::Address source{src, static_cast<socklen_t>(socklen)};
        log::critical(test_cat, "TCP CONNECTION ESTABLISHED -- SRC: {}", source);

        auto* b = evconnlistener_get_base(listener);
        auto* _bev = bufferevent_socket_new(b, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

        // int yes{1};
        // if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) < 0)
        // {
        //     log::critical(
        //             test_cat,
        //             "Failed to set keepalive on accepted TCP connection socket: {}",
        //             evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        //     return bufferevent_free(bevent);
        // }

        auto* handle = reinterpret_cast<TCPHandle*>(user_arg);
        assert(handle);

        // make TCPConnection here!
        auto* conn = handle->_conn_maker(_bev, fd, std::move(source));

        conn->stream->set_stream_data_cb([_bev](Stream& s, bstring_view data) {
            auto rv = _bev ? bufferevent_write(_bev, data.data(), data.size()) : -1;
            log::info(
                    test_cat,
                    "Stream (id: {}) {} {}B to TCP buffer",
                    s.stream_id(),
                    rv < 0 ? "failed to write" : "successfully wrote",
                    data.size());
        });

        conn->stream->set_stream_close_cb([_bev](Stream&, uint64_t) {
            log::critical(
                    test_cat, "Stream closed cb fired, {}...", _bev ? "freeing bufferevent" : "bufferevent already freed");
            if (_bev)
                bufferevent_free(_bev);
        });

        bufferevent_setcb(_bev, tcp_read_cb, nullptr, tcp_event_cb, conn);
        bufferevent_enable(_bev, EV_READ | EV_WRITE);
    }

    inline void tcp_err_cb(struct evconnlistener* /* e */, void* user_arg)
    {
        int ec = EVUTIL_SOCKET_ERROR();
        log::critical(test_cat, "TCP LISTENER RECEIVED ERROR CODE {}: {}", ec, evutil_socket_error_to_string(ec));

        [[maybe_unused]] auto* handle = reinterpret_cast<TCPHandle*>(user_arg);
        assert(handle);

        // DISCUSS: close everything here?
    }
}  //  namespace oxen::quic
