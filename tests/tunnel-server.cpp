/*
    Tunnel server binary
*/

#include "tcp.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC tunneled test server"};

    std::string log_file = "stderr", log_level = "info";
    add_log_opts(cli, log_file, log_level);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    Network server_net{};

    Address backend_tcp1{LOCALHOST, 5555}, backend_tcp2{LOCALHOST, 5566}, backend_tcp3{LOCALHOST, 5577};
    Address localhost_blank{LOCALHOST, 0}, manual_server_local1{LOCALHOST, 4444}, manual_server_local2{LOCALHOST, 4455},
            manual_server_local3{LOCALHOST, 4466};

    std::unordered_map<uint16_t, Address> localport_to_backendtcp{
            {manual_server_local1.port(), backend_tcp1},
            {manual_server_local2.port(), backend_tcp2},
            {manual_server_local3.port(), backend_tcp3}};

    std::unordered_map<uint16_t, Address> backendport_to_localaddr{
            //
    };

    // std::atomic<bool> initial_tunnel{false};

    auto server_tls = GNUTLSCreds::make_from_ed_keys(TUNNEL_SEED, TUNNEL_PUBKEY);

    Address tunnel_server_local{LOCALHOST, 3333};

    /** key: local address client connected to us at
        value: tunneled quic connection
    */
    std::unordered_map<Address, tunneled_connection> _tunnels;

    auto manual_server_stream_open_cb = [&](Stream& s) {
        // Path needs inversion because it is set by the client in manual routing
        auto path = s.path().invert();
        auto& remote = path.remote;
        auto& local = path.local;
        Address backend_addr;

        if (auto it = localport_to_backendtcp.find(local.port()); it != localport_to_backendtcp.end())
            backend_addr = it->second;
        else
            throw std::runtime_error{"You fucked your mapping up dan (local:{}, remote:{})"_format(local, remote)};

        log::info(test_cat, "Inbound new stream to local port {} routing to backend at: {}", local.port(), backend_addr);

        if (auto it_a = _tunnels.find(local); it_a != _tunnels.end())
        {
            auto& _handle = it_a->second.h;
            auto& conns = it_a->second.conns;

            // stream data callback is set in ::connect_to_backend(...)
            auto tcp_conn = _handle->connect_to_backend(s.shared_from_this(), backend_addr);

            // search for local manual_server port extracted from the path
            if (auto it_b = conns.find(local.port()); it_b != conns.end())
            {
                it_b->second._tcp_conns.insert_or_assign(backend_addr, std::move(tcp_conn));
            }
            else
                throw std::runtime_error{"Could not find paired TCP-QUIC for local port:{}"_format(local.port())};
        }
        else
            throw std::runtime_error{"Could not find tunnel to local:{}!"_format(local)};

        return 0;
    };

    auto manual_server_established = [&](connection_interface& ci) {
        // Path needs inversion because it is set by the client in manual routing
        auto path = ci.path().invert();
        auto& remote = path.remote;
        auto& local = path.local;

        // if (not initial_tunnel)
        // {
        //     log::info(test_cat, "Server established initial connection with remote endpoint!");
        //     initial_tunnel = true;
        //     return;
        // }

        log::debug(test_cat, "Server: (local:{}, remote:{})", local, remote);
        log::critical(test_cat, "Manual server established connection (path: {})...", path);

        auto _handle = TCPHandle::make_client(server_net.loop());

        if (not _handle)
            throw std::runtime_error{"Failed to start TCP Client!"};

        tunneled_connection tunneled_conn{};
        tunneled_conn.h = std::move(_handle);

        TCPQUIC tcp_quic{};
        tcp_quic._ci = ci.shared_from_this();

        // map against local manual server port
        // tunneled_conn.conns[local.port()] = std::move(tcp_quic);
        if (auto [_, b] = tunneled_conn.conns.emplace(local.port(), std::move(tcp_quic)); not b)
            throw std::runtime_error{"Failed to emplace tunneled_connection!"};

        _tunnels.emplace(local, std::move(tunneled_conn));
        log::info(test_cat, "TCP Client configured and ready to connect to TCP backend!");
    };

    try
    {
        log::debug(test_cat, "Starting up endpoint");

        std::shared_ptr<connection_interface> tunnel_ci;

        auto manual_server = server_net.endpoint(localhost_blank, opt::manual_routing{[&](const Path& p, bstring_view data) {
                                                     tunnel_ci->send_datagram(Packet(p, bstring{data}).bt_encode());
                                                 }});

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring data) {
            manual_server->manually_receive_packet(*Packet::bt_decode(std::move(data)));
        };

        std::promise<void> tunnel_prom;
        auto tunnel_fut = tunnel_prom.get_future();

        auto tunnel_server_established = [&](connection_interface& ci) {
            log::info(test_cat, "Tunnel server established connection to remote!");
            tunnel_ci = ci.shared_from_this();
        };

        auto tunnel_server =
                server_net.endpoint(tunnel_server_local, recv_dgram_cb, opt::enable_datagrams{Splitting::ACTIVE});

        log::critical(test_cat, "Tunnel server listening on address:{} ...", tunnel_server_local);

        tunnel_server->listen(server_tls, tunnel_server_established, opt::keep_alive{10s});
        manual_server->listen(server_tls, manual_server_established, manual_server_stream_open_cb, opt::keep_alive{10s});
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start server: {}!", e.what());
        return 1;
    }

    for (;;)
        std::this_thread::sleep_for(10min);
}
