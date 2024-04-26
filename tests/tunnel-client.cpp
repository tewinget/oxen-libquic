/*
    Tunnel client binary
*/

#include "tcp.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC tunneled test client"};

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

    Network client_net{};

    auto client_tls = GNUTLSCreds::make_from_ed_keys(TUNNEL_SEED, TUNNEL_PUBKEY);

    Address tunnel_client_local{LOCALHOST, 1111}, manual_client_local{LOCALHOST, 2222}, tunnel_server_local{LOCALHOST, 3333};

    Address localhost_blank{LOCALHOST, 0};

    // Remote manual server addresses
    std::vector<Address> remote_addrs{{LOCALHOST, 4444}, {LOCALHOST, 4455}, {LOCALHOST, 4466}};

    // TODO: make this a CLI arg and generate all the addresses?
    const int num_conns{3};

    std::atomic<int> current_conn{0};

    std::vector<std::promise<void>> conn_proms{};
    std::vector<std::future<void>> conn_futures{};

    for (int i = 0; i < num_conns; ++i)
    {
        conn_proms.push_back(std::promise<void>{});
        conn_futures.push_back(conn_proms.back().get_future());
    }

    // Connectable addresses
    std::vector<RemoteAddress> connect_addrs{};

    for (auto& r : remote_addrs)
        connect_addrs.push_back(RemoteAddress{TUNNEL_PUBKEY, r});

    // Paths from manual client to remote manual server
    std::vector<Path> paths{};

    // for (auto& r : remote_addrs)
    //     paths.push_back(Path{manual_client_local, r});

    /** key: remote address to which we are connecting
        value: tunneled quic connection
    */
    std::unordered_map<Address, tunneled_connection> _tunnels;

    // callback_waiter initial_tunnel_established{
    //         [](connection_interface&) { log::info(test_cat, "Initial tunnel established"); }};

    auto manual_client_established = [&](connection_interface& ci) {
        auto path = ci.path();
        paths.push_back(ci.path());  // make a copy for the list
        auto& remote = path.remote;

        auto _handle = TCPHandle::make_server(
                client_net.loop(), [&, p = path](struct bufferevent* _bev, evutil_socket_t _fd, Address src) {
                    auto& remote = p.remote;

                    if (auto it_a = _tunnels.find(remote); it_a != _tunnels.end())
                    {
                        auto& conns = it_a->second.conns;

                        if (auto it_b = conns.find(remote.port()); it_b != conns.end())
                        {
                            auto& tcp_quic = it_b->second;
                            auto& ci = tcp_quic._ci;

                            log::info(test_cat, "Opening stream...");
                            // data and close cb set after lambda execution
                            auto s = ci->open_stream();

                            log::info(test_cat, "Opening TCPConnection...");

                            auto tcp_conn = std::make_shared<TCPConnection>(_bev, _fd, std::move(s));
                            auto [it, _] = tcp_quic._tcp_conns.insert_or_assign(src, std::move(tcp_conn));

                            return it->second.get();
                        }
                        throw std::runtime_error{"Could not find paired TCP-QUIC for remote port:{}"_format(remote.port())};
                    }
                    throw std::runtime_error{"Could not find tunnel to remote:{}!"_format(remote)};
                });

        if (not _handle->is_bound())
            throw std::runtime_error{"Failed to bind TCP Handle listener!"};

        auto bind = *_handle->bind();

        log::info(
                test_cat,
                "Manual client established connection (path: {}); assigned TCPHandle listening on: {}",
                path,
                bind);

        tunneled_connection tunneled_conn{};
        tunneled_conn.h = std::move(_handle);

        TCPQUIC tcp_quic{};
        tcp_quic._ci = ci.shared_from_this();

        if (auto [_, b] = tunneled_conn.conns.emplace(remote.port(), std::move(tcp_quic)); not b)
            throw std::runtime_error{"Failed to emplace tunneled_connection!"};

        _tunnels.emplace(remote, std::move(tunneled_conn));

        if (current_conn >= num_conns)
            throw std::runtime_error{
                    "Client cannot accept more than configured number ({}) of connections!"_format(num_conns)};

        conn_proms[current_conn].set_value();
        current_conn += 1;
    };

    try
    {
        std::shared_ptr<connection_interface> tunnel_ci;

        auto manual_client =
                client_net.endpoint(manual_client_local, opt::manual_routing{[&](const Path& p, bstring_view data) {
                                        tunnel_ci->send_datagram(Packet(p, bstring{data}).bt_encode());
                                    }});

        dgram_data_callback recv_dgram_cb = [&](dgram_interface&, bstring data) {
            manual_client->manually_receive_packet(*Packet::bt_decode(std::move(data)));
        };

        auto tunnel_client_established = callback_waiter{
                [&](connection_interface&) { log::info(test_cat, "Tunnel client established connection to remote!"); }};

        auto tunnel_client =
                client_net.endpoint(tunnel_client_local, recv_dgram_cb, opt::enable_datagrams{Splitting::ACTIVE});

        RemoteAddress tunnel_server_addr{TUNNEL_PUBKEY, tunnel_server_local};

        log::info(test_cat, "Connecting tunnel client to server...");

        tunnel_ci = tunnel_client->connect(tunnel_server_addr, client_tls, opt::keep_alive{10s}, tunnel_client_established);
        tunnel_client_established.wait();

        // manual_client->connect(RemoteAddress{TUNNEL_PUBKEY, localhost_blank}, client_tls, initial_tunnel_established);
        // initial_tunnel_established.wait();

        for (int i = 0; i < num_conns; ++i)
        {
            manual_client->connect(connect_addrs[i], client_tls, manual_client_established, opt::keep_alive{10s});

            conn_futures[i].wait();
        }

        auto msg = "Client established {} tunneled connections:\n"_format(current_conn.load());

        for (auto& [addr, tun] : _tunnels)
            msg += "TCP Listener: {} --> Remote: {}\n"_format(*tun.h->bind(), addr);

        log::critical(test_cat, "{}", msg);
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start client: {}!", e.what());
        return 1;
    }

    for (;;)
        std::this_thread::sleep_for(10min);
}
