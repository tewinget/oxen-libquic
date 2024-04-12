#include <catch2/catch_test_macros.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    TEST_CASE("011 - Manual Transmission: Both ends re-route", "[011][manual]")
    {
        auto client_established = callback_waiter{[](connection_interface&) {}};
        auto server_established = callback_waiter{[](connection_interface&) {}};

        Network test_net{};
        auto good_msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promise.set_value(true);
        };

        std::shared_ptr<Endpoint> client_endpoint, server_endpoint;

        Address server_local{};
        Address client_local{};

        opt::manual_routing client_sender{[&](Path p, bstring_view d) {
            server_endpoint->manually_receive_packet(Packet{p.invert(), d});
        }};

        opt::manual_routing server_sender{[&](Path p, bstring_view d) {
            client_endpoint->manually_receive_packet(Packet{p.invert(), d});
        }};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        server_endpoint = test_net.endpoint(server_local, server_sender, server_established);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        client_endpoint = test_net.endpoint(client_local, client_sender, client_established);

        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait(1s));
        CHECK(server_established.wait(1s));

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg));

        require_future(d_future);
    }
}  //  namespace oxen::quic::test
