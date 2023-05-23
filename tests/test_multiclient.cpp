/*
    Test client binary
*/

#include <thread>

#include "quic.hpp"

using namespace oxen::quic;

bool run{true};

void signal_handler(int)
{
    run = false;
}

int main(int argc, char* argv[])
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    logger_config();

    Network client_net{};
    auto msg = "hello from the other siiiii-iiiiide"_bsv;

    opt::client_tls client_a_tls{
        0,
        "/home/dan/oxen/libquicinet/tests/certs/clientkey_a.pem"s,
        "/home/dan/oxen/libquicinet/tests/certs/clientcert_a.pem"s,
        "/home/dan/oxen/libquicinet/tests/certs/servercert.pem"s,
        ""s,
        nullptr};
    opt::client_tls client_b_tls{
        0,
        "/home/dan/oxen/libquicinet/tests/certs/clientkey_b.pem"s,
        "/home/dan/oxen/libquicinet/tests/certs/clientcert_b.pem"s,
        "/home/dan/oxen/libquicinet/tests/certs/servercert_b.pem"s,
        ""s,
        nullptr};
    // opt::client_tls client_c_tls{
    //     0,
    //     "/home/dan/oxen/libquicinet/tests/certs/clientkey_c.pem"s,
    //     "/home/dan/oxen/libquicinet/tests/certs/clientcert_c.pem"s,
    //     "/home/dan/oxen/libquicinet/tests/certs/servercert.pem"s,
    //     ""s,
    //     nullptr};
    // opt::client_tls client_d_tls{
    //     0,
    //     "/home/dan/oxen/libquicinet/tests/certs/clientkey_d.pem"s,
    //     "/home/dan/oxen/libquicinet/tests/certs/clientcert_d.pem"s,
    //     "/home/dan/oxen/libquicinet/tests/certs/servercert.pem"s,
    //     ""s,
    //     nullptr};

    opt::local_addr client_a_local{"127.0.0.1"s, static_cast<uint16_t>(4400)};
    opt::local_addr client_b_local{"127.0.0.1"s, static_cast<uint16_t>(4422)};
    // opt::local_addr client_c_local{"127.0.0.1"s, static_cast<uint16_t>(4444)};
    // opt::local_addr client_d_local{"127.0.0.1"s, static_cast<uint16_t>(4466)};
    opt::remote_addr client_a_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};
    opt::remote_addr client_b_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};
    // opt::remote_addr client_c_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};
    // opt::remote_addr client_d_remote{"127.0.0.1"s, static_cast<uint16_t>(5500)};

    log::debug(log_cat, "Calling 'client_connect'...");
    auto client_a = client_net.client_connect(client_a_local, client_a_remote, client_a_tls);

    // auto client_b = client_net.client_connect(client_b_local, client_b_remote, client_b_tls);
    // auto client_c = client_net.client_connect(client_c_local, client_c_remote, client_c_tls);
    // auto client_d = client_net.client_connect(client_d_local, client_d_remote, client_d_tls);

    std::thread ev_thread{[&]() {
        client_net.ev_loop->run();

        size_t counter = 0;
        do
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            if (++counter % 30 == 0)
                std::cout << "waiting..."
                          << "\n";
        } while (run);
    }};

    log::debug(log_cat, "Main thread call");
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    std::thread async_thread_a{[&]() {
        log::debug(log_cat, "Async thread 1 called");

        // auto stream_a = client_a->open_stream();
        // stream_a->send(msg);

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        auto client_b = client_net.client_connect(client_b_local, client_b_remote, client_b_tls);

        // auto stream_b = client_b->open_stream();
        // stream_b->send(msg);

        // std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // auto stream_c = client_c->open_stream();
        // stream_c->send(msg);
    }};

    // std::thread async_thread_b{[&]() {
    //     log::debug(log_cat, "Async thread 2 called");
    //     std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    //     // auto client_d = client_net.client_connect(client_d_local, client_a_remote,
    //     client_d_tls);

    //     std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    //     // auto stream_d = client_d->open_stream();
    //     // stream_d->send(msg);
    // }};

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    size_t counter = 0;
    do
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        if (++counter % 30 == 0)
            std::cout << "waiting..."
                      << "\n";
    } while (run);

    async_thread_a.join();
    // async_thread_b.join();
    ev_thread.join();

    return 0;
}
