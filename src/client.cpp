#include "client.hpp"
#include "connection.hpp"

#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <stdexcept>


namespace oxen::quic
{
    Client::Client(Tunnel& tun_endpoint, const uint16_t port, Address&& remote, uint16_t psuedo_port) 
        : Endpoint{tun_endpoint}
    {
        default_stream_bufsize = 0;

        local_addr.port(uint16_t{psuedo_port});

        if (port == 0)
            throw std::logic_error{"Cannot tunnel to port 0"};

        Path path
        {
            Address{reinterpret_cast<const sockaddr_in6&>(in6addr_loopback), uint16_t{0}},
            Address{reinterpret_cast<const sockaddr_in6&>(in6addr_loopback), uint16_t{psuedo_port}}
        };

        auto conn = std::make_shared<Connection>(*this, Connection::random(), std::move(path), port);

        //  TOFIX: start event loop here

        conns.emplace(conn->source_cid, std::move(conn));
    }


    size_t
    Client::write_packet_header(uint16_t remote_port, uint8_t ecn)
    {
        buf[0] = CLIENT_TO_SERVER;
        auto pseudo_port = local_addr.port();
        std::memcpy(&buf[1], &pseudo_port, 2);
        buf[3] = std::byte{ecn};
        return 4;
    }
}   // namespace oxen::quic
