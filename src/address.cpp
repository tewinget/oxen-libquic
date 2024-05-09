#include "address.hpp"

#include <oxenc/endian.h>

#include "internal.hpp"

namespace oxen::quic
{
    Address::Address(const std::string& addr, uint16_t port)
    {
        int rv = 1;
        if (
#ifndef OXEN_LIBQUIC_ADDRESS_NO_DUAL_STACK
                addr.empty() ||
#endif
                addr.find(':') != std::string_view::npos)
        {
            _sock_addr.ss_family = AF_INET6;
            auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
            sin6.sin6_port = oxenc::host_to_big(port);
            _addr.addrlen = sizeof(sockaddr_in6);
            if (!addr.empty())
                rv = inet_pton(AF_INET6, addr.c_str(), &sin6.sin6_addr);
            else
                // Otherwise default to all-0 IPv6 address with the dual stack flag enabled
                dual_stack = true;
        }
        else
        {
            _sock_addr.ss_family = AF_INET;
            auto& sin4 = reinterpret_cast<sockaddr_in&>(_sock_addr);
            sin4.sin_port = oxenc::host_to_big(port);
            _addr.addrlen = sizeof(sockaddr_in);
#ifdef OXEN_LIBQUIC_ADDRESS_NO_DUAL_STACK
            if (!addr.empty())
#endif
                rv = inet_pton(AF_INET, addr.c_str(), &sin4.sin_addr);
        }
        if (rv == 0)  // inet_pton returns this on invalid input
            throw std::invalid_argument{"Cannot construct address: invalid IP"};
        if (rv < 0)
            throw std::system_error{errno, std::system_category()};
    }

    Address::Address(const ngtcp2_addr& addr)
    {
        // if (addr.addrlen == sizeof(sockaddr_in6))
        if (addr.addr->sa_family == AF_INET6)
        {
            _sock_addr.ss_family = AF_INET6;
            auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
            auto& nin6 = reinterpret_cast<const sockaddr_in6&>(addr);
            sin6.sin6_addr = nin6.sin6_addr;
            sin6.sin6_port = nin6.sin6_port;
            update_socklen(sizeof(sockaddr_in6));
        }
        // else if (addr.addrlen == sizeof(sockaddr_in))
        else if (addr.addr->sa_family == AF_INET)
        {
            _sock_addr.ss_family = AF_INET;
            auto& sin = reinterpret_cast<sockaddr_in&>(_sock_addr);
            auto& nin = reinterpret_cast<const sockaddr_in&>(addr);
            sin.sin_addr = nin.sin_addr;
            sin.sin_port = nin.sin_port;
            update_socklen(sizeof(sockaddr_in));
        }
        else
            throw std::invalid_argument{"What on earth did you pass to this constructor?"};
    }

    Address::Address(ipv4 v4, uint16_t port)
    {
        _sock_addr.ss_family = AF_INET;

        auto& sin = reinterpret_cast<sockaddr_in&>(_sock_addr);
        sin.sin_port = oxenc::host_to_big(port);
        std::memcpy(&sin.sin_addr, &v4, sizeof(ipv4));

        update_socklen(sizeof(sockaddr_in));
    }

    Address::Address(ipv6 v6, uint16_t port)
    {
        _sock_addr.ss_family = AF_INET6;

        auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
        sin6.sin6_port = oxenc::host_to_big(port);

        // std::array<uint64_t, 2> arr{v6.hi, v6.lo};
        std::array<uint64_t, 2> arr{oxenc::big_to_host<uint64_t>(v6.hi), oxenc::big_to_host<uint64_t>(v6.lo)};
        std::memcpy(&sin6.sin6_addr.s6_addr, &arr, sizeof(arr));

        update_socklen(sizeof(sockaddr_in6));
    }

    void Address::set_addr(const struct in_addr* addr)
    {
        if (_sock_addr.ss_family == AF_INET6)
        {
            // We're changing from IPv6 to IPv4, so need to preserve the port value:
            auto p = reinterpret_cast<sockaddr_in6&>(_sock_addr).sin6_port;
            auto& sin = reinterpret_cast<sockaddr_in&>(_sock_addr);
            sin.sin_family = AF_INET;
            sin.sin_port = p;
            update_socklen(sizeof(sockaddr_in));
        }
        std::memcpy(&reinterpret_cast<sockaddr_in&>(_sock_addr).sin_addr, addr, sizeof(struct in_addr));
    }

    void Address::set_addr(const struct in6_addr* addr)
    {
        if (_sock_addr.ss_family == AF_INET)
        {
            // We're changing from IPv4 to IPv6, so need to preserve the port value and non-address
            // parts of the sockaddr_in6
            auto p = reinterpret_cast<sockaddr_in&>(_sock_addr).sin_port;
            auto& sin6 = reinterpret_cast<sockaddr_in6&>(_sock_addr);
            std::memset(&sin6, 0, sizeof(sockaddr_in6));
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port = p;
        }
        std::memcpy(&reinterpret_cast<sockaddr_in6&>(_sock_addr).sin6_addr, addr, sizeof(struct in6_addr));
    }

    static inline constexpr auto ipv6_ipv4_mapped_prefix = "\0\0\0\0\0\0\0\0\0\0\xff\xff"sv;
    static_assert(ipv6_ipv4_mapped_prefix.size() == 12);

    void Address::map_ipv4_as_ipv6()
    {
        if (!is_ipv4())
            throw std::logic_error{"Address::map_ipv4_as_ipv6 cannot be called on a non-IPv4 address"};
        const auto& a4 = in4();
        sockaddr_in6 a6{};
        a6.sin6_family = AF_INET6;
        a6.sin6_port = a4.sin_port;
        std::memcpy(&a6.sin6_addr.s6_addr[0], ipv6_ipv4_mapped_prefix.data(), 12);
        std::memcpy(&a6.sin6_addr.s6_addr[12], &a4.sin_addr.s_addr, 4);
        std::memcpy(&_sock_addr, &a6, sizeof(a6));
        update_socklen(sizeof(a6));
    }

    bool Address::is_ipv4_mapped_ipv6() const
    {
        return is_ipv6() && std::memcmp(in6().sin6_addr.s6_addr, ipv6_ipv4_mapped_prefix.data(), 12) == 0;
    }

    void Address::unmap_ipv4_from_ipv6()
    {
        if (!is_ipv4_mapped_ipv6())
            throw std::logic_error{"Address::unmap_ipv4_ipv6 cannot be called on a non-IPv4-mapped IPv6 address"};
        const auto& a6 = in6();
        sockaddr_in a4{};
        a4.sin_family = AF_INET;
        a4.sin_port = a6.sin6_port;
        std::memcpy(&a4.sin_addr.s_addr, &a6.sin6_addr.s6_addr[12], 4);
        std::memcpy(&_sock_addr, &a4, sizeof(a4));
        update_socklen(sizeof(a4));
    }

    bool Address::is_public_ip() const
    {
        if (is_any_addr())
            return false;
        if (is_ipv4())
        {
            ipv4 addr{oxenc::big_to_host<uint32_t>(in4().sin_addr.s_addr)};
            for (const auto& range : ipv4_nonpublic)
                if (range.contains(addr))
                    return false;
        }
        else if (is_ipv4_mapped_ipv6())
        {
            return unmapped_ipv4_from_ipv6().is_public();
        }
        else if (is_ipv6())
        {
            ipv6 addr{&in6().sin6_addr};
            for (const auto& range : ipv6_nonpublic)
                if (range.contains(addr))
                    return false;
        }
        return true;
    }

    bool Address::is_public() const
    {
        return is_any_port() ? false : is_public_ip();
    }

    bool Address::is_loopback() const
    {
        if (!is_addressable())
            return false;
        if (is_ipv4())
            return ipv4_loopback.contains(ipv4{oxenc::big_to_host<uint32_t>(in4().sin_addr.s_addr)});
        if (is_ipv4_mapped_ipv6())
            return unmapped_ipv4_from_ipv6().is_public();
        if (is_ipv6())
            return ipv6{&in6().sin6_addr} == ipv6_loopback;
        return false;
    }

    ipv4 Address::to_ipv4() const
    {
        return {in4().sin_addr.s_addr};
    }

    ipv6 Address::to_ipv6() const
    {
        return {&in6().sin6_addr};
    }

    std::string Address::host(bool no_format) const
    {
        char buf[INET6_ADDRSTRLEN] = {};
        if (is_ipv6())
        {
            inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_addr, buf, sizeof(buf));
            return no_format ? "{}"_format(buf) : "[{}]"_format(buf);
        }
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_addr, buf, sizeof(buf));
        return "{}"_format(buf);
    }

    std::string Address::to_string() const
    {
        return "{}:{}"_format(host(), port());
    }

    std::string Address::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;
        bt_encode(btdp);

        return std::move(btdp).str();
    }

    void Address::bt_encode(oxenc::bt_dict_producer& btdp) const
    {
        btdp.append("h", host(true));
        btdp.append("p", port());
    }

    std::optional<Address> Address::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        std::optional<Address> a = std::nullopt;
        std::string host;
        uint16_t port;

        try
        {
            host = btdc.require<std::string>("h");
            port = btdc.require<uint16_t>("p");

            a = Address{std::move(host), port};
        }
        catch (const std::exception& e)
        {
            log::critical(log_cat, "Exception parsing Address: {}", e.what());
            throw;
        }

        return a;
    }

    std::string Path::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;
        bt_encode(btdp);

        return std::move(btdp).str();
    }

    void Path::bt_encode(oxenc::bt_dict_producer& btdp) const
    {
        {
            auto subdict = btdp.append_dict("l");
            local.bt_encode(subdict);
        }

        {
            auto subdict = btdp.append_dict("r");
            remote.bt_encode(subdict);
        }
    }

    std::optional<Path> Path::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        std::optional<Path> p = std::nullopt;

        try
        {
            {
                auto [_, subdict] = btdc.next_dict_consumer();
                // this constructor will throw for failures
                p->local = *Address::bt_decode(subdict);
            }

            {
                auto [_, subdict] = btdc.next_dict_consumer();
                // this constructor will throw for failures
                p->remote = *Address::bt_decode(subdict);
            }
        }
        catch (const std::exception& e)
        {
            log::critical(log_cat, "Exception parsing Path: {}", e.what());
            throw;
        }

        return p;
    }

    void Path::set_new_remote(const ngtcp2_addr& new_remote)
    {
        memcpy(_path.remote.addr, new_remote.addr, new_remote.addrlen);
        _path.remote.addrlen = new_remote.addrlen;
        remote = Address{_path.remote.addr, _path.remote.addrlen};
    }

    std::string Path::to_string() const
    {
        return "{{{} ➙ {}}}"_format(local, remote);
    }

}  // namespace oxen::quic
