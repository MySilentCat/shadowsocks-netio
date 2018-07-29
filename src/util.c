//
// Created by raven on 2018/7/26.
//
#include <netinet/in.h>
#include "uv.h"
#include "shadowsocks-netio/shadowsocks-netio.h"
#include "internal.h"

int str_sockaddr(const struct sockaddr *addr, ADDRESS *addr_s) {
    const struct sockaddr_in6 *in6;
    const struct sockaddr_in *in;

    switch (addr->sa_family) {
    case AF_INET:
        in = (const struct sockaddr_in *)addr;
        CHECK(0 == uv_ip4_name(in, addr_s->host, sizeof(addr_s->host)));
        addr_s->port = htons_u(in->sin_port);

        break;
    case AF_INET6:
        in6 = (const struct sockaddr_in6 *)&addr;
        CHECK(0 == uv_ip6_name(in6, addr_s->host, sizeof(addr_s->host)));
        addr_s->port = htons_u(in6->sin6_port);

        break;
    default:
        UNREACHABLE();
    }

    return 0;
}


int str_tcp_endpoint(const uv_tcp_t *tcp_handle, endpoint ep, ADDRESS *addr_s) {
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    int addr_len = sizeof(s);

    if ( ep == peer ) {
        CHECK(0 == uv_tcp_getpeername(tcp_handle,
                                      &s.addr,
                                      &addr_len));
    } else if ( ep == sock ) {
        CHECK(0 == uv_tcp_getsockname(tcp_handle,
                                      &s.addr,
                                      &addr_len));
    } else {
        UNREACHABLE();
    }

    return str_sockaddr(&s.addr, addr_s);
}


int str_udp_endpoint(const uv_udp_t *udp_handle, ADDRESS *addr_s) {
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    int addr_len = sizeof(s);

    CHECK(0 == uv_udp_getsockname(udp_handle,
                                  &s.addr,
                                  &addr_len));

    return str_sockaddr(&s.addr, addr_s);
}
