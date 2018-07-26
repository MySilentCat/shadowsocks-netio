//
// Created by raven on 2018/7/26.
//

#ifndef SHADOWSOCKS_NETIO_INTERNAL_H
#define SHADOWSOCKS_NETIO_INTERNAL_H

#include <assert.h>
#include "../program/s5.h"

/* Session states. */
enum sess_state {
    s_handshake,        /* Wait for client handshake. */
    s_auth_start,       /* Start auth username password */
    s_req_start,        /* Start waiting for request data. */
    s_req_parse,        /* Wait for request data. */
    s_req_lookup,       /* Wait for upstream hostname DNS lookup to complete. */
    s_req_connect,      /* Wait for uv_tcp_connect() to complete. */
    s_proxy_start,      /* Connected. Start piping data. */
    s_proxy,            /* Connected. Pipe data back and forth. */
    s_kill,             /* Tear down session. */
    s_almost_dead_0,    /* Waiting for finalizers to complete. */
    s_almost_dead_1,    /* Waiting for finalizers to complete. */
    s_almost_dead_2,    /* Waiting for finalizers to complete. */
    s_almost_dead_3,    /* Waiting for finalizers to complete. */
    s_almost_dead_4,    /* Waiting for finalizers to complete. */
    s_dead,             /* Dead. Safe to free now. */

    s_max
};

enum conn_state {
    c_busy,  /* Busy; waiting for incoming data or for a write to complete. */
    c_done,  /* Done; read incoming data or write finished. */
    c_stop,  /* Stopped. */
    c_dead
};

typedef enum {
    peer,
    sock
}endpoint;


typedef struct {
    unsigned char rdstate;
    unsigned char wrstate;
    unsigned int idle_timeout;
    struct PROXY_NODE *pn;  /* Backlink */
    ssize_t result;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_timer_t timer_handle;  /* For detecting timeouts. */
    uv_write_t write_req;
    /* We only need one of these at a time so make them share memory. */
    union {
        uv_getaddrinfo_t addrinfo_req;
        uv_connect_t connect_req;
        uv_req_t req;
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } t;

    SSNETIO_BUF ss_buf;
} CONN;

typedef struct PROXY_NODE {
    int state;
    unsigned int index;
    CONN incoming;  /* Connection with the SOCKS client. */
    CONN outgoing;  /* Connection with upstream. */
    int outstanding;

    char link_info[128];

    void *data;
} PROXY_NODE;



#define BREAK_LABEL                                     \
    cleanup

#define BREAK_ON_FAILURE_WITH_LABEL(_status, label)     \
if ( (_status) != 0 )                                   \
    goto label

#define BREAK_ON_FAILURE(_status)                       \
    BREAK_ON_FAILURE_WITH_LABEL(_status, BREAK_LABEL)

#define BREAK_ON_NULL_WITH_LABEL(value, label)          \
if ( !(value) )                                         \
    goto label

#define BREAK_ON_NULL(_value)                           \
    BREAK_ON_NULL_WITH_LABEL(_value, BREAK_LABEL)

#define BREAK_ON_FALSE        BREAK_ON_NULL

#define BREAK_NOW                                       \
    goto BREAK_LABEL

#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)     do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS (0)
#else
# define ASSERT(exp)  assert(exp)
# define CHECK(exp)   assert(exp)
# define DEBUG_CHECKS (1)
#endif

#define ENSURE(exp)     do { if (!(exp)) abort(); } while (0)

#define UNREACHABLE()   CHECK(!"Unreachable code reached.")


#define htons_u(x)          (unsigned short)( (((x) & 0xffu) << 8u) | (((x) & 0xff00u) >> 8u) )
#define ntohs_u(x)          htons_u(x)

#define ntohl_u(x)        ( (((x) & 0xffu) << 24u) | \
                            (((x) & 0xff00u) << 8u) | \
                            (((x) & 0xff0000u) >> 8u) | \
                            (((x) & 0xff000000) >> 24u) )
#define htonl_u(x)          ntohl_u(x)


/* URIL.C */
int str_sockaddr(const struct sockaddr *addr, ADDRESS *addr_s);
int str_tcp_endpoint(const uv_tcp_t *tcp_handle, endpoint ep, ADDRESS *addr_s);
int str_udp_endpoint(const uv_udp_t *udp_handle, ADDRESS *addr_s);

#endif //SHADOWSOCKS_NETIO_INTERNAL_H
