//
// Created by raven on 2018/7/26.
//

#include <stdlib.h>
#include <assert.h>

#include "uv.h"
#include "../program/s5.h"
#include "shadowsocks-netio/shadowsocks-netio.h"
#include "internal.h"


static SSNETIO_SERVER_CTX srv_ctx;


static int server_run(SSNETIO_SERVER_CTX *ctx);

static void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void on_connection(uv_stream_t *server, int status);

static void conn_read(CONN *c);
static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void conn_close(CONN *c);
static void conn_close_done(uv_handle_t *handle);

static void do_next(PROXY_NODE *pn);
static int do_handshake(PROXY_NODE *pn);
static int do_kill(PROXY_NODE *pn);
static int do_almost_dead(PROXY_NODE *pn);

static void notify_msg_out(int level, const char *format, ...);
static void notify_bind(const char *host, unsigned short port);

static void handle_new_session(CONN *conn);
static void handle_alloc_mem(CONN *conn);
static void handle_free_mem(CONN *conn);
static int handle_data_recv(CONN *conn);

int ssnetio_server_launch(SSNETIO_SERVER_CTX *ctx) {
    int ret = -1;

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->callbacks.on_new_session);
    BREAK_ON_NULL(ctx->callbacks.on_data_recv);
    BREAK_ON_NULL(ctx->callbacks.on_alloc_mem);
    BREAK_ON_NULL(ctx->callbacks.on_free_mem);

    memcpy(&srv_ctx, ctx, sizeof(srv_ctx));
    if ( !srv_ctx.config.bind_host ) srv_ctx.config.bind_host = DEFAULT_SERVER_BIND_HOST;
    if ( !srv_ctx.config.bind_port ) srv_ctx.config.bind_port = DEFAULT_SERVER_BIND_PORT;
    if ( !srv_ctx.config.idel_timeout ) srv_ctx.config.idel_timeout = DEFAULT_SERVER_IDEL_TIMEOUT;

    ret = server_run(&srv_ctx);
BREAK_LABEL:
    return ret;
}

static int server_run(SSNETIO_SERVER_CTX *ctx) {
    struct addrinfo hints;
    uv_loop_t *loop;
    int ret;
    uv_getaddrinfo_t req;

    loop = uv_default_loop();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    uv_req_set_data((uv_req_t *)&req, loop);
    ret = uv_getaddrinfo(loop,
                         &req,
                         do_bind,
                         ctx->config.bind_host,
                         NULL,
                         &hints);
    if ( 0 != ret ) {
        notify_msg_out(1, "uv_getaddrinfo failed: %s", uv_strerror(ret));
    }
    BREAK_ON_FAILURE(ret);

    /* Start the event loop.  Control continues in do_bind(). */
    uv_run(loop, UV_RUN_DEFAULT);

    uv_loop_delete(loop);

BREAK_LABEL:

    return ret;
}


static void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    char addrbuf[INET6_ADDRSTRLEN + 1];
    unsigned int ipv4_naddrs;
    unsigned int ipv6_naddrs;
    unsigned short port;
    struct addrinfo *ai;
    const void *addrv = NULL;
    uv_loop_t *loop;
    int ret;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } s;
    uv_tcp_t *tcp_handle;


    if ( status < 0 ) {
        notify_msg_out(1, "uv_getaddrinfo failed: %s", uv_strerror(status));
        BREAK_NOW;
    }

    loop = uv_req_get_data((uv_req_t *)req);

    ipv4_naddrs = 0;
    ipv6_naddrs = 0;
    for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
        if ( ai->ai_family == AF_INET ) {
            ipv4_naddrs++;
        }
        else if ( ai->ai_family == AF_INET6 ) {
            ipv6_naddrs++;
        }
    }

    if ( ipv4_naddrs == 0 && ipv6_naddrs == 0 )
        BREAK_NOW;

    port = srv_ctx.config.bind_port;
    for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
        if ( ai->ai_family != AF_INET && ai->ai_family != AF_INET6 ) {
            continue;
        }

        if ( ai->ai_family == AF_INET ) {
            s.addr4 = *(const struct sockaddr_in *)ai->ai_addr;
            s.addr4.sin_port = htons_u(port);
            addrv = &s.addr4.sin_addr;
        }
        else if ( ai->ai_family == AF_INET6 ) {
            s.addr6 = *(const struct sockaddr_in6 *)ai->ai_addr;
            s.addr6.sin6_port = htons_u(port);
            addrv = &s.addr6.sin6_addr;
        }
        else {
            UNREACHABLE();
        }

        CHECK(0 == uv_inet_ntop(s.addr.sa_family, addrv, addrbuf, sizeof(addrbuf)));

        ENSURE((tcp_handle = malloc(sizeof(*tcp_handle))) != NULL);
        CHECK(0 == uv_tcp_init(loop, tcp_handle));

        ret = uv_tcp_bind(tcp_handle, &s.addr, 0);
        if ( 0 != ret ) {
            notify_msg_out(1, "tcp bind to %s:%d failed: %s", addrv, port, uv_strerror(ret));
            abort();
        }

        ret = uv_listen((uv_stream_t *)tcp_handle, SOMAXCONN, on_connection);
        if ( 0 != ret ) {
            notify_msg_out(1, "tcp listen to %s:%d failed: %s", addrv, port, uv_strerror(ret));
            abort();
        }

        notify_bind(addrbuf, port);
    }

BREAK_LABEL:
    if ( addrs )
        uv_freeaddrinfo(addrs);
}

static void on_connection(uv_stream_t *server, int status) {
    static unsigned int index = 0;
    uv_loop_t *loop;
    PROXY_NODE *pn;
    CONN *incoming;
    CONN *outgoing;

    CHECK(status == 0);

    loop = uv_handle_get_loop((uv_handle_t *)server);

    ENSURE((pn = malloc(sizeof(*pn))) != NULL);

    pn->state = s_handshake;
    pn->outstanding = 0;
    pn->index = index++;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    CHECK(0 == uv_tcp_init(loop, &incoming->handle.tcp));
    CHECK(0 == uv_accept(server, &incoming->handle.stream));
    uv_handle_set_data((uv_handle_t *)&incoming->handle.tcp, incoming);

    incoming->pn = pn;
    incoming->result = 0;
    incoming->rdstate = c_stop;
    incoming->wrstate = c_stop;
    incoming->idle_timeout = srv_ctx.config.idel_timeout;
    incoming->ss_buf.buf_base = NULL;
    incoming->ss_buf.buf_len = 0;
    CHECK(0 == uv_timer_init(loop, &incoming->timer_handle));


    CHECK(0 == uv_tcp_init(loop, &outgoing->handle.tcp));
    uv_handle_set_data((uv_handle_t *)&incoming->handle.tcp, incoming);
    outgoing->pn = pn;
    outgoing->result = 0;
    outgoing->rdstate = c_stop;
    outgoing->wrstate = c_stop;
    outgoing->idle_timeout = srv_ctx.config.idel_timeout;
    outgoing->ss_buf.buf_base = NULL;
    outgoing->ss_buf.buf_len = 0;
    CHECK(0 == uv_timer_init(loop, &outgoing->timer_handle));

    /* Emit a notify */
    handle_new_session(incoming);

    /* Wait for the initial packet. */
    conn_read(incoming);
}

static void conn_read(CONN *c) {
    ASSERT(c->rdstate == c_stop);
    CHECK(0 == uv_read_start(&c->handle.stream, conn_alloc, conn_read_done));
    c->rdstate = c_busy;
    // conn_timer_reset(c);
}

static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    CONN *conn;

    conn = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(conn->ss_buf.buf_base == buf->base);
    ASSERT(conn->rdstate == c_busy);
    conn->rdstate = c_done;
    conn->result = nread;

    uv_read_stop(&conn->handle.stream);
    do_next(conn->pn);
}

static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    CONN *conn;
    (void)size;

    conn = uv_handle_get_data(handle);

    handle_alloc_mem(conn);
    buf->base = conn->ss_buf.buf_base;
    buf->len = conn->ss_buf.buf_len;
}

static void conn_close(CONN *c) {
    ASSERT(c->rdstate != c_dead);
    ASSERT(c->wrstate != c_dead);
    c->rdstate = c_dead;
    c->wrstate = c_dead;
    c->timer_handle.data = c;
    c->handle.handle.data = c;
    uv_close(&c->handle.handle, conn_close_done);
    uv_close((uv_handle_t *) &c->timer_handle, conn_close_done);
}

static void conn_close_done(uv_handle_t *handle) {
    CONN *c;

    c = uv_handle_get_data(handle);
    do_next(c->pn);
}













static void do_next(PROXY_NODE *pn) {
    int new_state = s_max;

    ASSERT(pn->state != s_dead);
    switch (pn->state) {
    case s_handshake:
        new_state = do_handshake(pn);
        break;
    case s_auth_start:
//        new_state = do_auth_start(pn);
        break;
    case s_req_start:
//        new_state = do_req_start(pn);
        break;
    case s_req_parse:
//        new_state = do_req_parse(pn);
        break;
    case s_req_lookup:
//        new_state = do_req_lookup(pn);
        break;
    case s_req_connect:
//        new_state = do_req_connect(pn);
        break;
    case s_proxy_start:
//        new_state = do_proxy_start(pn);
        break;
    case s_proxy:
//        new_state = do_proxy(pn);
        break;
    case s_kill:
        new_state = do_kill(pn);
        break;
    case s_almost_dead_0:
    case s_almost_dead_1:
    case s_almost_dead_2:
    case s_almost_dead_3:
    case s_almost_dead_4:
        new_state = do_almost_dead(pn);
        break;
    default:
        UNREACHABLE();
    }
    pn->state = new_state;

//    if (pn->state == s_dead)
//        do_clear(pn);
}

static int do_handshake(PROXY_NODE *pn) {
    CONN *incoming;
    int ret, new_state = s_kill;

    incoming = &pn->incoming;

    ASSERT(incoming->rdstate == c_done);
    ASSERT(incoming->wrstate == c_stop);
    incoming->rdstate = c_stop;

    if (incoming->result < 0) {
        notify_msg_out(1, "[%d] Handshake Read Error: %s", pn->index, uv_strerror((int)incoming->result));
        return do_kill(pn);
    }

    /* Decrypt data first */
    ret = handle_data_recv(incoming);
    switch ( ret ) {
    case ACTION_NONE:
        break;
    case ACTION_NEEDMORE:
    case ACTION_REJECT:
        handle_free_mem(incoming);
        conn_read(incoming);
        new_state = s_handshake;
        BREAK_NOW;
    default:
        UNREACHABLE();
    }

    /* Parser to get dest address */

BREAK_LABEL:

    return new_state;
}



static int do_kill(PROXY_NODE *pn) {
    int new_state;

    if ( pn->outstanding != 0 ) {
        /* Wait for uncomplete write operation */
        notify_msg_out(2, "[%d] Waitting outstanding operation, current %d [%s]",
                       pn->index, pn->outstanding, pn->link_info);
        new_state = s_kill;
        BREAK_NOW;
    }


    if (pn->state >= s_almost_dead_0) {
        new_state = pn->state;
        BREAK_NOW;
    }

    /* Try to cancel the request. The callback still runs but if the
     * cancellation succeeded, it gets called with status=UV_ECANCELED.
     */
    new_state = s_almost_dead_1;
    if (pn->state == s_req_lookup) {
        new_state = s_almost_dead_0;
        uv_cancel(&pn->outgoing.t.req);
    }

    conn_close(&pn->incoming);
    conn_close(&pn->outgoing);

BREAK_LABEL:

    return new_state;
}

static int do_almost_dead(PROXY_NODE *pn) {
    ASSERT(pn->state >= s_almost_dead_0);
    return pn->state + 1;  /* Another finalizer completed. */
}












static void notify_msg_out(int level, const char *format, ...) {
    va_list ap;
    char fmtbuf[1024];

    BREAK_ON_NULL(srv_ctx.callbacks.on_msg);

    va_start(ap, format);

    vsnprintf(fmtbuf, sizeof(fmtbuf), format, ap);
    srv_ctx.callbacks.on_msg(level, fmtbuf);

    va_end(ap);

BREAK_LABEL:

    return;
}

static void notify_bind(const char *host, unsigned short port) {

    BREAK_ON_NULL(srv_ctx.callbacks.on_bind);

    srv_ctx.callbacks.on_bind(host, port);

BREAK_LABEL:

    return;
}

static void handle_new_session(CONN *conn) {
    ADDRESS addr;
    int accept = 1;
    void *data = NULL;

    BREAK_ON_NULL(srv_ctx.callbacks.on_new_session);

    memset(&addr, 0, sizeof(addr));
    CHECK(0 == str_tcp_endpoint(&conn->handle.tcp, peer, &addr));

    srv_ctx.callbacks.on_new_session(&addr, &accept, &data);
    /* TODO: Handle Reject status */
    ASSERT(accept);
    conn->pn->data = data;

BREAK_LABEL:

    return;
}

static void handle_alloc_mem(CONN *conn) {
    CHECK(NULL == conn->ss_buf.buf_base);
    srv_ctx.callbacks.on_alloc_mem(&conn->ss_buf, conn->pn->data);
    CHECK(conn->ss_buf.buf_base);
}

static void handle_free_mem(CONN *conn) {
    srv_ctx.callbacks.on_free_mem(&conn->ss_buf, conn->pn->data);
    conn->ss_buf.buf_base = NULL;
    conn->ss_buf.buf_len = 0;
}

static int handle_data_recv(CONN *conn) {
    SSNETIO_BUF buf_new = {0};
    int ret;

    ret = srv_ctx.callbacks.on_data_recv(&conn->ss_buf, &buf_new, conn->pn->data);

    if ( buf_new.buf_base != conn->ss_buf.buf_base && buf_new.buf_base ) {
        handle_free_mem(conn);
        conn->ss_buf = buf_new;
    }

    return ret;
}
