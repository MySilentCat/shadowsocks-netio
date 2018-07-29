//
// Created by raven on 2018/7/26.
//

#include <stdlib.h>
#include "uv.h"
#include "shadowsocks-netio/shadowsocks-netio.h"
#include "internal.h"


static SSNETIO_SERVER_CTX srv_ctx;

static int server_run(SSNETIO_SERVER_CTX *ctx);

static void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void on_connection(uv_stream_t *server, int status);

static void conn_read(CONN *c);
static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void conn_write(CONN *c, const void *data, unsigned int len);
static void conn_write_done(uv_write_t *req, int status);
static void conn_getaddrinfo_done(uv_getaddrinfo_t *req, int status, struct addrinfo *ai);
static void conn_connect_done(uv_connect_t *req, int status);
static int conn_cycle(const char *who, CONN *a, CONN *b);
static void conn_close(CONN *c);
static void conn_close_done(uv_handle_t *handle);
static void conn_timer_reset(CONN *c);
static void conn_timer_expire(uv_timer_t *handle);

static void do_next(PROXY_NODE *pn);
static int do_handshake(PROXY_NODE *pn);
static int do_req_lookup(PROXY_NODE *pn);
static int do_req_connect(PROXY_NODE *pn);
static int do_proxy_start(PROXY_NODE *pn);
static int do_proxy(PROXY_NODE *cx);
static int do_kill(PROXY_NODE *pn);
static int do_almost_dead(PROXY_NODE *pn);
static int do_clear(PROXY_NODE *pn);

static void notify_msg_out(int level, const char *format, ...);
static void notify_bind(const char *host, unsigned short port);

static void notify_connection_made(PROXY_NODE *pn);

static void handle_new_session(CONN *conn);

static void handle_session_teardown(PROXY_NODE *pn);

static int handle_alloc_mem(CONN *conn, size_t size);
static void handle_free_mem(CONN *conn);

static int handle_parse_addr(CONN *conn);
static int handle_data_recv(CONN *conn);


int ssnetio_server_launch(SSNETIO_SERVER_CTX *ctx) {
    int ret = -1;

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->callbacks.on_data_recv);
    BREAK_ON_NULL(ctx->callbacks.on_parse_addr);
    BREAK_ON_NULL(ctx->callbacks.on_alloc_mem);
    BREAK_ON_NULL(ctx->callbacks.on_free_mem);

    memcpy(&srv_ctx, ctx, sizeof(srv_ctx));
    if ( !srv_ctx.config.bind_host )
        srv_ctx.config.bind_host = DEFAULT_SERVER_BIND_HOST;
    if ( !srv_ctx.config.bind_port )
        srv_ctx.config.bind_port = DEFAULT_SERVER_BIND_PORT;
    if ( !srv_ctx.config.idel_timeout )
        srv_ctx.config.idel_timeout = DEFAULT_SERVER_IDEL_TIMEOUT;

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


static void do_bind(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
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

        CHECK(0 == uv_inet_ntop(
            s.addr.sa_family,
            addrv,
            addrbuf,
            sizeof(addrbuf)));

        ENSURE((tcp_handle = malloc(sizeof(*tcp_handle))) != NULL);
        CHECK(0 == uv_tcp_init(loop, tcp_handle));

        ret = uv_tcp_bind(tcp_handle, &s.addr, 0);
        if ( 0 != ret ) {
            notify_msg_out(
                1,
                "tcp bind to %s:%d failed: %s",
                addrbuf,
                port,
                uv_strerror(ret));
            abort();
        }

        ret = uv_listen((uv_stream_t *)tcp_handle, SOMAXCONN, on_connection);
        if ( 0 != ret ) {
            notify_msg_out(
                1,
                "tcp listen to %s:%d failed: %s",
                addrbuf,
                port,
                uv_strerror(ret));
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
    memset(pn, 0, sizeof(*pn));

    pn->state = s_handshake;
    pn->outstanding = 0;
    pn->index = index++;
    pn->loop = loop;
    pn->data = NULL;

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
    incoming->data_offset = 0;
    CHECK(0 == uv_timer_init(loop, &incoming->timer_handle));


    CHECK(0 == uv_tcp_init(loop, &outgoing->handle.tcp));
    uv_handle_set_data((uv_handle_t *)&outgoing->handle.tcp, outgoing);
    outgoing->pn = pn;
    outgoing->result = 0;
    outgoing->rdstate = c_stop;
    outgoing->wrstate = c_stop;
    outgoing->idle_timeout = srv_ctx.config.idel_timeout;
    outgoing->ss_buf.buf_base = NULL;
    outgoing->ss_buf.buf_len = 0;
    outgoing->data_offset = 0;
    CHECK(0 == uv_timer_init(loop, &outgoing->timer_handle));

    /* Emit a notify */
    handle_new_session(incoming);

    /* Wait for the initial packet. */
    conn_read(incoming);
}


static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    CONN *conn;

    conn = uv_handle_get_data(handle);

    handle_alloc_mem(conn, size);
    buf->base = conn->ss_buf.buf_base;
    buf->len = conn->ss_buf.buf_len;
}

static void conn_read(CONN *c) {
    ASSERT(c->rdstate == c_stop);
    CHECK(0 == uv_read_start(&c->handle.stream, conn_alloc, conn_read_done));
    c->rdstate = c_busy;
    conn_timer_reset(c);
}

static void conn_read_done(
    uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    CONN *conn;

    conn = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(conn->ss_buf.buf_base == buf->base);
    ASSERT(conn->rdstate == c_busy);
    conn->rdstate = c_done;
    conn->result = nread;

    if ( nread > 0 )
        handle_data_recv(conn);

    uv_read_stop(&conn->handle.stream);
    do_next(conn->pn);
}

static void conn_write(CONN *c, const void *data, unsigned int len) {
    uv_buf_t buf;

    ASSERT(c->wrstate == c_stop || c->wrstate == c_done);
    c->wrstate = c_busy;

    buf.base = (char *)data;
    buf.len = len;

    CHECK(0 == uv_write(&c->write_req,
                        &c->handle.stream,
                        &buf,
                        1,
                        conn_write_done));
    c->pn->outstanding++;
    conn_timer_reset(c);
}

static void conn_write_done(uv_write_t *req, int status) {
    CONN *c;
    CONN *p;

    c = CONTAINER_OF(req, CONN, write_req);
    c->pn->outstanding--;
    ASSERT(c->wrstate == c_busy);
    c->wrstate = c_done;
    c->result = status;

    p = c == &c->pn->incoming ? &c->pn->outgoing : &c->pn->incoming;
    handle_free_mem(p);

    do_next(c->pn);
}

static void conn_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *ai) {
    CONN *incoming;
    CONN *outgoing;

    outgoing = CONTAINER_OF(req, CONN, t.addrinfo_req);
    ASSERT(outgoing == &outgoing->pn->outgoing);
    outgoing->result = status;

    incoming = &outgoing->pn->incoming;

    if ( status == 0 ) {
        if ( ai->ai_family == AF_INET ) {
            outgoing->t.addr4 = *(const struct sockaddr_in *)ai->ai_addr;
            outgoing->t.addr4.sin_port = htons_u(outgoing->peer.port);
        }
        else if ( ai->ai_family == AF_INET6 ) {
            outgoing->t.addr6 = *(const struct sockaddr_in6 *)ai->ai_addr;
            outgoing->t.addr6.sin6_port = htons_u(outgoing->peer.port);
        }
        else {
            UNREACHABLE();
        }
    }

    uv_freeaddrinfo(ai);

    incoming->pn->outstanding--;
    do_next(incoming->pn);
}

static void conn_connect_done(uv_connect_t *req, int status) {
    CONN *c;

    c = CONTAINER_OF(req, CONN, t.connect_req);
    c->result = status;

    c->pn->outstanding--;
    do_next(c->pn);
}

static int conn_cycle(const char *who, CONN *a, CONN *b) {
    if ( a->result < 0 ) {
        if ( a->result != UV_EOF ) {
            notify_msg_out(
                1,
                "[%d] %s error: %s [%s]",
                a->pn->index,
                who,
                uv_strerror((int)a->result),
                a->pn->link_info);
        }

        return -1;
    }

    if ( b->result < 0 ) {
        return -1;
    }

    if ( a->wrstate == c_done ) {
        a->wrstate = c_stop;
    }

    /* The logic is as follows: read when we don't write and write when we don't
     * read.  That gives us back-pressure handling for free because if the peer
     * sends data faster than we consume it, TCP congestion control kicks in.
     */
    if ( a->wrstate == c_stop ) {
        if ( b->rdstate == c_stop ) {
            conn_read(b);
        }
        else if ( b->rdstate == c_done ) {
            conn_write(a, b->ss_buf.buf_base, (unsigned int)b->result);
            b->rdstate = c_stop;  /* Triggers the call to conn_read() above. */
        }
    }

    return 0;
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

static void conn_timer_reset(CONN *c) {
    CHECK(0 == uv_timer_start(&c->timer_handle,
                              conn_timer_expire,
                              c->idle_timeout,
                              0));
}

static void conn_timer_expire(uv_timer_t *handle) {
    CONN *c;
    CONN *incoming;
    CONN *outgoing;

    c = CONTAINER_OF(handle, CONN, timer_handle);

    incoming = &c->pn->incoming;
    outgoing = &c->pn->outgoing;

    switch ( c->pn->state ) {
    case s_handshake:
        ASSERT(c == incoming);
        incoming->result = UV_ETIMEDOUT;
        break;
    case s_req_lookup:
    case s_req_connect:
    case s_proxy_start:
        outgoing->result = UV_ETIMEDOUT;
        break;
    default:
        c->result = UV_ETIMEDOUT;
        break;
    }

    do_next(c->pn);
}



static void do_next(PROXY_NODE *pn) {
    int new_state = s_max;

    ASSERT(pn->state != s_dead);
    switch (pn->state) {
    case s_handshake:
        new_state = do_handshake(pn);
        break;
    case s_req_lookup:
        new_state = do_req_lookup(pn);
        break;
    case s_req_connect:
        new_state = do_req_connect(pn);
        break;
    case s_proxy_start:
        new_state = do_proxy_start(pn);
        break;
    case s_proxy:
        new_state = do_proxy(pn);
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

    if ( pn->state == s_dead )
        do_clear(pn);
}

static int do_handshake(PROXY_NODE *pn) {
    CONN *incoming;
    int ret, new_state;
    struct addrinfo hints;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        notify_msg_out(1, "[%d] Handshake Read Error: %s",
                       pn->index, uv_strerror((int)incoming->result));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_done);
    ASSERT(incoming->wrstate == c_stop);
    incoming->rdstate = c_stop;

    /* Parser to get dest address */
    ret = handle_parse_addr(incoming);
    if ( 0 != ret ) {
        notify_msg_out(1, "[%d] Handshake Parse Addr Error", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    uv_req_set_data((uv_req_t*)&pn->outgoing.t.addrinfo_req,
        (void*)(size_t)pn->index);

    CHECK(0 == uv_getaddrinfo(pn->loop,
                              &pn->outgoing.t.addrinfo_req,
                              conn_getaddrinfo_done,
                              pn->outgoing.peer.host,   /* Got from handle_parse_addr */
                              NULL,
                              &hints));
    pn->outstanding++;
    conn_timer_reset(&pn->outgoing);

    new_state = s_req_lookup;

BREAK_LABEL:

    return new_state;
}

static int do_req_lookup(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int ret = s_req_connect;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        notify_msg_out(1, "[%d] Lookup Error For %s : %s",
                       pn->index,
                       outgoing->peer.host,
                       uv_strerror((int)outgoing->result));

        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    ASSERT(outgoing->t.addr.sa_family == AF_INET ||
           outgoing->t.addr.sa_family == AF_INET6);

    CHECK(0 == uv_tcp_connect(&outgoing->t.connect_req,
                              &outgoing->handle.tcp,
                              &outgoing->t.addr,
                              conn_connect_done));
    pn->outstanding++;
    conn_timer_reset(outgoing);

BREAK_LABEL:

    return ret;
}


static int do_req_connect(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int ret;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result != 0 ) {
        notify_msg_out(
            1,
            "[%d] Connect to %s:%d failed: %s",
            pn->index,
            outgoing->peer.host,
            outgoing->peer.port,
            uv_strerror((int)outgoing->result));
        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    notify_connection_made(pn);

    memset(pn->link_info, 0, sizeof(pn->link_info));
    sprintf(pn->link_info, "%s:%d -> %s:%d",
            incoming->peer.host,
            incoming->peer.port,
            outgoing->peer.host,
            outgoing->peer.port);

    if ( incoming->ss_buf.data_len == incoming->data_offset ) {
        handle_free_mem(incoming);
        conn_read(incoming);
        conn_read(outgoing);
        ret = s_proxy;
    }
    else {
        CHECK(incoming->ss_buf.data_len > incoming->data_offset);
        conn_write(
            outgoing,
            incoming->ss_buf.buf_base + incoming->data_offset,
            (unsigned int)incoming->ss_buf.data_len - incoming->data_offset);
        ret = s_proxy_start;
    }

BREAK_LABEL:

    return ret;
}


static int do_proxy_start(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int ret = s_proxy;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        notify_msg_out(
            1,
            "[%d] Proxy Start Write Error: %s [%s]",
            pn->index,
            uv_strerror((int)outgoing->result), pn->link_info);
        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_done);
    outgoing->wrstate = c_stop;

    conn_read(incoming);
    conn_read(outgoing);

BREAK_LABEL:

    return ret;
}

static int do_proxy(PROXY_NODE *cx) {
    int ret = s_proxy;

    if ( conn_cycle("client", &cx->incoming, &cx->outgoing)) {
        ret = do_kill(cx);
        BREAK_NOW;
    }

    if ( conn_cycle("upstream", &cx->outgoing, &cx->incoming)) {
        ret = do_kill(cx);
        BREAK_NOW;
    }

BREAK_LABEL:

    return ret;
}



static int do_kill(PROXY_NODE *pn) {
    int new_state = s_almost_dead_1;

    if ( pn->outstanding != 0 ) {
        /* Wait for uncomplete write operation */
        notify_msg_out(
            2,
            "[%d] Waitting outstanding operation, current %d [%s]",
            pn->index, pn->outstanding, pn->link_info);
        new_state = s_kill;
        BREAK_NOW;
    }


    if ( pn->state >= s_almost_dead_0 ) {
        new_state = pn->state;
        BREAK_NOW;
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

static int do_clear(PROXY_NODE *pn) {

    if ( pn->incoming.ss_buf.buf_base ) {
        handle_free_mem(&pn->incoming);
    }
    if ( pn->outgoing.ss_buf.buf_base ) {
        handle_free_mem(&pn->outgoing);
    }

    handle_session_teardown(pn);

    if ( DEBUG_CHECKS) {
        memset(pn, -1, sizeof(*pn));
    }
    free(pn);

    return 0;
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

static void notify_connection_made(PROXY_NODE *pn) {
    ADDRESS_PAIR pair;

    BREAK_ON_NULL(srv_ctx.callbacks.on_connection_made);

    pair.local = &pn->incoming.peer;
    pair.remote = &pn->outgoing.peer;

    srv_ctx.callbacks.on_connection_made(&pair, pn->data);

BREAK_LABEL:

    return;
}

static void handle_new_session(CONN *conn) {
    void *data = NULL;

    BREAK_ON_NULL(srv_ctx.callbacks.on_new_session);

    CHECK(0 == str_tcp_endpoint(&conn->handle.tcp, peer, &conn->peer));

    srv_ctx.callbacks.on_new_session(&conn->peer, &data);
    conn->pn->data = data;

BREAK_LABEL:

    return;
}

static void handle_session_teardown(PROXY_NODE *pn) {

    BREAK_ON_NULL(srv_ctx.callbacks.on_session_teardown);

    srv_ctx.callbacks.on_session_teardown(pn->data);

BREAK_LABEL:

    return;
}

static int handle_alloc_mem(CONN *conn, size_t size) {
    int ret;

    /* The suggest size from libuv too large */
    (void)size;

    CHECK(NULL == conn->ss_buf.buf_base);

    ret = srv_ctx.callbacks.on_alloc_mem(
        &conn->ss_buf,
        DEFAULT_MEMORY_BLOCK_SIZE,
        conn->pn->data);
    CHECK(NULL != conn->ss_buf.buf_base);

    return ret;
}

static void handle_free_mem(CONN *conn) {
    srv_ctx.callbacks.on_free_mem(&conn->ss_buf, conn->pn->data);
    conn->ss_buf.buf_base = NULL;
    conn->ss_buf.buf_len = 0;
    conn->ss_buf.data_len = 0;
}

static int handle_parse_addr(CONN *conn) {
    int ret;
    int offset;

    ASSERT(conn == &conn->pn->incoming);

    ret = srv_ctx.callbacks.on_parse_addr(
        &conn->pn->outgoing.peer,
        &conn->ss_buf,
        &offset,
        conn->pn->data);
    conn->data_offset = offset;

    return ret;
}

static int handle_data_recv(CONN *conn) {
    SSNETIO_BUF buf_new;
    int ret;

    int direct = conn == &conn->pn->incoming ? STREAM_UP : STREAM_DOWN;

    conn->ss_buf.data_len = (unsigned int)conn->result;
    ret = srv_ctx.callbacks.on_data_recv(
        &conn->ss_buf,
        &buf_new,
        direct,
        conn->pn->data);

    if ( buf_new.buf_base != conn->ss_buf.buf_base && buf_new.buf_base ) {
        handle_free_mem(conn);
        conn->ss_buf = buf_new;
    }
    conn->result = buf_new.data_len;

    return ret;
}
