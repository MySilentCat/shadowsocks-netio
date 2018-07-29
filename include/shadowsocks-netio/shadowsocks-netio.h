//
// Created by raven on 2018/7/26.
//

#ifndef SHADOWSOCKS_NETIO_H
#define SHADOWSOCKS_NETIO_H

#include <stddef.h>
#include <netinet/in.h>
#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_MEMORY_BLOCK_SIZE       10240

#define DEFAULT_SERVER_BIND_HOST        ("0.0.0.0")
#define DEFAULT_SERVER_BIND_PORT        (14450)
#define DEFAULT_SERVER_IDEL_TIMEOUT     (60 * 1000)

#define DEFAULT_CLIENT_BIND_HOST        ("127.0.0.1")
#define DEFAULT_CLIENT_BIND_PORT        (14550)
#define DEFAULT_CLIENT_IDEL_TIMEOUT     (60 * 1000)

enum {
    STREAM_UP,      /* local -> remote */
    STREAM_DOWN     /* remote -> local */
};

enum {
    ACTION_ACCEPT,
    ACTION_REJECT
};

typedef struct SSNETIO_BUF{
    char *buf_base;
    size_t buf_len;
    size_t data_len;
}SSNETIO_BUF;

typedef struct ADDRESS{
    char host[64];      /* HostName or IpAddress */
    unsigned short port;
}ADDRESS;

typedef struct ADDRESS_PAIR{
    ADDRESS *local;
    ADDRESS *remote;
}ADDRESS_PAIR;

typedef struct SSNETIO_CONFIG{
    const char *bind_host;
    unsigned short bind_port;
    unsigned int idel_timeout;
}SSNETIO_CONFIG;

typedef struct SSNETIO_SERVER_CALLBACKS{
    /* Event Notify, Can be NULL */
    void (*on_msg)(int level, const char *msg);

    void (*on_bind)(const char *host, unsigned short port);

    void (*on_connection_made)(ADDRESS_PAIR *addr, void *data);

    /* A new request coming,
     * set data to a context associate with this session
     * */
    void (*on_new_session)(ADDRESS *addr, void **data);
    void (*on_session_teardown)(void *data);


    /* Data Event, CANNOT be NULL */

    /* When data incoming, on_data_recv will be called,
     * buf contains the data received, before on_data_recv return,
     * new_buf should be filled with the encrypted/decrypted data.
     *
     * on_free_mem will be called when the buf in new_buf is no longer used.
     *
     * NOTE: if buf and new_buf has same buf_base (means data does not need to be encrypt/decrypt),
     *       on_free_mem will NOT be called twice on it.
     */
    int (*on_data_recv)(SSNETIO_BUF *buf, SSNETIO_BUF *new_buf, int direct, void *data);

    /* Parse the host/ip and port from incoming data. Set data_offset to actual data offset within buf */
    int (*on_parse_addr)(ADDRESS *addr, SSNETIO_BUF *buf, int *data_offset, void *data);

    /* Alloc/Free memory for recv operation */
    int (*on_alloc_mem)(SSNETIO_BUF *buf, size_t size, void *data);
    void (*on_free_mem)(SSNETIO_BUF *buf, void *data);
}SSNETIO_SERVER_CALLBACKS;

typedef struct SSNETIO_SERVER_CTX{
    SSNETIO_CONFIG config;
    SSNETIO_SERVER_CALLBACKS callbacks;
}SSNETIO_SERVER_CTX;

/* Negative value returned when error occur */
int ssnetio_server_launch(SSNETIO_SERVER_CTX *ctx);


#ifdef __cplusplus
}
#endif

#endif //SHADOWSOCKS_NETIO_H
