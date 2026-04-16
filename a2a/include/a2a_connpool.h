#ifndef A2A_CONNPOOL_H
#define A2A_CONNPOOL_H

#include "a2a_message.h"

#define POOL_MAX_CONNS  64

typedef struct {
    char key[A2A_MAX_HOST_LEN + 12];  /* "host:port\0" */
    int  fd;
    uint64_t last_used_us;
    int  valid;
} pool_entry_t;

typedef struct {
    pool_entry_t entries[POOL_MAX_CONNS];
    int          count;
} conn_pool_t;

void conn_pool_init   (conn_pool_t *pool);
void conn_pool_destroy(conn_pool_t *pool);

/*
 * Send msg via a pooled connection to host:port.
 * Serializes, connects (or reuses), sends, handles retry.
 * Returns 0 on success, -1 on failure.
 */
int  conn_pool_send(conn_pool_t *pool,
                    const char *host, int port,
                    const a2a_message_t *msg);

/* Evict all connections idle longer than idle_us microseconds */
void conn_pool_gc(conn_pool_t *pool, uint64_t idle_us);


/* Evict a single peer's connection (safe: does not touch other peers) */
void conn_pool_evict_peer(conn_pool_t *pool, const char *host, int port);
#endif /* A2A_CONNPOOL_H */
