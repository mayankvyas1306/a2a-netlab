#include <unistd.h>
#include "a2a_connpool.h"
#include "a2a_serialize.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "a2a_framing.h"
#include <sys/select.h>
#include <sys/time.h>
#include <poll.h>
#include "a2a_log.h"

static void make_key(char *key, const char *host, int port)
{
    snprintf(key, A2A_MAX_HOST_LEN + 12, "%s:%d", host, port);
}

static int raw_connect(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    /* Non-blocking connect with 200ms timeout */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
    {
        close(fd);
        return -1;
    }

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS)
    {
        close(fd);
        return -1;
    }

    /* poll() instead of select() — same non-blocking connect, but
     * does not artificially serialize on a 200ms timeout per call.
     * 50ms is sufficient for LAN; longer means the peer is unreachable. */
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    if (poll(&pfd, 1, 50) <= 0 || !(pfd.revents & POLLOUT))
    {
        close(fd);
        return -1;
    }
    /* Check for connect error */
    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err)
    {
        close(fd);
        return -1;
    }

    /* Restore blocking */
    fcntl(fd, F_SETFL, flags);
    return fd;
}

void conn_pool_init(conn_pool_t *pool)
{
    memset(pool, 0, sizeof(*pool));
    for (int i = 0; i < POOL_MAX_CONNS; i++)
        pool->entries[i].fd = -1;
}

void conn_pool_destroy(conn_pool_t *pool)
{
    for (int i = 0; i < POOL_MAX_CONNS; i++)
        if (pool->entries[i].valid && pool->entries[i].fd >= 0)
            close(pool->entries[i].fd);
    memset(pool, 0, sizeof(*pool));
    for (int i = 0; i < POOL_MAX_CONNS; i++)
    {
        pool->entries[i].fd = -1;
    }
}

static pool_entry_t *pool_find(conn_pool_t *pool, const char *key)
{
    for (int i = 0; i < POOL_MAX_CONNS; i++)
        if (pool->entries[i].valid &&
            strcmp(pool->entries[i].key, key) == 0)
            return &pool->entries[i];
    return NULL;
}

static pool_entry_t *pool_alloc(conn_pool_t *pool)
{
    /* Try to find empty slot */
    for (int i = 0; i < POOL_MAX_CONNS; i++)
    {
        if (!pool->entries[i].valid)
            return &pool->entries[i];
    }

    /* Pool full — evict oldest */
    pool_entry_t *oldest = &pool->entries[0];

    for (int i = 1; i < POOL_MAX_CONNS; i++)
    {
        if (pool->entries[i].last_used_us < oldest->last_used_us)
            oldest = &pool->entries[i];
    }

    if (oldest->fd >= 0)
        close(oldest->fd);

    memset(oldest, 0, sizeof(*oldest));

    oldest->fd = -1;
    oldest->valid = 0;

    return oldest;
}

static void pool_evict(conn_pool_t *pool, const char *key)
{
    pool_entry_t *e = pool_find(pool, key);
    if (!e)
        return;
    if (e->fd >= 0)
        close(e->fd);
    memset(e, 0, sizeof(*e));
    e->fd = -1;
}

/* Public: evict the pooled connection to a specific peer.
 * Used by on_peer_timeout to close only the dead peer's socket
 * without touching connections to any other peer.
 */
void conn_pool_evict_peer(conn_pool_t *pool,
                          const char *host, int port)
{
    char key[A2A_MAX_HOST_LEN + 12];
    make_key(key, host, port);
    pool_evict(pool, key);
    LOG_D("POOL", "evicted connection to %s", key);
}

int conn_pool_send(conn_pool_t *pool,
                   const char *host, int port,
                   const a2a_message_t *msg)
{
    char key[A2A_MAX_HOST_LEN + 12];
    make_key(key, host, port);

    char *json = a2a_serialize(msg);
    if (!json)
        return -1;

    for (int attempt = 0; attempt < 2; attempt++)
    {

        // ALWAYS try fresh connection after first failure
        pool_entry_t *e = pool_find(pool, key);

        if (attempt > 0 && e)
        {
            /* Evict stale connection and wait briefly before retry.
             * The remote TCP stack needs time to accept a new SYN
             * after closing the previous connection. */
            pool_evict(pool, key);
            e = NULL;
            usleep(50000); /* 50ms: enough for TCP RST to clear */
        }

        if (!e)
        {
            int fd = raw_connect(host, port);
            if (fd < 0)
            {
                LOG_W("POOL", "connect failed key=%s attempt=%d", key, attempt + 1);
                continue; /* immediate retry — no blocking sleep */
            }

            e = pool_alloc(pool);
            strncpy(e->key, key, sizeof(e->key) - 1);
            e->fd = fd;
            e->valid = 1;
        }

        if (frame_send(e->fd, json) == 0)
        {
            e->last_used_us = a2a_now_us();
            free(json);
            return 0;
        }

        LOG_W("POOL", "send failed key=%s attempt=%d", key, attempt + 1);

        //  ALWAYS evict on failure
        pool_evict(pool, key);
    }

    LOG_E("POOL", "final send failure key=%s", key);

    free(json);
    return -1;
}
void conn_pool_gc(conn_pool_t *pool, uint64_t idle_us)
{
    uint64_t now = a2a_now_us();
    for (int i = 0; i < POOL_MAX_CONNS; i++)
    {
        pool_entry_t *e = &pool->entries[i];
        if (!e->valid)
            continue;
        /*
         * Skip entries whose last_used_us is 0 (just-allocated,
         * never sent through).  now - 0 wraps to a huge number
         * and would immediately evict a freshly-opened connection.
         */
        if (e->last_used_us == 0)
            continue;
        if (now - e->last_used_us > idle_us)
        {
            LOG_D("POOL", "GC: evicting idle conn %s", e->key);
            if (e->fd >= 0)
                close(e->fd);
            memset(e, 0, sizeof(*e));
            e->fd = -1;
        }
    }
}
