#include "a2a_transport.h"
#include "a2a_serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "a2a_framing.h"
#include "a2a_event.h"
#include "a2a_agent.h"
#include "a2a_fsm.h"
#include "a2a_log.h"

#define MAX_EVENTS 64
#define RECV_BUF 65540
#define MAX_CLIENT_FDS 256
#define MAX_MSG_BYTES 65536u /* hard cap: reject oversized frames */
#define MAX_EXT_FDS 16

extern int ovsdb_connect(void);
extern int ovsdb_send_monitor(int fd);
extern void ovsdb_process_update(const char *json, a2a_agent_t *agent);
/* Store OVSDB fd for ovs_set_port_state */
extern void ovs_set_ovsdb_fd(int fd);

typedef enum
{
    WAITING_HEADER,
    WAITING_BODY
} recv_state_t;

typedef struct
{
    int fd;

    recv_state_t state;

    uint32_t expected_len;
    uint32_t received;

    int header_received;
    unsigned char header[4];

    char buf[RECV_BUF];

} fd_buf_t;

static fd_buf_t fd_bufs[MAX_CLIENT_FDS];

struct a2a_server
{
    int listen_fd;
    int epoll_fd;
    int port;
    int ovsdb_fd;
    char *ovsdb_buf;      /* dynamic — allocated at server_create */
    size_t ovsdb_buf_cap; /* total allocated capacity              */
    size_t ovsdb_buf_len; /* bytes currently in buffer             */
    char agent_id[A2A_MAX_AGENT_ID];
    a2a_msg_handler_t handler;
    void *userdata;

    struct
    {
        int fd;
        void (*handler)(int fd, void *ud);
        void *userdata;
    } ext_fds[MAX_EXT_FDS];

    int ext_fd_count;
};

/* ───────── FD BUFFER HELPERS ───────── */

static fd_buf_t *fd_buf_get(int fd)
{
    for (int i = 0; i < MAX_CLIENT_FDS; i++)
        if (fd_bufs[i].fd == fd)
            return &fd_bufs[i];
    return NULL;
}

static fd_buf_t *fd_buf_alloc(int fd)
{
    for (int i = 0; i < MAX_CLIENT_FDS; i++)
    {
        if (fd_bufs[i].fd == -1)
        {
            fd_bufs[i].fd = fd;
            fd_bufs[i].state = WAITING_HEADER;
            fd_bufs[i].expected_len = 0;
            fd_bufs[i].received = 0;
            fd_bufs[i].header_received = 0;
            return &fd_bufs[i];
        }
    }
    return NULL;
}

static void fd_buf_free(int fd)
{
    for (int i = 0; i < MAX_CLIENT_FDS; i++)
    {
        if (fd_bufs[i].fd == fd)
        {
            memset(&fd_bufs[i], 0, sizeof(fd_bufs[i]));

            fd_bufs[i].fd = -1;
            fd_bufs[i].state = WAITING_HEADER;

            return;
        }
    }
}

/* ───────── UTILS ───────── */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ───────── SERVER CREATE ───────── */

a2a_server_t *a2a_server_create(const char *agent_id,
                                int port,
                                a2a_msg_handler_t handler,
                                void *userdata)
{
    for (int i = 0; i < MAX_CLIENT_FDS; i++)
    {
        fd_bufs[i].fd = -1;
    }
    a2a_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv)
        return NULL;

    strncpy(srv->agent_id, agent_id, A2A_MAX_AGENT_ID - 1);
    srv->port = port;
    srv->handler = handler;
    srv->userdata = userdata;

    srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->listen_fd < 0)
    {
        free(srv);
        return NULL;
    }

    int opt = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(srv->listen_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    set_nonblocking(srv->listen_fd);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(srv->listen_fd);
        free(srv);
        return NULL;
    }
    if (listen(srv->listen_fd, 32) < 0)
    {
        perror("listen");
        close(srv->listen_fd);
        free(srv);
        return NULL;
    }

    srv->epoll_fd = epoll_create1(0);

    /* Dynamic OVSDB buffer — 256KB; initial monitor responses can exceed 64KB */
#define OVSDB_BUF_INIT_CAP (256 * 1024)
    srv->ovsdb_buf = malloc(OVSDB_BUF_INIT_CAP);
    if (!srv->ovsdb_buf)
    {
        close(srv->listen_fd);
        epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, srv->listen_fd, NULL);
        free(srv);
        return NULL;
    }
    srv->ovsdb_buf_cap = OVSDB_BUF_INIT_CAP;
    srv->ovsdb_buf_len = 0;

    /* OVSDB handled at agent layer — transport must not own it */
    srv->ovsdb_fd = -1;

    if (srv->epoll_fd < 0)
    {
        close(srv->listen_fd);
        free(srv);
        return NULL;
    }

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = srv->listen_fd};
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, srv->listen_fd, &ev);
    LOG_I("TRANSPORT", "%s listening on 0.0.0.0:%d", agent_id, port);
    return srv;
}

/* ───────── SERVER POLL ───────── */

int a2a_server_poll(a2a_server_t *srv, int timeout_ms)
{
    struct epoll_event events[MAX_EVENTS];
    int n = epoll_wait(srv->epoll_fd, events, MAX_EVENTS, timeout_ms);

    for (int i = 0; i < n; i++)
    {
        int fd = events[i].data.fd;

        /* External fd (OpenFlow, Netlink) — dispatch to registered handler */
        if (fd != srv->listen_fd && !fd_buf_get(fd))
        {
            int handled = 0;

            for (int ei = 0; ei < srv->ext_fd_count; ei++)
            {
                if (srv->ext_fds[ei].fd == fd)
                {
                    srv->ext_fds[ei].handler(
                        fd,
                        srv->ext_fds[ei].userdata);
                    handled = 1;
                    break;
                }
            }

            if (!handled)
            {
                epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                LOG_W("TRANSPORT", "Unknown fd=%d removed", fd);
            }
            continue;
        }

        if (fd == srv->listen_fd)
        {
            int client_fd;
            while ((client_fd = accept(srv->listen_fd, NULL, NULL)) >= 0)
            {
                set_nonblocking(client_fd);
                fd_buf_alloc(client_fd);
                struct epoll_event ev = {
                    .events = EPOLLIN,
                    .data.fd = client_fd};
                epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                LOG_I("TRANSPORT", "Client accepted fd=%d", client_fd);
            }
            continue; 
        }

        char tmp[RECV_BUF];
        ssize_t nbytes = recv(fd, tmp, sizeof(tmp), 0);

        if (nbytes <= 0)
        {
            if (nbytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                continue;

            epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            close(fd);
            fd_buf_free(fd);
            continue;
        }

        fd_buf_t *fdb = fd_buf_get(fd);
        if (!fdb)
            continue;

        int offset = 0;

        while (offset < nbytes)
        {

            /* HEADER */
            if (fdb->state == WAITING_HEADER)
            {

                int need = 4 - fdb->header_received;
                int take = (nbytes - offset < need) ? (nbytes - offset) : need;

                memcpy(fdb->header + fdb->header_received,
                       tmp + offset, take);

                fdb->header_received += take;
                offset += take;

                if (fdb->header_received == 4)
                {
                    uint32_t netlen;
                    memcpy(&netlen, fdb->header, 4);
                    fdb->expected_len = ntohl(netlen);

                    if (fdb->expected_len == 0 ||
                        fdb->expected_len > MAX_MSG_BYTES)
                    {
                        LOG_E("TRANSPORT",
                              "Invalid frame len=%u fd=%d — closing",
                              fdb->expected_len, fd);
                        if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL,
                                      fd, NULL) < 0 &&
                            errno != ENOENT)
                            LOG_W("TRANSPORT", "epoll_ctl DEL errno=%d", errno);
                        close(fd);
                        fd_buf_free(fd);
                        break;
                    }

                    fdb->received = 0;
                    fdb->state = WAITING_BODY;
                }
            }

            /* BODY */
            else if (fdb->state == WAITING_BODY)
            {

                int need = fdb->expected_len - fdb->received;
                int take = (nbytes - offset < need) ? (nbytes - offset) : need;

                memcpy(fdb->buf + fdb->received,
                       tmp + offset, take);

                fdb->received += take;
                offset += take;

                if (fdb->received == fdb->expected_len)
                {

                    fdb->buf[fdb->received] = '\0';

                    a2a_message_t msg = {0};
                    if (a2a_deserialize(fdb->buf, &msg) == 0 && srv->handler)
                        srv->handler(&msg, srv->userdata);

                    /* reset */
                    fdb->state = WAITING_HEADER;
                    fdb->header_received = 0;
                    fdb->expected_len = 0;
                    fdb->received = 0;
                }
            }
        }
    }

    return n;
}

/* Register external fds (Netlink, OpenFlow) with the server's epoll. */
int a2a_server_add_fd(a2a_server_t *srv, int fd)
{
    if (!srv || fd < 0)
        return -1;
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
    if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        LOG_E("TRANSPORT", "epoll_ctl ADD fd=%d errno=%d", fd, errno);
        return -1;
    }
    LOG_I("TRANSPORT", "External fd=%d added to epoll", fd);
    return 0;
}

int a2a_server_del_fd(a2a_server_t *srv, int fd)
{
    if (!srv || fd < 0)
        return -1;
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    return 0;
}

/* ───────── DESTROY ───────── */

void a2a_server_destroy(a2a_server_t *srv)
{
    if (!srv)
        return;

    /* Null callbacks first to prevent use-after-free from in-flight events */
    srv->handler = NULL;
    srv->userdata = NULL;

    /* Close OVSDB fd if open */
    if (srv->ovsdb_fd >= 0)
    {
        epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, srv->ovsdb_fd, NULL);
        close(srv->ovsdb_fd);
        srv->ovsdb_fd = -1;
    }

    /* Close all accepted client fds tracked in fd_bufs */
    for (int i = 0; i < MAX_CLIENT_FDS; i++)
    {
        if (fd_bufs[i].fd >= 0)
        {
            epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, fd_bufs[i].fd, NULL);
            close(fd_bufs[i].fd);
            fd_bufs[i].fd = -1;
        }
    }

    /* Free dynamic OVSDB buffer */
    free(srv->ovsdb_buf);
    srv->ovsdb_buf = NULL;

    /* Close listen socket and epoll instance */
    close(srv->listen_fd);
    close(srv->epoll_fd);
    free(srv);
}

/* ───────── SEND ───────── */

int a2a_send(const char *dst_host, int dst_port, const a2a_message_t *msg)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)dst_port);

    if (inet_pton(AF_INET, dst_host, &addr.sin_addr) <= 0)
    {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

    char *json = a2a_serialize(msg);
    if (!json)
    {
        close(fd);
        return -1;
    }

    int rc = frame_send(fd, json);
    free(json);
    close(fd);

    return (rc < 0) ? -1 : 0;
}

int a2a_server_add_ext_fd(a2a_server_t *srv,
                          int fd,
                          void (*handler)(int fd, void *ud),
                          void *ud)
{
    if (!srv || fd < 0 || !handler)
        return -1;

    if (srv->ext_fd_count >= MAX_EXT_FDS)
        return -1;

    srv->ext_fds[srv->ext_fd_count].fd = fd;
    srv->ext_fds[srv->ext_fd_count].handler = handler;
    srv->ext_fds[srv->ext_fd_count].userdata = ud;
    srv->ext_fd_count++;

    return 0;
}

void a2a_server_del_ext_fd(a2a_server_t *srv, int fd)
{
    if (!srv)
        return;

    for (int i = 0; i < srv->ext_fd_count; i++)
    {
        if (srv->ext_fds[i].fd == fd)
        {
            srv->ext_fds[i] = srv->ext_fds[srv->ext_fd_count - 1];
            srv->ext_fd_count--;
            return;
        }
    }
}