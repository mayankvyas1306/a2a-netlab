#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

/*
 * send_all() — send exactly 'len' bytes, retrying on partial sends.
 * Returns 0 on success, -1 on error or connection close.
 * MSG_NOSIGNAL prevents SIGPIPE on broken connections.
 */
static int send_all(int fd, const void *data, size_t len)
{
    const char *ptr = (const char *)data;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t n = send(fd, ptr, remaining, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue; /* signal interrupted, retry */
            return -1;
        }
        if (n == 0) return -1; /* connection closed */
        ptr       += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/* Send framed message: [4-byte big-endian length][json body] */
int frame_send(int fd, const char *json)
{
    uint32_t len    = (uint32_t)strlen(json);
    uint32_t netlen = htonl(len);

    /* Send 4-byte header — must be sent atomically to avoid split-header
     * corruption.  send_all() retries until all 4 bytes are accepted. */
    if (send_all(fd, &netlen, 4) < 0)
        return -1;

    /* Send body with partial-send retry */
    if (send_all(fd, json, len) < 0)
        return -1;

    return 0;
}
