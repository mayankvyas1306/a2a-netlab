#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

/* Send exactly 'len' bytes, retrying on partial sends. MSG_NOSIGNAL prevents SIGPIPE. */
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

    /* Header must be sent atomically; send_all retries until complete */
    if (send_all(fd, &netlen, 4) < 0)
        return -1;

    if (send_all(fd, json, len) < 0)
        return -1;

    return 0;
}
