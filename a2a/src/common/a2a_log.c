#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "a2a_log.h"

static log_level_t g_log_level = LOG_INFO;

void a2a_log(log_level_t level, const char *module,
             const char *fmt, ...)
{
    if (level < g_log_level)
        return;

    static const char *lvl_str[] = {
        "DEBUG", "INFO ", "WARN ", "ERROR"
    };

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm_buf;
    localtime_r(&ts.tv_sec, &tm_buf);

    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm_buf);

    fprintf(stderr, "[%s.%03ld][%s][%s] ",
            tbuf, ts.tv_nsec / 1000000,
            lvl_str[level], module);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}