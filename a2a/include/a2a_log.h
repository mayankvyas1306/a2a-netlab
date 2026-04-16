#ifndef A2A_LOG_H
#define A2A_LOG_H

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;

void a2a_log(log_level_t level, const char *module,
             const char *fmt, ...);

#define LOG_D(mod, fmt, ...) a2a_log(LOG_DEBUG, mod, fmt, ##__VA_ARGS__)
#define LOG_I(mod, fmt, ...) a2a_log(LOG_INFO,  mod, fmt, ##__VA_ARGS__)
#define LOG_W(mod, fmt, ...) a2a_log(LOG_WARN,  mod, fmt, ##__VA_ARGS__)
#define LOG_E(mod, fmt, ...) a2a_log(LOG_ERROR, mod, fmt, ##__VA_ARGS__)

#endif