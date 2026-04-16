#ifndef A2A_TRANSPORT_H
#define A2A_TRANSPORT_H

#include "a2a_message.h"

#define A2A_MAX_CLIENTS 64

#define MAX_EXT_FDS 16

typedef void (*a2a_msg_handler_t)(const a2a_message_t *msg, void *userdata);

typedef struct a2a_server a2a_server_t;

a2a_server_t *a2a_server_create(const char *agent_id,
                                 int port,
                                 a2a_msg_handler_t handler,
                                 void *userdata);

int  a2a_server_poll(a2a_server_t *srv, int timeout_ms);
void a2a_server_destroy(a2a_server_t *srv);

int  a2a_send(const char *dst_host, int dst_port, const a2a_message_t *msg);


int a2a_server_add_ext_fd(a2a_server_t *srv,
                          int fd,
                          void (*handler)(int fd, void *ud),
                          void *ud);

void a2a_server_del_ext_fd(a2a_server_t *srv, int fd);

int  a2a_server_add_fd(a2a_server_t *srv, int fd);
int  a2a_server_del_fd(a2a_server_t *srv, int fd);
#endif
