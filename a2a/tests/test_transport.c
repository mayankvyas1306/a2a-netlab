#include <stdio.h>
#include <string.h>
#include "a2a_message.h"
#include "a2a_serialize.h"
#include "a2a_transport.h"
static int ok = 0;
void hb(const a2a_message_t *m, void *u) {
    (void)u;
    a2a_message_t p = {0};
    p.msg_id = 2; p.msg_type = MSG_PONG;
    strncpy(p.src_agent, "agent-b", A2A_MAX_AGENT_ID-1);
    strncpy(p.dst_agent, m->src_agent, A2A_MAX_AGENT_ID-1);
    strncpy(p.payload,   "pong", A2A_MAX_PAYLOAD-1);
    p.timestamp_us = a2a_now_us();
    a2a_send("127.0.0.1", 7801, &p);
}
void ha(const a2a_message_t *m, void *u) { (void)m; (void)u; ok = 1; }
int main(void) {
    a2a_server_t *sa = a2a_server_create("agent-a", 7801, ha, NULL);
    a2a_server_t *sb = a2a_server_create("agent-b", 7802, hb, NULL);
    a2a_message_t m = {0};
    m.msg_id = 1; m.msg_type = MSG_PING;
    strncpy(m.src_agent, "agent-a", A2A_MAX_AGENT_ID-1);
    strncpy(m.dst_agent, "agent-b", A2A_MAX_AGENT_ID-1);
    strncpy(m.payload,   "ping",    A2A_MAX_PAYLOAD-1);
    m.timestamp_us = a2a_now_us();
    a2a_send("127.0.0.1", 7802, &m);
    a2a_server_poll(sb, 300);
    a2a_server_poll(sa, 300);
    printf(ok ? "[PASS] transport\n" : "[FAIL] transport\n");
    a2a_server_destroy(sa);
    a2a_server_destroy(sb);
    return ok ? 0 : 1;
}
