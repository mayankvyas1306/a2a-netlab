#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "a2a_message.h"
#include "a2a_serialize.h"
int main(void) {
    a2a_message_t msg = {0};
    msg.msg_id = 1; msg.msg_type = MSG_PING;
    strncpy(msg.src_agent, "agent-a", A2A_MAX_AGENT_ID-1);
    strncpy(msg.dst_agent, "agent-b", A2A_MAX_AGENT_ID-1);
    strncpy(msg.payload,   "hello",   A2A_MAX_PAYLOAD-1);
    msg.timestamp_us = a2a_now_us();
    char *json = a2a_serialize(&msg);
    a2a_message_t msg2 = {0};
    a2a_deserialize(json, &msg2);
    int pass = (msg2.msg_id == 1 &&
                msg2.msg_type == MSG_PING &&
                strcmp(msg2.src_agent, "agent-a") == 0 &&
                strcmp(msg2.payload, "hello") == 0);
    free(json);
    printf(pass ? "[PASS] serialize\n" : "[FAIL] serialize\n");
    return pass ? 0 : 1;
}
