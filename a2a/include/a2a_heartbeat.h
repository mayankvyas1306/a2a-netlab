#ifndef A2A_HEARTBEAT_H
#define A2A_HEARTBEAT_H

#include "a2a_agent.h"
#include "a2a_message.h"

void heartbeat_send_all(a2a_agent_t *agent);
void heartbeat_check_peers(a2a_agent_t *agent);
void heartbeat_on_received(a2a_agent_t *agent, const a2a_message_t *msg);

#endif
