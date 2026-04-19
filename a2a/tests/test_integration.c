#include <stdio.h>
#include <string.h>
#include "a2a_message.h"
#include "a2a_agent.h"
#include "a2a_event.h"
#include "a2a_fsm.h"
#include "l2_agent.h"
#include "l3_agent.h"

int main(void) {
    /* Create L3 agent (mock OVS so no OVS daemon needed) */
    l3_agent_ctx_t *l3 = l3_agent_create(
        "agent-l3-test", "sw-test", "br0", "127.0.0.1", 7810, 1);
    if (!l3) { printf("[FAIL] l3_agent_create\n"); return 1; }

    /* Prime L3 FSM */
    a2a_event_t start = {0};
    start.fsm_event = FSM_EVENT_START;
    fsm_process(l3->agent, &start);

    /* Create L2 agent (mock OVS) */
    l2_agent_ctx_t *l2 = l2_agent_create(
        "agent-l2-test", "sw-test", "br0", "127.0.0.1", 7811, 1);
    if (!l2) { printf("[FAIL] l2_agent_create\n"); return 1; }

    /* Prime L2 FSM */
    fsm_process(l2->agent, &start);

    /* Seed L3 peer into L2 agent */
    a2a_agent_add_peer(l2->agent, "agent-l3-test",
                       AGENT_TYPE_L3, "sw-test", "127.0.0.1", 7810);

    /* Inject PEER_DISCOVERED so L2 sends REGISTER to L3 */
    a2a_event_t disc = {0};
    disc.type = A2A_EV_PEER_DISCOVERED;
    disc.fsm_event = FSM_EVENT_PEER_DISCOVERED;
    disc.timestamp_us = a2a_now_us();
    disc.data.peer.agent_type = AGENT_TYPE_L3;
    disc.data.peer.port = 7810;
    snprintf(disc.data.peer.agent_id, A2A_MAX_AGENT_ID, "agent-l3-test");
    snprintf(disc.data.peer.host, A2A_MAX_HOST_LEN, "127.0.0.1");
    snprintf(disc.data.peer.switch_id, A2A_MAX_AGENT_ID, "sw-test");
    event_queue_push(&l2->agent->eq, &disc);

    /* Run both agents for a few poll cycles */
    for (int i = 0; i < 10; i++) {
        a2a_server_poll(l2->agent->server, 30);
        a2a_server_poll(l3->agent->server, 30);

        a2a_event_t ev;
        while (event_queue_pop(&l2->agent->eq, &ev) == 0)
            fsm_process(l2->agent, &ev);
        while (event_queue_pop(&l3->agent->eq, &ev) == 0)
            fsm_process(l3->agent, &ev);
    }

    int l2_active = (l2->agent->fsm_state == FSM_STATE_ACTIVE ||
                     l2->agent->fsm_state == FSM_STATE_REGISTERING);
    int l3_got_register = (l3->agent->peer_count > 0);

    int pass = l2_active && l3_got_register;
    printf(pass ? "[PASS] integration\n" : "[FAIL] integration (l2_state=%s peers_l3=%d)\n",
           fsm_state_str(l2->agent->fsm_state), l3->agent->peer_count);

    l2_agent_destroy(l2);
    l3_agent_destroy(l3);
    return pass ? 0 : 1;
}