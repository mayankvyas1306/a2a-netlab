#include <stdio.h>
#include <string.h>
#include "a2a_message.h"
#include "a2a_agent.h"
#include "l2_agent.h"
#include "l3_agent.h"
int main(void) {
    l3_agent_ctx_t *l3 = l3_agent_create(
        "agent-l3-test", "ovs-sw1", "127.0.0.1", 7810);
    l2_agent_ctx_t *l2 = l2_agent_create(
        "agent-l2-test", "ovs-sw1", "127.0.0.1", 7811,
        "agent-l3-test", "127.0.0.1", 7810);
    a2a_agent_poll(l3->agent, 200);
    a2a_agent_poll(l2->agent, 200);
    l2_agent_learn_mac(l2, "aa:bb:cc:dd:ee:ff", 1);
    a2a_agent_poll(l3->agent, 200);
    a2a_agent_poll(l2->agent, 200);
    int pass = (l2->agent->state == AGENT_STATE_ACTIVE &&
                l3->l2_events_received >= 1);
    printf(pass ? "[PASS] integration\n" : "[FAIL] integration\n");
    l2_agent_destroy(l2);
    l3_agent_destroy(l3);
    return pass ? 0 : 1;
}
