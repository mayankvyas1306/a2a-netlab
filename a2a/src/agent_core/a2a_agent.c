#include "a2a_agent.h"
#include "a2a_transport.h"
#include "a2a_serialize.h"
#include "a2a_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Push an inbound message into the agent event queue */
static void agent_recv_handler(const a2a_message_t *msg, void *userdata)
{
    a2a_agent_t *agent = (a2a_agent_t *)userdata;
    agent->msgs_received++;

    a2a_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.type        = A2A_EV_MSG_RECEIVED;
    ev.fsm_event   = FSM_EVENT_MSG_RECEIVED;
    ev.timestamp_us = a2a_now_us();
    ev.data.msg    = *msg;

    if (event_queue_push(&agent->eq, &ev) < 0) {
        agent->events_dropped++;
        LOG_W("AGENT", "[%s] event queue full — drop msg_type=%d",
              agent->card.agent_id, msg->msg_type);
    }
}




a2a_agent_t *a2a_agent_create(const char *agent_id, agent_type_t type,
                               const char *switch_id,
                               const char *host, int port)
{
    a2a_agent_t *agent = calloc(1, sizeof(*agent));
    if (!agent)
        return NULL;

    strncpy(agent->card.agent_id, agent_id, A2A_MAX_AGENT_ID - 1);
    strncpy(agent->card.switch_id, switch_id, A2A_MAX_AGENT_ID - 1);
    strncpy(agent->card.host, host, A2A_MAX_HOST_LEN - 1);
    agent->card.type  = type;
    agent->card.port  = port;

    agent->fsm_state   = FSM_STATE_INIT;
    agent->start_time_us = a2a_now_us();

    /* Initialise per-instance FSM with safe defaults */
    fsm_init(&agent->fsm);

    conn_pool_init(&agent->pool);
    event_queue_init(&agent->eq);

    agent->server = a2a_server_create(agent_id, port,
                                      agent_recv_handler, agent);
    if (!agent->server) {
        conn_pool_destroy(&agent->pool);
        free(agent);
        return NULL;
    }

    LOG_I("AGENT", "[%s] started type=%s switch=%s addr=%s:%d",
          agent_id,
          type == AGENT_TYPE_L2 ? "L2" : "L3",
          switch_id, host, port);

    

    /* NOTE: main.c calls fsm_process(START) directly after agent_create.
     * Do NOT push START into the queue here — that would cause a second
     * START to fire when the queue drains, hitting an unregistered
     * (DISCOVERY + START) → ERROR cell and corrupting the FSM silently. */

    return agent;
}

void a2a_agent_destroy(a2a_agent_t *agent)
{
    if (!agent)
        return;
    conn_pool_destroy(&agent->pool);
    a2a_server_destroy(agent->server);
    free(agent);
}

int a2a_agent_register_handler(a2a_agent_t *agent,
                                a2a_msg_type_t msg_type,
                                agent_msg_handler_t handler)
{
    if (agent->dispatch_count >= A2A_DISPATCH_MAX)
        return -1;
    agent->dispatch[agent->dispatch_count].msg_type = msg_type;
    agent->dispatch[agent->dispatch_count].handler  = handler;
    agent->dispatch_count++;
    return 0;
}

void a2a_agent_compact_peers(a2a_agent_t *agent)
{
    int w = 0;
    for (int r = 0; r < agent->peer_count; r++)
        if (agent->peers[r].alive)
            agent->peers[w++] = agent->peers[r];
    if (w != agent->peer_count)
        LOG_I("AGENT", "[%s] peer table compacted %d→%d",
              agent->card.agent_id, agent->peer_count, w);
    agent->peer_count = w;
}

int a2a_agent_add_peer(a2a_agent_t *agent, const char *peer_id,
                       agent_type_t type, const char *switch_id,
                       const char *host, int port)
{
    if (agent->peer_count >= A2A_MAX_PEERS)
        return -1;

    /* ── Deduplication ─────────────────────────────────────────
     * Pass 1: exact agent_id match → refresh and return.
     * Pass 2: same host:port, different (synthetic) id →
     *         upgrade seed entry in-place; eliminates phantom peer.
     * ─────────────────────────────────────────────────────── */
    for (int i = 0; i < agent->peer_count; i++) {
        agent_peer_t *ex = &agent->peers[i];

        if (strcmp(ex->agent_id, peer_id) == 0) {
            /* Exact match: refresh host/port, switch_id, and liveness.
             * switch_id can change if a peer restarts with new config. */
            snprintf(ex->host,      sizeof(ex->host),      "%s", host);
            snprintf(ex->switch_id, sizeof(ex->switch_id), "%s", switch_id);
            ex->port = port;
            if (!ex->alive) {
                ex->alive             = 1;
                ex->last_heartbeat_us = a2a_now_us();
                ex->last_send_attempt_us = 0;
                LOG_I("AGENT", "[%s] peer %s re-registered (was dead)",
                      agent->card.agent_id, peer_id);
            }
            return 0;
        }

        if (strcmp(ex->host, host) == 0 && ex->port == port &&
            strcmp(ex->agent_id, peer_id) != 0)
        {
            /* Same address, different id: upgrade seed → real */
            LOG_I("AGENT",
                  "[%s] upgrading seed peer '%s' → '%s' @ %s:%d",
                  agent->card.agent_id,
                  ex->agent_id, peer_id, host, port);
            snprintf(ex->agent_id,  sizeof(ex->agent_id),  "%s", peer_id);
            snprintf(ex->switch_id, sizeof(ex->switch_id), "%s", switch_id);
            ex->type              = type;
            ex->alive             = 1;
            ex->last_heartbeat_us = a2a_now_us();
            ex->last_send_attempt_us = 0;
            return 0;
        }
    }

    /* New peer — append */
    agent_peer_t *p = &agent->peers[agent->peer_count++];
    snprintf(p->agent_id,  sizeof(p->agent_id),  "%s", peer_id);
    snprintf(p->switch_id, sizeof(p->switch_id), "%s", switch_id);
    snprintf(p->host,      sizeof(p->host),      "%s", host);
    p->type              = type;
    p->port              = port;
    p->alive             = 1;
    p->last_heartbeat_us = a2a_now_us();
    p->registered_at_us  = p->last_heartbeat_us;
    return 0;
}
