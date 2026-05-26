/*
 * a2a_heartbeat.c — Peer liveness via periodic heartbeat
 *
 * Heartbeats are sent to ALL peers (alive or dead) so recovery is detected.
 * Timeout fires one event per peer per epoch. Dead peers remain in the
 * table for a grace period (see a2a_agent_compact_peers).
 */

#include "a2a_heartbeat.h"
#include "a2a_agent.h"
#include "a2a_event.h"
#include "a2a_message.h"
#include "a2a_log.h"
#include <string.h>
#include <stdio.h>

#define HEARTBEAT_INTERVAL_US (3ULL * 1000000ULL)
#define PEER_TIMEOUT_US (15ULL * 1000000ULL)
#define PEER_DEAD_RETRY_US (30ULL * 1000000ULL) /* retry reconnect every 30s */

/* Send heartbeat to ALL known peers (alive or dead).
 * Dead peers are probed at PEER_DEAD_RETRY_US intervals;
 * liveness is determined by received heartbeats, not send success. */
void heartbeat_send_all(a2a_agent_t *agent)
{
    static unsigned hb_tick = 0;
    int verbose = ((++hb_tick % 5) == 0); /* log every 5 ticks = 15s */

    heartbeat_payload_t hb = {0};
    hb.uptime_us = a2a_now_us() - agent->start_time_us;
    hb.peer_count = agent->peer_count;
    hb.fsm_state = (int)agent->fsm_state;

    a2a_message_t msg = {0};
    msg.msg_id = ++agent->msg_counter;
    msg.msg_type = MSG_HEARTBEAT;
    msg.timestamp_us = a2a_now_us();
    snprintf(msg.src_agent, sizeof(msg.src_agent),
             "%s", agent->card.agent_id);
    a2a_msg_set_heartbeat(&msg, &hb);

    for (int i = 0; i < agent->peer_count; i++)
    {
        agent_peer_t *p = &agent->peers[i];

        /* Throttle dead-peer probes to PEER_DEAD_RETRY_US intervals */
        if (!p->alive)
        {
            /* Skip peers with no send address (pre-inserted or corrupted) */
            if (p->host[0] == '\0' || p->port == 0)
            {
                LOG_D("HB", "[%s] skipping peer %s (no address)",
                      agent->card.agent_id, p->agent_id);
                continue;
            }
            uint64_t now = a2a_now_us();
            if (p->last_send_attempt_us > 0 &&
                now - p->last_send_attempt_us < PEER_DEAD_RETRY_US)
                continue;
            p->last_send_attempt_us = now;
            LOG_D("HB", "[%s] probing dead peer %s",
                  agent->card.agent_id, p->agent_id);
        }
        snprintf(msg.dst_agent, sizeof(msg.dst_agent),
                 "%s", p->agent_id);

        int rc = conn_pool_send(&agent->pool, p->host, p->port, &msg);
        if (rc == 0)
        {
            agent->msgs_sent++;
            if (verbose)
                LOG_I("HB", "[%s] → %s HB ok (uptime=%.0fs peers=%d)",
                      agent->card.agent_id, p->agent_id,
                      (double)(a2a_now_us() - agent->start_time_us) / 1e6,
                      agent->peer_count);
            else
                LOG_D("HB", "[%s] → %s HB sent ok",
                      agent->card.agent_id, p->agent_id);
        }
        else
        {
            agent->send_failures++;
            LOG_W("HB", "[%s] → %s HB SEND FAILED (peer alive=%d)",
                  agent->card.agent_id, p->agent_id, p->alive);
        }
    }
}

/* Check peer liveness based on last received heartbeat.
 * Timeout fires once per epoch; compaction happens elsewhere. */
void heartbeat_check_peers(a2a_agent_t *agent)
{
    uint64_t now = a2a_now_us();

    for (int i = 0; i < agent->peer_count; i++)
    {
        agent_peer_t *p = &agent->peers[i];

        /* Peer that has never exchanged a heartbeat yet — grace period */
        if (p->last_heartbeat_us == 0)
        {
            p->last_heartbeat_us = now;
            continue;
        }

        uint64_t age = now - p->last_heartbeat_us;

        /* Warn at 2/3 of timeout window so operator can diagnose */
        if (p->alive && age > (PEER_TIMEOUT_US * 2 / 3) &&
            age <= PEER_TIMEOUT_US)
        {
            LOG_W("HB", "[%s] peer %s STALE: last seen %.1fs ago "
                        "(timeout in %.1fs)",
                  agent->card.agent_id, p->agent_id,
                  (double)age / 1e6,
                  (double)(PEER_TIMEOUT_US - age) / 1e6);
        }

        if (p->alive && age > PEER_TIMEOUT_US)
        {
            p->alive = 0;
            p->tombstone_us = a2a_now_us();

            LOG_W("HB",
                  "[%s] peer TIMEOUT: %s "
                  "(last seen %.1fs ago)",
                  agent->card.agent_id,
                  p->agent_id,
                  (double)age / 1e6);

            a2a_event_t ev = {0};
            ev.type = A2A_EV_PEER_TIMEOUT;
            ev.fsm_event = FSM_EVENT_PEER_TIMEOUT;
            ev.timestamp_us = now;
            snprintf(ev.data.peer.agent_id, sizeof(ev.data.peer.agent_id),
                     "%s", p->agent_id);
            snprintf(ev.data.peer.host, sizeof(ev.data.peer.host),
                     "%s", p->host);
            ev.data.peer.port = p->port;
            ev.data.peer.agent_type = (int)p->type;

            event_queue_push(&agent->eq, &ev);
        }
    }
}

/* Heartbeat received — unconditionally restore liveness.
 * Self-healing: a timed-out peer recovers on first received heartbeat
 * without requiring re-registration. */
void heartbeat_on_received(a2a_agent_t *agent, const a2a_message_t *msg)
{
    uint64_t now = a2a_now_us();

    for (int i = 0; i < agent->peer_count; i++)
    {
        agent_peer_t *p = &agent->peers[i];
        if (strcmp(p->agent_id, msg->src_agent) != 0)
            continue;

        p->last_heartbeat_us = now;

        if (!p->alive)
        {
            /* Self-healing: peer recovered before tombstone eviction */
            p->alive = 1;
            p->tombstone_us = 0;
            p->last_send_attempt_us = 0;

            LOG_I("HB",
                  "[%s] peer RECOVERED: %s",
                  agent->card.agent_id,
                  p->agent_id);
        }
        return;
    }
    /* Unknown sender — startup race; REGISTER handshake will add it */
    LOG_D("HB", "[%s] heartbeat from UNKNOWN peer %s — ignoring (startup race)",
      agent->card.agent_id, msg->src_agent);
}
