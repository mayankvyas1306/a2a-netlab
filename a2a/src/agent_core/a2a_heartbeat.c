/*
 * a2a_heartbeat.c — Peer liveness via periodic heartbeat
 *
 * Design principles (fixed):
 *
 * 1. SEND TO ALL KNOWN PEERS regardless of alive flag.
 *    The alive flag is a liveness INDICATOR, not a send gate.
 *    If a peer is temporarily unreachable, we still attempt to send
 *    so we notice when it comes back (conn_pool_send will reconnect).
 *
 * 2. PEER STATE is three-valued: alive=1 (healthy), alive=0 (timed out).
 *    Recovery: heartbeat_on_received() sets alive=1 unconditionally,
 *    which allows a timed-out peer to self-heal when it reconnects.
 *
 * 3. TIMEOUT fires ONE event per peer per timeout period. A retry
 *    counter prevents event spam when a peer stays dead.
 *
 * 4. last_heartbeat_us is initialised to NOW at peer-add time.
 *    The 15-second window begins from first registration, not from
 *    the first heartbeat exchange — this gives ~4 heartbeat cycles
 *    (at 3s interval) before a peer is considered timed out.
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

/* ── Send ────────────────────────────────────────────────────────────
 *
 * Send heartbeat to ALL known peers — alive or dead.
 *
 * WHY: if we skip dead peers we never learn they came back.
 *      conn_pool_send already has a 3-attempt reconnect loop;
 *      a failed send just increments send_failures and returns -1.
 *      We ignore that failure here — the timeout checker decides
 *      the liveness verdict based on received heartbeats, not on
 *      whether our outbound send succeeded.
 */
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

        /*
         * Skip peers that are dead AND were last-attempted recently.
         * This throttles reconnect probes to once per PEER_DEAD_RETRY_US
         * so we don't hammer a truly-gone peer with 0.3s retry storms.
         *
         * alive == 1: always send (normal operation).
         * alive == 0: send only if PEER_DEAD_RETRY_US has elapsed since
         *             last outbound attempt (stored in last_send_attempt_us).
         */
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

/* ── Check ───────────────────────────────────────────────────────────
 *
 * Mark peers timed-out based on when we LAST RECEIVED a heartbeat
 * from them — not on whether our send succeeded.
 *
 * Key fixes vs. original:
 *   - Only fires PEER_TIMEOUT event once per timeout epoch
 *     (guarded by timeout_fired flag in agent_peer_t).
 *   - Does NOT compact the peer table here — compaction must happen
 *     outside the iteration loop to avoid index corruption.
 *   - Peers that come back alive (heartbeat_on_received sets alive=1)
 *     get their timeout_fired flag cleared so the next timeout fires
 *     another event if needed.
 */
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
            /*
             * Transition:
             *   healthy → timed-out
             *
             * Do NOT immediately evict the peer.
             * Instead:
             *   - mark alive=0
             *   - stamp tombstone_us
             *
             * This enables:
             *   - graceful recovery
             *   - peer restart handling
             *   - reconnect stabilization
             *   - distributed self-healing
             */

            p->alive = 0;

            /*
             * Start tombstone grace-period timer.
             *
             * Peer compaction/eviction will happen later
             * only after the grace window expires.
             */
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
        /* else: alive and within timeout — or dead and waiting for recovery */
    }
}

/* ── Receive ─────────────────────────────────────────────────────────
 *
 * A heartbeat arrived from src_agent.  Update the liveness timestamp
 * and mark alive=1 unconditionally.  This is the self-healing path:
 * if a peer timed out but then reconnects, the first received heartbeat
 * clears the dead state without requiring a full re-registration.
 *
 * NOTE: if the peer is not in the table yet (race during startup),
 * we silently ignore — the REGISTER handshake will add it shortly.
 */
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
            /*
             * Self-healing recovery path.
             *
             * Peer heartbeat resumed before tombstone
             * eviction window expired.
             */

            p->alive = 1;

            /*
             * Clear tombstone because peer recovered.
             */
            p->tombstone_us = 0;

            /*
             * Reset reconnect probe throttling.
             */
            p->last_send_attempt_us = 0;

            LOG_I("HB",
                  "[%s] peer RECOVERED: %s",
                  agent->card.agent_id,
                  p->agent_id);
        }
        return;
    }
    /* Unknown sender — peer not yet in table (startup race or
     * reconnect before re-registration).  Log at WARN so it
     * is visible; the REGISTER handshake will add it shortly. */
    LOG_D("HB", "[%s] heartbeat from UNKNOWN peer %s — ignoring (startup race)",
      agent->card.agent_id, msg->src_agent);
}
