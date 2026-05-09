#include "l2_agent.h"
#include "a2a_event.h"
#include "a2a_message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "a2a_heartbeat.h"

#include "a2a_log.h"
#include <dirent.h>
#include <sys/stat.h>
#include "ovs_interface.h"
#include <sys/socket.h>

/* Forward declarations to avoid circular include with a2a_metrics.h */
typedef struct a2a_metrics_t a2a_metrics_t;
void metrics_record_latency(a2a_metrics_t *m, uint64_t sent_us);

void ovsdb_process_update(const char *json, a2a_agent_t *agent);

extern int ovs_of_connect(const char *bridge);
extern void ovs_set_ovsdb_fd(int fd);
extern void ovsdb_iterate_ifaces(void (*cb)(const char *name, int ofport,
                                            int link_up, void *ud),
                                 void *ud);

int ovsdb_connect(void);
int ovsdb_send_monitor(int fd);

/* ── FSM action handlers ─────────────────────────────────────────────── */

static void l2_report_anomaly(l2_agent_ctx_t *ctx,
                              int anomaly_type,
                              int port,
                              uint32_t pps,
                              const char *mac,
                              const char *reason);
static const char *l2_get_neighbor_ip(const char *switch_id);
static const char *l2_get_gateway_ip(const char *switch_id);
static const char *l2_get_interswitch_port(const char *switch_id);

static void on_msg_received(a2a_agent_t *agent, const a2a_event_t *ev)
{
    l2_agent_ctx_t *ctx = (l2_agent_ctx_t *)agent->userdata;
    const a2a_message_t *msg = &ev->data.msg;

    switch (msg->msg_type)
    {

    /* HANDLE REGISTER */
    case MSG_REGISTER:
    {
        LOG_I("L2", "REGISTER received from %s (switch=%s)",
              msg->src_agent, ctx->switch_id);

        a2a_message_t reply = {0};
        reply.msg_id = ++agent->msg_counter;
        reply.msg_type = MSG_REGISTER_ACK;
        reply.timestamp_us = a2a_now_us();

        strncpy(reply.src_agent, agent->card.agent_id, A2A_MAX_AGENT_ID - 1);
        strncpy(reply.dst_agent, msg->src_agent, A2A_MAX_AGENT_ID - 1);

        /* send using peer table */
        register_payload_t reg = {0};
        a2a_msg_get_register(msg, &reg);

        /*  Send ACK directly using sender info */
        if (conn_pool_send(&agent->pool, reg.host, reg.port, &reply) != 0)
        {
            ctx->agent->send_failures++;
            LOG_W("L2", "Send failed to peer %s", msg->src_agent);
        }

        /*  NOW add peer */
        a2a_agent_add_peer(agent, msg->src_agent,
                           reg.agent_type,
                           reg.switch_id,
                           reg.host,
                           reg.port);
        LOG_I("L2", "REGISTER_ACK sent to %s", msg->src_agent);

        /* === SEND PEER LIST BACK === */
        a2a_message_t plist_msg = {0};
        plist_msg.msg_id = ++agent->msg_counter;
        plist_msg.msg_type = MSG_PEER_LIST;
        plist_msg.timestamp_us = a2a_now_us();

        strncpy(plist_msg.src_agent, agent->card.agent_id, A2A_MAX_AGENT_ID - 1);
        strncpy(plist_msg.dst_agent, msg->src_agent, A2A_MAX_AGENT_ID - 1);

        peer_list_payload_t pl = {0};
        /* Cap at MAX_PEERS_IN_MSG to avoid overflowing the payload struct */
        int max_share = agent->peer_count < PEER_LIST_MAX
                            ? agent->peer_count
                            : PEER_LIST_MAX;
        pl.count = max_share;

        for (int i = 0; i < agent->peer_count && i < PEER_LIST_MAX; i++)
        {
            strncpy(pl.peers[i].agent_id, agent->peers[i].agent_id, A2A_MAX_AGENT_ID - 1);
            strncpy(pl.peers[i].host, agent->peers[i].host, A2A_MAX_HOST_LEN - 1);
            strncpy(pl.peers[i].switch_id, agent->peers[i].switch_id, A2A_MAX_AGENT_ID - 1);
            pl.peers[i].port = agent->peers[i].port;
            pl.peers[i].agent_type = agent->peers[i].type;
        }

        a2a_msg_set_peer_list(&plist_msg, &pl);

        conn_pool_send(&agent->pool, reg.host, reg.port, &plist_msg);

        break;
    }

    case MSG_FLOW_INSTALL:
    {
        flow_install_payload_t fl = {0};
        if (a2a_msg_get_flow(msg, &fl) == 0)
        {
            ovs_flow_t ovs_fl = {0};
            ovs_fl.priority = fl.priority;
            ovs_fl.idle_timeout = fl.idle_timeout;
            ovs_fl.hard_timeout = fl.hard_timeout;
            strncpy(ovs_fl.match, fl.match, sizeof(ovs_fl.match) - 1);
            strncpy(ovs_fl.actions, fl.actions, sizeof(ovs_fl.actions) - 1);
            if (ovs_add_flow(ctx->bridge, &ovs_fl) == 0)
            {
                ctx->flows_installed++;
                LOG_I("L2", "Flow installed match=%s actions=%s", fl.match, fl.actions);
            }
        }
        break;
    }

    case MSG_TOPOLOGY:
    {
        l3_event_payload_t pl = {0};
        if (a2a_msg_get_l3_event(msg, &pl) == 0)
        {
            LOG_I("L2", "Route update from %s prefix=%s nexthop=%s withdrawn=%d",
                  msg->src_agent, pl.prefix, pl.nexthop, pl.is_withdraw);
        }
        break;
    }

    case MSG_HEARTBEAT:
        heartbeat_on_received(agent, msg);
        break;

    case MSG_REGISTER_ACK:
        LOG_I("L2", "Registered with peer %s", msg->src_agent);

        /*
         * Refresh the heartbeat timestamp for this peer.
         * The peer was added at seed/discover time; if REGISTER
         * exchange took a few seconds the timeout clock is already
         * running.  Stamping here resets the 15s window from the
         * moment we confirm bidirectional communication works.
         */
        for (int _i = 0; _i < agent->peer_count; _i++)
        {
            if (strcmp(agent->peers[_i].agent_id, msg->src_agent) == 0)
            {
                agent->peers[_i].last_heartbeat_us = a2a_now_us();
                agent->peers[_i].alive = 1;
                break;
            }
        }
        if (agent->fsm_state == FSM_STATE_REGISTERING ||
            agent->fsm_state == FSM_STATE_DISCOVERY ||
            agent->fsm_state == FSM_STATE_RECEIVING)
        {
            a2a_event_t reg_ev = {0};
            reg_ev.type = A2A_EV_MSG_RECEIVED;
            reg_ev.fsm_event = FSM_EVENT_REGISTERED;
            reg_ev.timestamp_us = a2a_now_us();
            event_queue_push(&agent->eq, &reg_ev);
        }
        break;

    case MSG_L3_EVENT:
    {
        /* L3 sends route updates (MSG_L3_EVENT) when syncing routes
         * to a newly-registered L2 peer.  L2 logs but does not act;
         * topology changes arrive via MSG_TOPOLOGY. */
        l3_event_payload_t pl = {0};
        if (a2a_msg_get_l3_event(msg, &pl) == 0)
            LOG_I("L2", "Route info from %s: prefix=%s nh=%s metric=%d%s",
                  msg->src_agent, pl.prefix, pl.nexthop, pl.metric,
                  pl.is_withdraw ? " [WITHDRAW]" : "");
        break;
    }

    case MSG_POLICY_CMD:
    {
        policy_cmd_payload_t pl = {0};
        if (a2a_msg_get_policy_cmd(msg, &pl) == 0)
        {
            LOG_I("L2", "[%s] Policy received type=%d port=%d rate=%u",
                  ctx->switch_id, pl.policy_type, pl.port, pl.rate_limit);

            for (int i = 0; i < ctx->port_count; i++)
            {
                if (ctx->ports[i].port_no != pl.port)
                    continue;

                const char *ifname = ctx->ports[i].ifname;

                switch (pl.policy_type)
                {
                case POLICY_ISOLATE_PORT:
                {
                    /*
                     * Safety guard: never isolate uplink ports (ports connected to
                     * core routers). Uplink ports are identified as having an
                     * interface name matching the switch-to-core naming convention
                     * (e.g., s1c1, s3c2, etc.) or if only one port leads to the
                     * data-plane gateway.
                     * Heuristic: skip if ifname contains 'c' followed by a digit
                     * (s1c1, s3c2, etc.) as those are core uplinks.
                     */
                    int is_uplink = 0;
                    size_t nl = strlen(ifname);
                    for (size_t ci = 0; ci < nl - 1; ci++)
                    {
                        if (ifname[ci] == 'c' && ifname[ci + 1] >= '1' &&
                            ifname[ci + 1] <= '9')
                        {
                            is_uplink = 1;
                            break;
                        }
                    }
                    if (is_uplink)
                    {
                        LOG_W("L2", "[%s] Refusing to isolate uplink port %d (%s) — "
                                    "applying rate-limit instead",
                              ctx->switch_id, pl.port, ifname);
                        /* Downgrade to rate-limit to contain the anomaly.
                         * Use meter 2 to avoid overwriting the broadcast
                         * protection meter (meter 1, 1500 kbps). */
                        ovs_of_add_meter(ctx->bridge, 2, 10000); /* 10 Mbps cap */
                        ovs_flow_t fl = {0};
                        fl.priority = 1;
                        snprintf(fl.match, sizeof(fl.match), "in_port=%d", pl.port);
                        snprintf(fl.actions, sizeof(fl.actions), "meter:2,output:normal");
                        ovs_add_flow(ctx->bridge, &fl);
                        LOG_W("L2", "Rate limit applied on uplink port %d instead of isolate",
                              pl.port);
                        break;
                    }
                    ovs_set_port_state(ctx->bridge, ifname, 0);
                    ovs_flow_t drop_fl = {0};
                    drop_fl.priority = 500;
                    snprintf(drop_fl.match, sizeof(drop_fl.match),
                             "in_port=%d", pl.port);
                    snprintf(drop_fl.actions, sizeof(drop_fl.actions), "drop");
                    ovs_add_flow(ctx->bridge, &drop_fl);
                    LOG_W("L2", "Port %d isolated", pl.port);
                    break;
                }
                case POLICY_RESTORE_PORT:
                {
                    ovs_set_port_state(ctx->bridge, ifname, 1);
                    /* Remove the rate-limit flow that was installed by POLICY_RATE_LIMIT.
                     * Without this deletion, the priority=1 flow stays permanently and
                     * the port remains metered even after the storm is gone. */
                    char rl_match[64];
                    snprintf(rl_match, sizeof(rl_match), "in_port=%d", pl.port);
                    ovs_del_flow(ctx->bridge, rl_match);
                    LOG_I("L2", "Port %d restored (rate-limit flow removed)", pl.port);
                    break;
                }                
                case POLICY_RATE_LIMIT:
                {
                    /* Use meter 2 for per-port rate limiting.
                     * Meter 1 is reserved exclusively for broadcast/multicast
                     * storm protection (1500 kbps). Overwriting meter 1 here
                     * destroys broadcast protection. pl.rate_limit is in pps,
                     * not kbps, so multiplying it produces an unintended
                     * near-unlimited rate. Use a fixed 10 Mbps cap on meter 2. */
                    ovs_of_add_meter(ctx->bridge, 2, 10000);
                    ovs_flow_t fl = {0};
                    fl.priority = 1;
                    snprintf(fl.match, sizeof(fl.match),
                             "in_port=%d", pl.port);
                    snprintf(fl.actions, sizeof(fl.actions),
                             "meter:2,output:normal");

                    ovs_add_flow(ctx->bridge, &fl);

                    LOG_W("L2", "Rate limit applied on port %d (10Mbps cap)",
                          pl.port);
                    break;
                }

                case POLICY_BLACKHOLE_MAC:
                {
                    ovs_flow_t fl = {0};
                    fl.priority = 300;
                    snprintf(fl.match, sizeof(fl.match),
                             "dl_src=%s", pl.mac);
                    snprintf(fl.actions, sizeof(fl.actions),
                             "drop");

                    ovs_add_flow(ctx->bridge, &fl);

                    LOG_W("L2", "MAC %s blackholed", pl.mac);
                    break;
                }

                case POLICY_FLUSH_PORT:
                {
                    ovs_flush_mac(ctx->bridge, NULL);
                    LOG_W("L2", "Flows flushed on bridge %s", ctx->bridge);
                    break;
                }

                default:
                    break;
                }
            }
        }
        break;
    }

    case MSG_PEER_LIST:
    {
        peer_list_payload_t pl = {0};

        if (a2a_msg_get_peer_list(msg, &pl) != 0)
            break;

        LOG_I("L2", "[%s] Received PEER_LIST (%d peers)",
              ctx->switch_id, pl.count);

        for (int i = 0; i < pl.count; i++)
        {
            /* Skip self */
            if (strcmp(pl.peers[i].agent_id, ctx->agent->card.agent_id) == 0)
                continue;

            /* Check if already known */
            int exists = 0;
            for (int j = 0; j < ctx->agent->peer_count; j++)
            {
                if (strcmp(ctx->agent->peers[j].agent_id,
                           pl.peers[i].agent_id) == 0)
                {
                    exists = 1;
                    break;
                }
            }

            if (exists)
                continue;

            LOG_I("L2", "[%s] New peer discovered via PEER_LIST: %s",
                  ctx->switch_id, pl.peers[i].agent_id);

            /* Add peer */
            if (ctx->agent->peer_count < A2A_MAX_PEERS)
            {
                a2a_agent_add_peer(ctx->agent,
                                   pl.peers[i].agent_id,
                                   pl.peers[i].agent_type,
                                   pl.peers[i].switch_id,
                                   pl.peers[i].host,
                                   pl.peers[i].port);
            }

            /* Trigger REGISTER via FSM */
            a2a_event_t ev = {0};
            ev.type = A2A_EV_PEER_DISCOVERED;
            ev.fsm_event = FSM_EVENT_PEER_DISCOVERED;
            ev.timestamp_us = a2a_now_us();
            strncpy(ev.data.peer.agent_id, pl.peers[i].agent_id, A2A_MAX_AGENT_ID - 1);
            strncpy(ev.data.peer.host, pl.peers[i].host, A2A_MAX_HOST_LEN - 1);
            strncpy(ev.data.peer.switch_id, pl.peers[i].switch_id, A2A_MAX_AGENT_ID - 1);

            ev.data.peer.port = pl.peers[i].port;
            ev.data.peer.agent_type = pl.peers[i].agent_type;

            event_queue_push(&ctx->agent->eq, &ev);
        }

        break;
    }

    default:
        LOG_W("L2", "[%s] unhandled msg_type=%d from %s",
              ctx->switch_id, msg->msg_type, msg->src_agent);
        break;
    }
    {
        extern a2a_metrics_t g_metrics;
        metrics_record_latency(&g_metrics, ev->data.msg.timestamp_us);
    }
    /* return to ACTIVE */
    a2a_event_t done = {0};
    done.type = A2A_EV_MSG_RECEIVED;
    done.fsm_event = FSM_EVENT_PROCESSING_DONE;
    event_queue_push(&agent->eq, &done);
}

/* ── rest of file unchanged ─────────────────────────────────────────── */
static void on_peer_discovered(a2a_agent_t *agent, const a2a_event_t *ev)
{
    l2_agent_ctx_t *ctx = (l2_agent_ctx_t *)agent->userdata;
    const peer_info_t *p = &ev->data.peer;
    LOG_I("L2", "[%s] Peer discovered: %s type=%s — sending REGISTER",
          ctx->switch_id, p->agent_id,
          p->agent_type == AGENT_TYPE_L3 ? "L3" : "L2");

    register_payload_t reg = {0};
    strncpy(reg.host, agent->card.host, A2A_MAX_HOST_LEN - 1);
    strncpy(reg.switch_id, ctx->switch_id, A2A_MAX_AGENT_ID - 1);
    reg.port = agent->card.port;
    reg.agent_type = AGENT_TYPE_L2;

    a2a_message_t msg = {0};
    msg.msg_id = ++agent->msg_counter;
    msg.msg_type = MSG_REGISTER;
    msg.timestamp_us = a2a_now_us();
    strncpy(msg.src_agent, agent->card.agent_id, A2A_MAX_AGENT_ID - 1);
    strncpy(msg.dst_agent, p->agent_id, A2A_MAX_AGENT_ID - 1);
    a2a_msg_set_register(&msg, &reg);
    if (conn_pool_send(&agent->pool, p->host, p->port, &msg) != 0)
    {
        ctx->agent->send_failures++;
        LOG_W("L2", "Send failed to peer %s", p->agent_id);
    }
    LOG_I("L2", "[%s] REGISTER sent to %s (%s:%d)",
          ctx->switch_id,
          p->agent_id,
          p->host,
          p->port);
}

static void on_peer_timeout(a2a_agent_t *agent, const a2a_event_t *ev)
{
    l2_agent_ctx_t *ctx = (l2_agent_ctx_t *)agent->userdata;
    const char *dead_id = ev->data.peer.agent_id;

    LOG_W("L2", "[%s] peer timeout: %s", ctx->switch_id, dead_id);

    /*
     * Mark the specific peer dead — heartbeat_check_peers already did
     * this, but we do it here too so the FSM action is idempotent.
     * Do NOT compact peers here: compaction inside a per-peer loop
     * causes index corruption.  Compaction runs in the GC cycle.
     */
    for (int i = 0; i < agent->peer_count; i++)
    {
        if (strcmp(agent->peers[i].agent_id, dead_id) == 0)
        {
            agent->peers[i].alive = 0;
            break;
        }
    }

    /*
     * Evict ONLY this peer's pooled connection so the next heartbeat
     * probe attempts a fresh TCP connect.  Destroying the entire pool
     * disconnects ALL other healthy peers — never do that.
     */
    conn_pool_evict_peer(&agent->pool, ev->data.peer.host,
                         ev->data.peer.port);
}
static void on_heartbeat_tick(a2a_agent_t *agent, const a2a_event_t *ev)
{
    (void)ev;
    heartbeat_send_all(agent);
    heartbeat_check_peers(agent);
}

/* ── MAC table management ────────────────────────────────────────────── */

void l2_mac_sync(l2_agent_ctx_t *ctx)
{
    ovs_mac_entry_t raw[L2_MAX_MAC_TABLE];
    memset(raw, 0, sizeof(raw));
    int n = ovs_get_mac_table(ctx->bridge, raw, L2_MAX_MAC_TABLE);
    if (n < 0)
        return;

    uint64_t now = a2a_now_us();

    for (int i = 0; i < n; i++)
    {
        /* Look for existing entry */
        int found = 0;
        for (int j = 0; j < ctx->mac_count; j++)
        {
            if (strcmp(ctx->mac_table[j].mac, raw[i].mac) == 0)
            {
                if (ctx->mac_table[j].port != raw[i].port)
                {
                    LOG_W("L2", "MAC moved: %s %d→%d",
                          raw[i].mac,
                          ctx->mac_table[j].port,
                          raw[i].port);
                    l2_report_anomaly(ctx,
                                      L2_ANOMALY_MAC_SPOOF,
                                      raw[i].port,
                                      0,
                                      raw[i].mac,
                                      "mac_spoof");
                }

                ctx->mac_table[j].last_seen_us = now;
                ctx->mac_table[j].port = raw[i].port;
                found = 1;
                break;
            }
        }
        if (!found) {

            /* Final duplicate check */
            int dup = 0;

            for (int j = 0; j < ctx->mac_count; j++) {
                if (strncmp(ctx->mac_table[j].mac, raw[i].mac, 17) == 0) {
                    ctx->mac_table[j].last_seen_us = now;
                    ctx->mac_table[j].port = raw[i].port;
                    dup = 1;
                    break;
                }
            }

            if (dup)
                continue;

            /* Get free slot or evict LRU entry */
            mac_entry_t *slot = NULL;

            if (ctx->mac_count < L2_MAX_MAC_TABLE) {

                /* Append new entry */
                slot = &ctx->mac_table[ctx->mac_count++];

            } else {

                /* Find least recently used entry */
                slot = &ctx->mac_table[0];

                for (int j = 1; j < ctx->mac_count; j++) {
                    if (ctx->mac_table[j].last_seen_us <
                        slot->last_seen_us)
                    {
                        slot = &ctx->mac_table[j];
                    }
                }

                /* Remove stale OVS flow */
                char evict_match[128];

                snprintf(evict_match, sizeof(evict_match),
                         "dl_dst=%s", slot->mac);

                ovs_del_flow(ctx->bridge, evict_match);

                LOG_D("L2", "[%s] MAC table full — LRU evict: %s "
                      "(age=%.1fs, replacing with %s)",
                      ctx->switch_id, slot->mac,
                      (double)(now - slot->last_seen_us) / 1e6,
                      raw[i].mac);
            }

            /* Populate MAC entry */
            memcpy(slot->mac, raw[i].mac, 17);

            slot->mac[17]       = '\0';
            slot->port          = raw[i].port;
            slot->learned_at_us = now;
            slot->last_seen_us  = now;
            slot->pkt_count     = 1;

            LOG_I("L2", "[%s] New MAC: %s on port %d (table: %d/%d)",
                  ctx->switch_id, slot->mac, slot->port,
                  ctx->mac_count, L2_MAX_MAC_TABLE);
        }
    }

    /* Age out stale entries */
    for (int i = 0; i < ctx->mac_count;)
    {
        if (now - ctx->mac_table[i].last_seen_us > MAC_AGE_US)
        {
            LOG_D("L2", "MAC aged out: %s", ctx->mac_table[i].mac);
            char match[128];
            snprintf(match, sizeof(match), "dl_dst=%s", ctx->mac_table[i].mac);
            ovs_del_flow(ctx->bridge, match);
            /* Compact the array */
            ctx->mac_table[i] = ctx->mac_table[--ctx->mac_count];
        }
        else
        {
            i++;
        }
    }

    ctx->last_mac_sync_us = now;

    /* ── MAC flood detection ──────────────────────────────────────────
     * Count how many distinct MACs are present per port in this sync.
     * If a single port has more than MAC_FLOOD_THRESHOLD entries in a
     * short window, it is likely being flooded.
     */
#define MAC_FLOOD_THRESHOLD 50 /* distinct MACs per port per 2s window */

    /* Count UNIQUE MACs per port using a seen-MAC dedup array */
    int per_port[L2_MAX_PORTS];
    memset(per_port, 0, sizeof(per_port));

    /* Dedup: only count each unique MAC once per port in this sync */
    for (int i = 0; i < ctx->mac_count; i++)
    {
        int port = ctx->mac_table[i].port;
        int counted = 0;
        /* Check if this MAC has already been counted for this port */
        for (int k = 0; k < i; k++)
        {
            if (ctx->mac_table[k].port == port &&
                strcmp(ctx->mac_table[k].mac, ctx->mac_table[i].mac) == 0)
            {
                counted = 1;
                break;
            }
        }
        if (counted)
            continue;

        for (int j = 0; j < ctx->port_count; j++)
        {
            if (ctx->ports[j].port_no == port)
            {
                per_port[j]++;
                break;
            }
        }
    }

    for (int j = 0; j < ctx->port_count; j++)
    {
        if (per_port[j] >= MAC_FLOOD_THRESHOLD)
        {
            LOG_W("L2", "[%s] MAC FLOOD DETECTED port=%d distinct_macs=%d",
                  ctx->switch_id, ctx->ports[j].port_no, per_port[j]);

            if (now - ctx->ports[j].last_event_sent_us > 1000000ULL)
            {
                l2_report_anomaly(ctx,
                                  L2_ANOMALY_FLOOD,
                                  ctx->ports[j].port_no,
                                  per_port[j],
                                  NULL,
                                  "mac_flood");
                ctx->ports[j].last_event_sent_us = now;
            }
        }
    }
}

/* ── Storm detection ─────────────────────────────────────────────────── */

void l2_detect_storm(l2_agent_ctx_t *ctx, int port_idx, uint64_t pps)
{
    port_state_t *ps = &ctx->ports[port_idx];
    uint64_t now = a2a_now_us();

    /* Force explicit thresholds to guarantee test visibility with 5000 pkts */
    uint64_t thresh_active = (uint64_t)STORM_THRESHOLD_PPS;
    uint64_t thresh_clear = (uint64_t)STORM_CLEAR_PPS;

    /* ───── STORM DETECTED ───── */
    if (!ps->storm_active && pps >= thresh_active)
    {
        ps->storm_active = 1;
        ps->current_pps = (uint32_t)pps;
        ctx->storms_detected++;

        LOG_W("L2", "STORM DETECTED port=%d pps=%lu", ps->port_no, pps);

        if (now - ps->last_event_sent_us > 1000000)
        {
            l2_report_anomaly(ctx, L2_ANOMALY_STORM, ps->port_no, (uint32_t)pps, NULL, "storm_detected");
            ps->last_event_sent_us = now;
        }

        a2a_event_t ev = {0};
        ev.type = A2A_EV_ANOMALY;
        ev.fsm_event = FSM_EVENT_OVS_EVENT;
        ev.timestamp_us = now;
        ev.data.ovs.port = ps->port_no;
        event_queue_push(&ctx->agent->eq, &ev);
    }
    /* ───── STORM CONTINUES ───── */
    else if (ps->storm_active && pps >= thresh_active)
    {
        ps->current_pps = (uint32_t)pps;
        if (now - ps->last_event_sent_us > 1000000)
        {
            l2_report_anomaly(ctx, L2_ANOMALY_STORM, ps->port_no, (uint32_t)pps, NULL, "storm_continues");
            ps->last_event_sent_us = now;
        }
    }
    /* ───── STORM CLEARED ───── */
    else if (ps->storm_active && pps < thresh_clear)
    {
        ps->storm_active = 0;
        LOG_I("L2", "Storm CLEARED port=%d", ps->port_no);

        /*
         * STORM_CLEAR must always be sent — no rate-limit guard.
         * The guard fires too early (storm clears ~100ms after detection,
         * but the guard window is 1s). Suppressing STORM_CLEAR causes
         * the OVS rate-limit meter flow to stay installed permanently,
         * keeping the port throttled indefinitely.
         * STORM_CLEAR is a one-shot state transition (ps->storm_active
         * is cleared above), so it can only fire once per storm episode.
         */
        l2_report_anomaly(ctx, L2_ANOMALY_STORM_CLEAR, ps->port_no, 0, NULL, "storm_cleared");
        ps->last_event_sent_us = now;
    }
}

/* ── Port polling ────────────────────────────────────────────────────── */

void l2_port_poll(l2_agent_ctx_t *ctx)
{
    uint64_t now = a2a_now_us();

    for (int i = 0; i < ctx->port_count; i++)
    {
        port_state_t *ps = &ctx->ports[i];
        ovs_port_stats_t stats = {0};

        int rc = ovs_get_port_stats(ctx->bridge, ps->ifname, &stats);

        /* Skip if not yet in OVSDB shadow */
        if (rc < 0)
            continue;

                /* Link state handling with duplicate protection */
        if (stats.link_up) {
            /* Mark port as active */
            ps->was_up_ever = 1;

            /* Reset one-shot flag after link recovery */
            if (ps->link_down_reported) {
                ps->link_down_reported = 0;

                LOG_I("L2", "[%s] Link RESTORED on port %d (%s) "
                      "— poll path reset",
                      ctx->switch_id, ps->port_no, ps->ifname);

                if (ps->alternate_active)
                {
                    ps->alternate_active = 0;
                    const char *gateway = l2_get_gateway_ip(ctx->switch_id);
                    char cmd[256];

                    /*
                     * Restore: flush MACs learned via alternate path so
                     * they re-learn on the restored primary uplink.
                     * No redirect flows to remove (failover doesn't
                     * install any — OVS NORMAL handles forwarding).
                     */

                    /* Step 1: Flush learned MAC flows */
                    ovs_flush_mac(ctx->bridge, NULL);

                    /* Step 2: Restore kernel route */
                    if (gateway)
                    {
                        snprintf(cmd, sizeof(cmd),
                                 "ip route replace default via %s 2>/dev/null",
                                 gateway);
                        (void)system(cmd);
                    }

                    /* Notify L3 peers that the uplink is back.
                     * L3 agent uses this to remove the secondary kernel
                     * routes (metric=50) installed on core routers during
                     * LINK_DOWN failover. */
                    l2_report_anomaly(ctx, L2_ANOMALY_LINK_UP,
                                     ps->port_no, 0, NULL, "link_restored");

                    LOG_I("L2", "[%s] Uplink RESTORED port=%d: "
                          "flushed MACs, reverted kernel route to %s",
                          ctx->switch_id, ps->port_no,
                          gateway ? gateway : "unknown");
                }
            }

        } else {
            /* Ignore startup false negatives */
            if (!ps->was_up_ever)
                continue;

            /* Clear storm state on link-down */
            if (ps->storm_active) {
                ps->storm_active = 0;
                ps->current_pps  = 0;

                LOG_D("L2", "[%s] Cleared storm state for downed port %d",
                      ctx->switch_id, ps->port_no);
            }

            /* Fire link-down event only once */
            if (!ps->link_down_reported) {
                ps->link_down_reported = 1;

                LOG_W("L2", "[%s] Link DOWN detected on port %d (%s) "
                      "— poll path",
                      ctx->switch_id, ps->port_no, ps->ifname);

                a2a_event_t ev = {0};
                ev.type            = A2A_EV_OVS_LINK_DOWN;
                ev.fsm_event       = FSM_EVENT_OVS_EVENT;
                ev.timestamp_us    = now;
                ev.data.ovs.port   = ps->port_no;
                ev.data.ovs.link_down = 1;

                strncpy(ev.data.ovs.bridge, ctx->bridge,
                        sizeof(ev.data.ovs.bridge) - 1);

                if (event_queue_push(&ctx->agent->eq, &ev) != 0) {
                    LOG_W("L2", "[%s] Event queue full — dropping link-down "
                          "for port %d", ctx->switch_id, ps->port_no);
                }
            }

            /* Skip PPS checks for down ports */
            continue;
        }

        /* Compute PPS over the last interval */
        uint64_t elapsed_us = now - ps->last_check_us;
        if (elapsed_us < 100000ULL) /* require at least 100ms between samples */
            continue;

        /* First sample: establish baseline without computing PPS */
        if (ps->rx_packets_prev == 0 && stats.rx_packets > 0)
        {
            ps->rx_packets_prev = stats.rx_packets;
            ps->last_check_us = now;
            continue;
        }

        uint64_t delta_pkts = (stats.rx_packets >= ps->rx_packets_prev)
                                  ? stats.rx_packets - ps->rx_packets_prev
                                  : 0; /* counter wrap guard */
        uint64_t pps = (elapsed_us > 0)
                           ? delta_pkts * 1000000ULL / elapsed_us
                           : 0;

        ps->rx_packets_prev = stats.rx_packets;
        ps->last_check_us = now;
        ps->current_pps = (uint32_t)pps;

        /* Monitor broadcast drop rate from OVS meter */
        if (ps->bcast_rx_prev > 0 && stats.rx_dropped >= ps->bcast_rx_prev) {
            uint64_t drop_delta = stats.rx_dropped - ps->bcast_rx_prev;

            ps->bcast_drop_pps = (uint32_t)(elapsed_us > 0
                                 ? drop_delta * 1000000ULL / elapsed_us
                                 : 0);

            if (ps->bcast_drop_pps > 0) {
                LOG_D("L2", "[%s] Port %d (%s): broadcast drops=%u pps "
                      "(meter active)",
                      ctx->switch_id, ps->port_no, ps->ifname,
                      ps->bcast_drop_pps);
            }
        }

        ps->bcast_rx_prev = stats.rx_dropped;

        l2_detect_storm(ctx, i, pps);
    }
}

/* ── tick: main per-cycle work ───────────────────────────────────────── */

void l2_agent_tick(l2_agent_ctx_t *ctx)
{
    uint64_t now = a2a_now_us();

    if (now - ctx->last_ovsdb_sync_us > 2000000ULL) // every 2 sec
    {
        l2_sync_ports_from_ovsdb(ctx);
        ctx->last_ovsdb_sync_us = now;
    }

    /* Poll ports for storm detection */
    if (now - ctx->last_poll_us >= L2_POLL_INTERVAL_US)
    {
        if (ctx->agent->fsm_state == FSM_STATE_ACTIVE)
            l2_port_poll(ctx);
        ctx->last_poll_us = now;
    }

    /* Sync MAC table every 2s */
    if (now - ctx->last_mac_sync_us >= L2_MAC_SYNC_INTERVAL)
    {
        if (ctx->agent->fsm_state == FSM_STATE_ACTIVE)
            l2_mac_sync(ctx);
        ctx->last_mac_sync_us = now;
    }
}

/* ── FSM wiring ──────────────────────────────────────────────────────── */

static void on_ovs_event(a2a_agent_t *agent, const a2a_event_t *ev)
{
    l2_agent_ctx_t *ctx = (l2_agent_ctx_t *)agent->userdata;
    if (ev->data.ovs.link_down)
        l2_handle_link_down(ctx, (a2a_event_t *)ev);
}

void l2_agent_init_fsm(l2_agent_ctx_t *ctx)
{
    agent_fsm_t *fsm = &ctx->agent->fsm;
    fsm_init(fsm); /* fill all cells with ERROR default */

    /* DISCOVERY */
    fsm_register(fsm, FSM_STATE_DISCOVERY, FSM_EVENT_PEER_DISCOVERED,
                 FSM_STATE_REGISTERING, on_peer_discovered);
    fsm_register(fsm, FSM_STATE_DISCOVERY, FSM_EVENT_MSG_RECEIVED,
                 FSM_STATE_RECEIVING, on_msg_received);
    /* Send heartbeats even in DISCOVERY so seeded peers stay alive */
    fsm_register(fsm, FSM_STATE_DISCOVERY, FSM_EVENT_HEARTBEAT_TICK,
                 FSM_STATE_DISCOVERY, on_heartbeat_tick);

    /* REGISTERING */
    fsm_register(fsm, FSM_STATE_REGISTERING, FSM_EVENT_MSG_RECEIVED,
                 FSM_STATE_RECEIVING, on_msg_received);
    fsm_register(fsm, FSM_STATE_REGISTERING, FSM_EVENT_REGISTERED,
                 FSM_STATE_ACTIVE, NULL);
    fsm_register(fsm, FSM_STATE_REGISTERING, FSM_EVENT_PEER_DISCOVERED,
                 FSM_STATE_REGISTERING, on_peer_discovered);
    fsm_register(fsm, FSM_STATE_REGISTERING, FSM_EVENT_HEARTBEAT_TICK,
                 FSM_STATE_REGISTERING, on_heartbeat_tick);

    /* RECEIVING */
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_PROCESSING_DONE,
                 FSM_STATE_ACTIVE, NULL);
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_MSG_RECEIVED,
                 FSM_STATE_RECEIVING, on_msg_received);
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_HEARTBEAT_TICK,
                 FSM_STATE_RECEIVING, on_heartbeat_tick);
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_OVS_EVENT,
                 FSM_STATE_RECEIVING, NULL);
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_PEER_TIMEOUT,
                 FSM_STATE_RECEIVING, on_peer_timeout);
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_REGISTERED,
                 FSM_STATE_ACTIVE, NULL);
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_PEER_DISCOVERED,
                 FSM_STATE_RECEIVING, on_peer_discovered);

    /* ACTIVE */
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_MSG_RECEIVED,
                 FSM_STATE_RECEIVING, on_msg_received);
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_HEARTBEAT_TICK,
                 FSM_STATE_ACTIVE, on_heartbeat_tick);
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_PEER_TIMEOUT,
                 FSM_STATE_ACTIVE, on_peer_timeout);
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_PEER_DISCOVERED,
                 FSM_STATE_ACTIVE, on_peer_discovered);
    /* OVS_EVENT in ACTIVE — link-down handler */
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_OVS_EVENT,
                 FSM_STATE_ACTIVE, on_ovs_event);
}
/* ── Lifecycle ───────────────────────────────────────────────────────── */

/*
 * l2_port_enumerate_from_sys() — enumerate ports for a bridge using
 * /sys/class/net/<bridge>/brif/ (no popen, no system call).
 *
 * Falls back to a single synthetic port entry in mock mode.
 * In real mode, OVSDB will later supply the ofport mapping once the
 * monitor fires; we seed from sysfs so polling works immediately.
 */
static int l2_port_enumerate_from_sys(l2_agent_ctx_t *ctx,
                                      const char *bridge,
                                      int use_mock)
{
    if (use_mock)
    {
        /* Synthetic ports for testing */
        static const char *mock_ports[] = {"eth1", "eth2", "eth3", NULL};
        int idx = 0;
        for (; mock_ports[idx] && idx < L2_MAX_PORTS; idx++)
        {
            ctx->ports[idx].port_no = idx + 1;
            strncpy(ctx->ports[idx].ifname, mock_ports[idx],
                    sizeof(ctx->ports[idx].ifname) - 1);
            ctx->ports[idx].last_check_us = a2a_now_us();
        }
        return idx;
    }

    /*
     * Read bridge member interfaces from /sys/class/net/<br>/brif/.
     * Each directory entry is a port name.
     * This is kernel-level, no CLI needed.
     */
    char brif_path[256];
    snprintf(brif_path, sizeof(brif_path),
             "/sys/class/net/%s/brif", bridge);

    DIR *d = opendir(brif_path);
    int idx = 0;

    if (d)
    {
        struct dirent *de;
        while ((de = readdir(d)) != NULL && idx < L2_MAX_PORTS)
        {
            if (de->d_name[0] == '.')
                continue;
            ctx->ports[idx].port_no = idx + 1;
            strncpy(ctx->ports[idx].ifname, de->d_name,
                    sizeof(ctx->ports[idx].ifname) - 1);
            ctx->ports[idx].last_check_us = a2a_now_us();
            LOG_I("L2", "Port mapped port=%d ifname=%s",
                  idx + 1, de->d_name);
            idx++;
        }
        closedir(d);
    }

    return idx;
}

/* ── OVSDB-driven port discovery ─────────────────────────────────────
 * Called from ovsdb_process_update() after the Interface table update.
 * Populates ctx->ports from the OVSDB shadow (ovsdb_get_port_stats +
 * ovsdb_get_ofport) so storm detection uses real OVS port numbers.
 *
 * This replaces the sysfs brif/ approach which only works for Linux
 * native bridges, not OVS bridges.
 */
/* ── OVSDB-driven port discovery callback ─────────────────────────── */
/* Passed to ovsdb_iterate_ifaces() — must be a top-level function */
typedef struct
{
    l2_agent_ctx_t *ctx;
} _l2_port_cb_arg_t;

static void _l2_port_sync_cb(const char *name, int ofport,
                             int link_up, void *ud)
{
    (void)link_up;
    l2_agent_ctx_t *ctx = ((_l2_port_cb_arg_t *)ud)->ctx;

    if (ofport <= 0)
        return; /* skip bridge-internal / unassigned ports */

    /* Check if already known — update ofport if so */
    for (int i = 0; i < ctx->port_count; i++)
    {
        if (strcmp(ctx->ports[i].ifname, name) == 0)
        {
            if (ctx->ports[i].port_no != ofport)
            {
                LOG_D("L2", "[%s] Port %s ofport updated %d→%d",
                      ctx->switch_id, name, ctx->ports[i].port_no, ofport);
                ctx->ports[i].port_no = ofport;
            }
            return;
        }
    }

    if (ctx->port_count >= L2_MAX_PORTS)
        return;

    port_state_t *ps = &ctx->ports[ctx->port_count++];
    ps->port_no = ofport;
    ps->last_check_us = a2a_now_us();
    strncpy(ps->ifname, name, sizeof(ps->ifname) - 1);

    LOG_I("L2", "[%s] Port discovered from OVSDB: if=%s ofport=%d",
          ctx->switch_id, name, ofport);
}

static void l2_ovsdb_epoll_handler(int fd, void *ud)
{
    l2_agent_ctx_t *ctx = (l2_agent_ctx_t *)ud;

    ssize_t n = recv(fd,
                     ctx->ovsdb_buf + ctx->ovsdb_len,
                     sizeof(ctx->ovsdb_buf) - ctx->ovsdb_len - 1,
                     MSG_DONTWAIT);

    if (n <= 0)
        return;

    ctx->ovsdb_len += n;
    ctx->ovsdb_buf[ctx->ovsdb_len] = '\0';

    /* OVSDB sends one JSON object per message, terminated by '\n'.
     * However the initial monitor response may be very large and
     * arrive in chunks. Try newline split first; if none found but
     * buffer contains a complete JSON object (balanced braces),
     * process it directly to avoid dropping the initial state dump. */
    char *p = ctx->ovsdb_buf;
    char *nl;

    while ((nl = strchr(p, '\n')) != NULL)
    {
        *nl = '\0';
        if (nl > p)
            ovsdb_process_update(p, ctx->agent);
        p = nl + 1;
    }

    /* If no newline found but buffer has content, check for complete JSON */
    size_t remaining = (size_t)(ctx->ovsdb_buf + ctx->ovsdb_len - p);
    if (remaining > 0 && p[0] == '{')
    {
        /* Count braces to detect complete JSON object */
        int depth = 0;
        int complete = 0;
        for (size_t i = 0; i < remaining; i++)
        {
            if (p[i] == '{')
                depth++;
            else if (p[i] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    complete = 1;
                    break;
                }
            }
        }
        if (complete)
        {
            ovsdb_process_update(p, ctx->agent);
            remaining = 0;
        }
    }

    memmove(ctx->ovsdb_buf, p, remaining);
    ctx->ovsdb_len = remaining;
}

void l2_sync_ports_from_ovsdb(l2_agent_ctx_t *ctx)
{

    _l2_port_cb_arg_t arg = {.ctx = ctx};
    ovsdb_iterate_ifaces(_l2_port_sync_cb, &arg);
}

l2_agent_ctx_t *l2_agent_create(const char *agent_id,
                                const char *switch_id,
                                const char *bridge,
                                const char *host, int port,
                                int use_mock_ovs)
{
    ovs_init(use_mock_ovs);

    l2_agent_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    strncpy(ctx->switch_id, switch_id, A2A_MAX_AGENT_ID - 1);
    strncpy(ctx->bridge, bridge, sizeof(ctx->bridge) - 1);

    ctx->agent = a2a_agent_create(agent_id, AGENT_TYPE_L2,
                                  switch_id, host, port);

    if (!ctx->agent)
    {
        free(ctx);
        return NULL;
    }

    ctx->agent->userdata = ctx;

    /* Initialize OVSDB buffer */
    ctx->ovsdb_len = 0;
    memset(ctx->ovsdb_buf, 0, sizeof(ctx->ovsdb_buf));

    /* Discover bridge ports */
    ctx->port_count =
        l2_port_enumerate_from_sys(ctx, bridge, use_mock_ovs);

    if (ctx->port_count == 0)
    {
        LOG_W("L2", "[%s] No ports found on bridge %s "
                    "(OVSDB monitor will populate once connected)",
              switch_id, bridge);
    }

    /* Setup OpenFlow + OVSDB connections */
    if (!use_mock_ovs)
    {
        /* Connect OpenFlow channel */
        int of_fd = ovs_of_connect(bridge);

        if (of_fd < 0)
        {
            LOG_W("L2", "[%s] OpenFlow connect failed — "
                  "MAC learning disabled",
                  switch_id);

        } else {

            ovs_of_register_epoll(ctx->agent->server);

            LOG_I("L2", "[%s] OpenFlow connected fd=%d",
                  switch_id, of_fd);

            /* Install broadcast storm meter */
            if (ovs_of_add_meter(bridge, 1, 1500) == 0)
            {
                LOG_I("L2", "[%s] Storm meter installed "
                      "(1500 kbps ≈ 1000 pps)",
                      switch_id);
            }
            else
            {
                LOG_W("L2", "[%s] Failed to install storm meter — "
                      "hardware enforcement disabled",
                      switch_id);
            }

            /* Broadcast storm protection flow */
            {
                ovs_flow_t bcast_fl = {0};

                bcast_fl.priority     = 50;
                bcast_fl.idle_timeout = 0;
                bcast_fl.hard_timeout = 0;

                snprintf(bcast_fl.match,
                         sizeof(bcast_fl.match),
                         "dl_dst=ff:ff:ff:ff:ff:ff");

                snprintf(bcast_fl.actions,
                         sizeof(bcast_fl.actions),
                         "meter:1,output:normal");

                if (ovs_add_flow(bridge, &bcast_fl) == 0)
                {
                    ctx->flows_installed++;

                    LOG_I("L2", "[%s] Broadcast storm flow installed "
                          "(priority=50, meter:1,output:normal)",
                          switch_id);
                }
                else
                {
                    LOG_W("L2", "[%s] Failed to install "
                          "broadcast storm flow",
                          switch_id);
                }
            }

            /* Multicast storm protection flow */
            {
                ovs_flow_t mcast_fl = {0};

                mcast_fl.priority     = 45;
                mcast_fl.idle_timeout = 0;
                mcast_fl.hard_timeout = 0;

                snprintf(mcast_fl.match,
                         sizeof(mcast_fl.match),
                         "dl_dst=01:00:00:00:00:00/"
                         "01:00:00:00:00:00");

                snprintf(mcast_fl.actions,
                         sizeof(mcast_fl.actions),
                         "meter:1,output:normal");

                if (ovs_add_flow(bridge, &mcast_fl) == 0)
                {
                    ctx->flows_installed++;

                    LOG_I("L2", "[%s] Multicast storm flow installed "
                          "(priority=45, meter:1,output:normal)",
                          switch_id);
                }
                else
                {
                    LOG_W("L2", "[%s] Failed to install "
                          "multicast storm flow",
                          switch_id);
                }
            }

            /* No catch-all forwarding flow is installed here.
             *
             * Unknown destination MAC packets must hit the
             * OpenFlow table-miss rule (priority=0 -> CONTROLLER),
             * generating PACKET_IN events for the L2 agent.
             *
             * The agent then performs:
             *   1. source MAC learning
             *   2. MAC-to-port mapping
             *   3. dynamic dl_dst flow installation
             *
             * Learned destination flows are installed later at
             * higher priority (priority=10).
             *
             * This ensures forwarding decisions remain fully
             * controller-driven instead of bypassing logic through
             * OVS NORMAL switching behavior.
             */
            LOG_I("L2",
                  "[%s] Dynamic MAC learning enabled via PACKET_IN",
                  switch_id);
        }

        /* OVSDB connection */
        int ovsdb_fd = ovsdb_connect();

        if (ovsdb_fd >= 0)
        {
            ovsdb_send_monitor(ovsdb_fd);

            /* Enable ovs_set_port_state() */
            ovs_set_ovsdb_fd(ovsdb_fd);

            a2a_server_add_fd(ctx->agent->server, ovsdb_fd);

            a2a_server_add_ext_fd(
                ctx->agent->server,
                ovsdb_fd,
                l2_ovsdb_epoll_handler,
                ctx);

            LOG_I("L2", "[%s] OVSDB connected fd=%d",
                  switch_id, ovsdb_fd);
        }
        else
        {
            LOG_W("L2", "[%s] OVSDB connect failed",
                  switch_id);
        }
    }

    l2_agent_init_fsm(ctx);

    LOG_I("L2", "[%s] Created bridge=%s addr=%s:%d "
          "ports=%d OVS=%s",
          switch_id, bridge, host, port,
          ctx->port_count,
          use_mock_ovs ? "mock" : "real");

    return ctx;
}

void l2_agent_destroy(l2_agent_ctx_t *ctx)
{
    if (!ctx)
        return;
    a2a_agent_destroy(ctx->agent);
    free(ctx);
}

void l2_print_table(l2_agent_ctx_t *ctx)
{
    /*
     * Use structured logging instead of printf().
     *
     * In detached Docker/container execution,
     * stdout may not appear in runtime logs.
     *
     * LOG_I() ensures:
     *   - docker logs visibility
     *   - centralized logging
     *   - timestamped structured output
     *   - production-grade observability
     */

    LOG_I("L2",
          "[%s] MAC Table (%d entries):",
          ctx->switch_id,
          ctx->mac_count);

    LOG_I("L2",
          "  %-20s %-6s %-10s",
          "MAC",
          "PORT",
          "PKTS");

    LOG_I("L2",
          "  %-20s %-6s %-10s",
          "---",
          "----",
          "----");

    for (int i = 0; i < ctx->mac_count; i++)
    {
        LOG_I("L2",
              "  %-20s %-6d %-10u",
              ctx->mac_table[i].mac,
              ctx->mac_table[i].port,
              ctx->mac_table[i].pkt_count);
    }
}
/* ── Topology helpers ────────────────────────────────────────────────── */
/*
 * Return the inter-switch port name for a given switch.
 * Topology: sw1 ↔ sw2 via s1s2/s2s1, sw3 ↔ sw4 via s3s4/s4s3, etc.
 * This is the port we redirect traffic to when the uplink fails.
 */
static const char *l2_get_interswitch_port(const char *switch_id)
{
    if (strcmp(switch_id, "sw1") == 0) return "s1s2";
    if (strcmp(switch_id, "sw2") == 0) return "s2s1";
    if (strcmp(switch_id, "sw3") == 0) return "s3s4";
    if (strcmp(switch_id, "sw4") == 0) return "s4s3";
    if (strcmp(switch_id, "sw5") == 0) return "s5s6";
    if (strcmp(switch_id, "sw6") == 0) return "s6s5";
    if (strcmp(switch_id, "sw7") == 0) return "s7s8";
    if (strcmp(switch_id, "sw8") == 0) return "s8s7";
    return NULL;
}

static const char *l2_get_neighbor_ip(const char *switch_id)
{
    if (strcmp(switch_id, "sw1") == 0) return "10.0.0.252";
    if (strcmp(switch_id, "sw2") == 0) return "10.0.0.251";
    if (strcmp(switch_id, "sw3") == 0) return "20.0.0.252";
    if (strcmp(switch_id, "sw4") == 0) return "20.0.0.251";
    if (strcmp(switch_id, "sw5") == 0) return "30.0.0.252";
    if (strcmp(switch_id, "sw6") == 0) return "30.0.0.251";
    if (strcmp(switch_id, "sw7") == 0) return "40.0.0.252";
    if (strcmp(switch_id, "sw8") == 0) return "40.0.0.251";
    return NULL;
}

static const char *l2_get_gateway_ip(const char *switch_id)
{
    if (strcmp(switch_id, "sw1") == 0 ||
        strcmp(switch_id, "sw2") == 0) return "10.0.0.254";
    if (strcmp(switch_id, "sw3") == 0 ||
        strcmp(switch_id, "sw4") == 0) return "20.0.0.254";
    if (strcmp(switch_id, "sw5") == 0 ||
        strcmp(switch_id, "sw6") == 0) return "30.0.0.254";
    if (strcmp(switch_id, "sw7") == 0 ||
        strcmp(switch_id, "sw8") == 0) return "40.0.0.254";
    return NULL;
}

void l2_handle_link_down(l2_agent_ctx_t *ctx, a2a_event_t *ev)
{
    int port = ev->data.ovs.port;

    /*
     * Idempotency guard — prevents double execution when both OVSDB
     * monitor and l2_port_poll() detect the same link-down event.
     * Once alternate_active=1 is set, any subsequent call for the
     * same port is a no-op. This is the authoritative guard; the
     * link_down_reported flag in the callers is best-effort.
     */
    for (int _i = 0; _i < ctx->port_count; _i++)
    {
        if (ctx->ports[_i].port_no == port)
        {
            if (ctx->ports[_i].alternate_active)
            {
                LOG_D("L2", "[%s] link_down port=%d: already in alternate mode — skip",
                      ctx->switch_id, port);
                return;
            }
            break;
        }
    }

    LOG_E("L2", "Link DOWN on port %d — notifying L3 peers", port);

    /* Mark storm cleared on this port */
    for (int i = 0; i < ctx->port_count; i++)
    {
        if (ctx->ports[i].port_no == port)
        {
            ctx->ports[i].storm_active = 0;
            break;
        }
    }

    /*
     * Intra-subnet alternate path when uplink fails.
     *
     * The failing port must be the uplink (core-facing). Uplink port names
     * follow the pattern sNcN (e.g., s1c1). Host-facing ports are sNhN.
     * Inter-switch ports are sNsN. We detect uplinks by 'c' after a digit.
     *
     * When sw1's uplink (s1c1, port 1) goes down:
     *   Physical alternate: sw1 → s1s2 → sw2 → s2c1 → core1(c1s2 kernel)
     *
     * Two actions needed:
     *   1. OVS: redirect all existing flows pointing to the dead port
     *      to the inter-switch port instead. This covers:
     *      - dl_dst=core1_MAC → was output:1, must become output:5
     *      - ip,nw_dst=X.X.X.0/24 flows (will be re-matched by NORMAL)
     *   2. Kernel: redirect default route via neighbor switch IP so that
     *      sw1's own kernel-originated packets (ARP, etc.) also use the
     *      alternate path.
     */
    int is_uplink = 0;
    const char *uplink_ifname = NULL;

    for (int i = 0; i < ctx->port_count; i++)
    {
        if (ctx->ports[i].port_no != port)
            continue;
        uplink_ifname = ctx->ports[i].ifname;
        /* Uplink: pattern is sNcN — has 'c' after a digit */
        size_t nl = strlen(uplink_ifname);
        for (size_t ci = 1; ci < nl; ci++)
        {
            if (uplink_ifname[ci] == 'c' &&
                uplink_ifname[ci-1] >= '1' &&
                uplink_ifname[ci-1] <= '9')
            {
                is_uplink = 1;
                break;
            }
        }
        break;
    }

    if (is_uplink)
    {
        const char *isw_port  = l2_get_interswitch_port(ctx->switch_id);
        const char *neighbor  = l2_get_neighbor_ip(ctx->switch_id);
        const char *gateway   = l2_get_gateway_ip(ctx->switch_id);

        /* Find the OVS ofport number of the inter-switch port */
        int isw_ofport = -1;
        if (isw_port)
        {
            for (int i = 0; i < ctx->port_count; i++)
            {
                if (strcmp(ctx->ports[i].ifname, isw_port) == 0)
                {
                    isw_ofport = ctx->ports[i].port_no;
                    break;
                }
            }
        }

        if (isw_ofport > 0 && neighbor)
        {
            /*
             * Failover strategy — OVS NORMAL handles rerouting:
             *
             * 1. Flush learned MAC flows. After flush, all unknown-dst
             *    packets hit table-miss → CONTROLLER → PACKET_IN.
             *    The agent replies with PACKET_OUT(NORMAL). OVS NORMAL
             *    floods to all UP ports — since s1c1 is DOWN, OVS
             *    automatically excludes it from the flood set.
             *    Packets reach core1 via s1s2→sw2→s2c1→c1s2.
             *
             * 2. Do NOT install catch-all IP/ARP redirect flows.
             *    priority=8 ip and priority=15 arp would override
             *    table-miss for ALL traffic including local same-switch
             *    packets (host1→host3), breaking intra-switch connectivity.
             *    OVS standalone fail_mode already handles dead port
             *    exclusion during NORMAL flooding.
             *
             * 3. Change kernel route so sw1's own kernel-originated
             *    packets (OSPF, management) use the alternate next-hop.
             */

            /* Step 1: Flush learned MAC flows — forces re-learning */
            ovs_flush_mac(ctx->bridge, NULL);

            LOG_I("L2", "[%s] Uplink DOWN port=%d: flushed MACs, "
                  "OVS NORMAL will flood via %s(ofport=%d)",
                  ctx->switch_id, port, isw_port, isw_ofport);

            /* Step 2: Kernel route redirect for sw1's own traffic */
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                     "ip route replace default via %s 2>/dev/null",
                     neighbor);
            (void)system(cmd);

            LOG_I("L2", "[%s] Alternate path: kernel route → %s, "
                  "OVS flood via port %d",
                  ctx->switch_id, neighbor, isw_ofport);

            /* Mark alternate active on this port */
            for (int i = 0; i < ctx->port_count; i++)
            {
                if (ctx->ports[i].port_no == port)
                {
                    ctx->ports[i].alternate_active = 1;
                    break;
                }
            }
        }
        else
        {
            LOG_W("L2", "[%s] Cannot install alternate: isw_ofport=%d "
                  "neighbor=%s gateway=%s",
                  ctx->switch_id, isw_ofport,
                  neighbor ? neighbor : "NULL",
                  gateway ? gateway : "NULL");
        }
    }

    /* Notify L3 peers */
    l2_report_anomaly(ctx, L2_ANOMALY_LINK_DOWN, port, 0, NULL, "link_down");
}
static void l2_report_anomaly(l2_agent_ctx_t *ctx,
                              int anomaly_type,
                              int port,
                              uint32_t pps,
                              const char *mac,
                              const char *reason)
{
    l2_anomaly_payload_t pl = {0};

    pl.anomaly_type = anomaly_type;
    pl.port = port;
    pl.pps = pps;
    pl.mac_count = ctx->mac_count;

    if (mac)
        strncpy(pl.mac, mac, sizeof(pl.mac) - 1);

    strncpy(pl.switch_id, ctx->switch_id, A2A_MAX_AGENT_ID - 1);
    strncpy(pl.reason, reason, sizeof(pl.reason) - 1);

    a2a_message_t msg = {0};
    msg.msg_id = ++ctx->agent->msg_counter;
    msg.msg_type = MSG_L2_ANOMALY;
    msg.timestamp_us = a2a_now_us();

    strncpy(msg.src_agent, ctx->agent->card.agent_id, A2A_MAX_AGENT_ID - 1);

    a2a_msg_set_l2_anomaly(&msg, &pl);

    for (int i = 0; i < ctx->agent->peer_count; i++)
    {
        agent_peer_t *p = &ctx->agent->peers[i];
        if (p->type != AGENT_TYPE_L3 || !p->alive)
            continue;

        strncpy(msg.dst_agent, p->agent_id, A2A_MAX_AGENT_ID - 1);

        if (conn_pool_send(&ctx->agent->pool, p->host, p->port, &msg) == 0)
            ctx->l3_notifies_sent++;
        else
            ctx->agent->send_failures++;
    }
}