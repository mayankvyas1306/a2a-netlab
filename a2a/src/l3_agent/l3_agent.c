#include "l3_agent.h"
#include "a2a_event.h"
#include "a2a_message.h"
#include "a2a_heartbeat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "a2a_log.h"
#include "a2a_transport.h"
#include <sys/socket.h>

extern int ovsdb_get_ofport(const char *ifname);
extern int ovs_of_connect(const char *bridge);
extern void ovs_set_ovsdb_fd(int fd);

int ovsdb_connect(void);
int ovsdb_send_monitor(int fd);

/* ── Internal helpers ────────────────────────────────────────────────── */

static route_entry_t *find_route(l3_agent_ctx_t *ctx,
                                 const char *prefix,
                                 const char *ifname)
{
    for (int i = 0; i < ctx->route_count; i++)
    {
        if (strcmp(ctx->routes[i].prefix, prefix) == 0 &&
            strcmp(ctx->routes[i].egress_ifname, ifname) == 0)
            return &ctx->routes[i];
    }
    return NULL;
}

/*
 * Find best alternate route for prefix that does NOT go
 * through failed_switch. Returns NULL if none found.
 */
static route_entry_t *find_alternate(l3_agent_ctx_t *ctx,
                                     const char *prefix,
                                     const char *failed_switch)
{
    route_entry_t *best = NULL;
    for (int i = 0; i < ctx->route_count; i++)
    {
        route_entry_t *r = &ctx->routes[i];
        if (strcmp(r->prefix, prefix) != 0)
            continue;
        if (r->state == ROUTE_STATE_WITHDRAWN)
            continue;
        if (strcmp(r->via_switch, failed_switch) == 0)
            continue;
        /* Check via_switch is still alive in peer table */
        int alive = 0;
        for (int j = 0; j < ctx->agent->peer_count; j++)
        {
            if (strcmp(ctx->agent->peers[j].agent_id,
                       r->via_switch) == 0 &&
                ctx->agent->peers[j].alive)
            {
                alive = 1;
                break;
            }
        }
        /* local routes are always alive */
        if (r->is_local)
            alive = 1;
        if (!alive)
            continue;
        if (!best || r->metric < best->metric)
            best = r;
    }
    return best;
}

/* Install a flow via OVS for the given route.
 *
 * Correct L3 forwarding action:
 *   1. dec_ttl            — decrement IP TTL (required for routing)
 *   2. mod_dl_dst:<mac>   — rewrite dst MAC to next-hop MAC (from ARP cache)
 *   3. mod_dl_src:<mac>   — rewrite src MAC to local bridge MAC
 *   4. output:<ofport>    — forward out the egress OpenFlow port
 *
 * Falls back to output:normal when ARP is not yet resolved.
 */
/* Install a flow via OVS for the given route. */
void install_route_flow(l3_agent_ctx_t *ctx, const route_entry_t *r)
{
    char nexthop_mac[18] = "";
    char local_mac[18] = "";
    int out_port = -1;

    /* 1. Handle Kernel/System Transit Links (e.g., c1c2) */
    if (r->egress_ifname[0])
    {
        out_port = ovsdb_get_ofport(r->egress_ifname);
        
        // If the port isn't in OVS, delegate to the Linux Kernel routing stack
        if (out_port <= 0)
        {
            LOG_I("L3", "[%s] Egress '%s' not in OVS. Installing NORMAL flow for %s",
                  ctx->switch_id, r->egress_ifname, r->prefix);
            
            ovs_flow_t fl = {0};
            fl.priority = 100;
            snprintf(fl.match, sizeof(fl.match), "ip,nw_dst=%s", r->prefix);
            snprintf(fl.actions, sizeof(fl.actions), "output:NORMAL");
            ovs_add_flow(ctx->bridge, &fl);
            return;
        }
    }

    /* 2. Handle OVS-Attached Links */
    int arp_ok = (l3_arp_resolve(r->nexthop, nexthop_mac, sizeof(nexthop_mac)) == 0);
    int mac_ok = (l3_get_local_mac(ctx->bridge, local_mac, sizeof(local_mac)) == 0);

    if (!arp_ok && strcmp(r->nexthop, "0.0.0.0") != 0)
    {
        LOG_W("L3", "ARP miss for %s", r->nexthop);
    }

    ovs_flow_t fl = {0};
    fl.priority = 100;
    snprintf(fl.match, sizeof(fl.match), "ip,nw_dst=%s", r->prefix);

    /* Only rewrite MACs if we have a valid OVS port and ARP resolution */
    if (arp_ok && mac_ok && out_port > 0 && out_port < (int)0xFFFFFFF0)
    {
        snprintf(fl.actions, sizeof(fl.actions),
                 "dec_ttl,mod_dl_dst:%s,mod_dl_src:%s,output:%d",
                 nexthop_mac, local_mac, out_port);
        LOG_I("L3", "Flow installed: %s via %s out_port=%d",
              r->prefix, nexthop_mac, out_port);
    }
    else
    {
        /* 3. CRITICAL FIX: Fallback to NORMAL, not CONTROLLER. 
           This allows the kernel to answer ARPs for local gateway subnets */
        snprintf(fl.actions, sizeof(fl.actions), "output:NORMAL");
        LOG_I("L3", "Fallback -> NORMAL flow for %s (Kernel routing will handle)", r->prefix);
    }

    ovs_add_flow(ctx->bridge, &fl);
}
/* Withdraw (delete) the flow for a route */
void withdraw_route_flow(l3_agent_ctx_t *ctx,
                         const route_entry_t *r)
{
    char match[256];

    snprintf(match, sizeof(match),
             "ip,nw_dst=%s", r->prefix);

    ovs_del_flow(ctx->bridge, match);

    LOG_I("L3", "Flow removed: %s", r->prefix);
}

/* Notify all known L2 peers of a route/topology change */
static void notify_l2_peers_topology(l3_agent_ctx_t *ctx,
                                     const route_entry_t *r,
                                     int is_withdraw)
{
    l3_event_payload_t pl = {0};
    snprintf(pl.prefix, sizeof(pl.prefix), "%s", r->prefix);
    snprintf(pl.nexthop, sizeof(pl.nexthop), "%s", r->nexthop);
    strncpy(pl.via_switch, r->via_switch, A2A_MAX_AGENT_ID - 1);
    pl.metric = r->metric;
    pl.is_withdraw = is_withdraw;
    strncpy(pl.reason, is_withdraw ? "reroute" : "install",
            sizeof(pl.reason) - 1);

    a2a_message_t msg = {0};
    msg.msg_id = ++ctx->agent->msg_counter;
    msg.msg_type = MSG_TOPOLOGY;
    msg.timestamp_us = a2a_now_us();
    strncpy(msg.src_agent, ctx->agent->card.agent_id,
            A2A_MAX_AGENT_ID - 1);
    a2a_msg_set_l3_event(&msg, &pl);

    for (int i = 0; i < ctx->agent->peer_count; i++)
    {
        agent_peer_t *p = &ctx->agent->peers[i];
        if (p->type != AGENT_TYPE_L2 || !p->alive)
            continue;
        strncpy(msg.dst_agent, p->agent_id, A2A_MAX_AGENT_ID - 1);
        if (conn_pool_send(&ctx->agent->pool, p->host, p->port, &msg) != 0)
        {
            ctx->agent->send_failures++;
            LOG_W("L3", "Send failed to peer %s", p->agent_id);
        }
    }
}

/* ── Route operations ────────────────────────────────────────────────── */

int l3_add_route(l3_agent_ctx_t *ctx, const char *prefix,
                 const char *nexthop, const char *via_switch, const char *ifname,
                 int metric, int is_local)
{
    if (ctx->route_count >= L3_MAX_ROUTES)
        return -1;
    route_entry_t *r = &ctx->routes[ctx->route_count++];
    strncpy(r->prefix, prefix, sizeof(r->prefix) - 1);
    strncpy(r->nexthop, nexthop, sizeof(r->nexthop) - 1);
    strncpy(r->via_switch, via_switch, A2A_MAX_AGENT_ID - 1);
    strncpy(r->egress_ifname, ifname,
            sizeof(r->egress_ifname) - 1);
    r->metric = metric;
    r->state = ROUTE_STATE_ACTIVE;
    r->installed_at_us = a2a_now_us();
    r->last_verified_us = r->installed_at_us;
    r->is_local = is_local;

    install_route_flow(ctx, r);
    notify_l2_peers_topology(ctx, r, 0);

    LOG_I("L3", "[%s] Route installed: %s via %s nh=%s metric=%d",
          ctx->switch_id, prefix, via_switch, nexthop, metric);
    return 0;
}

int l3_withdraw_route(l3_agent_ctx_t *ctx, const char *prefix,
                      const char *reason)
{
    route_entry_t *r = NULL;
    for (int i = 0; i < ctx->route_count; i++)
    {
        if (strcmp(ctx->routes[i].prefix, prefix) == 0)
        {
            r = &ctx->routes[i];
            break;
        }
    }
    if (!r)
        return -1;
    r->state = ROUTE_STATE_WITHDRAWN;
    withdraw_route_flow(ctx, r);
    notify_l2_peers_topology(ctx, r, 1);
    LOG_I("L3", "[%s] Route withdrawn: %s  reason=%s",
          ctx->switch_id, prefix, reason);
    return 0;
}

void l3_reroute_around(l3_agent_ctx_t *ctx,
                       const char *failed_switch, int failed_port)
{
    LOG_I("L3", "[%s] Rerouting around failed switch=%s port=%d",
          ctx->switch_id, failed_switch, failed_port);

    for (int i = 0; i < ctx->route_count; i++)
    {
        route_entry_t *r = &ctx->routes[i];
        if (r->state == ROUTE_STATE_WITHDRAWN)
            continue;
        if (strcmp(r->via_switch, failed_switch) != 0)
            continue;

        /* This route is affected */
        route_entry_t *alt = find_alternate(ctx, r->prefix,
                                            failed_switch);
        if (alt)
        {
            LOG_I("L3", "[%s] Prefix %s: rerouting via %s → %s "
                        "(metric %d→%d)",
                  ctx->switch_id, r->prefix,
                  r->via_switch, alt->via_switch,
                  r->metric, alt->metric);
            withdraw_route_flow(ctx, r);
            r->state = ROUTE_STATE_DEGRADED;
            /*
             * Update via_switch so heartbeat verification does not
             * see the failed switch and immediately trigger another
             * reroute on the next tick — creating a reroute storm.
             */
            snprintf(r->via_switch, sizeof(r->via_switch),
                     "%s", alt->via_switch);
            snprintf(r->nexthop, sizeof(r->nexthop),
                     "%s", alt->nexthop);
            r->metric = alt->metric;
            r->state = ROUTE_STATE_ACTIVE;
            install_route_flow(ctx, r);
            notify_l2_peers_topology(ctx, r, 0);
            ctx->reroutes_performed++;
        }
        else
        {
            LOG_W("L3", "[%s] Prefix %s: NO ALTERNATE — marking degraded",
                  ctx->switch_id, r->prefix);
            r->state = ROUTE_STATE_DEGRADED;
            /* Alert all L3 peers */
            l3_event_payload_t pl = {0};
            strncpy(pl.prefix, r->prefix, sizeof(pl.prefix) - 1);
            strncpy(pl.via_switch, failed_switch, A2A_MAX_AGENT_ID - 1);
            pl.is_withdraw = 1;
            strncpy(pl.reason, "no_alternate", sizeof(pl.reason) - 1);

            a2a_message_t msg = {0};
            msg.msg_id = ++ctx->agent->msg_counter;
            msg.msg_type = MSG_L3_EVENT;
            msg.timestamp_us = a2a_now_us();
            strncpy(msg.src_agent, ctx->agent->card.agent_id,
                    A2A_MAX_AGENT_ID - 1);
            a2a_msg_set_l3_event(&msg, &pl);

            for (int j = 0; j < ctx->agent->peer_count; j++)
            {
                agent_peer_t *p = &ctx->agent->peers[j];
                if (p->type != AGENT_TYPE_L3 || !p->alive)
                    continue;
                strncpy(msg.dst_agent, p->agent_id,
                        A2A_MAX_AGENT_ID - 1);
                if (conn_pool_send(&ctx->agent->pool, p->host, p->port, &msg) != 0)
                {
                    ctx->agent->send_failures++;
                    LOG_W("L3", "Send failed to peer %s", p->agent_id);
                }
            }
        }
    }
}

void l3_sync_routes_to_peer(l3_agent_ctx_t *ctx,
                            const char *peer_id,
                            const char *peer_host, int peer_port)
{
    for (int i = 0; i < ctx->route_count; i++)
    {
        route_entry_t *r = &ctx->routes[i];
        if (r->state == ROUTE_STATE_WITHDRAWN)
            continue;

        l3_event_payload_t pl = {0};
        strncpy(pl.prefix, r->prefix, sizeof(pl.prefix) - 1);
        strncpy(pl.nexthop, r->nexthop, sizeof(pl.nexthop) - 1);
        strncpy(pl.via_switch, r->via_switch, A2A_MAX_AGENT_ID - 1);
        pl.metric = r->metric;

        a2a_message_t msg = {0};
        msg.msg_id = ++ctx->agent->msg_counter;
        msg.msg_type = MSG_L3_EVENT;
        msg.timestamp_us = a2a_now_us();
        strncpy(msg.src_agent, ctx->agent->card.agent_id,
                A2A_MAX_AGENT_ID - 1);
        strncpy(msg.dst_agent, peer_id, A2A_MAX_AGENT_ID - 1);
        a2a_msg_set_l3_event(&msg, &pl);
        if (conn_pool_send(&ctx->agent->pool, peer_host, peer_port, &msg) != 0)
        {
            ctx->agent->send_failures++;
            LOG_W("L3", "Send failed to peer %s", peer_id);
        }
    }
}

static void l3_send_policy(l3_agent_ctx_t *ctx,
                           const char *target_l2,
                           policy_type_t type,
                           int port,
                           const char *mac,
                           uint32_t rate)
{
    a2a_message_t msg = {0};
    msg.msg_id = ++ctx->agent->msg_counter;
    msg.msg_type = MSG_POLICY_CMD;
    msg.timestamp_us = a2a_now_us();

    strncpy(msg.src_agent, ctx->agent->card.agent_id, A2A_MAX_AGENT_ID - 1);
    strncpy(msg.dst_agent, target_l2, A2A_MAX_AGENT_ID - 1);

    policy_cmd_payload_t pl = {0};
    pl.policy_type = type;
    pl.port = port;
    pl.rate_limit = rate;
    strncpy(pl.switch_id, ctx->switch_id, A2A_MAX_AGENT_ID - 1);
    if (mac)
        strncpy(pl.mac, mac, sizeof(pl.mac) - 1);

    a2a_msg_set_policy_cmd(&msg, &pl);

    for (int i = 0; i < ctx->agent->peer_count; i++)
    {
        agent_peer_t *p = &ctx->agent->peers[i];
        if (strcmp(p->agent_id, target_l2) == 0 && p->alive)
        {
            if (conn_pool_send(&ctx->agent->pool, p->host, p->port, &msg) != 0)
            {
                ctx->agent->send_failures++;
                LOG_W("L3", "Policy send failed to %s", target_l2);
            }
            else
            {
                LOG_I("L3", "[%s] policy sent → %s type=%d port=%d",
                      ctx->switch_id, target_l2, type, port);
            }
            return;
        }
    }
}

#define L2_ANOMALY_SOURCES_MAX 16

static struct
{
    char src[A2A_MAX_AGENT_ID];
    uint64_t last_action_us;
} g_anomaly_rate[L2_ANOMALY_SOURCES_MAX];

static void l3_handle_l2_anomaly(l3_agent_ctx_t *ctx,
                                 const a2a_message_t *msg)
{
    uint64_t now = a2a_now_us();

    /*  Per-source 500ms rate limit */
    int slot = -1;

    for (int i = 0; i < L2_ANOMALY_SOURCES_MAX; i++)
    {
        if (g_anomaly_rate[i].src[0] == '\0')
        {
            if (slot < 0)
                slot = i;
            continue;
        }

        if (strcmp(g_anomaly_rate[i].src, msg->src_agent) == 0)
        {
            slot = i;

            if (now - g_anomaly_rate[i].last_action_us < 500000ULL)
                return;

            break;
        }
    }

    if (slot < 0)
        slot = 0; /* fallback */

    strncpy(g_anomaly_rate[slot].src,
            msg->src_agent,
            A2A_MAX_AGENT_ID - 1);

    g_anomaly_rate[slot].last_action_us = now;

    l2_anomaly_payload_t pl = {0};
    if (a2a_msg_get_l2_anomaly(msg, &pl) < 0)
        return;

    ctx->l2_events_received++;

    LOG_I("L3", "[%s] anomaly from %s type=%d port=%d pps=%u",
          ctx->switch_id, msg->src_agent,
          pl.anomaly_type, pl.port, pl.pps);

    switch (pl.anomaly_type)
    {
    case L2_ANOMALY_STORM:
        LOG_I("L3", "Decision: STORM → reroute + rate limit");
        l3_reroute_around(ctx, pl.switch_id, pl.port);
        l3_send_policy(ctx, msg->src_agent,
                       POLICY_RATE_LIMIT,
                       pl.port, NULL, pl.pps);
        break;

    case L2_ANOMALY_FLOOD:
        LOG_I("L3", "Decision: FLOOD → isolate + reroute");
        l3_reroute_around(ctx, pl.switch_id, pl.port);
        l3_send_policy(ctx, msg->src_agent,
                       POLICY_ISOLATE_PORT,
                       pl.port, NULL, 0);
        break;

    case L2_ANOMALY_MAC_SPOOF:
        LOG_I("L3", "Decision: MAC_SPOOF → blackhole");
        l3_send_policy(ctx, msg->src_agent,
                       POLICY_BLACKHOLE_MAC,
                       pl.port, pl.mac, 0);
        break;

    case L2_ANOMALY_LINK_DOWN:
        LOG_I("L3", "Decision: LINK_DOWN → reroute");
        l3_reroute_around(ctx, pl.switch_id, pl.port);
        break;

    case L2_ANOMALY_STORM_CLEAR:
        LOG_I("L3", "Decision: STORM_CLEAR → restore");
        l3_send_policy(ctx, msg->src_agent,
                       POLICY_RESTORE_PORT,
                       pl.port, NULL, 0);
        break;

    default:
        break;
    }
}

/* ── FSM action handlers ─────────────────────────────────────────────── */

static void on_msg_received(a2a_agent_t *agent, const a2a_event_t *ev)
{
    l3_agent_ctx_t *ctx = (l3_agent_ctx_t *)agent->userdata;
    const a2a_message_t *msg = &ev->data.msg;

    switch (msg->msg_type)
    {

    case MSG_L2_ANOMALY:
        l3_handle_l2_anomaly(ctx, msg);
        break;

    case MSG_L3_EVENT:
    {
        l3_event_payload_t pl = {0};
        if (a2a_msg_get_l3_event(msg, &pl) < 0)
            break;
        LOG_I("L3", "[%s] Route update from peer %s: %s via %s metric=%d%s",
              ctx->switch_id, msg->src_agent,
              pl.prefix, pl.via_switch, pl.metric,
              pl.is_withdraw ? " [WITHDRAW]" : "");

        if (pl.is_withdraw)
        {
            l3_withdraw_route(ctx, pl.prefix, pl.reason);
        }
        else
        {
            /* Add/update route from peer */
            route_entry_t *existing = NULL;

            for (int i = 0; i < ctx->route_count; i++)
            {
                if (strcmp(ctx->routes[i].prefix, pl.prefix) == 0)
                {
                    existing = &ctx->routes[i];
                    break;
                }
            }
            if (!existing)
            {
                l3_add_route(ctx, pl.prefix, pl.nexthop,
                             pl.via_switch, "", pl.metric + 1, 0);
            }
            else if (pl.metric < existing->metric)
            {
                /* Better route found */
                snprintf(existing->nexthop, sizeof(existing->nexthop), "%s", pl.nexthop);
                strncpy(existing->via_switch, pl.via_switch,
                        A2A_MAX_AGENT_ID - 1);
                existing->metric = pl.metric + 1;
                existing->state = ROUTE_STATE_ACTIVE;
                withdraw_route_flow(ctx, existing);
                install_route_flow(ctx, existing);
            }
        }
        break;
    }

    case MSG_REGISTER:
    {
        register_payload_t reg = {0};
        a2a_msg_get_register(msg, &reg);

        if (reg.agent_type == AGENT_TYPE_L3)
        {
            LOG_I("L3", "[%s] Ignoring REGISTER from L3 peer %s (avoid loop)",
                  ctx->switch_id, msg->src_agent);
            break;
        }

        LOG_I("L3", "[%s] REGISTER from %s type=%s switch=%s",
              ctx->switch_id, msg->src_agent,
              reg.agent_type == AGENT_TYPE_L2 ? "L2" : "L3",
              reg.switch_id);

        /* ─────────────────────────────────────────────
         * 1. Add peer to peer table
         * ───────────────────────────────────────────── */
        a2a_agent_add_peer(agent, msg->src_agent,
                           (agent_type_t)reg.agent_type,
                           reg.switch_id,
                           reg.host,
                           reg.port);

        /* ─────────────────────────────────────────────
         * 2. Send REGISTER_ACK
         * ───────────────────────────────────────────── */
        a2a_message_t ack = {0};
        ack.msg_id = ++agent->msg_counter;
        ack.msg_type = MSG_REGISTER_ACK;
        ack.timestamp_us = a2a_now_us();

        strncpy(ack.src_agent, agent->card.agent_id, A2A_MAX_AGENT_ID - 1);
        strncpy(ack.dst_agent, msg->src_agent, A2A_MAX_AGENT_ID - 1);

        if (conn_pool_send(&agent->pool, reg.host, reg.port, &ack) != 0)
        {
            ctx->agent->send_failures++;
            LOG_W("L3", "Send failed to peer %s", msg->src_agent);
        }

        LOG_I("L3", "[%s] Sent REGISTER_ACK to %s",
              ctx->switch_id, msg->src_agent);

        /* ─────────────────────────────────────────────
         * 3. Sync routes to new peer
         * ───────────────────────────────────────────── */
        l3_sync_routes_to_peer(ctx, msg->src_agent,
                               reg.host, reg.port);

        /* ─────────────────────────────────────────────
         * 4. SEND PEER LIST
         * ───────────────────────────────────────────── */
        {
            peer_list_payload_t pl = {0};

            for (int i = 0; i < agent->peer_count && pl.count < PEER_LIST_MAX; i++)
            {
                agent_peer_t *p = &agent->peers[i];

                if (!p->alive)
                    continue;

                strncpy(pl.peers[pl.count].agent_id, p->agent_id, A2A_MAX_AGENT_ID - 1);
                strncpy(pl.peers[pl.count].host, p->host, A2A_MAX_HOST_LEN - 1);
                strncpy(pl.peers[pl.count].switch_id, p->switch_id, A2A_MAX_AGENT_ID - 1);

                pl.peers[pl.count].port = p->port;
                pl.peers[pl.count].agent_type = p->type;

                pl.count++;
            }

            a2a_message_t peer_msg = {0};
            peer_msg.msg_id = ++agent->msg_counter;
            peer_msg.msg_type = MSG_PEER_LIST;
            peer_msg.timestamp_us = a2a_now_us();

            strncpy(peer_msg.src_agent, agent->card.agent_id, A2A_MAX_AGENT_ID - 1);
            strncpy(peer_msg.dst_agent, msg->src_agent, A2A_MAX_AGENT_ID - 1);

            a2a_msg_set_peer_list(&peer_msg, &pl);

            if (conn_pool_send(&agent->pool, reg.host, reg.port, &peer_msg) != 0)
            {
                ctx->agent->send_failures++;
                LOG_W("L3", "Failed to send PEER_LIST to %s", msg->src_agent);
            }
            else
            {
                LOG_I("L3", "Sent PEER_LIST (%d peers) to %s", pl.count, msg->src_agent);
            }
        }
        /*
         * Push PEER_DISCOVERED so the FSM calls on_peer_discovered,
         * which sends REGISTER from L3 → L2.
         *
         * This is the CRITICAL step that:
         * 1. Causes L2 to call a2a_agent_add_peer("agent-l3-coreX", host, port)
         *    upgrading the seed entry from "seed-IP-PORT" to the real agent_id.
         * 2. Ensures heartbeat_on_received on L2 can find the peer by correct agent_id
         *    and update last_heartbeat_us, preventing spurious 15s timeout.
         * 3. Establishes full bidirectional registration required for MSG_L2_ANOMALY
         *    delivery (L2 must have L3 in peer table as alive=1).
         */
        {
            a2a_event_t disc_ev = {0};
            disc_ev.type = A2A_EV_PEER_DISCOVERED;
            disc_ev.fsm_event = FSM_EVENT_PEER_DISCOVERED;
            disc_ev.timestamp_us = a2a_now_us();
            disc_ev.data.peer.port = reg.port;
            disc_ev.data.peer.agent_type = (int)reg.agent_type;
            strncpy(disc_ev.data.peer.agent_id, msg->src_agent,
                    A2A_MAX_AGENT_ID - 1);
            strncpy(disc_ev.data.peer.host, reg.host,
                    A2A_MAX_HOST_LEN - 1);
            strncpy(disc_ev.data.peer.switch_id, reg.switch_id,
                    A2A_MAX_AGENT_ID - 1);
            event_queue_push(&agent->eq, &disc_ev);
        }
        break;
    }
    case MSG_HEARTBEAT:
        heartbeat_on_received(agent, msg);
        break;
    case MSG_REGISTER_ACK:
    {
        LOG_I("L3", "[%s] REGISTER_ACK from %s",
              ctx->switch_id, msg->src_agent);

        /* Refresh heartbeat timestamp — same race prevention as L2 */
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
            a2a_event_t ev2 = {0};
            ev2.type = A2A_EV_MSG_RECEIVED;
            ev2.fsm_event = FSM_EVENT_REGISTERED;
            ev2.timestamp_us = a2a_now_us();
            event_queue_push(&agent->eq, &ev2);
        }
        break;
    }

    case MSG_PEER_LIST:
    {
        peer_list_payload_t pl = {0};

        if (a2a_msg_get_peer_list(msg, &pl) != 0)
            break;

        LOG_I("L3", "[%s] Received PEER_LIST (%d peers)",
              ctx->switch_id, pl.count);

        for (int i = 0; i < pl.count; i++)
        {
            if (strcmp(pl.peers[i].agent_id, ctx->agent->card.agent_id) == 0)
                continue;

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

            LOG_I("L3", "[%s] New peer via PEER_LIST: %s",
                  ctx->switch_id, pl.peers[i].agent_id);

            if (ctx->agent->peer_count < A2A_MAX_PEERS)
            {
                a2a_agent_add_peer(ctx->agent,
                                   pl.peers[i].agent_id,
                                   pl.peers[i].agent_type,
                                   pl.peers[i].switch_id,
                                   pl.peers[i].host,
                                   pl.peers[i].port);
            }

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
        LOG_W("L3", "[%s] Unhandled msg type=%d from %s",
              ctx->switch_id, msg->msg_type, msg->src_agent);
        break;
    }

    a2a_event_t done = {0};
    done.type = A2A_EV_MSG_RECEIVED;
    done.fsm_event = FSM_EVENT_PROCESSING_DONE;
    event_queue_push(&agent->eq, &done);
}

static void on_peer_timeout(a2a_agent_t *agent, const a2a_event_t *ev)
{
    l3_agent_ctx_t *ctx = (l3_agent_ctx_t *)agent->userdata;
    const char *dead_peer = ev->data.peer.agent_id;

    LOG_W("L3", "[%s] peer timeout: %s — triggering reroute",
          ctx->switch_id, dead_peer);

    /* Mark dead — do NOT compact here (index corruption risk) */
    for (int i = 0; i < agent->peer_count; i++)
    {
        if (strcmp(agent->peers[i].agent_id, dead_peer) == 0)
        {
            agent->peers[i].alive = 0;
            break;
        }
    }

    /* Reroute away from the dead peer's routes */
    l3_reroute_around(ctx, dead_peer, -1);

    /*
     * Evict only this peer's TCP connection.  A full pool destroy
     * would disconnect all other healthy peers simultaneously.
     */
    conn_pool_evict_peer(&agent->pool, ev->data.peer.host,
                         ev->data.peer.port);
}

static void on_peer_discovered(a2a_agent_t *agent, const a2a_event_t *ev)
{
    l3_agent_ctx_t *ctx = (l3_agent_ctx_t *)agent->userdata;
    const peer_info_t *p = &ev->data.peer;

    /* prevent L3↔L3 infinite REGISTER loop */
    if (p->agent_type == AGENT_TYPE_L3)
    {
        LOG_I("L3", "[%s] Skipping REGISTER to L3 peer %s (avoid loop)",
              ctx->switch_id, p->agent_id);
        return;
    }

    LOG_I("L3", "[%s] Peer discovered: %s — sending REGISTER",
          ctx->switch_id, p->agent_id);

    register_payload_t reg = {0};
    strncpy(reg.host, agent->card.host, A2A_MAX_HOST_LEN - 1);
    strncpy(reg.switch_id, ctx->switch_id, A2A_MAX_AGENT_ID - 1);
    reg.port = agent->card.port;
    reg.agent_type = AGENT_TYPE_L3;

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
        LOG_W("L3", "Send failed to peer %s", p->agent_id);
    }
}

static void on_heartbeat_tick(a2a_agent_t *agent, const a2a_event_t *ev)
{
    (void)ev;
    l3_agent_ctx_t *ctx = (l3_agent_ctx_t *)agent->userdata;
    heartbeat_send_all(agent);
    heartbeat_check_peers(agent);

    /* Verify routes whose via_switch is still alive */
    uint64_t now = a2a_now_us();
    for (int i = 0; i < ctx->route_count; i++)
    {
        route_entry_t *r = &ctx->routes[i];
        if (r->state != ROUTE_STATE_ACTIVE)
            continue;
        if (r->is_local)
        {
            r->last_verified_us = now;
            continue;
        }
        int alive = 0;
        for (int j = 0; j < ctx->agent->peer_count; j++)
        {
            if (strcmp(ctx->agent->peers[j].agent_id,
                       r->via_switch) == 0 &&
                ctx->agent->peers[j].alive)
            {
                alive = 1;
                break;
            }
        }
        if (alive)
        {
            r->last_verified_us = now;
        }
        else if (now - r->last_verified_us > ROUTE_STALE_US)
        {
            LOG_W("L3", "[%s] Route stale (via_switch=%s dead): %s",
                  ctx->switch_id, r->via_switch, r->prefix);
            l3_reroute_around(ctx, r->via_switch, -1);
        }
    }
}

void l3_agent_init_fsm(l3_agent_ctx_t *ctx)
{
    agent_fsm_t *fsm = &ctx->agent->fsm;
    fsm_init(fsm);

    /* DISCOVERY */
    fsm_register(fsm, FSM_STATE_DISCOVERY, FSM_EVENT_PEER_DISCOVERED,
                 FSM_STATE_REGISTERING, on_peer_discovered);
    fsm_register(fsm, FSM_STATE_DISCOVERY, FSM_EVENT_MSG_RECEIVED,
                 FSM_STATE_RECEIVING, on_msg_received);
    /* Send heartbeats even in DISCOVERY */
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
}

/* Netlink callback dispatched from a2a_server_poll() */
static void l3_netlink_epoll_handler(int fd, void *ud)
{
    (void)fd;
    l3_agent_ctx_t *ctx = (l3_agent_ctx_t *)ud;
    l3_netlink_process(ctx);
}

static void l3_ovsdb_epoll_handler(int fd, void *ud)
{
    l3_agent_ctx_t *ctx = (l3_agent_ctx_t *)ud;

    char buf[65536];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
    if (n <= 0)
        return;

    buf[n] = '\0';

    char *p = buf;
    char *nl;

    while ((nl = strchr(p, '\n')) != NULL)
    {
        *nl = '\0';
        if (nl > p)
            ovsdb_process_update(p, ctx->agent);
        p = nl + 1;
    }
    /* Fallback: process complete JSON object without trailing newline */
    size_t remaining = (size_t)(buf + n - p);
    if (remaining > 0 && p[0] == '{')
    {
        int depth = 0, complete = 0;
        for (size_t i = 0; i < remaining; i++)
        {
            if (p[i] == '{')
                depth++;
            else if (p[i] == '}')
            {
                if (--depth == 0)
                {
                    complete = 1;
                    break;
                }
            }
        }
        if (complete)
            ovsdb_process_update(p, ctx->agent);
    }
}

l3_agent_ctx_t *l3_agent_create(const char *agent_id,
                                const char *switch_id,
                                const char *bridge,
                                const char *host, int port,
                                int use_mock_ovs)
{
    ovs_init(use_mock_ovs);

    l3_agent_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    strncpy(ctx->switch_id, switch_id, A2A_MAX_AGENT_ID - 1);
    strncpy(ctx->bridge, bridge, sizeof(ctx->bridge) - 1);
    ctx->netlink_fd = -1;

    ctx->agent = a2a_agent_create(agent_id, AGENT_TYPE_L3,
                                  switch_id, host, port);
    if (!ctx->agent)
    {
        free(ctx);
        return NULL;
    }

    ctx->agent->userdata = ctx;

    int ovsdb_fd = ovsdb_connect();
    if (ovsdb_fd >= 0)
    {
        ovsdb_send_monitor(ovsdb_fd);

        a2a_server_add_fd(ctx->agent->server, ovsdb_fd);
        a2a_server_add_ext_fd(ctx->agent->server,
                              ovsdb_fd,
                              l3_ovsdb_epoll_handler,
                              ctx);
        ovs_set_ovsdb_fd(ovsdb_fd);
    }

    /* Register per-agent FSM transitions */
    l3_agent_init_fsm(ctx);

    /* Start OpenFlow connection eagerly (installs table-miss entry)
     * and register for PACKET_IN events via epoll. */

    if (!use_mock_ovs)
    {
        int of_fd = ovs_of_connect(bridge);
        if (of_fd >= 0)
        {
            ovs_of_register_epoll(ctx->agent->server);
            LOG_I("L3", "[%s] OpenFlow connected fd=%d", switch_id, of_fd);
        }
        else
        {
            LOG_W("L3", "[%s] OpenFlow connect failed", switch_id);
        }
    }

    /* Start Netlink routing monitor */
    if (!use_mock_ovs)
    {
        int nl_fd = l3_netlink_init();
        if (nl_fd >= 0)
        {
            ctx->netlink_fd = nl_fd;
            /* Register with the server epoll loop */
            a2a_server_add_fd(ctx->agent->server, nl_fd);
            a2a_server_add_ext_fd(ctx->agent->server,
                                  nl_fd,
                                  l3_netlink_epoll_handler,
                                  ctx);
            /* Dump initial route table */
            l3_netlink_dump_routes(ctx);
            LOG_I("L3", "[%s] Netlink monitor active fd=%d",
                  switch_id, nl_fd);
        }
        else
        {
            LOG_W("L3", "[%s] Netlink init failed — routing events disabled",
                  switch_id);
        }
    }

    LOG_I("L3", "[%s] Created bridge=%s addr=%s:%d OVS=%s",
          switch_id, bridge, host, port,
          use_mock_ovs ? "mock" : "real");
    return ctx;
}

void l3_agent_destroy(l3_agent_ctx_t *ctx)
{
    if (!ctx)
        return;

    /*
     * Remove Netlink fd from epoll BEFORE destroying the server.
     * If we close the fd first without removing it from epoll,
     * epoll_wait may return a stale event on the closed fd and
     * the handler dereferences ctx — use-after-free / segfault.
     */
    if (ctx->netlink_fd >= 0 && ctx->agent && ctx->agent->server)
    {
        a2a_server_del_fd(ctx->agent->server, ctx->netlink_fd);
    }
    l3_netlink_close();

    a2a_agent_destroy(ctx->agent);
    free(ctx);
}

void l3_agent_tick(l3_agent_ctx_t *ctx)
{
    /* L3 tick is driven by FSM events; no additional periodic work here
       beyond what on_heartbeat_tick handles. */
    (void)ctx;
}

void l3_print_routes(l3_agent_ctx_t *ctx)
{
    static const char *snames[] = {"ACTIVE", "DEGRADED", "WITHDRAWN"};
    printf("\n[L3:%s] Route Table (%d routes):\n",
           ctx->switch_id, ctx->route_count);
    printf("  %-20s %-16s %-20s %-6s %s\n",
           "PREFIX", "NEXTHOP", "VIA-SWITCH", "METRIC", "STATE");
    printf("  %-20s %-16s %-20s %-6s %s\n",
           "------", "-------", "----------", "------", "-----");
    for (int i = 0; i < ctx->route_count; i++)
    {
        route_entry_t *r = &ctx->routes[i];
        printf("  %-20s %-16s %-20s %-6d %s%s\n",
               r->prefix, r->nexthop, r->via_switch, r->metric,
               snames[r->state], r->is_local ? " [local]" : "");
    }
}
