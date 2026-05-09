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
#include <errno.h>
#include <net/if.h>

/* Forward declarations to avoid circular include with a2a_metrics.h */
typedef struct a2a_metrics_t a2a_metrics_t;
void metrics_record_latency(a2a_metrics_t *m, uint64_t sent_us);

void ovsdb_process_update(const char *json, a2a_agent_t *agent);

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

        if (out_port <= 0)
        {
            /*
             * Egress interface (e.g., c1c2, c1r1) is a kernel-only L3
             * interface, not an OVS bridge port.  We MUST still install
             * an OVS flow, because OVS intercepts every packet before
             * the kernel sees it.  Without a flow, the table-miss
             * CONTROLLER handler floods the packet on L2 ports only —
             * it never reaches the kernel routing stack.
             *
             * output:NORMAL tells OVS to use its built-in L2 pipeline.
             * For packets whose dst MAC equals the bridge's own MAC,
             * OVS delivers them to the br0 internal port (ofport 65534),
             * which hands them to the kernel.  The kernel's routing table
             * then forwards via c1c2, c1r1, etc. as needed.
             *
             * This is identical to how Linux bridges work: packets
             * addressed to the bridge are passed up to the IP stack.
             */
            ovs_flow_t fl = {0};
            fl.priority    = 100;
            fl.idle_timeout = 0;
            fl.hard_timeout = 0;
            snprintf(fl.match, sizeof(fl.match),
                     "ip,nw_dst=%s", r->prefix);
            snprintf(fl.actions, sizeof(fl.actions), "output:NORMAL");
            ovs_add_flow(ctx->bridge, &fl);
            LOG_I("L3",
                  "[%s] Fallback → NORMAL flow for %s"
                  " (kernel routes via %s)",
                  ctx->switch_id, r->prefix, r->egress_ifname);
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
        // ARP not yet resolved for this nexthop.
        // For direct-connected routes (nexthop == 0.0.0.0), use NORMAL
        // so ARP requests from hosts can reach the gateway.
        // For remote routes (nexthop is a real IP), skip installation —
        // handle_neigh() will reinstall this flow once ARP resolves.
        if (strcmp(r->nexthop, "0.0.0.0") == 0)
        {
            snprintf(fl.actions, sizeof(fl.actions), "output:NORMAL");
            LOG_I("L3", "[%s] Direct-connected route %s — installing NORMAL (ARP handled by kernel)",
                  ctx->switch_id, r->prefix);
            ovs_add_flow(ctx->bridge, &fl);
        }
        else
        {
            LOG_I("L3", "[%s] Deferring flow for %s (nexthop %s not ARP-resolved yet)",
                  ctx->switch_id, r->prefix, r->nexthop);
            // Flow will be installed by handle_neigh() when ARP resolves.
            // Proactively trigger ARP resolution:
            char arp_cmd[128];
            snprintf(arp_cmd, sizeof(arp_cmd), "arping -c 1 -I %s %s >/dev/null 2>&1 &",
                     r->egress_ifname, r->nexthop);
            system(arp_cmd);
        }
    }
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
     ctx->route_installs++;  /* Track for metrics */
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
     ctx->route_withdrawals++;  /* Track for metrics */
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

        /*
         * Match routes affected by this failure.
         *
         * L2 agents report their own switch_id (e.g., "sw1").
         * L3 routes store via_switch as the local router id (e.g., "core1").
         * Direct name comparison never matches.
         *
         * Instead: a route is affected if its egress interface is the
         * access-side port connected to the reporting switch.
         *
         * The access port naming convention is:
         *   core1's access port to sw1 = c1s1 (configured in network_setup.sh)
         *   core2's access port to sw3 = c2s3, etc.
         *
         * We detect this by checking whether the egress interface name
         * contains the failed switch's numeric ID.
         * E.g., failed_switch="sw1" → digit='1' → matches c1s1, s1c1, etc.
         *
         * For port-based matching: failed_port matches the OVS ofport
         * of the access interface (port 1 = c1s1 on core1).
         *
         * Use EITHER criterion: egress ifname contains switch digit,
         * OR egress_ifname is empty (local direct routes via br0).
         */
        int affected = 0;

        /* Extract digit from switch name ("sw1" → '1', "sw3" → '3') */
        const char *sw_digit_ptr = failed_switch;
        while (*sw_digit_ptr && !(*sw_digit_ptr >= '0' && *sw_digit_ptr <= '9'))
            sw_digit_ptr++;
        char sw_digit = *sw_digit_ptr; /* '1', '2', ... '8' or '\0' */

        if (r->egress_ifname[0] && sw_digit != '\0')
        {
            /* Check if egress interface name contains the switch digit
             * at a position that indicates it is an access port.
             */
            const char *ef = r->egress_ifname;
            for (int ci = 0; ef[ci]; ci++)
            {
                if (ef[ci] == sw_digit &&
                    ci > 0 &&
                    ef[ci-1] == 's')
                {
                    affected = 1;
                    break;
                }
            }
        }
        else if (r->egress_ifname[0] == '\0' ||
                 strcmp(r->egress_ifname, "kernel") == 0)
        {
            /* Local/direct routes with no specific egress port —
             * not affected by access-layer link failures. */
            affected = 0;
        }

        if (!affected)
            continue;

        // This route goes through the failed switch/port.
        // Find an alternate path.
        route_entry_t *alt = find_alternate(ctx, r->prefix, r->via_switch);

        if (alt)
        {
            // Withdraw the broken flow and install the alternate
            withdraw_route_flow(ctx, r);
            r->state = ROUTE_STATE_WITHDRAWN;
            ctx->route_withdrawals++;

            // Install the alternate route flow
            install_route_flow(ctx, alt);
            ctx->reroutes_performed++;

            LOG_I("L3", "[%s] Reroute complete: %s via alternate %s",
                  ctx->switch_id, r->prefix, alt->egress_ifname);

            notify_l2_peers_topology(ctx, r, 1);   // withdraw old
            notify_l2_peers_topology(ctx, alt, 0); // install new
        }
        else
        {
            LOG_W("L3", "[%s] No alternate found for %s — marking degraded",
                  ctx->switch_id, r->prefix);

            /*
             * Even without an OVS-level alternate route, we must fix the
             * kernel routing table so return traffic can reach the subnet
             * via the secondary access port (c1s2 when c1s1 is down).
             *
             * The secondary port naming convention:
             *   Primary:   cNsM   (e.g., c1s1 for core1→sw1)
             *   Secondary: cNsM'  (e.g., c1s2 for core1→sw2)
             *
             * When sw1 (digit=1) fails and egress=c1s1, the secondary
             * access is c1s2. We add a kernel host route via the secondary
             * port so return traffic reaches sw2→sw1→hosts.
             *
             * This is a kernel-level fix; the OVS flow on core1 can still
             * use output:normal since c1s2 is a kernel interface not in OVS.
             */
            if (r->egress_ifname[0] && sw_digit != '\0')
            {
                /* Build secondary port name: replace digit at position */
                char sec_if[IF_NAMESIZE] = {0};
                strncpy(sec_if, r->egress_ifname, sizeof(sec_if)-1);

                /*
                 * Find the switch digit in the egress ifname and
                 * determine secondary switch.
                 * sw1↔sw2, sw3↔sw4, sw5↔sw6, sw7↔sw8.
                 * Secondary digit: odd→even, even→odd.
                 */
                char sec_digit = '\0';
                int sw_num = sw_digit - '0';
                if (sw_num >= 1 && sw_num <= 8)
                {
                    /* pair: (1,2), (3,4), (5,6), (7,8) */
                    int sec_num = (sw_num % 2 == 1) ? sw_num + 1 : sw_num - 1;
                    sec_digit = '0' + sec_num;
                }

                if (sec_digit != '\0')
                {
                    /* Replace the switch digit in the interface name */
                    for (int ci = 0; sec_if[ci]; ci++)
                    {
                        if (sec_if[ci] == sw_digit &&
                            ci > 0 && sec_if[ci-1] == 's')
                        {
                            sec_if[ci] = sec_digit;
                            break;
                        }
                    }

                    /* Verify secondary interface exists and is up */
                    char chk[128];
                    snprintf(chk, sizeof(chk),
                             "ip link show %s 2>/dev/null | grep -q 'state UP'",
                             sec_if);
                    if (system(chk) == 0)
                    {
                        /*
                         * Add kernel route for the subnet via secondary if.
                         * Use 'ip route replace' to be idempotent.
                         * metric=50 to prefer the primary when it comes back.
                         */
                        char cmd[256];
                        snprintf(cmd, sizeof(cmd),
                                 "ip route replace %s dev %s metric 50 2>/dev/null",
                                 r->prefix, sec_if);
                        (void)system(cmd);

                        LOG_I("L3", "[%s] Kernel route repair: %s via dev %s (secondary access)",
                              ctx->switch_id, r->prefix, sec_if);

                        r->state = ROUTE_STATE_DEGRADED;
                    }
                    else
                    {
                        LOG_W("L3", "[%s] Secondary if %s not UP — cannot repair kernel route",
                              ctx->switch_id, sec_if);
                    }
                }
            }

        }
    }

    /*
     * Direct kernel route repair for the access subnet.
     *
     * The route-matching loop above fails for directly-connected subnets
     * because the kernel reports egress_ifname="br0" (the OVS bridge),
     * not the physical port name "c1s1". The digit-matching logic
     * never matches "br0", so the kernel route repair is skipped.
     *
     * Fix: directly compute the subnet and secondary interface from
     * the topology naming convention and install the route.
     *
     * Topology mapping:
     *   sw1 down -> core1 needs 10.0.0.0/24 via c1s2
     *   sw3 down -> core2 needs 20.0.0.0/24 via c2s4
     *   sw5 down -> core3 needs 30.0.0.0/24 via c3s6
     *   sw7 down -> core4 needs 40.0.0.0/24 via c4s8
     *
     * Only odd-numbered switches need repair (they connect to the
     * primary port on the core's br0). Even-numbered switches connect
     * to the secondary port which is a raw kernel interface -- when
     * they fail, the primary route via br0 still works.
     *
     * We use "ip route replace" (no metric) to REPLACE the unusable
     * br0 route. metric=50 doesn't work because the kernel always
     * prefers the metric=0 br0 route even when br0's only port is down
     * (br0 itself stays UP as a virtual device).
     */
    {
        const char *sw_dp = failed_switch;
        while (*sw_dp && !(*sw_dp >= '0' && *sw_dp <= '9'))
            sw_dp++;
        if (*sw_dp)
        {
            int sw_n = *sw_dp - '0';
            /* Only odd switches need repair */
            if (sw_n >= 1 && sw_n <= 8 && (sw_n % 2 == 1))
            {
                int sec_n = sw_n + 1;

                /* Extract core digit from our own switch_id */
                const char *cp = ctx->switch_id;
                while (*cp && !(*cp >= '1' && *cp <= '9'))
                    cp++;

                if (*cp)
                {
                    char sec_if[32];
                    snprintf(sec_if, sizeof(sec_if), "c%cs%d", *cp, sec_n);

                    const char *subnet = NULL;
                    if (sw_n == 1) subnet = "10.0.0.0/24";
                    else if (sw_n == 3) subnet = "20.0.0.0/24";
                    else if (sw_n == 5) subnet = "30.0.0.0/24";
                    else if (sw_n == 7) subnet = "40.0.0.0/24";

                    if (subnet)
                    {
                        char chk[128];
                        snprintf(chk, sizeof(chk),
                                 "ip link show %s 2>/dev/null | grep -q 'state UP'",
                                 sec_if);
                        if (system(chk) == 0)
                        {
                            char cmd[256];
                            snprintf(cmd, sizeof(cmd),
                                     "ip route replace %s dev %s 2>/dev/null",
                                     subnet, sec_if);
                            (void)system(cmd);

                            LOG_I("L3", "[%s] Kernel route repair: %s via dev %s "
                                  "(direct access failover)",
                                  ctx->switch_id, subnet, sec_if);
                        }
                        else
                        {
                            LOG_W("L3", "[%s] Secondary if %s not UP",
                                  ctx->switch_id, sec_if);
                        }
                    }
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

    /* Parse payload first so we can exempt STORM_CLEAR from rate limiting.
     * STORM_CLEAR must always reach the handler — it restores port state.
     * If suppressed, the rate-limit flow installed during the storm is never
     * removed and the port stays throttled indefinitely. */
    l2_anomaly_payload_t pl = {0};
    if (a2a_msg_get_l2_anomaly(msg, &pl) < 0)
        return;

    ctx->l2_events_received++;

    LOG_I("L3", "[%s] anomaly from %s type=%d port=%d pps=%u",
          ctx->switch_id, msg->src_agent,
          pl.anomaly_type, pl.port, pl.pps);

    /* STORM_CLEAR bypasses the rate limiter unconditionally.
     * All other anomaly types go through the 2s per-source rate limit. */
    if (pl.anomaly_type == L2_ANOMALY_STORM_CLEAR) {
        LOG_I("L3", "Decision: STORM_CLEAR → restore");
        l3_send_policy(ctx, msg->src_agent,
                       POLICY_RESTORE_PORT,
                       pl.port, NULL, 0);
        return;
    }

    /* Per-source 2s rate limit for all other anomaly types */
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

            if (now - g_anomaly_rate[i].last_action_us < 2000000ULL)
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
        /*
         * Use RATE_LIMIT instead of ISOLATE_PORT for MAC-flood anomalies.
         * ISOLATE cuts the port completely (including uplinks), which kills
         * routing. Rate-limiting contains the flood while preserving
         * connectivity for legitimate traffic.
         * Rate = 2x reported pps as headroom for legitimate traffic.
         */
        {
            uint32_t rate = pl.pps > 0 ? pl.pps * 2 : 10000;
            l3_send_policy(ctx, msg->src_agent,
                           POLICY_RATE_LIMIT,
                           pl.port, NULL, rate);
        }
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

    case L2_ANOMALY_LINK_UP:
    {
        LOG_I("L3", "Decision: LINK_UP → restore routes for switch %s",
              pl.switch_id);

        /*
         * Restore the primary kernel route via br0 when the access
         * link comes back up. This reverses the "ip route replace"
         * done in l3_reroute_around.
         *
         * Also remove any metric=50 secondary routes that may have
         * been installed by the old code path.
         */
        const char *sw_dp = pl.switch_id;
        while (*sw_dp && !(*sw_dp >= '0' && *sw_dp <= '9'))
            sw_dp++;

        if (*sw_dp)
        {
            int sw_n = *sw_dp - '0';
            if (sw_n >= 1 && sw_n <= 8 && (sw_n % 2 == 1))
            {
                int sec_n = sw_n + 1;

                const char *cp = ctx->switch_id;
                while (*cp && !(*cp >= '1' && *cp <= '9'))
                    cp++;

                if (*cp)
                {
                    char sec_if[32];
                    snprintf(sec_if, sizeof(sec_if), "c%cs%d", *cp, sec_n);

                    const char *subnet = NULL;
                    const char *gw_ip = NULL;
                    if (sw_n == 1) { subnet = "10.0.0.0/24"; gw_ip = "10.0.0.254"; }
                    else if (sw_n == 3) { subnet = "20.0.0.0/24"; gw_ip = "20.0.0.254"; }
                    else if (sw_n == 5) { subnet = "30.0.0.0/24"; gw_ip = "30.0.0.254"; }
                    else if (sw_n == 7) { subnet = "40.0.0.0/24"; gw_ip = "40.0.0.254"; }

                    if (subnet && gw_ip)
                    {
                        /* Restore primary route via br0 */
                        char cmd[256];
                        snprintf(cmd, sizeof(cmd),
                                 "ip route replace %s dev br0 src %s 2>/dev/null",
                                 subnet, gw_ip);
                        (void)system(cmd);

                        /* Also remove any stale metric=50 route */
                        snprintf(cmd, sizeof(cmd),
                                 "ip route del %s dev %s metric 50 2>/dev/null",
                                 subnet, sec_if);
                        (void)system(cmd);

                        LOG_I("L3", "[%s] Kernel route cleanup: restored %s via br0, "
                              "removed secondary via %s",
                              ctx->switch_id, subnet, sec_if);
                    }
                }
            }
        }

        /* Also restore any DEGRADED routes tracked by the route table */
        for (int ri = 0; ri < ctx->route_count; ri++)
        {
            route_entry_t *r = &ctx->routes[ri];
            if (r->state == ROUTE_STATE_DEGRADED)
            {
                r->state = ROUTE_STATE_ACTIVE;
                r->last_verified_us = a2a_now_us();
            }
        }
        break;
    }

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
    {
        extern a2a_metrics_t g_metrics;
        metrics_record_latency(&g_metrics, ev->data.msg.timestamp_us);
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

/*
 * Handle incoming OVSDB messages for L3 agent.
 * Reassembles partial JSON messages and processes complete updates.
 */
/*
 * Handle OVSDB messages for L3 agent.
 * Supports partial JSON reassembly.
 */
static void l3_ovsdb_epoll_handler(int fd, void *ud)
{
    l3_agent_ctx_t *ctx = (l3_agent_ctx_t *)ud;

    /* Reset if buffer is nearly full */
    if (ctx->ovsdb_len >= sizeof(ctx->ovsdb_buf) - 1024) {
        LOG_E("L3-OVSDB", "[%s] OVSDB buffer overflow (%zu bytes) — resetting",
              ctx->switch_id, ctx->ovsdb_len);
        ctx->ovsdb_len = 0;
        memset(ctx->ovsdb_buf, 0, sizeof(ctx->ovsdb_buf));
    }

    /* Append new data into buffer */
    ssize_t n = recv(fd,
                     ctx->ovsdb_buf + ctx->ovsdb_len,
                     sizeof(ctx->ovsdb_buf) - ctx->ovsdb_len - 1,
                     MSG_DONTWAIT);

    if (n <= 0) {
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_E("L3-OVSDB", "[%s] OVSDB recv error errno=%d",
                  ctx->switch_id, errno);
        }
        return;
    }

    ctx->ovsdb_len += (size_t)n;
    ctx->ovsdb_buf[ctx->ovsdb_len] = '\0';

    LOG_D("L3-OVSDB", "[%s] OVSDB recv %zd bytes (total=%zu)",
          ctx->switch_id, n, ctx->ovsdb_len);

    /* Process newline-terminated JSON messages */
    char *p   = ctx->ovsdb_buf;
    char *nl;

    while ((nl = strchr(p, '\n')) != NULL) {
        *nl = '\0';   /* terminate JSON string */

        if (nl > p) { /* skip empty lines */
            LOG_D("L3-OVSDB", "[%s] Processing OVSDB message (%zu bytes)",
                  ctx->switch_id, (size_t)(nl - p));
            ovsdb_process_update(p, ctx->agent);
        }

        p = nl + 1;   /* move to next message */
    }

    /* Handle complete JSON without newline */
    size_t remaining = (size_t)(ctx->ovsdb_buf + ctx->ovsdb_len - p);

    if (remaining > 0 && p[0] == '{') {
        int   depth    = 0;
        int   complete = 0;
        int   in_str   = 0;  /* inside string */
        char  prev     = 0;

        for (size_t i = 0; i < remaining; i++) {
            char c = p[i];

            /* Ignore braces inside strings */
            if (c == '"' && prev != '\\') {
                in_str = !in_str;
            } else if (!in_str) {
                if (c == '{') depth++;
                else if (c == '}') {
                    if (--depth == 0) {
                        complete = 1;
                        break;
                    }
                }
            }
            prev = (c == '\\' && prev == '\\') ? 0 : c;
        }

        if (complete) {
            LOG_D("L3-OVSDB", "[%s] Processing complete JSON object "
                  "(brace-counted, %zu bytes)",
                  ctx->switch_id, remaining);
            ovsdb_process_update(p, ctx->agent);
            remaining = 0;  /* fully consumed */
        }
        /* keep partial JSON for next recv() */
    }

    /* Move remaining bytes to buffer start */
    if (remaining > 0 && p != ctx->ovsdb_buf) {
        memmove(ctx->ovsdb_buf, p, remaining);
    }
    ctx->ovsdb_len = remaining;

    /* Clear consumed buffer region */
    if (remaining < sizeof(ctx->ovsdb_buf)) {
        memset(ctx->ovsdb_buf + remaining, 0,
               sizeof(ctx->ovsdb_buf) - remaining);
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

    /* Initialize OVSDB buffer and convergence stats */
    ctx->ovsdb_len   = 0;
    ctx->conv_min_us = UINT64_MAX;
    ctx->conv_count  = 0;
    ctx->conv_sum_us = 0;
    ctx->conv_max_us = 0;
    /* conv_log[] already zeroed by calloc() */

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
            // Proactively ARP all transit nexthops so OVS flows get installed
            // immediately rather than waiting for the first packet.
            LOG_I("L3", "[%s] Probing ARP for all kernel nexthops...", ctx->switch_id);
            system("ip neigh flush all 2>/dev/null; "
                   "for nh in $(ip route | awk '/via/ {print $3}' | sort -u); do "
                   "    dev=$(ip route get $nh | awk '/dev/ {for(i=1;i<NF;i++) if($i==\"dev\") print $(i+1)}'); "
                   "    arping -c 2 -I $dev $nh >/dev/null 2>&1 & "
                   "done");
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
    /*
     * Periodic L3 maintenance and health monitoring.
     * Runs from the main loop every few milliseconds.
     */

    static uint64_t last_health_log_us = 0;

    uint64_t now = a2a_now_us();

    /* Log route health every 60 seconds */
    if (now - last_health_log_us < 60ULL * 1000000ULL)
        return;

    last_health_log_us = now;

    /* Count routes by state */
    int active = 0;
    int degraded = 0;
    int withdrawn = 0;
    int local = 0;

    for (int i = 0; i < ctx->route_count; i++) {

        switch (ctx->routes[i].state) {

        case ROUTE_STATE_ACTIVE:
            active++;

            if (ctx->routes[i].is_local)
                local++;

            break;

        case ROUTE_STATE_DEGRADED:
            degraded++;
            break;

        case ROUTE_STATE_WITHDRAWN:
            withdrawn++;
            break;
        }
    }

    /* Route health summary */
    LOG_I("L3", "[%s] Route health: active=%d (local=%d) "
          "degraded=%d withdrawn=%d | reroutes=%u "
          "l2_events=%u installs=%u withdrawals=%u",
          ctx->switch_id,
          active,
          local,
          degraded,
          withdrawn,
          ctx->reroutes_performed,
          ctx->l2_events_received,
          ctx->route_installs,
          ctx->route_withdrawals);

    /* Print convergence statistics */
    if (ctx->conv_count > 0) {

        LOG_I("L3", "[%s] Convergence: n=%u "
              "min=%.1fms avg=%.1fms max=%.1fms",
              ctx->switch_id,
              ctx->conv_count,
              ctx->conv_min_us == UINT64_MAX
                  ? 0.0
                  : (double)ctx->conv_min_us / 1000.0,
              (double)ctx->conv_sum_us
                  / ctx->conv_count / 1000.0,
              (double)ctx->conv_max_us / 1000.0);
    }

    /* Warn about long degraded routes */
    for (int i = 0; i < ctx->route_count; i++) {

        route_entry_t *r = &ctx->routes[i];

        if (r->state != ROUTE_STATE_DEGRADED)
            continue;

        uint64_t degraded_for_us =
            now - r->last_verified_us;

        if (degraded_for_us > 60ULL * 1000000ULL) {

            LOG_W("L3", "[%s] Route STUCK DEGRADED "
                  "for %.0fs: %s via %s",
                  ctx->switch_id,
                  (double)degraded_for_us / 1e6,
                  r->prefix,
                  r->via_switch);
        }
    }
}

void l3_print_routes(l3_agent_ctx_t *ctx)
{
    static const char *snames[] = {
        "ACTIVE",
        "DEGRADED",
        "WITHDRAWN"
    };

    /*
     * Use structured logging instead of printf().
     *
     * In detached Docker/container environments,
     * stdout is often not visible in runtime logs.
     *
     * LOG_I() ensures:
     *   - docker logs visibility
     *   - centralized logging
     *   - timestamped output
     *   - production-grade observability
     */

    LOG_I("L3",
          "[%s] Route Table (%d routes):",
          ctx->switch_id,
          ctx->route_count);

    LOG_I("L3",
          "  %-20s %-16s %-20s %-6s %s",
          "PREFIX",
          "NEXTHOP",
          "VIA-SWITCH",
          "METRIC",
          "STATE");

    LOG_I("L3",
          "  %-20s %-16s %-20s %-6s %s",
          "------",
          "-------",
          "----------",
          "------",
          "-----");

    for (int i = 0; i < ctx->route_count; i++)
    {
        route_entry_t *r = &ctx->routes[i];

        LOG_I("L3",
              "  %-20s %-16s %-20s %-6d %s%s",
              r->prefix,
              r->nexthop,
              r->via_switch,
              r->metric,
              snames[r->state],
              r->is_local ? " [local]" : "");
    }

    /*
     * Route convergence metrics.
     *
     * These metrics measure:
     *   - failover convergence
     *   - reroute convergence
     *   - distributed recovery timing
     */

    if (ctx->conv_count > 0)
    {
        LOG_I("L3",
              "  Route Convergence Statistics:");

        LOG_I("L3",
              "    Samples : %u",
              ctx->conv_count);

        LOG_I("L3",
              "    Min     : %.1f ms",
              ctx->conv_min_us == UINT64_MAX
                  ? 0.0
                  : (double)ctx->conv_min_us / 1000.0);

        LOG_I("L3",
              "    Average : %.1f ms",
              (double)ctx->conv_sum_us
                  / ctx->conv_count / 1000.0);

        LOG_I("L3",
              "    Max     : %.1f ms",
              (double)ctx->conv_max_us / 1000.0);
    }
    else
    {
        LOG_I("L3",
              "  Route Convergence: no events recorded yet");
    }
}
