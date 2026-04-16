/*
 * l3_netlink.c — Real-time Linux routing monitor via RTNETLINK
 *
 * Subscribes to:
 *   RTMGRP_IPV4_ROUTE → RTM_NEWROUTE, RTM_DELROUTE
 *   RTMGRP_LINK       → RTM_NEWLINK,  RTM_DELLINK
 *   RTMGRP_IPV4_IFADDR → interface address changes
 *   RTMGRP_NEIGH      → ARP/neighbor table (next-hop MAC resolution)
 *
 * Dumps the initial route table on startup via RTM_GETROUTE.
 * The fd is returned and must be added to the agent's epoll loop.
 * l3_netlink_process() is called when epoll signals the fd readable.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <sys/socket.h>

#include "l3_agent.h"
#include "a2a_log.h"

// Forward declarations from l3_agent.c
void install_route_flow(l3_agent_ctx_t *ctx, const route_entry_t *r);
void withdraw_route_flow(l3_agent_ctx_t *ctx, const route_entry_t *r);

static int g_nl_fd = -1;
static int g_nl_seq = 1;

/* ── Neighbour table (ARP cache) ─────────────────────────────────── */

#define NEIGH_TABLE_MAX 256

typedef struct
{
    uint32_t ip; /* network byte order */
    uint8_t mac[6];
    int valid;
} neigh_entry_t;

static neigh_entry_t g_neigh[NEIGH_TABLE_MAX];

static void neigh_update(uint32_t ip, const uint8_t *mac)
{
    for (int i = 0; i < NEIGH_TABLE_MAX; i++)
    {
        if (g_neigh[i].valid && g_neigh[i].ip == ip)
        {
            memcpy(g_neigh[i].mac, mac, 6);
            return;
        }
    }
    for (int i = 0; i < NEIGH_TABLE_MAX; i++)
    {
        if (!g_neigh[i].valid)
        {
            g_neigh[i].ip = ip;
            g_neigh[i].valid = 1;
            memcpy(g_neigh[i].mac, mac, 6);
            return;
        }
    }
}

/*
 * Resolve a next-hop IP to its MAC address from the ARP cache.
 * Returns 0 on success (mac_out filled), -1 if not found.
 */
int l3_arp_resolve(const char *nexthop_ip, char *mac_out, int mac_out_sz)
{
    struct in_addr a;
    if (inet_pton(AF_INET, nexthop_ip, &a) != 1)
        return -1;
    uint32_t ip = a.s_addr;

    for (int i = 0; i < NEIGH_TABLE_MAX; i++)
    {
        if (!g_neigh[i].valid || g_neigh[i].ip != ip)
            continue;
        snprintf(mac_out, mac_out_sz,
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 g_neigh[i].mac[0], g_neigh[i].mac[1],
                 g_neigh[i].mac[2], g_neigh[i].mac[3],
                 g_neigh[i].mac[4], g_neigh[i].mac[5]);
        return 0;
    }
    return -1; /* not in cache */
}

/* Read local MAC of bridge/interface from /sys/class/net/<if>/address */
int l3_get_local_mac(const char *ifname, char *mac_out, int mac_out_sz)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(mac_out, mac_out_sz, f))
    {
        fclose(f);
        return -1;
    }
    fclose(f);
    /* strip newline */
    char *nl = strchr(mac_out, '\n');
    if (nl)
        *nl = '\0';
    return 0;
}

/* ── Netlink helpers ─────────────────────────────────────────────── */

static int nl_send_request(int fd, int type, int flags,
                           void *data, int data_len)
{
    struct
    {
        struct nlmsghdr nlh;
        uint8_t data[256];
    } req = {0};

    req.nlh.nlmsg_len = NLMSG_LENGTH(data_len);
    req.nlh.nlmsg_type = type;
    req.nlh.nlmsg_flags = flags;
    req.nlh.nlmsg_seq = g_nl_seq++;
    req.nlh.nlmsg_pid = 0;

    if (data && data_len > 0)
        memcpy(req.data, data, data_len);

    return (int)send(fd, &req, req.nlh.nlmsg_len, 0);
}

/* ── Route message parser ────────────────────────────────────────── */

typedef struct
{
    char prefix[48];  /* "A.B.C.D/N" */
    char nexthop[48]; /* "A.B.C.D"   */
    char ifname[IF_NAMESIZE];
    int metric;
    int prefix_len;
} parsed_route_t;

static int parse_route_msg(struct nlmsghdr *nlh, parsed_route_t *r)
{
    struct rtmsg *rtm = NLMSG_DATA(nlh);
    memset(r, 0, sizeof(*r));

    if (rtm->rtm_family != AF_INET)
        return -1;
    if (rtm->rtm_table != RT_TABLE_MAIN)
        return -1;
    if (rtm->rtm_type != RTN_UNICAST)
        return -1;

    r->prefix_len = rtm->rtm_dst_len;

    struct rtattr *rta = RTM_RTA(rtm);
    int rta_len = (int)RTM_PAYLOAD(nlh);

    char dst_str[INET_ADDRSTRLEN] = "0.0.0.0";
    char gw_str[INET_ADDRSTRLEN] = "";

    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len))
    {
        switch (rta->rta_type)
        {
        case RTA_DST:
        {
            struct in_addr a;
            memcpy(&a, RTA_DATA(rta), sizeof(a));
            inet_ntop(AF_INET, &a, dst_str, sizeof(dst_str));
            break;
        }
        case RTA_GATEWAY:
        {
            struct in_addr a;
            memcpy(&a, RTA_DATA(rta), sizeof(a));
            inet_ntop(AF_INET, &a, gw_str, sizeof(gw_str));
            break;
        }
        case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rta), r->ifname);
            break;
        case RTA_PRIORITY:
            r->metric = *(int *)RTA_DATA(rta);
            break;
        }
    }

    snprintf(r->prefix, sizeof(r->prefix), "%s/%d",
             dst_str, r->prefix_len);

    if (gw_str[0])
        snprintf(r->nexthop, sizeof(r->nexthop), "%s", gw_str);
    else
        snprintf(r->nexthop, sizeof(r->nexthop), "0.0.0.0");

    return 0;
}

/* ── Link-down helper ────────────────────────────────────────────── */

static void handle_link_change(struct nlmsghdr *nlh, l3_agent_ctx_t *ctx,
                               int is_del)
{
    struct ifinfomsg *ifi = NLMSG_DATA(nlh);
    char ifname[IF_NAMESIZE] = "";
    if_indextoname(ifi->ifi_index, ifname);

    if (is_del || !(ifi->ifi_flags & IFF_UP))
    {
        LOG_W("NETLINK", "Link %s: %s — triggering reroute",
              is_del ? "DEL" : "DOWN", ifname);
        l3_reroute_around(ctx, ifname, -1);
    }
    else
    {
        LOG_I("NETLINK", "Link UP: %s", ifname);
    }
}

/* ── Neighbour (ARP) message parser ─────────────────────────────── */

static void handle_neigh(struct nlmsghdr *nlh, l3_agent_ctx_t *ctx)
{
    struct ndmsg *ndm = NLMSG_DATA(nlh);
    if (ndm->ndm_family != AF_INET)
        return;
    if (!(ndm->ndm_state & (NUD_REACHABLE | NUD_STALE |
                            NUD_DELAY | NUD_PROBE | NUD_PERMANENT)))
        return;

    uint32_t ip = 0;
    uint8_t mac[6] = {0};
    int has_ip = 0, has_mac = 0;

    struct rtattr *rta = (struct rtattr *)((uint8_t *)ndm + sizeof(struct ndmsg));
    int rta_len = (int)NLMSG_PAYLOAD(nlh, sizeof(struct ndmsg));

    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len))
    {
        if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) == 4)
        { memcpy(&ip, RTA_DATA(rta), 4); has_ip = 1; }
        if (rta->rta_type == NDA_LLADDR && RTA_PAYLOAD(rta) == 6)
        { memcpy(mac, RTA_DATA(rta), 6); has_mac = 1; }
    }

    if (has_ip && has_mac)
    {
        neigh_update(ip, mac);

        char ip_str[INET_ADDRSTRLEN];
        struct in_addr a; a.s_addr = ip;
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
        LOG_D("NETLINK", "ARP: %s → %02x:%02x:%02x:%02x:%02x:%02x",
              ip_str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        /* FIX B4: Re-install flows for all active routes whose nexthop
         * just became ARP-resolved.  Routes previously installed as
         * output:NORMAL fallback will now get the correct L3 forwarding
         * actions (dec_ttl + MAC rewrite + port output). */
        if (ctx) {
            char nh_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, nh_str, sizeof(nh_str));
            for (int i = 0; i < ctx->route_count; i++) {
                route_entry_t *r = &ctx->routes[i];
                if (r->state == ROUTE_STATE_WITHDRAWN) continue;
                if (strcmp(r->nexthop, nh_str) == 0) {
                    LOG_I("NETLINK", "ARP resolved for nexthop %s — "
                          "reinstalling flow for %s", nh_str, r->prefix);
                    install_route_flow(ctx, r);
                }
            }
        }
    }
}

/* ── Public API ──────────────────────────────────────────────────── */

int l3_netlink_init(void)
{
    g_nl_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                     NETLINK_ROUTE);
    if (g_nl_fd < 0)
    {
        LOG_E("NETLINK", "socket() failed errno=%d", errno);
        return -1;
    }

    struct sockaddr_nl sa = {0};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = (uint32_t)(RTMGRP_IPV4_ROUTE |
                              RTMGRP_LINK |
                              RTMGRP_IPV4_IFADDR |
                              RTMGRP_NEIGH);

    if (bind(g_nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        LOG_E("NETLINK", "bind() failed errno=%d", errno);
        close(g_nl_fd);
        g_nl_fd = -1;
        return -1;
    }

    LOG_I("NETLINK", "Routing monitor started fd=%d groups=0x%08x",
          g_nl_fd, sa.nl_groups);
    return g_nl_fd;
}

int l3_netlink_dump_routes(l3_agent_ctx_t *ctx)
{
    if (g_nl_fd < 0)
        return -1;

    struct rtmsg rtm = {0};
    rtm.rtm_family = AF_INET;

    int rc = nl_send_request(g_nl_fd, RTM_GETROUTE,
                             NLM_F_REQUEST | NLM_F_DUMP,
                             &rtm, sizeof(rtm));
    if (rc < 0)
    {
        LOG_E("NETLINK", "RTM_GETROUTE dump failed errno=%d", errno);
        return -1;
    }

    /* Responses arrive via l3_netlink_process() on next epoll tick */
    LOG_I("NETLINK", "[%s] Route dump requested", ctx->switch_id);
    return 0;
}

/* Also export find_route for Netlink dedup check */
route_entry_t *find_route_pub(l3_agent_ctx_t *ctx,
                              const char *prefix,
                              const char *ifname)
{
    for (int i = 0; i < ctx->route_count; i++)
    {
        if (strcmp(ctx->routes[i].prefix, prefix) == 0 &&
            strcmp(ctx->routes[i].egress_ifname, ifname) == 0)
        {
            return &ctx->routes[i];
        }
    }
    return NULL;
}

void l3_netlink_process(l3_agent_ctx_t *ctx)
{
    if (g_nl_fd < 0)
        return;

    char buf[16384];

    for (;;)
    {
        ssize_t n = recv(g_nl_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            LOG_E("NETLINK", "recv failed errno=%d", errno);
            break;
        }
        if (n == 0)
            break;

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

        for (; NLMSG_OK(nlh, (unsigned int)n);
             nlh = NLMSG_NEXT(nlh, n))
        {
            if (nlh->nlmsg_type == NLMSG_DONE)
                break;
            if (nlh->nlmsg_type == NLMSG_ERROR)
            {
                LOG_W("NETLINK", "NLMSG_ERROR received");
                break;
            }

            switch (nlh->nlmsg_type)
            {

            case RTM_NEWROUTE:
            {
                parsed_route_t r;
                if (parse_route_msg(nlh, &r) < 0)
                    break;
                LOG_I("NETLINK", "RTM_NEWROUTE: %s via %s dev %s metric %d",
                      r.prefix, r.nexthop, r.ifname, r.metric);

                const char *ifname = r.ifname[0] ? r.ifname : "kernel";
                route_entry_t *ex = find_route_pub(ctx, r.prefix, ifname);
                if (!ex)
                {
                    l3_add_route(ctx,
                                 r.prefix,
                                 r.nexthop,
                                 ctx->switch_id,
                                 ifname,
                                 r.metric,
                                 1);
                }
                else if (r.metric < ex->metric)
                {
                    withdraw_route_flow(ctx, ex);

                    strncpy(ex->nexthop, r.nexthop, sizeof(ex->nexthop) - 1);
                    ex->nexthop[sizeof(ex->nexthop) - 1] = '\0';

                    strncpy(ex->egress_ifname, ifname,
                            sizeof(ex->egress_ifname) - 1);
                    ex->egress_ifname[sizeof(ex->egress_ifname) - 1] = '\0';

                    ex->metric = r.metric;

                    install_route_flow(ctx, ex);

                    LOG_I("NETLINK", "Route updated: %s new metric=%d",
                          r.prefix, r.metric);
                }
                break;
            }

            case RTM_DELROUTE:
            {
                parsed_route_t r;
                if (parse_route_msg(nlh, &r) < 0)
                    break;
                LOG_I("NETLINK", "RTM_DELROUTE: %s via %s",
                      r.prefix, r.nexthop);
                l3_withdraw_route(ctx, r.prefix, "kernel_del");
                break;
            }

            case RTM_NEWLINK:
            case RTM_DELLINK:
                handle_link_change(nlh, ctx,
                                   nlh->nlmsg_type == RTM_DELLINK);
                break;

            case RTM_NEWNEIGH:
            case RTM_DELNEIGH:
                handle_neigh(nlh,ctx);
                break;

            default:
                break;
            }
        }
    }
}

int l3_netlink_fd(void) { return g_nl_fd; }
void l3_netlink_close(void)
{
    if (g_nl_fd >= 0)
    {
        close(g_nl_fd);
        g_nl_fd = -1;
    }
}
