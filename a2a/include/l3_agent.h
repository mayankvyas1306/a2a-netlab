#ifndef L3_AGENT_H
#define L3_AGENT_H

#include "a2a_agent.h"
#include "a2a_fsm.h"
#include "ovs_interface.h"

#define L3_MAX_ROUTES        128
#define L3_MAX_ALT_ROUTES    4
#define ROUTE_STALE_US       (30ULL * 1000000ULL)

typedef enum {
    ROUTE_STATE_ACTIVE    = 0,
    ROUTE_STATE_DEGRADED  = 1,
    ROUTE_STATE_WITHDRAWN = 2
} route_state_t;

typedef struct {
    char          prefix[48];          /* "A.B.C.D/N\0" */
    char          nexthop[48];         /* "A.B.C.D\0"   */
    char          egress_ifname[64];   /* kernel interface name */
    char          via_switch[A2A_MAX_AGENT_ID];
    int           metric;
    route_state_t state;
    uint64_t      installed_at_us;
    uint64_t      last_verified_us;
    int           is_local;
} route_entry_t;

typedef struct {
    a2a_agent_t  *agent;
    char          bridge[64];
    char          switch_id[A2A_MAX_AGENT_ID];

    route_entry_t routes[L3_MAX_ROUTES];
    int           route_count;

    int           netlink_fd;  /* RTNETLINK fd, added to epoll */

    /* Stats */
    uint32_t      l2_events_received;
    uint32_t      reroutes_performed;
    uint32_t      route_installs;
    uint32_t      route_withdrawals;
    
    /* OVSDB message reassembly buffer */
    char          ovsdb_buf[262144];  /* 256KB buffer for large OVSDB JSON messages */
    size_t        ovsdb_len;          /* Current buffer usage */

    /* Route convergence tracking */
    struct {
        char     prefix[48];   /* Route prefix */
        uint64_t withdraw_us;  /* Route withdrawal timestamp */
        int      valid;        /* Entry active flag */
    } conv_log[L3_MAX_ROUTES];

    uint32_t conv_count;       /* Total convergence events */
    uint64_t conv_sum_us;      /* Sum of convergence times */
    uint64_t conv_min_us;      /* Minimum convergence time */
    uint64_t conv_max_us;      /* Maximum convergence time */
        /* ── Route oscillation tracking ─────────────────────── */
    struct {
        char     prefix[48];
        uint32_t withdraw_count;
        uint32_t install_count;
        uint64_t window_start_us;
        int      oscillating;
        int      valid;
    } osc_log[L3_MAX_ROUTES];

    /* ── Blackhole / isolation tracking per route ────────── */
    struct {
        uint64_t last_pkt_count;
        uint32_t zero_intervals;
        int      blackhole_alerted;
        int      isolation_alerted;
    } route_traffic[L3_MAX_ROUTES];

    uint64_t blackhole_check_last_us;

} l3_agent_ctx_t;

/* Lifecycle */
l3_agent_ctx_t *l3_agent_create(const char *agent_id,
                                 const char *switch_id,
                                 const char *bridge,
                                 const char *host, int port,
                                 int use_mock_ovs);
void l3_agent_destroy(l3_agent_ctx_t *ctx);
void l3_agent_tick   (l3_agent_ctx_t *ctx);

/* Route operations */
int l3_add_route(l3_agent_ctx_t *ctx,
                 const char *prefix,
                 const char *nexthop,
                 const char *via_switch,
                 const char *ifname,
                 int metric,
                 int is_local);
int  l3_withdraw_route(l3_agent_ctx_t *ctx, const char *prefix,
                       const char *reason);
void l3_reroute_around(l3_agent_ctx_t *ctx, const char *failed_switch,
                       int failed_port, int is_link_failure);
void l3_reroute_specific_route(l3_agent_ctx_t *ctx, route_entry_t *r);
void l3_sync_routes_to_peer(l3_agent_ctx_t *ctx, const char *peer_id,
                             const char *peer_host, int peer_port);
void l3_print_routes (l3_agent_ctx_t *ctx);

/* FSM init */
void l3_agent_init_fsm(l3_agent_ctx_t *ctx);

/* Netlink integration (l3_netlink.c) */
int         l3_netlink_init        (void);
int         l3_netlink_dump_routes (l3_agent_ctx_t *ctx);
void        l3_netlink_process     (l3_agent_ctx_t *ctx);
int         l3_netlink_fd          (void);
void        l3_netlink_close       (void);
int         l3_arp_resolve         (const char *nexthop_ip,
                                    char *mac_out, int mac_out_sz);
int         l3_get_local_mac       (const char *ifname,
                                    char *mac_out, int mac_out_sz);
route_entry_t *find_route_pub(l3_agent_ctx_t *ctx,
                              const char *prefix,
                              const char *ifname);
void install_route_flow(l3_agent_ctx_t *ctx,
                        const route_entry_t *r);

void withdraw_route_flow(l3_agent_ctx_t *ctx,
                         const route_entry_t *r);

#endif /* L3_AGENT_H */