#ifndef L2_AGENT_H
#define L2_AGENT_H

#include "a2a_agent.h"
#include "a2a_fsm.h"
#include "ovs_interface.h"

#define L2_MAX_MAC_TABLE 256
#define L2_MAX_PORTS 48
#define MAC_AGE_US (300ULL * 1000000ULL) /* 5 min */
/* Storm threshold: 1000 pps for production; override with -DL2_STORM_THRESHOLD_PPS=N */
#ifndef STORM_THRESHOLD_PPS
#define STORM_THRESHOLD_PPS 1000         /* pkts/s per port */
#endif
#define STORM_CLEAR_PPS 200
#define L2_POLL_INTERVAL_US (50ULL * 1000ULL)    /* 50ms */
#define L2_MAC_SYNC_INTERVAL (2ULL * 1000000ULL) /* 2s   */

#define MAC_SPOOF_WINDOW_US  (10ULL * 1000000ULL)  /* 10-second window */
#define MAC_SPOOF_THRESHOLD  3                      /* 3 port changes = alert */
#define MAC_SPOOF_MAX_EVENTS 16                     /* ring buffer size, must be power of 2 */

#define MAC_FLAP_WINDOW_US   (30ULL * 1000000ULL)
#define MAC_FLAP_THRESHOLD   10
#define MAC_FLAP_MULTI_MAC   5   /* 5+ MACs flapping simultaneously = loop */

/* L2 poll interval — slowed for flow-stat polling */
#define L2_FLOW_STAT_INTERVAL_US (500ULL * 1000ULL)   /* 500ms */

/* FDB overflow threshold (80% of 1024 max flows) */
#define FDB_OVERFLOW_THRESHOLD 820

/* ARP storm threshold */
#define ARP_STORM_THRESHOLD_PPS 500

/* Unicast flood threshold */
#define UNICAST_FLOOD_THRESHOLD_PPS 200

typedef struct {
    char mac[18];
    int port;
    uint64_t learned_at_us;
    uint64_t last_seen_us;
    uint32_t pkt_count;
    uint64_t port_change_times[MAC_SPOOF_MAX_EVENTS]; /* ring buffer of timestamps */
    int      port_change_head;   /* index of next write position */
    int      port_change_count;  /* total events recorded (capped at MAC_SPOOF_MAX_EVENTS) */
    int      spoof_alerted;      /* 1 = already sent alert, prevents spam */
    int      is_flapping;
    uint32_t flap_count;
    uint64_t flap_window_start_us;
} mac_entry_t;

typedef struct
{
    int      port_no;
    uint64_t rx_packets_prev;
    uint64_t last_check_us;
    uint64_t last_event_sent_us;
    uint64_t storm_detected_us;
    int      storm_active;
    uint32_t current_pps;
    char     ifname[64];
    int      was_up_ever;

    /* Prevent duplicate link-down events */
    int       link_down_reported;  /* 1 = already reported */
    int       alternate_active;    /* 1 if kernel alternate route is installed */
    /* Broadcast drop tracking */
    uint64_t   bcast_rx_prev;    /* previous rx_dropped value */
    uint32_t   bcast_drop_pps;   /* broadcast drops per second */
    uint32_t   last_notified_pps;  /* pps value of last storm notification sent */
} port_state_t;

/* Topology info learned from L3 via MSG_TOPOLOGY messages */
typedef struct {
    char prefix[48];       /* "10.0.0.0/24" */
    char nexthop[48];      /* gateway IP "10.0.0.254" */
    char neighbor_ip[48];  /* secondary switch IP */
} l2_topo_info_t;

typedef struct
{
    a2a_agent_t *agent;
    char bridge[64];
    char switch_id[A2A_MAX_AGENT_ID];

    mac_entry_t mac_table[L2_MAX_MAC_TABLE];
    int mac_count;

    port_state_t ports[L2_MAX_PORTS];
    int port_count;

    uint64_t last_mac_sync_us;
    uint64_t last_poll_us;
    uint64_t last_ovsdb_sync_us;

    /* Stats */
    uint32_t storms_detected;
    uint32_t flows_installed;
    uint32_t l3_notifies_sent;

    /* OVSDB receive buffer — 256KB covers ~128 interfaces with full statistics */
    char ovsdb_buf[262144];
    size_t ovsdb_len;
    l2_topo_info_t topo;    
    char gateway_ip[48];
        /* ── Flow-stat tracking (from OFPST_FLOW) ──────────── */
    uint64_t bcast_pkt_count_prev;
    uint64_t mcast_pkt_count_prev;
    uint64_t arp_pkt_count_prev;
    uint64_t flow_stat_last_us;          /* timestamp of last SUCCESSFUL read only */
    uint64_t flow_stat_last_attempt_us;  /* timestamp of last attempt, success or not */

    /* ── Meter drop tracking ─────────────────────────────── */
    uint64_t bcast_drop_prev;
    uint64_t mcast_drop_prev;
    uint64_t arp_drop_prev;

    /* ── ARP storm tracking ──────────────────────────────── */
    uint32_t arp_pps;
    int      arp_storm_active;
    uint32_t aggregate_flood_pps; /* sum of bcast+mcast pps from OF stats */
    int      meter4_installed;   /* 1 if meter:4 already exists in OVS */

    /* ── Unicast flood tracking (PACKET_IN counts) ───────── */
    uint32_t unicast_flood_pps[L2_MAX_PORTS];

    /* ── Table/FDB overflow ──────────────────────────────── */
    uint32_t of_active_flow_count;
    uint64_t table_stat_last_us;
    int      fdb_overflow_alerted;

} l2_agent_ctx_t;

/* Lifecycle */
l2_agent_ctx_t *l2_agent_create(const char *agent_id,
                                const char *switch_id,
                                const char *bridge,
                                const char *host, int port,
                                int use_mock_ovs);
void l2_agent_destroy(l2_agent_ctx_t *ctx);

/* Main loop — call repeatedly */
void l2_agent_tick(l2_agent_ctx_t *ctx);

/* FSM action registrations */
void l2_agent_init_fsm(l2_agent_ctx_t *ctx);

/* Internal (exposed for testing) */
void l2_mac_sync(l2_agent_ctx_t *ctx);
void l2_port_poll(l2_agent_ctx_t *ctx);
void l2_detect_storm(l2_agent_ctx_t *ctx, int port_idx,
                     uint64_t pps);
void l2_notify_l3(l2_agent_ctx_t *ctx, int port,
                  uint32_t pps, int is_clear);
void l2_print_table(l2_agent_ctx_t *ctx);
void l2_handle_link_down(l2_agent_ctx_t *ctx, a2a_event_t *ev);
/* Called from OVSDB update handler to sync port list from Interface shadow */
void l2_sync_ports_from_ovsdb(l2_agent_ctx_t *ctx);
void mac_check_spoof_window(l2_agent_ctx_t *ctx, mac_entry_t *entry,
                             int new_port, uint64_t now_us);

#endif /* L2_AGENT_H */