#ifndef L2_AGENT_H
#define L2_AGENT_H

#include "a2a_agent.h"
#include "a2a_fsm.h"
#include "ovs_interface.h"

#define L2_MAX_MAC_TABLE 256
#define L2_MAX_PORTS 48
#define MAC_AGE_US (300ULL * 1000000ULL) /* 5 min */
/*
 * Storm threshold: 1000 pps is production-grade.
 * For lab testing with iperf/flood tools, lower to 100 pps.
 * Set via compile flag -DL2_STORM_THRESHOLD_PPS=100 or keep default.
 */
#ifndef STORM_THRESHOLD_PPS
#define STORM_THRESHOLD_PPS 1000         /* pkts/s per port */
#endif
#define STORM_CLEAR_PPS 200
#define L2_POLL_INTERVAL_US (50ULL * 1000ULL)    /* 50ms */
#define L2_MAC_SYNC_INTERVAL (2ULL * 1000000ULL) /* 2s   */

typedef struct
{
    char mac[18];
    int port;
    uint64_t learned_at_us;
    uint64_t last_seen_us;
    uint32_t pkt_count;
} mac_entry_t;

typedef struct
{
    int      port_no;
    uint64_t rx_packets_prev;
    uint64_t last_check_us;
    uint64_t last_event_sent_us;
    int      storm_active;
    uint32_t current_pps;
    char     ifname[64];
    int      was_up_ever;

    /* Prevent duplicate link-down events */
    int      link_down_reported;  /* 1 = already reported */
    int alternate_active;    /* 1 if kernel alternate route is installed */
    /* Broadcast drop tracking */
    uint64_t bcast_rx_prev;    /* previous rx_dropped value */
    uint32_t bcast_drop_pps;   /* broadcast drops per second */
} port_state_t;

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

    /*
     * OVSDB receive buffer.
     * The initial monitor response for a full OVS table can be
     * several hundred KB.  262144 (256 KB) is safe for up to ~128
     * interfaces with full statistics.
     */
    char ovsdb_buf[262144];
    size_t ovsdb_len;
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

#endif /* L2_AGENT_H */