#ifndef OVS_INTERFACE_H
#define OVS_INTERFACE_H

#include <stdint.h>

/* ── Data types ──────────────────────────────────────────────────────── */
typedef struct {
    char     mac[18];
    int      port;
    uint64_t learned_at_us;
} ovs_mac_entry_t;

typedef struct {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    int      link_up;
} ovs_port_stats_t;

typedef struct {
    uint16_t priority;
    char     match[256];
    char     actions[256];
    uint32_t idle_timeout;
    uint32_t hard_timeout;
    uint64_t packet_count;
} ovs_flow_t;

/* ── OVS backend API ─────────────────────────────────────────────────── */
int ovs_init(int use_mock);
void ovs_cleanup(void);

/* Flow management */
int ovs_add_flow  (const char *bridge, const ovs_flow_t *flow);
int ovs_del_flow  (const char *bridge, const char *match);
int ovs_list_flows(const char *bridge, ovs_flow_t *out, int max);

/* MAC / FDB */
int ovs_get_mac_table(const char *bridge, ovs_mac_entry_t *out, int max);
int ovs_flush_mac    (const char *bridge, const char *mac);

/* Port state */
int ovs_get_port_stats(const char *bridge,
                       const char *ifname,
                       ovs_port_stats_t *out);
int ovs_set_port_state(const char *bridge,
                       const char *ifname,
                       int up);

/* Bridge */
int ovs_bridge_exists(const char *bridge);

/*
 * Meter management (OpenFlow 1.3 METER_MOD).
 * Creates/replaces a DROP meter with the given rate in kbps.
 * Called by POLICY_RATE_LIMIT before installing the metered flow.
 */
int ovs_of_add_meter(const char *bridge, uint32_t meter_id,
                     uint32_t rate_kbps);

/* Require including a2a_transport.h before this if using epoll functions */
struct a2a_server;
void ovs_of_register_epoll  (struct a2a_server *server);
void ovs_of_deregister_epoll(struct a2a_server *server);
int ovs_of_del_flow_at_priority(const char *bridge, const char *match, uint16_t priority);
#endif /* OVS_INTERFACE_H */