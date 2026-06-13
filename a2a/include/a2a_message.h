#ifndef A2A_MESSAGE_H
#define A2A_MESSAGE_H
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <time.h>
#define A2A_MAX_AGENT_ID   64
#define A2A_MAX_PAYLOAD    4096
#define A2A_MAX_HOST_LEN   128

#define A2A_DEFAULT_PORT   7777
#define PEER_LIST_MAX 16
/* ── Typed payload structs ───────────────────────────────────────────── */

/* MSG_REGISTER / MSG_REGISTER_ACK */
typedef struct {
    char host[A2A_MAX_HOST_LEN];
    int  port;
    int  agent_type;        /* AGENT_TYPE_L2 or AGENT_TYPE_L3 */
    char switch_id[A2A_MAX_AGENT_ID];
} register_payload_t;

/* MSG_L2_EVENT */
typedef struct {
    char     mac[18];       /* "aa:bb:cc:dd:ee:ff\0" */
    int      port;
    char     switch_id[A2A_MAX_AGENT_ID];
    uint32_t pkt_count;
    int      is_anomaly;    /* 1 = broadcast storm detected */
    uint32_t anomaly_pps;   /* packets/sec at time of detection */
    char     reason[64];
} l2_event_payload_t;

/* MSG_L3_EVENT */
typedef struct {
    char prefix[48];        /* "10.0.0.0/24" */
    char nexthop[48];       /* "192.168.1.1" */
    char via_switch[A2A_MAX_AGENT_ID];
    int  metric;
    int  is_withdraw;       /* 1 = route being removed */
    char reason[64];        /* "link_down", "metric_change", etc. */
} l3_event_payload_t;

/* MSG_HEARTBEAT */
typedef struct {
    uint64_t uptime_us;
    int      peer_count;
    int      fsm_state;
} heartbeat_payload_t;


/* MSG_FLOW_INSTALL */
typedef struct {
    char     bridge[64];
    uint16_t priority;
    char     match[256];    /* OpenFlow match string */
    char     actions[256];  /* OpenFlow actions string */
    uint32_t idle_timeout;
    uint32_t hard_timeout;
} flow_install_payload_t;

typedef struct {
    int      anomaly_type;   /* l2_anomaly_type_t */
    int      port;
    char     switch_id[A2A_MAX_AGENT_ID];
    char     ifname[64];
    uint32_t pps;
    uint32_t mac_count;
    char     mac[18];       
    char     reason[64];
} l2_anomaly_payload_t;

typedef enum {
    POLICY_RATE_LIMIT = 1,
    POLICY_ISOLATE_PORT = 2,
    POLICY_BLACKHOLE_MAC = 3,
    POLICY_RESTORE_PORT = 4,
    POLICY_FLUSH_PORT = 5
} policy_type_t;

typedef struct {
    int      policy_type;
    int      port;
    char     switch_id[A2A_MAX_AGENT_ID];
    char     mac[18];
    uint32_t rate_limit;
} policy_cmd_payload_t;


typedef struct {
    int count;

    struct {
        char agent_id[A2A_MAX_AGENT_ID];
        char host[A2A_MAX_HOST_LEN];
        int  port;
        int  agent_type;
        char switch_id[A2A_MAX_AGENT_ID];
    } peers[PEER_LIST_MAX];

} peer_list_payload_t;

/* A2A message types */
typedef enum {
    MSG_PING          = 1,
    MSG_PONG          = 2,
    MSG_REGISTER      = 3,
    MSG_REGISTER_ACK  = 4,
    MSG_HEARTBEAT     = 5,
    MSG_PEER_LIST     = 6,
    MSG_L2_EVENT      = 10,
    MSG_L3_EVENT      = 11,
    MSG_FLOW_INSTALL  = 20,
    MSG_FLOW_DELETE   = 21,
    MSG_TOPOLOGY      = 30,
    MSG_ANOMALY       = 31,
    MSG_ERROR         = 99,
    MSG_L2_ANOMALY    = 40,
    MSG_POLICY_CMD    = 41,
    MSG_L3_ANOMALY    = 42
} a2a_msg_type_t;


typedef struct {
    uint32_t        msg_id;
    char            src_agent[A2A_MAX_AGENT_ID];
    char            dst_agent[A2A_MAX_AGENT_ID];
    a2a_msg_type_t  msg_type;
    uint64_t        timestamp_us;
    char            payload[A2A_MAX_PAYLOAD];
    uint32_t        payload_len;
} a2a_message_t;

/* L2 anomaly types */
typedef enum {
    L2_ANOMALY_STORM        = 1,
    L2_ANOMALY_FLOOD        = 2,
    L2_ANOMALY_MAC_SPOOF    = 3,
    L2_ANOMALY_LINK_DOWN    = 4,
    L2_ANOMALY_STORM_CLEAR  = 5,
    L2_ANOMALY_LINK_UP      = 6,
    L2_ANOMALY_ARP_STORM    = 7,
    L2_ANOMALY_MAC_FLAP     = 8,
    L2_ANOMALY_FDB_OVERFLOW = 9,
    L2_ANOMALY_UNICAST_FLOOD = 10
} l2_anomaly_type_t;

typedef enum {
    L3_ANOMALY_BLACKHOLE   = 1,
    L3_ANOMALY_OSCILLATION = 2,
    L3_ANOMALY_ISOLATED    = 3
} l3_anomaly_type_t;



/* Serialize typed payload into msg->payload (JSON) */
int a2a_msg_set_l2_event(a2a_message_t *msg, const l2_event_payload_t *pl);
int a2a_msg_set_l3_event(a2a_message_t *msg, const l3_event_payload_t *pl);
int a2a_msg_set_register (a2a_message_t *msg, const register_payload_t *pl);
int a2a_msg_set_heartbeat(a2a_message_t *msg, const heartbeat_payload_t *pl);
int a2a_msg_set_flow     (a2a_message_t *msg, const flow_install_payload_t *pl);

/* Deserialize msg->payload into typed struct */
int a2a_msg_get_l2_event(const a2a_message_t *msg, l2_event_payload_t *pl);
int a2a_msg_get_l3_event(const a2a_message_t *msg, l3_event_payload_t *pl);
int a2a_msg_get_register (const a2a_message_t *msg, register_payload_t *pl);
int a2a_msg_get_heartbeat(const a2a_message_t *msg, heartbeat_payload_t *pl);
int a2a_msg_get_flow     (const a2a_message_t *msg, flow_install_payload_t *pl);


int a2a_msg_set_l2_anomaly(a2a_message_t *msg, const l2_anomaly_payload_t *pl);
int a2a_msg_get_l2_anomaly(const a2a_message_t *msg, l2_anomaly_payload_t *pl);

int a2a_msg_set_policy_cmd(a2a_message_t *msg, const policy_cmd_payload_t *pl);
int a2a_msg_get_policy_cmd(const a2a_message_t *msg, policy_cmd_payload_t *pl);


static inline uint64_t a2a_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}
int a2a_msg_set_peer_list(a2a_message_t *msg, const peer_list_payload_t *pl);
int a2a_msg_get_peer_list(const a2a_message_t *msg, peer_list_payload_t *pl);

#endif
