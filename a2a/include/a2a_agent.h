#ifndef A2A_AGENT_H
#define A2A_AGENT_H

#include "a2a_message.h"
#include "a2a_transport.h"
#include "a2a_fsm.h"
#include "a2a_event.h"
#include "a2a_connpool.h"


typedef enum {
    AGENT_TYPE_L2 = 1,
    AGENT_TYPE_L3 = 2
} agent_type_t;

#define A2A_DISPATCH_MAX 16
#define A2A_MAX_PEERS    16

typedef struct a2a_agent a2a_agent_t;
typedef void (*agent_msg_handler_t)(a2a_agent_t *agent, const a2a_message_t *msg);

typedef struct {
    a2a_msg_type_t    msg_type;
    agent_msg_handler_t handler;
} agent_dispatch_entry_t;

typedef struct {
    char         agent_id[A2A_MAX_AGENT_ID];
    agent_type_t type;
    char         switch_id[A2A_MAX_AGENT_ID];
    char         host[A2A_MAX_HOST_LEN];
    int          port;

    uint64_t     last_heartbeat_us;   /* last successful heartbeat rx */

    uint64_t     last_send_attempt_us; /* throttle reconnect attempts */

    uint64_t     registered_at_us;    /* first registration time */

    uint64_t     tombstone_us;        /* alive→dead transition; 0 = alive */

    int          alive;               /* current liveness state */

} agent_peer_t;

typedef struct {
    char         agent_id[A2A_MAX_AGENT_ID];
    agent_type_t type;
    char         switch_id[A2A_MAX_AGENT_ID];
    char         host[A2A_MAX_HOST_LEN];
    int          port;
} agent_card_t;

struct a2a_agent {
    agent_card_t  card;
    fsm_state_t   fsm_state;
    agent_fsm_t   fsm;           /* per-instance FSM table */
    event_queue_t eq;
    conn_pool_t   pool;
    a2a_server_t *server;

    uint32_t      msg_counter;
    agent_peer_t  peers[A2A_MAX_PEERS];
    int           peer_count;


    agent_dispatch_entry_t dispatch[A2A_DISPATCH_MAX];
    int            dispatch_count;

    void          *userdata;

    /* Diagnostics */
    uint64_t msgs_sent;
    uint64_t msgs_received;
    uint64_t start_time_us;
    uint64_t send_failures;
    uint64_t events_dropped;
    uint64_t msg_parse_errors;
    uint64_t fsm_invalid_transitions;
    uint64_t latency_sum_us;
    uint64_t latency_count;
};

a2a_agent_t *a2a_agent_create(const char *agent_id, agent_type_t type,
                               const char *switch_id,
                               const char *host, int port);
void         a2a_agent_destroy(a2a_agent_t *agent);
int          a2a_agent_register_handler(a2a_agent_t *agent,
                                        a2a_msg_type_t msg_type,
                                        agent_msg_handler_t handler);
int          a2a_agent_add_peer(a2a_agent_t *agent, const char *peer_id,
                                agent_type_t type, const char *switch_id,
                                const char *host, int port);
void         a2a_agent_compact_peers(a2a_agent_t *agent);

#endif /* A2A_AGENT_H */
