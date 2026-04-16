#ifndef A2A_EVENT_H
#define A2A_EVENT_H

#include "a2a_message.h"
#include "a2a_fsm.h"
#include <stdint.h>

/* ── Event types ─────────────────────────────────────────────────────── */
typedef enum {
    A2A_EV_MSG_RECEIVED    = 0,  /* inbound A2A message                */
    A2A_EV_PEER_DISCOVERED = 1,  /* UDP announce received              */
    A2A_EV_PEER_TIMEOUT    = 2,  /* peer missed heartbeat deadline     */
    A2A_EV_HEARTBEAT_TICK  = 3,  /* periodic timer                     */
    A2A_EV_OVS_MAC_LEARNED = 4,  /* OVS reported a new MAC             */
    A2A_EV_OVS_LINK_DOWN   = 5,  /* OVS reported a port going down     */
    A2A_EV_ANOMALY         = 6,  /* agent logic detected an anomaly    */
    A2A_EV_SHUTDOWN        = 7,
    A2A_EV_COUNT           = 8
} a2a_ev_type_t;

/* Peer-info carried by PEER_DISCOVERED and PEER_TIMEOUT events */
typedef struct {
    char agent_id[A2A_MAX_AGENT_ID];
    int  agent_type;   /* AGENT_TYPE_L2 or AGENT_TYPE_L3 */
    char switch_id[A2A_MAX_AGENT_ID];
    char host[A2A_MAX_HOST_LEN];
    int  port;
} peer_info_t;

/* OVS event data */
typedef struct {
    char   bridge[64];
    char   mac[18];     /* "aa:bb:cc:dd:ee:ff" */
    int    port;
    int    link_down;   /* 1 if this is a link-down event */
} ovs_ev_data_t;

/* ── The event struct ────────────────────────────────────────────────── */
typedef struct a2a_event {
    a2a_ev_type_t    type;
    fsm_event_type_t fsm_event;  /* mapped FSM event for fsm_process() */
    uint64_t         timestamp_us;

    union {
        a2a_message_t  msg;       /* for A2A_EV_MSG_RECEIVED            */
        peer_info_t    peer;      /* for PEER_DISCOVERED / PEER_TIMEOUT  */
        ovs_ev_data_t  ovs;       /* for OVS_MAC_LEARNED / OVS_LINK_DOWN*/
    } data;
} a2a_event_t;

/* ── Ring-buffer event queue (single-producer, single-consumer) ──────── */
#define EVENT_QUEUE_SIZE 256   /* must be power of 2                    */

typedef struct {
    a2a_event_t  buf[EVENT_QUEUE_SIZE];
    volatile unsigned head;   /* producer writes here                   */
    volatile unsigned tail;   /* consumer reads here                    */
} event_queue_t;

void event_queue_init(event_queue_t *q);
int  event_queue_push(event_queue_t *q, const a2a_event_t *ev); /* 0=ok,-1=full */
int  event_queue_pop (event_queue_t *q, a2a_event_t *out);      /* 0=ok,-1=empty*/
int  event_queue_size(const event_queue_t *q);

/* Map an A2A event type to the FSM event type */
fsm_event_type_t ev_to_fsm(a2a_ev_type_t type);

#endif /* A2A_EVENT_H */
