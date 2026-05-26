#include "a2a_event.h"
#include <string.h>

void event_queue_init(event_queue_t *q) {
    memset(q, 0, sizeof(*q));
}

int event_queue_push(event_queue_t *q, const a2a_event_t *ev) {
    unsigned next = (q->head + 1) & (EVENT_QUEUE_SIZE - 1);
    if (next == q->tail) return -1;  /* full */
    q->buf[q->head] = *ev;
    q->head = next;
    return 0;
}

int event_queue_pop(event_queue_t *q, a2a_event_t *out) {
    if (q->head == q->tail) return -1;  /* empty */
    *out   = q->buf[q->tail];
    q->tail = (q->tail + 1) & (EVENT_QUEUE_SIZE - 1);
    return 0;
}

int event_queue_size(const event_queue_t *q) {
    return (int)((q->head - q->tail) & (EVENT_QUEUE_SIZE - 1));
}

/* Map internal event type to FSM event type */
fsm_event_type_t ev_to_fsm(a2a_ev_type_t type) {
    switch (type) {
        case A2A_EV_MSG_RECEIVED:    return FSM_EVENT_MSG_RECEIVED;
        case A2A_EV_PEER_DISCOVERED: return FSM_EVENT_PEER_DISCOVERED;
        case A2A_EV_PEER_TIMEOUT:    return FSM_EVENT_PEER_TIMEOUT;
        case A2A_EV_HEARTBEAT_TICK:  return FSM_EVENT_HEARTBEAT_TICK;
        case A2A_EV_OVS_MAC_LEARNED: return FSM_EVENT_OVS_EVENT;
        case A2A_EV_OVS_LINK_DOWN:   return FSM_EVENT_OVS_EVENT;
        case A2A_EV_ANOMALY:         return FSM_EVENT_OVS_EVENT;
        case A2A_EV_SHUTDOWN:        return FSM_EVENT_SHUTDOWN;
        default:                     return FSM_EVENT_ERROR;
    }
}
