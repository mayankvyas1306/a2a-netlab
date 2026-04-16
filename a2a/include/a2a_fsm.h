#ifndef A2A_FSM_H
#define A2A_FSM_H

typedef struct a2a_agent  a2a_agent_t;
typedef struct a2a_event  a2a_event_t;
typedef struct agent_fsm  agent_fsm_t;

/* ── States ──────────────────────────────────────────────────────── */
typedef enum {
    FSM_STATE_INIT        = 0,
    FSM_STATE_DISCOVERY   = 1,
    FSM_STATE_REGISTERING = 2,
    FSM_STATE_ACTIVE      = 3,
    FSM_STATE_RECEIVING   = 4,
    FSM_STATE_PROCESSING  = 5,
    FSM_STATE_SENDING     = 6,
    FSM_STATE_ERROR       = 7,
    FSM_STATE_SHUTDOWN    = 8,
    FSM_STATE_COUNT       = 9
} fsm_state_t;

/* ── Events ──────────────────────────────────────────────────────── */
typedef enum {
    FSM_EVENT_START           = 0,
    FSM_EVENT_PEER_DISCOVERED = 1,
    FSM_EVENT_REGISTERED      = 2,
    FSM_EVENT_MSG_RECEIVED    = 3,
    FSM_EVENT_PROCESSING_DONE = 4,
    FSM_EVENT_SEND_DONE       = 5,
    FSM_EVENT_HEARTBEAT_TICK  = 6,
    FSM_EVENT_PEER_TIMEOUT    = 7,
    FSM_EVENT_OVS_EVENT       = 8,
    FSM_EVENT_ERROR           = 9,
    FSM_EVENT_RECOVER         = 10,
    FSM_EVENT_SHUTDOWN        = 11,
    FSM_EVENT_COUNT           = 12
} fsm_event_type_t;

typedef void (*fsm_action_fn)(a2a_agent_t *agent, const a2a_event_t *event);

typedef struct {
    fsm_state_t      from_state;
    fsm_event_type_t on_event;
    fsm_state_t      to_state;
    fsm_action_fn    action;       /* NULL = transition only, no side effect */
} fsm_transition_t;

/*
 * Per-agent FSM table — embedded inside a2a_agent_t.
 * Zero global state: multiple agents in one process are safe.
 */
struct agent_fsm {
    fsm_transition_t table[FSM_STATE_COUNT][FSM_EVENT_COUNT];
};

/* ── Core API ────────────────────────────────────────────────────── */
void        fsm_init    (agent_fsm_t *fsm);
void        fsm_register(agent_fsm_t *fsm,
                         fsm_state_t from, fsm_event_type_t on_event,
                         fsm_state_t to,   fsm_action_fn action);
int         fsm_process (a2a_agent_t *agent, const a2a_event_t *event);
const char *fsm_state_str(fsm_state_t state);
const char *fsm_event_str(fsm_event_type_t ev);

#endif /* A2A_FSM_H */
