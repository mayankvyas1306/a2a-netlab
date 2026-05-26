#include "a2a_fsm.h"
#include "a2a_agent.h"
#include "a2a_event.h"
#include "a2a_log.h"
#include <stdio.h>
#include <string.h>

/* ── Init ─────────────────────────────────────────────────────────── */

void fsm_init(agent_fsm_t *fsm)
{
    memset(fsm->table, 0, sizeof(fsm->table));

    /* Default: every unregistered (state, event) → ERROR */
    for (int s = 0; s < FSM_STATE_COUNT; s++)
        for (int e = 0; e < FSM_EVENT_COUNT; e++)
        {
            fsm->table[s][e].from_state = (fsm_state_t)s;
            fsm->table[s][e].on_event = (fsm_event_type_t)e;
            fsm->table[s][e].to_state = FSM_STATE_ERROR;
            fsm->table[s][e].action = NULL;
        }

    /* ── Universal base transitions (agent-type independent) ──── */

    /* INIT → DISCOVERY on START */
    fsm_register(fsm, FSM_STATE_INIT, FSM_EVENT_START,
                 FSM_STATE_DISCOVERY, NULL);

    /* DISCOVERY: heartbeat stays in DISCOVERY */
    fsm_register(fsm, FSM_STATE_DISCOVERY, FSM_EVENT_HEARTBEAT_TICK,
                 FSM_STATE_DISCOVERY, NULL);

    /* DISCOVERY: inbound message → RECEIVING */
    fsm_register(fsm, FSM_STATE_DISCOVERY, FSM_EVENT_MSG_RECEIVED,
                 FSM_STATE_RECEIVING, NULL);

    /* REGISTERING: heartbeat stays */
    fsm_register(fsm, FSM_STATE_REGISTERING, FSM_EVENT_HEARTBEAT_TICK,
                 FSM_STATE_REGISTERING, NULL);

    /* REGISTERING: registered → ACTIVE */
    fsm_register(fsm, FSM_STATE_REGISTERING, FSM_EVENT_REGISTERED,
                 FSM_STATE_ACTIVE, NULL);

    /* REGISTERING: another peer discovered */
    fsm_register(fsm, FSM_STATE_REGISTERING, FSM_EVENT_PEER_DISCOVERED,
                 FSM_STATE_REGISTERING, NULL);

    /* ACTIVE: heartbeat stays */
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_HEARTBEAT_TICK,
                 FSM_STATE_ACTIVE, NULL);

    /* ACTIVE: message → RECEIVING */
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_MSG_RECEIVED,
                 FSM_STATE_RECEIVING, NULL);

    /* ACTIVE: peer discovered → ACTIVE (re-register) */
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_PEER_DISCOVERED,
                 FSM_STATE_ACTIVE, NULL);

    /* ACTIVE: peer timeout → ACTIVE */
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_PEER_TIMEOUT,
                 FSM_STATE_ACTIVE, NULL);

    /* ACTIVE: OVS event → ACTIVE (action registered per agent type) */
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_OVS_EVENT,
                 FSM_STATE_ACTIVE, NULL);
    
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_PROCESSING_DONE,
                 FSM_STATE_ACTIVE, NULL);
                 
    fsm_register(fsm, FSM_STATE_ACTIVE, FSM_EVENT_REGISTERED,
                 FSM_STATE_ACTIVE, NULL);
    /* RECEIVING: processing done → ACTIVE */
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_PROCESSING_DONE,
                 FSM_STATE_ACTIVE, NULL);

    /* RECEIVING: another message → stay RECEIVING */
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_MSG_RECEIVED,
                 FSM_STATE_RECEIVING, NULL);

    /* RECEIVING: heartbeat ok */
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_HEARTBEAT_TICK,
                 FSM_STATE_RECEIVING, NULL);

    /* RECEIVING: OVS event — ignore safely */
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_OVS_EVENT,
                 FSM_STATE_RECEIVING, NULL);

    /* RECEIVING: peer timeout */
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_PEER_TIMEOUT,
                 FSM_STATE_RECEIVING, NULL);

    /* RECEIVING: registered (async) → ACTIVE */
    fsm_register(fsm, FSM_STATE_RECEIVING, FSM_EVENT_REGISTERED,
                 FSM_STATE_ACTIVE, NULL);

    /* PROCESSING / SENDING → ACTIVE */
    fsm_register(fsm, FSM_STATE_PROCESSING, FSM_EVENT_SEND_DONE,
                 FSM_STATE_ACTIVE, NULL);
    fsm_register(fsm, FSM_STATE_SENDING, FSM_EVENT_SEND_DONE,
                 FSM_STATE_ACTIVE, NULL);

    /* ERROR recovery */
    fsm_register(fsm, FSM_STATE_ERROR, FSM_EVENT_RECOVER,
                 FSM_STATE_DISCOVERY, NULL);
    fsm_register(fsm, FSM_STATE_ERROR, FSM_EVENT_HEARTBEAT_TICK,
                 FSM_STATE_ERROR, NULL);

    /* SHUTDOWN and ERROR universal transitions */
    for (int s = 0; s < FSM_STATE_COUNT; s++)
    {
        fsm_register(fsm, (fsm_state_t)s, FSM_EVENT_ERROR,
                     FSM_STATE_ERROR, NULL);
        fsm_register(fsm, (fsm_state_t)s, FSM_EVENT_SHUTDOWN,
                     FSM_STATE_SHUTDOWN, NULL);
    }
}

/* ── Register ─────────────────────────────────────────────────────── */

void fsm_register(agent_fsm_t *fsm,
                  fsm_state_t from, fsm_event_type_t ev,
                  fsm_state_t to, fsm_action_fn action)
{
    if (from >= FSM_STATE_COUNT || ev >= FSM_EVENT_COUNT)
        return;
    fsm->table[from][ev].from_state = from;
    fsm->table[from][ev].on_event = ev;
    fsm->table[from][ev].to_state = to;
    fsm->table[from][ev].action = action;
}

/* ── Dispatch ─────────────────────────────────────────────────────── */

int fsm_process(a2a_agent_t *agent, const a2a_event_t *event)
{
    fsm_state_t cur = agent->fsm_state;
    fsm_event_type_t ev = event->fsm_event;

    if (cur >= FSM_STATE_COUNT || ev >= FSM_EVENT_COUNT)
    {
        LOG_E("FSM", "[%s] OOB state=%d event=%d",
              agent->card.agent_id, cur, ev);
        agent->fsm_invalid_transitions++;
        return -1;
    }

    const fsm_transition_t *tr = &agent->fsm.table[cur][ev];

    /* Unregistered transition: to_state == ERROR, action == NULL.
     * Treat as a harmless ignore — prevents crash from spurious events. */
    if (tr->to_state == FSM_STATE_ERROR && tr->action == NULL)
    {
        LOG_W("FSM", "[%s] INVALID TRANSITION: %s + %s",
              agent->card.agent_id,
              fsm_state_str(cur),
              fsm_event_str(ev));

        agent->fsm_invalid_transitions++;

        return -1;
    }

    LOG_D("FSM", "[%s] %s + %s → %s",
          agent->card.agent_id,
          fsm_state_str(cur), fsm_event_str(ev),
          fsm_state_str(tr->to_state));

    /* Transition state FIRST so action callbacks see the new state */
    agent->fsm_state = tr->to_state;

    if (tr->action)
        tr->action(agent, event);

    return 0;
}

/* ── String helpers ───────────────────────────────────────────────── */

const char *fsm_state_str(fsm_state_t s)
{
    static const char *names[] = {
        "INIT", "DISCOVERY", "REGISTERING", "ACTIVE",
        "RECEIVING", "PROCESSING", "SENDING", "ERROR", "SHUTDOWN"};
    if ((unsigned)s < FSM_STATE_COUNT)
        return names[s];
    return "UNKNOWN";
}

const char *fsm_event_str(fsm_event_type_t e)
{
    static const char *names[] = {
        "START", "PEER_DISCOVERED", "REGISTERED", "MSG_RECEIVED",
        "PROCESSING_DONE", "SEND_DONE", "HEARTBEAT_TICK", "PEER_TIMEOUT",
        "OVS_EVENT", "ERROR", "RECOVER", "SHUTDOWN"};
    if ((unsigned)e < FSM_EVENT_COUNT)
        return names[e];
    return "UNKNOWN";
}
