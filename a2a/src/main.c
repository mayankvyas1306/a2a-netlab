/*
 * main.c — A2A Agent entry point
 *
 * Production-grade: all events driven by real OVS/Netlink data.
 * No hardcoded scenarios, no --scenario flags, no mock triggers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include "a2a_message.h"
#include "a2a_agent.h"
#include "a2a_fsm.h"
#include "a2a_event.h"
#include "a2a_heartbeat.h"
#include "a2a_transport.h"
#include "l2_agent.h"
#include "l3_agent.h"
#include "a2a_log.h"
#include "a2a_metrics.h"


#define HEARTBEAT_INTERVAL_US (3ULL * 1000000ULL)
#define POOL_GC_INTERVAL_US (30ULL * 1000000ULL)
#define DISCOVERY_INTERVAL_US (5ULL * 1000000ULL)

static volatile int g_running = 1;
static volatile int g_dump_state = 0;

a2a_metrics_t g_metrics;

static void handle_sigint(int sig)
{
    (void)sig;
    g_running = 0;
}
static void handle_sigusr1(int sig)
{
    (void)sig;
    g_dump_state = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s --type l2|l3 --id ID --host HOST --port PORT\n"
            "       [--switch NAME] [--bridge BR]\n"
            "       [--real-ovs | --mock-ovs]\n\n"
            "Options:\n"
            "  --type l2|l3     Agent type\n"
            "  --id   ID        Unique agent identifier\n"
            "  --host HOST      Agent's own IP (used for A2A TCP listen)\n"
            "  --port PORT      TCP port for A2A messaging\n"
            "  --switch NAME    Logical switch/router name\n"
            "  --bridge BR      OVS bridge name (default: br0)\n"
            "  --real-ovs       Connect to real OVS (default)\n"
            "  --mock-ovs       Use synthetic data (unit testing only)\n"
            "  --l3-host HOST   Seed an L3 peer (cross-subnet bootstrap)\n"
            "  --l3-port PORT   Port of the seeded L3 peer\n\n"
            "Events are fully driven by OVSDB and Netlink — no manual triggers.\n",
            prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    /* ── Argument parsing ────────────────────────────────────────── */
    char type[8] = "";
    char id[A2A_MAX_AGENT_ID] = "";
    char host[A2A_MAX_HOST_LEN] = "0.0.0.0";
    char sw_name[A2A_MAX_AGENT_ID] = "";
    char bridge[64] = "br0";
    char l3_host[A2A_MAX_HOST_LEN] = "";
    int port = 7700;
    int l3_port = 0;
    int mock_ovs = 0; /* REAL OVS is the default in production */

    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "--type") && i + 1 < argc)
            strncpy(type, argv[++i], 7);
        else if (!strcmp(argv[i], "--id") && i + 1 < argc)
            strncpy(id, argv[++i], A2A_MAX_AGENT_ID - 1);
        else if (!strcmp(argv[i], "--host") && i + 1 < argc)
            strncpy(host, argv[++i], A2A_MAX_HOST_LEN - 1);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--switch") && i + 1 < argc)
            strncpy(sw_name, argv[++i], A2A_MAX_AGENT_ID - 1);
        else if (!strcmp(argv[i], "--bridge") && i + 1 < argc)
            strncpy(bridge, argv[++i], 63);
        else if (!strcmp(argv[i], "--l3-host") && i + 1 < argc)
            strncpy(l3_host, argv[++i], A2A_MAX_HOST_LEN - 1);
        else if (!strcmp(argv[i], "--l3-port") && i + 1 < argc)
            l3_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--mock-ovs"))
            mock_ovs = 1;
        else if (!strcmp(argv[i], "--real-ovs"))
            mock_ovs = 0;
        else if (!strcmp(argv[i], "--help"))
            usage(argv[0]);
    }

    if (!type[0] || !id[0])
    {
        fprintf(stderr, "ERROR: --type and --id are required\n");
        usage(argv[0]);
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);
    signal(SIGUSR1, handle_sigusr1);
    signal(SIGPIPE, SIG_IGN);
    char log_file[256];
    snprintf(log_file, sizeof(log_file),
             "/tmp/agent-%s.log", id);

    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║   A2A Agent                                      ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
    printf("  type=%s id=%s host=%s:%d bridge=%s OVS=%s\n\n",
           type, id, host, port, bridge,
           mock_ovs ? "MOCK" : "REAL");

    /* ── Agent creation ──────────────────────────────────────────── */
    l2_agent_ctx_t *l2 = NULL;
    l3_agent_ctx_t *l3 = NULL;
    a2a_agent_t *agent = NULL;

    if (!strcmp(type, "l2"))
    {
        if (!sw_name[0])
        {
            fprintf(stderr, "ERROR: --switch required for l2\n");
            usage(argv[0]);
        }
        l2 = l2_agent_create(id, sw_name, bridge, host, port, mock_ovs);
        if (!l2)
        {
            fprintf(stderr, "Failed to create L2 agent\n");
            return 1;
        }
        agent = l2->agent;
    }
    else if (!strcmp(type, "l3"))
    {
        if (!sw_name[0])
            strncpy(sw_name, id, A2A_MAX_AGENT_ID - 1);
        l3 = l3_agent_create(id, sw_name, bridge, host, port, mock_ovs);
        if (!l3)
        {
            fprintf(stderr, "Failed to create L3 agent\n");
            return 1;
        }
        agent = l3->agent;

        /*
         * In real mode the Netlink dump will populate routes from the
         * kernel.  In mock mode we seed a local route so the agent
         * has something to advertise.
         */
        if (mock_ovs)
        {
            char local_prefix[48];
            snprintf(local_prefix, sizeof(local_prefix),
                     "10.0.%d.0/24", port % 256);
            l3_add_route(l3, local_prefix, "0.0.0.0", sw_name, "", 0, 1);
        }
    }
    else
    {
        fprintf(stderr, "ERROR: --type must be l2 or l3\n");
        usage(argv[0]);
    }

    /* ── Prime FSM: INIT → DISCOVERY ────────────────────────────── */
    {
        a2a_event_t start = {0};
        start.type = A2A_EV_MSG_RECEIVED;
        start.fsm_event = FSM_EVENT_START;
        start.timestamp_us = a2a_now_us();
        fsm_process(agent, &start);

        /*
         * Drain any events that agent_create may have enqueued
         * (discovery announcements, internal transitions) before the
         * main loop begins.  This ensures the FSM is in DISCOVERY
         * before the first inbound TCP message can arrive and be
         * dispatched — otherwise INIT + MSG_RECEIVED is unregistered
         * and the message is silently dropped.
         */
        a2a_event_t ev;
        while (event_queue_pop(&agent->eq, &ev) == 0)
            fsm_process(agent, &ev);
    }

    /* ── Optional: seed a known L3 peer for cross-subnet bootstrap ─
     *  In production, UDP multicast handles peer discovery within a
     *  subnet.  For agents on different subnets, --l3-host/--l3-port
     *  provides an initial contact point.                            */
    if (l3_host[0] && l3_port > 0)
    {
        char peer_id[A2A_MAX_AGENT_ID];
        snprintf(peer_id, sizeof(peer_id), "seed-%s-%d", l3_host, l3_port);

        a2a_agent_add_peer(agent, peer_id, AGENT_TYPE_L3,
                           "unknown", l3_host, l3_port);

        a2a_event_t seed_ev = {0};
        seed_ev.type = A2A_EV_PEER_DISCOVERED;
        seed_ev.fsm_event = FSM_EVENT_PEER_DISCOVERED;
        seed_ev.timestamp_us = a2a_now_us();
        seed_ev.data.peer.port = l3_port;
        seed_ev.data.peer.agent_type = AGENT_TYPE_L3;
        strncpy(seed_ev.data.peer.host, l3_host, A2A_MAX_HOST_LEN - 1);
        strncpy(seed_ev.data.peer.agent_id, peer_id, A2A_MAX_AGENT_ID - 1);
        strncpy(seed_ev.data.peer.switch_id,"unknown", A2A_MAX_AGENT_ID - 1);
        event_queue_push(&agent->eq, &seed_ev);
        LOG_I("MAIN", "Seeded L3 peer %s:%d", l3_host, l3_port);
    }

    /* ── Main event loop ─────────────────────────────────────────── */
    uint64_t next_hb_us = a2a_now_us() + HEARTBEAT_INTERVAL_US;
    uint64_t next_gc_us = a2a_now_us() + POOL_GC_INTERVAL_US;
    uint64_t next_discovery_us = a2a_now_us() + DISCOVERY_INTERVAL_US;


    metrics_init(&g_metrics);

    LOG_I("MAIN", "%s agent running. Ctrl-C to stop.", type);

    while (g_running)
    {

        /*
         * 1. TCP + OVSDB + Netlink (via epoll).
         *    epoll_wait timeout = 5ms so the loop is not a busy-spin
         *    but still reacts within 5ms to any network event.
         */
        a2a_server_poll(agent->server, 5);

        uint64_t now = a2a_now_us();

        /* 3. Heartbeat timer */
        if (now >= next_hb_us)
        {
            a2a_event_t hb = {0};
            hb.type = A2A_EV_HEARTBEAT_TICK;
            hb.fsm_event = FSM_EVENT_HEARTBEAT_TICK;
            hb.timestamp_us = now;
            event_queue_push(&agent->eq, &hb);
            next_hb_us += HEARTBEAT_INTERVAL_US;
        }

        if (now >= next_discovery_us)
        {
            for (int _i = 0; _i < agent->peer_count; _i++)
            {
                agent_peer_t *_p = &agent->peers[_i];

                /* Retry if:
                 *   (a) peer is dead (alive==0), OR
                 *   (b) peer is alive but has NEVER exchanged a heartbeat
                 *       (last_heartbeat_us was set to now() at add-time, so
                 *        check registered_at_us == 0 OR age < 3s means it
                 *        was just added — use msgs_received proxy: if peer
                 *        has no inbound HB yet, re-trigger discovery).
                 * The simplest correct guard: retry if peer has no
                 * confirmed two-way comms yet, detected by
                 * last_heartbeat_us being within 1s of registered_at_us
                 * (i.e., it was just stamped at add-time, not by a real HB).
                 */
                int needs_register =
                    !_p->alive ||
                    (_p->alive && _p->registered_at_us > 0 &&
                     (_p->last_heartbeat_us - _p->registered_at_us) < 1000000ULL);

                if (!needs_register)
                    continue;

                /* Skip peers with no address */
                if (_p->host[0] == '\0' || _p->port == 0)
                    continue;

                a2a_event_t ev = {0};
                ev.type       = A2A_EV_PEER_DISCOVERED;
                ev.fsm_event  = FSM_EVENT_PEER_DISCOVERED;
                ev.timestamp_us = now;

                strncpy(ev.data.peer.host,     _p->host,     A2A_MAX_HOST_LEN - 1);
                strncpy(ev.data.peer.agent_id, _p->agent_id, A2A_MAX_AGENT_ID - 1);
                strncpy(ev.data.peer.switch_id,_p->switch_id,A2A_MAX_AGENT_ID - 1);

                ev.data.peer.port       = _p->port;
                ev.data.peer.agent_type = _p->type;

                event_queue_push(&agent->eq, &ev);
            }

            next_discovery_us = now + DISCOVERY_INTERVAL_US;
        }

        /* 5. Drain event queue through per-agent FSM */
        a2a_event_t ev;
        while (event_queue_pop(&agent->eq, &ev) == 0)
            fsm_process(agent, &ev);

        /* 6. Agent-specific periodic work */
        if (l2)
            l2_agent_tick(l2);
        if (l3)
            l3_agent_tick(l3);

        /* 7. Connection pool GC + peer table compaction */
        if (now >= next_gc_us)
        {
            conn_pool_gc(&agent->pool, 60ULL * 1000000ULL);
            a2a_agent_compact_peers(agent);
            next_gc_us += POOL_GC_INTERVAL_US;
        }

        /* 8. SIGUSR1 state dump */
        if (g_dump_state)
        {
            g_dump_state = 0;

            /*
             * Update throughput/CPU metrics before dumping.
             * metrics_record_latency() is called per-message so
             * latency data is always current.
             */
            metrics_update(&g_metrics, agent);

            /*
             * JSON metrics line — parseable by monitoring tools.
             * Format: {"metrics":{...}}\n
             * Each SIGUSR1 produces exactly one line.
             */
            metrics_dump(&g_metrics, agent, l2, l3);

            /* Human-readable state for log inspection */
            LOG_I("DEBUG", "=== STATE DUMP ===");
            LOG_I("DEBUG", "fsm_state=%s peers=%d uptime=%.0fs",
                  fsm_state_str(agent->fsm_state),
                  agent->peer_count,
                  (double)(a2a_now_us() - agent->start_time_us) / 1e6);
            LOG_I("DEBUG", "msgs sent=%lu recv=%lu dropped=%lu",
                  agent->msgs_sent, agent->msgs_received,
                  agent->events_dropped);
            LOG_I("DEBUG", "send_failures=%lu fsm_invalid=%lu "
                  "latency_avg=%.1fus",
                  agent->send_failures,
                  agent->fsm_invalid_transitions,
                  g_metrics.latency_count > 0
                      ? (double)g_metrics.latency_sum_us
                        / g_metrics.latency_count
                      : 0.0);
            LOG_I("DEBUG", "event_queue_size=%d/%d",
                  event_queue_size(&agent->eq), EVENT_QUEUE_SIZE);

            if (l2) l2_print_table(l2);
            if (l3) l3_print_routes(l3);
        }
    }

    /* ── Graceful shutdown ───────────────────────────────────────── */
    LOG_I("MAIN", "Shutting down...");

    a2a_event_t shut = {0};
    shut.type = A2A_EV_SHUTDOWN;
    shut.fsm_event = FSM_EVENT_SHUTDOWN;
    fsm_process(agent, &shut);

    /* Capture stats before destroy frees the agent struct */
    uint64_t _sf = agent->send_failures;
    uint64_t _ed = agent->events_dropped;
    uint64_t _fi = agent->fsm_invalid_transitions;
    uint64_t _ms = agent->msgs_sent;
    uint64_t _mr = agent->msgs_received;

    if (l2)
    {
        l2_print_table(l2);
        l2_agent_destroy(l2);
    }
    if (l3)
    {
        l3_print_routes(l3);
        l3_agent_destroy(l3);
    }
    ovs_cleanup();

    LOG_I("STATS", "send_failures=%lu events_dropped=%lu "
                   "fsm_invalid=%lu msgs_sent=%lu msgs_recv=%lu",
          _sf, _ed, _fi, _ms, _mr);

    LOG_I("MAIN", "Shutdown complete.");
    return 0;
}
