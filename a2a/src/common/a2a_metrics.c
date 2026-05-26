#define _GNU_SOURCE

#include "a2a_metrics.h"
#include "a2a_log.h"
#include "a2a_message.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void metrics_init(a2a_metrics_t *m)
{
    memset(m, 0, sizeof(*m));

    m->latency_min_us = UINT64_MAX;

    m->last_sample_us = a2a_now_us();
    m->cpu_sample_us  = a2a_now_us();
}

void metrics_record_latency(a2a_metrics_t *m, uint64_t sent_us)
{
    uint64_t now = a2a_now_us();

    if (sent_us == 0 || sent_us > now)
        return;

    uint64_t lat = now - sent_us;

    /* Reject outliers > 60s */
    if (lat > 60ULL * 1000000ULL) {

        LOG_D("METRICS",
              "Rejecting outlier latency: %.1fs",
              (double)lat / 1e6);

        return;
    }

    if (lat < m->latency_min_us)
        m->latency_min_us = lat;

    if (lat > m->latency_max_us)
        m->latency_max_us = lat;

    m->latency_sum_us += lat;
    m->latency_count++;
}

/* Read resident memory usage from /proc/self/status */
static long read_rss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");

    if (!f)
        return 0;

    char line[256];
    long rss = 0;

    while (fgets(line, sizeof(line), f)) {

        if (strncmp(line, "VmRSS:", 6) == 0) {

            sscanf(line + 6, "%ld", &rss);
            break;
        }
    }

    fclose(f);

    return rss;
}

/* Read CPU tick counters from /proc/self/stat */
static void read_cpu_ticks(unsigned long *utime,
                           unsigned long *stime)
{
    FILE *f = fopen("/proc/self/stat", "r");

    if (!f) {
        *utime = *stime = 0;
        return;
    }

    unsigned long u = 0;
    unsigned long s = 0;

    fscanf(f,
           "%*d %*s %*c %*d %*d %*d %*d %*d %*u "
           "%*u %*u %*u %*u "
           "%lu %lu",
           &u, &s);

    fclose(f);

    *utime = u;
    *stime = s;
}

void metrics_update(a2a_metrics_t *m,
                    const a2a_agent_t *agent)
{
    uint64_t now = a2a_now_us();

    double elapsed_s =
        (double)(now - m->last_sample_us) / 1e6;

    /* Update message throughput */
    if (elapsed_s > 0.1) {

        m->msgs_sent_per_sec =
            (double)(agent->msgs_sent -
                     m->msgs_sent_prev) / elapsed_s;

        m->msgs_recv_per_sec =
            (double)(agent->msgs_received -
                     m->msgs_recv_prev) / elapsed_s;

        m->msgs_sent_prev = agent->msgs_sent;
        m->msgs_recv_prev = agent->msgs_received;

        m->last_sample_us = now;
    }

    /* Update memory usage */
    m->rss_kb = read_rss_kb();

    /* Update CPU usage */
    unsigned long utime, stime;

    read_cpu_ticks(&utime, &stime);

    double cpu_elapsed_s =
        (double)(now - m->cpu_sample_us) / 1e6;

    if (cpu_elapsed_s > 0.1 &&
        (m->utime_prev + m->stime_prev) > 0)
    {
        unsigned long delta =
            (utime + stime) -
            (m->utime_prev + m->stime_prev);

        m->cpu_pct =
            (double)delta / 100.0 /
            cpu_elapsed_s * 100.0;

        if (m->cpu_pct > 100.0)
            m->cpu_pct = 100.0;
    }

    m->utime_prev    = utime;
    m->stime_prev    = stime;
    m->cpu_sample_us = now;
}

void metrics_dump(const a2a_metrics_t *m,
                  const a2a_agent_t   *agent,
                  const l2_agent_ctx_t *l2,
                  const l3_agent_ctx_t *l3)
{
    double avg_lat_us =
        (m->latency_count > 0)
        ? (double)m->latency_sum_us /
          m->latency_count
        : 0.0;

    double uptime_s =
        (double)(a2a_now_us() -
                 agent->start_time_us) / 1e6;

    fprintf(stderr,
            "{\"metrics\":{"
            "\"agent\":\"%s\","
            "\"type\":\"%s\","
            "\"uptime_s\":%.1f,"
            "\"fsm_state\":\"%s\","
            "\"peer_count\":%d,"
            "\"msgs_sent\":%lu,"
            "\"msgs_recv\":%lu,"
            "\"send_failures\":%lu,"
            "\"events_dropped\":%lu,"
            "\"fsm_invalid\":%lu,"
            "\"throughput_tx_pps\":%.1f,"
            "\"throughput_rx_pps\":%.1f,"
            "\"latency_min_us\":%.1f,"
            "\"latency_avg_us\":%.1f,"
            "\"latency_max_us\":%.1f,"
            "\"latency_samples\":%lu,"
            "\"rss_kb\":%ld,"
            "\"cpu_pct\":%.1f",
            agent->card.agent_id,
            (agent->card.type == AGENT_TYPE_L2)
                ? "L2" : "L3",
            uptime_s,
            fsm_state_str(agent->fsm_state),
            agent->peer_count,
            agent->msgs_sent,
            agent->msgs_received,
            agent->send_failures,
            agent->events_dropped,
            agent->fsm_invalid_transitions,
            m->msgs_sent_per_sec,
            m->msgs_recv_per_sec,
            (m->latency_count > 0 &&
             m->latency_min_us != UINT64_MAX)
                ? (double)m->latency_min_us
                : 0.0,
            avg_lat_us,
            (double)m->latency_max_us,
            m->latency_count,
            m->rss_kb,
            m->cpu_pct);

    /* L2-specific metrics */
    if (l2) {

        fprintf(stderr,
                ",\"l2_storms_detected\":%u,"
                "\"l2_flows_installed\":%u,"
                "\"l2_l3_notifies\":%u,"
                "\"l2_mac_count\":%d,"
                "\"l2_port_count\":%d,"
                "\"l2_mac_table_capacity\":%d",
                l2->storms_detected,
                l2->flows_installed,
                l2->l3_notifies_sent,
                l2->mac_count,
                l2->port_count,
                L2_MAX_MAC_TABLE);
    }

    /* L3-specific metrics */
    if (l3) {

        double conv_avg_ms =
            (l3->conv_count > 0)
            ? (double)l3->conv_sum_us /
              l3->conv_count / 1000.0
            : 0.0;

        fprintf(stderr,
                ",\"l3_reroutes\":%u,"
                "\"l3_route_count\":%d,"
                "\"l3_route_capacity\":%d,"
                "\"l3_l2_events\":%u,"
                "\"l3_route_installs\":%u,"
                "\"l3_route_withdrawals\":%u,"
                "\"l3_conv_count\":%u,"
                "\"l3_conv_avg_ms\":%.2f,"
                "\"l3_conv_min_ms\":%.2f,"
                "\"l3_conv_max_ms\":%.2f",
                l3->reroutes_performed,
                l3->route_count,
                L3_MAX_ROUTES,
                l3->l2_events_received,
                l3->route_installs,
                l3->route_withdrawals,
                l3->conv_count,
                conv_avg_ms,
                (l3->conv_count > 0 &&
                 l3->conv_min_us != UINT64_MAX)
                    ? (double)l3->conv_min_us /
                      1000.0
                    : 0.0,
                (double)l3->conv_max_us / 1000.0);
    }

    fprintf(stderr, "}}\n");

    fflush(stderr);
}