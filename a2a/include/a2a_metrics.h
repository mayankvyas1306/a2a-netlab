#ifndef A2A_METRICS_H
#define A2A_METRICS_H

/*
 * Performance metrics collection for A2A agents.
 * Metrics are computed on demand and exported as JSON.
 */

#include <stdint.h>
#include "a2a_agent.h"
#include "l2_agent.h"
#include "l3_agent.h"

typedef struct a2a_metrics_t {

    /* Message latency statistics */
    uint64_t latency_min_us;    /* minimum latency */
    uint64_t latency_max_us;    /* maximum latency */
    uint64_t latency_sum_us;    /* total latency */
    uint64_t latency_count;     /* number of samples */

    /* Message throughput statistics */
    uint64_t msgs_sent_prev;    /* previous TX counter */
    uint64_t msgs_recv_prev;    /* previous RX counter */
    uint64_t last_sample_us;    /* last throughput sample time */
    double   msgs_sent_per_sec; /* TX rate */
    double   msgs_recv_per_sec; /* RX rate */

    /* Resource usage statistics */
    long     rss_kb;            /* resident memory usage */
    double   cpu_pct;           /* CPU usage percentage */

    /* Previous CPU counters */
    unsigned long utime_prev;   /* previous user CPU ticks */
    unsigned long stime_prev;   /* previous system CPU ticks */
    uint64_t      cpu_sample_us;/* last CPU sample time */

} a2a_metrics_t;

/* Initialize metrics structure */
void metrics_init(a2a_metrics_t *m);

/* Record one latency sample */
void metrics_record_latency(a2a_metrics_t *m, uint64_t sent_us);

/* Refresh throughput and resource metrics */
void metrics_update(a2a_metrics_t *m, const a2a_agent_t *agent);

/* Dump metrics as JSON */
void metrics_dump(const a2a_metrics_t *m,
                  const a2a_agent_t   *agent,
                  const l2_agent_ctx_t *l2,   /* NULL for L3 */
                  const l3_agent_ctx_t *l3);  /* NULL for L2 */

#endif /* A2A_METRICS_H */