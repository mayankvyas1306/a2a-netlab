//src/ovs/ovs_interface.c

/*
 * OVS backend abstraction layer
 *
 * REAL mode: data from OVSDB shadow and OpenFlow socket (no popen/system).
 * MOCK mode: synthesised data for unit testing without live OVS.
 */

#include "ovs_interface.h"
#include "a2a_log.h"
#include "a2a_message.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* Declarations from sibling OVS modules */
extern int ovsdb_get_port_stats(const char *ifname, ovs_port_stats_t *out);
extern int ovsdb_get_ofport(const char *ifname);
extern int ovs_of_connect(const char *bridge);
extern int ovs_of_add_flow(const char *bridge, const ovs_flow_t *flow);
extern int ovs_of_del_flow(const char *bridge, const char *match);
extern int ovs_of_list_flows(const char *bridge, ovs_flow_t *out, int max);
extern int ovs_of_flush_mac(const char *bridge);
extern int ovsdb_set_admin_state(int ovsdb_fd, const char *ifname, int up);
extern int ovs_of_get_all_flow_stats(const char *bridge, of_flow_stat_t *out,
                                      int max, int *count_out);
extern int ovs_of_get_meter_stats(const char *bridge, uint32_t meter_id,
                                   of_meter_stat_t *out);
extern int ovs_of_get_table_stats(const char *bridge, of_table_stat_t *out);

static int g_ovsdb_fd = -1;

void ovs_set_ovsdb_fd(int fd) {
    g_ovsdb_fd = fd;
}

/* Mock MAC table for unit tests */
static ovs_mac_entry_t g_mock_macs[4] = {
    {"aa:bb:cc:dd:00:01", 1, 0},
    {"aa:bb:cc:dd:00:02", 2, 0},
    {"aa:bb:cc:dd:00:03", 3, 0},
    {"", 0, 0}};
static uint64_t g_mock_pkt_counter = 0;

/* ── Backend selection ───────────────────────────────────────────── */

static int g_use_mock = 0; /* default: REAL — require explicit --mock-ovs */

int ovs_init(int use_mock)
{
    g_use_mock = use_mock;
    LOG_I("OVS", "Backend=%s", use_mock ? "MOCK" : "REAL");
    if (!use_mock)
    {
    /* Prime OpenFlow eagerly; bridge name unknown here, deferred */
    }
    return 0;
}

void ovs_cleanup(void)
{
    /* Cleanup handled by ovs_openflow.c */
}

/* ── Flow management ─────────────────────────────────────────────── */

int ovs_add_flow(const char *bridge, const ovs_flow_t *flow)
{
    if (g_use_mock)
    {
        LOG_D("OVS", "MOCK add_flow bridge=%s priority=%u match=%s",
              bridge, flow->priority, flow->match);
        return 0;
    }
    return ovs_of_add_flow(bridge, flow);
}

int ovs_del_flow(const char *bridge, const char *match)
{
    if (g_use_mock)
    {
        LOG_D("OVS", "MOCK del_flow bridge=%s match=%s", bridge, match);
        return 0;
    }
    return ovs_of_del_flow(bridge, match);
}

int ovs_list_flows(const char *bridge, ovs_flow_t *out, int max)
{
    if (g_use_mock)
    {
        (void)out;
        (void)max;
        LOG_D("OVS", "MOCK list_flows bridge=%s", bridge);
        return 0;
    }
    return ovs_of_list_flows(bridge, out, max);
}

extern int ovs_of_get_all_flow_stats(const char *bridge,
                                      of_flow_stat_t *out, int max,
                                      int *count_out);
extern int ovs_of_get_meter_stats(const char *bridge,
                                   uint32_t meter_id,
                                   of_meter_stat_t *out);
extern int ovs_of_get_table_stats(const char *bridge,
                                   of_table_stat_t *out);

/* ── MAC / FDB ───────────────────────────────────────────────────── */

/* In real mode the MAC table is populated by PACKET_IN in ovs_openflow.c. */
extern int ovs_of_get_mac_table(ovs_mac_entry_t *out, int max);

int ovs_get_mac_table(const char *bridge, ovs_mac_entry_t *out, int max)
{
    (void)bridge;
    if (g_use_mock)
    {
        uint64_t now = a2a_now_us();
        int count = 3 < max ? 3 : max;
        for (int i = 0; i < count; i++)
        {
            out[i] = g_mock_macs[i];
            out[i].learned_at_us = now - (uint64_t)(i * 1000000ULL);
        }
        return count;
    }
    return ovs_of_get_mac_table(out, max);
}

int ovs_flush_mac(const char *bridge, const char *mac)
{
    (void)mac;
    if (g_use_mock)
    {
        LOG_D("OVS", "MOCK flush_mac bridge=%s", bridge);
        return 0;
    }
    return ovs_of_flush_mac(bridge);
}

/* ── Port statistics ─────────────────────────────────────────────── */

int ovs_get_port_stats(const char *bridge,
                       const char *ifname,
                       ovs_port_stats_t *out)
{
    (void)bridge;
    memset(out, 0, sizeof(*out));

    if (g_use_mock)
    {
        g_mock_pkt_counter += 50;
        out->rx_packets = g_mock_pkt_counter;
        out->tx_packets = g_mock_pkt_counter / 2;
        out->link_up = 1;
        return 0;
    }

    /* Real path: read from OVSDB Interface.statistics shadow table. */
    return ovsdb_get_port_stats(ifname, out);
}

/* ── Port admin state ────────────────────────────────────────────── */

int ovs_set_port_state(const char *bridge, const char *ifname, int up)
{
    if (g_use_mock) {
        LOG_D("OVS", "MOCK set_port_state bridge=%s if=%s up=%d",
              bridge, ifname, up);
        return 0;
    }

    int rc = ovsdb_set_admin_state(g_ovsdb_fd, ifname, up);

    if (rc == 0)
        LOG_I("OVS", "set_port_state %s %s → %s",
              bridge, ifname, up ? "UP" : "DOWN");
    else
        LOG_W("OVS", "set_port_state failed: %s %s (ovsdb_fd=%d)",
              bridge, ifname, g_ovsdb_fd);

    return rc;
}
/* ── Bridge existence ────────────────────────────────────────────── */

int ovs_bridge_exists(const char *bridge)
{
    if (g_use_mock)
        return 1;

/* Probe bridge existence via OpenFlow connection attempt. */
#ifdef ENABLE_L2_OPENFLOW
    int fd = ovs_of_connect(bridge);
#else
    int fd = -1;
#endif
    if (fd >= 0)
    {
        /* ovs_of_connect caches the fd internally */
        return 1;
    }
    return 0;
}
