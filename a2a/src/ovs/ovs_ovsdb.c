//src/ovs/ovs_ovsdb.c

/*
 * OVSDB JSON-RPC monitor
 *
 * Subscribes to Port, Interface, and Bridge tables via db.sock.
 * Maintains an in-memory shadow so ovs_interface.c can query
 * port stats without popen/system.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <cjson/cJSON.h>

#include "a2a_event.h"
#include "a2a_agent.h"
#include "l2_agent.h"
#include "a2a_fsm.h"
#include "a2a_log.h"
#include "ovs_interface.h"

#define OVSDB_SOCK "/var/run/openvswitch/db.sock"

/* ── In-memory shadow of OVS Interface table ─────────────────────── */
#define OVSDB_MAX_IFACES 128

/* Forward declaration — defined in l2_agent.c */
void l2_sync_ports_from_ovsdb(l2_agent_ctx_t *ctx);


typedef struct
{
    char name[64];
    char uuid[64];
    int ofport;
    int link_up;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    int valid;
} ovsdb_iface_shadow_t;

static ovsdb_iface_shadow_t g_ifaces[OVSDB_MAX_IFACES];



/* Find or allocate an entry in the interface shadow table */
static ovsdb_iface_shadow_t *iface_find_or_alloc(const char *name)
{
    for (int i = 0; i < OVSDB_MAX_IFACES; i++)
    {
        if (g_ifaces[i].valid &&
            strcmp(g_ifaces[i].name, name) == 0)
            return &g_ifaces[i];
    }
    for (int i = 0; i < OVSDB_MAX_IFACES; i++)
    {
        if (!g_ifaces[i].valid)
        {
            memset(&g_ifaces[i], 0, sizeof(g_ifaces[i]));
            strncpy(g_ifaces[i].name, name, sizeof(g_ifaces[i].name) - 1);
            g_ifaces[i].valid = 1;
            return &g_ifaces[i];
        }
    }
    return NULL; /* table full */
}

/* Public API used by ovs_interface.c (no popen) */
int ovsdb_get_port_stats(const char *ifname, ovs_port_stats_t *out)
{
    memset(out, 0, sizeof(*out));
    for (int i = 0; i < OVSDB_MAX_IFACES; i++)
    {
        if (!g_ifaces[i].valid)
            continue;
        if (strcmp(g_ifaces[i].name, ifname) != 0)
            continue;
        out->rx_packets = g_ifaces[i].rx_packets;
        out->tx_packets = g_ifaces[i].tx_packets;
        out->rx_bytes = g_ifaces[i].rx_bytes;
        out->tx_bytes = g_ifaces[i].tx_bytes;
        out->rx_dropped = g_ifaces[i].rx_dropped;
        out->link_up = g_ifaces[i].link_up;
        return 0;
    }
    return -1; /* not yet seen in OVSDB */
}

int ovsdb_get_ofport(const char *ifname)
{
    for (int i = 0; i < OVSDB_MAX_IFACES; i++)
    {
        if (g_ifaces[i].valid &&
            strcmp(g_ifaces[i].name, ifname) == 0)
            return g_ifaces[i].ofport;
    }
    return -1;
}

/* Iterate over all known interfaces in the shadow table.
 * Called by l2_sync_ports_from_ovsdb() to populate the port list. */
void ovsdb_iterate_ifaces(void (*cb)(const char *name, int ofport,
                                     int link_up, void *ud),
                          void *ud)
{
    for (int i = 0; i < OVSDB_MAX_IFACES; i++)
    {
        if (!g_ifaces[i].valid)
            continue;
        cb(g_ifaces[i].name, g_ifaces[i].ofport, g_ifaces[i].link_up, ud);
    }
}

/* ── Connection ──────────────────────────────────────────────────── */

int ovsdb_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        LOG_E("OVSDB", "socket() failed errno=%d", errno);
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, OVSDB_SOCK, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOG_W("OVSDB", "connect %s failed errno=%d (OVS not running?)",
              OVSDB_SOCK, errno);
        close(fd);
        return -1;
    }

    LOG_I("OVSDB", "Connected to %s fd=%d", OVSDB_SOCK, fd);
    return fd;
}

/* ── Monitor subscription ────────────────────────────────────────── */

int ovsdb_send_monitor(int fd)
{
    /* Monitor Port, Interface, and Bridge tables.
     * Initial response contains full state; incremental updates follow. */
    const char *req =
        "{\"method\":\"monitor\","
        "\"params\":[\"Open_vSwitch\",null,"
        "{"
        "\"Port\":{"
        "\"columns\":[\"name\",\"interfaces\"]"
        "},"
        "\"Interface\":{"
        "\"columns\":[\"name\",\"statistics\",\"ofport\","
        "\"link_state\",\"admin_state\"]"
        "},"
        "\"Bridge\":{"
        "\"columns\":[\"name\",\"ports\"]"
        "}"
        "}"
        "],\"id\":1}\n";

    ssize_t sent = send(fd, req, strlen(req), MSG_NOSIGNAL);
    if (sent < 0)
    {
        LOG_E("OVSDB", "send monitor request failed errno=%d", errno);
        return -1;
    }
    LOG_I("OVSDB", "Monitor request sent (%zd bytes)", sent);
    return (int)sent;
}

/* ── Helpers for OVSDB value extraction ─────────────────────────── */

/* OVSDB encodes optionals as either scalars or ["type", value] arrays. */
static const char *ovsdb_str(cJSON *item)
{
    if (!item) return NULL;
    if (cJSON_IsString(item)) return item->valuestring;
    if (cJSON_IsArray(item) && cJSON_GetArraySize(item) == 2)
    {
        cJSON *val = cJSON_GetArrayItem(item, 1);
        if (cJSON_IsString(val)) return val->valuestring;
                /* Handle OVSDB ["set", ["string"]] wrapper */
        if (cJSON_IsArray(val) && cJSON_GetArraySize(val) == 1) {
            cJSON *inner = cJSON_GetArrayItem(val, 0);
            if (cJSON_IsString(inner)) return inner->valuestring;
        }
    }
    return NULL;
}

/* Parse OVSDB statistics map: ["map", [["key", value], ...]] */
static void parse_statistics_map(cJSON *jstats, ovsdb_iface_shadow_t *iface)
{
    if (!jstats || !cJSON_IsArray(jstats))
        return;
    if (cJSON_GetArraySize(jstats) != 2)
        return;

    cJSON *tag = cJSON_GetArrayItem(jstats, 0);
    cJSON *pairs = cJSON_GetArrayItem(jstats, 1);

    if (!cJSON_IsString(tag) ||
        strcmp(tag->valuestring, "map") != 0)
        return;
    if (!cJSON_IsArray(pairs))
        return;

    cJSON *pair = NULL;
    cJSON_ArrayForEach(pair, pairs)
    {
        if (!cJSON_IsArray(pair) || cJSON_GetArraySize(pair) < 2)
            continue;
        cJSON *k = cJSON_GetArrayItem(pair, 0);
        cJSON *v = cJSON_GetArrayItem(pair, 1);
        if (!cJSON_IsString(k) || !cJSON_IsNumber(v))
            continue;

        uint64_t val = (uint64_t)v->valuedouble;
        const char *key = k->valuestring;

        if (!strcmp(key, "rx_packets"))
            iface->rx_packets = val;
        else if (!strcmp(key, "tx_packets"))
            iface->tx_packets = val;
        else if (!strcmp(key, "rx_bytes"))
            iface->rx_bytes = val;
        else if (!strcmp(key, "tx_bytes"))
            iface->tx_bytes = val;
        else if (!strcmp(key, "rx_dropped"))
            iface->rx_dropped = val;
        else if (!strcmp(key, "tx_dropped"))
            iface->tx_dropped = val;
    }
}

/* ── Interface table update handler ─────────────────────────────── */

static void process_interface_table(cJSON *iface_table, a2a_agent_t *agent)
{
    if (!iface_table) return;

    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, iface_table)
    {
        cJSON *new_obj = cJSON_GetObjectItem(entry, "new");
        if (!new_obj) continue;

        const char *uuid = entry->string;
        cJSON *jname  = cJSON_GetObjectItem(new_obj, "name");
        cJSON *jstats = cJSON_GetObjectItem(new_obj, "statistics");
        cJSON *jofp   = cJSON_GetObjectItem(new_obj, "ofport");
        cJSON *jlink  = cJSON_GetObjectItem(new_obj, "link_state");

        const char *ifname = NULL;
        if (jname && cJSON_IsString(jname)) ifname = jname->valuestring;
        
        ovsdb_iface_shadow_t *iface = NULL;

        if (ifname && ifname[0]) {
            iface = iface_find_or_alloc(ifname);
            if (iface && uuid) {
                strncpy(iface->uuid, uuid, sizeof(iface->uuid) - 1);
            }
        } else if (uuid && uuid[0]) {
            for (int i = 0; i < OVSDB_MAX_IFACES; i++) {
                if (g_ifaces[i].valid && strcmp(g_ifaces[i].uuid, uuid) == 0) {
                    iface = &g_ifaces[i];
                    break;
                }
            }
        }

        if (!iface) continue;
        int was_up = iface->link_up;
        int prev_ofport = iface->ofport;

        if (jstats) parse_statistics_map(jstats, iface);

        if (jofp) {
            if (cJSON_IsNumber(jofp)) iface->ofport = (int)jofp->valuedouble;
            else if (cJSON_IsArray(jofp) && cJSON_GetArraySize(jofp) == 2) {
                cJSON *v = cJSON_GetArrayItem(jofp, 1);
                if (cJSON_IsNumber(v)) iface->ofport = (int)v->valuedouble;
            } else {
                iface->ofport = -1;
            }
        }

        /* Handle OVSDB ["set", []] meaning DOWN */
        int is_up = 1;
        if (jlink) {
            if (cJSON_IsString(jlink) && strcmp(jlink->valuestring, "up") == 0) {
                is_up = 1;
            } else if (cJSON_IsArray(jlink) && cJSON_GetArraySize(jlink) == 2) {
                cJSON *val = cJSON_GetArrayItem(jlink, 1);
                if (cJSON_IsArray(val) && cJSON_GetArraySize(val) == 0) {
                    is_up = 0; /* Empty array -> explicitly DOWN */
                } else if (cJSON_IsArray(val) && cJSON_GetArraySize(val) == 1) {
                    cJSON *inner = cJSON_GetArrayItem(val, 0);
                    if (cJSON_IsString(inner) && strcmp(inner->valuestring, "up") == 0) {
                        is_up = 1;
                    } else {
                        is_up = 0;
                    }
                } else if (cJSON_IsString(val) && strcmp(val->valuestring, "up") == 0) {
                    is_up = 1;
                } else {
                    is_up = 0;
                }
            } else {
                is_up = 0;
            }
        }
        iface->link_up = is_up;
        int port_no = iface->ofport > 0 ? iface->ofport : prev_ofport;

        int changed = (iface->link_up != was_up) || (iface->ofport != prev_ofport);
        if (changed || (iface->ofport > 0 && iface->ofport != prev_ofport)) {
            LOG_I("OVSDB", "Interface updated: %s ofport=%d link=%s",
                    iface->name, port_no, iface->link_up ? "up" : "down");
        } else {
            LOG_D("OVSDB", "Interface polled (no change): %s ofport=%d link=%s",
                    iface->name, port_no, iface->link_up ? "up" : "down");
        }

        if (was_up && !iface->link_up && agent && agent->card.type == AGENT_TYPE_L2 && agent->userdata) {
            l2_agent_ctx_t *ctx = (l2_agent_ctx_t *)agent->userdata;
            if (port_no > 0) {
                /* Prevent duplicate link-down events (OVSDB fires before poll) */
                int already_reported = 0;
                for (int pi = 0; pi < ctx->port_count; pi++)
                {
                    if (ctx->ports[pi].port_no == port_no)
                    {
                        already_reported = ctx->ports[pi].link_down_reported;
                        if (!already_reported)
                            ctx->ports[pi].link_down_reported = 1;
                        break;
                    }
                }
                if (already_reported)
                {
                    LOG_D("OVSDB", "LINK DOWN dedup: if=%s ofport=%d (already reported)",
                          iface->name, port_no);
                }
                else
                {
                    LOG_W("OVSDB", "LINK DOWN: if=%s ofport=%d", iface->name, port_no);
                    a2a_event_t ev = {0};
                    ev.type = A2A_EV_OVS_LINK_DOWN;
                    ev.fsm_event = FSM_EVENT_OVS_EVENT;
                    ev.timestamp_us = a2a_now_us();
                    ev.data.ovs.port = port_no;
                    ev.data.ovs.link_down = 1;
                    snprintf(ev.data.ovs.bridge, sizeof(ev.data.ovs.bridge), "%s", ctx->bridge);
                    event_queue_push(&agent->eq, &ev);
                }
            }
        }
    }
}

/* ── Port table update handler ───────────────────────────────────── */

static void process_port_table(cJSON *port_table, a2a_agent_t *agent)
{
    if (!port_table || !agent || !agent->userdata)
        return;

    /* Guard: only L2 agents have a port table */
    if (agent->card.type != AGENT_TYPE_L2)
        return;

    l2_agent_ctx_t *ctx = (l2_agent_ctx_t *)agent->userdata;

    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, port_table)
    {
        cJSON *new_obj = cJSON_GetObjectItem(entry, "new");
        if (!new_obj)
            continue;

        cJSON *jname = cJSON_GetObjectItem(new_obj, "name");
        cJSON *jlink = cJSON_GetObjectItem(new_obj, "link_state");

        const char *ifname = ovsdb_str(jname);
        const char *state = ovsdb_str(jlink);

        if (!ifname || !state)
            continue;

        /* Find the port number from L2 context */
        int port_no = -1;
        for (int i = 0; i < ctx->port_count; i++)
        {
            if (strcmp(ctx->ports[i].ifname, ifname) == 0)
            {
                port_no = ctx->ports[i].port_no;
                break;
            }
        }
        if (port_no < 0)
            continue;

        if (strcmp(state, "down") == 0)
        {
            /* Interface table already fires link-down; log only here */
            LOG_W("OVSDB", "Port table: LINK DOWN if=%s port=%d (no duplicate event)",
                  ifname, port_no);
        }
        else if (strcmp(state, "up") == 0)
        {
            LOG_I("OVSDB", "LINK UP: if=%s port=%d", ifname, port_no);
        }
    }
}

/* ── Main update dispatcher ──────────────────────────────────────── */

void ovsdb_process_update(const char *json, a2a_agent_t *agent)
{
    if (!json || !json[0])
        return;

    cJSON *root = cJSON_Parse(json);
    if (!root)
    {
        LOG_W("OVSDB", "JSON parse error on update");
        return;
    }

    /* Handle both initial monitor response and incremental updates */
    cJSON *tables = NULL;

    cJSON *method = cJSON_GetObjectItem(root, "method");
    if (method && cJSON_IsString(method) &&
        strcmp(method->valuestring, "update") == 0)
    {
        /* Incremental update: params[1] contains the table diffs */
        cJSON *params = cJSON_GetObjectItem(root, "params");
        if (params && cJSON_IsArray(params) &&
            cJSON_GetArraySize(params) >= 2)
            tables = cJSON_GetArrayItem(params, 1);
    }
    else
    {
        /* Initial monitor response: result contains full table state */
        cJSON *result = cJSON_GetObjectItem(root, "result");
        if (result && cJSON_IsObject(result))
            tables = result;
    }

    if (!tables)
    {
        cJSON_Delete(root);
        return;
    }

    /* Update Interface shadow first (Port handler may reference it) */
    cJSON *iface_tbl = cJSON_GetObjectItem(tables, "Interface");
    if (iface_tbl)
        process_interface_table(iface_tbl, agent);

    cJSON *port_tbl = cJSON_GetObjectItem(tables, "Port");
    if (port_tbl)
        process_port_table(port_tbl, agent);

    /* After Interface table update, re-sync L2 port list from OVSDB shadow.
     * This is how OVS ports are discovered at runtime — sysfs brif/ is empty
     * for OVS bridges. */
    if (iface_tbl && agent && agent->card.type == AGENT_TYPE_L2 &&
        agent->userdata)
    {
        l2_sync_ports_from_ovsdb((l2_agent_ctx_t *)agent->userdata);
    }

    cJSON_Delete(root);
}


/*
 * Set interface admin_state through OVSDB JSON-RPC.
 */
int ovsdb_set_admin_state(int ovsdb_fd, const char *ifname, int up)
{
    if (ovsdb_fd < 0) {
        LOG_E("OVSDB", "ovsdb_set_admin_state: invalid fd=%d", ovsdb_fd);
        return -1;
    }

    if (!ifname || ifname[0] == '\0') {
        LOG_E("OVSDB", "ovsdb_set_admin_state: empty ifname");
        return -1;
    }

    /* Generate unique request ID */
    unsigned long long req_id =
        (unsigned long long)(a2a_now_us() % 1000000ULL);

    char req[512];

    int req_len = snprintf(req, sizeof(req),
        "{"
          "\"method\":\"transact\","
          "\"params\":["
            "\"Open_vSwitch\","
            "[{"
              "\"op\":\"update\","
              "\"table\":\"Interface\","
              "\"where\":[[\"name\",\"==\",\"%s\"]],"
              "\"row\":{\"admin_state\":\"%s\"}"
            "}]"
          "],"
          "\"id\":%llu"
        "}\n",
        ifname,
        up ? "up" : "down",
        req_id);

    /* Check request buffer size */
    if (req_len <= 0 || req_len >= (int)sizeof(req)) {
        LOG_E("OVSDB", "ovsdb_set_admin_state: request buffer overflow "
              "(ifname='%s')", ifname);
        return -1;
    }

    /* Send OVSDB request */
    ssize_t n = send(ovsdb_fd, req, (size_t)req_len, MSG_NOSIGNAL);

    if (n < 0) {
        LOG_E("OVSDB", "ovsdb_set_admin_state: send failed errno=%d "
              "(ifname='%s', state=%s)",
              errno, ifname, up ? "up" : "down");
        return -1;
    }

    /* Guard against partial sends */
    if (n < req_len) {
        LOG_W("OVSDB", "ovsdb_set_admin_state: partial send %zd/%d bytes",
              n, req_len);
        return -1;
    }

    LOG_D("OVSDB", "ovsdb_set_admin_state: %s → %s "
          "(req_id=%llu, fd=%d)",
          ifname, up ? "up" : "down",
          req_id, ovsdb_fd);

    return 0;
}

/* ── OVSDB Interface statistics (per-port native read) ──────────── */

int ovs_ovsdb_get_interface_stats(const char *bridge,
                                  const char *ifname,
                                  ovsdb_if_stats_t *out)
{
    (void)bridge; /* OVSDB socket is global, bridge param reserved */
    memset(out, 0, sizeof(*out));

    int fd = ovsdb_connect();
    if (fd < 0)
        return -1;

    /* OVSDB transact: select Interface row by name, get statistics column */
    char req[512];
    static unsigned long long req_id = 0x2000;
    int req_len = snprintf(req, sizeof(req),
        "{\"id\":%llu,\"method\":\"transact\",\"params\":["
        "\"Open_vSwitch\","
        "{\"op\":\"select\",\"table\":\"Interface\","
        "\"where\":[[\"name\",\"==\",\"%s\"]],"
        "\"columns\":[\"statistics\"]}]}\n",
        req_id++, ifname);

    if (req_len <= 0 || req_len >= (int)sizeof(req)) {
        close(fd);
        return -1;
    }

    if (send(fd, req, (size_t)req_len, MSG_NOSIGNAL) < 0) {
        close(fd);
        return -1;
    }

    char buf[8192];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root)
        return -1;

    /* Navigate: result[0].rows[0].statistics */
    cJSON *result = cJSON_GetObjectItem(root, "result");
    if (!result) { cJSON_Delete(root); return -1; }

    cJSON *r0 = cJSON_GetArrayItem(result, 0);
    if (!r0)    { cJSON_Delete(root); return -1; }

    cJSON *rows = cJSON_GetObjectItem(r0, "rows");
    if (!rows || cJSON_GetArraySize(rows) == 0) {
        cJSON_Delete(root); return -1;
    }

    cJSON *row   = cJSON_GetArrayItem(rows, 0);
    cJSON *stats = cJSON_GetObjectItem(row, "statistics");
    if (!stats)  { cJSON_Delete(root); return -1; }

    /* OVSDB map: ["map", [["key", val], ...]] */
    cJSON *pairs = NULL;
    if (cJSON_IsArray(stats) && cJSON_GetArraySize(stats) == 2)
        pairs = cJSON_GetArrayItem(stats, 1);
    else
        pairs = stats; /* already the array of pairs */

    if (!pairs) { cJSON_Delete(root); return -1; }

    int np = cJSON_GetArraySize(pairs);
    for (int i = 0; i < np; i++) {
        cJSON *pair = cJSON_GetArrayItem(pairs, i);
        if (!pair || cJSON_GetArraySize(pair) < 2) continue;
        cJSON *kitem = cJSON_GetArrayItem(pair, 0);
        cJSON *vitem = cJSON_GetArrayItem(pair, 1);
        if (!kitem || !vitem) continue;
        const char *key = cJSON_IsString(kitem) ? kitem->valuestring : NULL;
        long long   val = (long long)vitem->valuedouble;
        if (!key) continue;

        if      (strcmp(key, "rx_packets") == 0) out->rx_packets = val;
        else if (strcmp(key, "tx_packets") == 0) out->tx_packets = val;
        else if (strcmp(key, "rx_bytes")   == 0) out->rx_bytes   = val;
        else if (strcmp(key, "tx_bytes")   == 0) out->tx_bytes   = val;
        else if (strcmp(key, "rx_errors")  == 0) out->rx_errors  = val;
        else if (strcmp(key, "tx_errors")  == 0) out->tx_errors  = val;
        else if (strcmp(key, "rx_dropped") == 0) out->rx_dropped = val;
        else if (strcmp(key, "tx_dropped") == 0) out->tx_dropped = val;
    }

    cJSON_Delete(root);
    return 0;
}