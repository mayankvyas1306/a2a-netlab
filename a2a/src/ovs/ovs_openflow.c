/*
 * ovs_openflow.c — Native OpenFlow 1.3 integration
 *
 * Connects to /var/run/openvswitch/<bridge>.mgmt
 * Implements:
 *   - HELLO handshake
 *   - FEATURES_REQUEST
 *   - FLOW_MOD (ADD / DELETE) with OXM match + action encoding
 *   - PACKET_IN handling for real MAC learning
 *   - Table-miss entry installation
 *
 * No popen(), no system(), no ovs-ofctl subprocess.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/ethernet.h>

#include "ovs_interface.h"
#include "a2a_log.h"
#include "a2a_message.h"
#include "a2a_transport.h"

/* Forward declarations */
void ovs_of_process_packet_in(const char *bridge, int fd);
/* for a2a_now_us() */

/* ── OpenFlow 1.3 wire constants ─────────────────────────────────── */

#define OFP13_VERSION 0x04
#define OFPT_HELLO 0
#define OFPT_FEATURES_REQUEST 5
#define OFPT_FEATURES_REPLY 6
#define OFPT_SET_CONFIG 9
#define OFPT_PACKET_IN 10
#define OFPT_FLOW_MOD 14
#define OFPT_STATS_REQUEST 18
#define OFPT_STATS_REPLY 19
#define OFPT_PACKET_OUT 13

/* Flow mod commands */
#define OFPFC_ADD 0
#define OFPFC_MODIFY 1
#define OFPFC_DELETE 3
#define OFPFC_DELETE_STRICT 4

/* Match type */
#define OFPMT_OXM 1

/* Action types */
#define OFPAT_OUTPUT 0
#define OFPAT_SET_FIELD 25
#define OFPAT_DEC_NW_TTL 24
#define OFPIT_APPLY_ACTIONS 4
#define OFPIT_METER 6 /* OpenFlow 1.3 meter instruction */

/* OXM field headers (class=OPENFLOW_BASIC=0x8000) */
#define OXM_OF_IN_PORT 0x80000000
#define OXM_OF_ETH_DST 0x80000606
#define OXM_OF_ETH_SRC 0x80000806
#define OXM_OF_ETH_TYPE 0x80000a02
#define OXM_OF_IPV4_DST 0x80001804   /* exact */
#define OXM_OF_IPV4_DST_W 0x80001908 /* masked (prefix) */
#define OXM_OF_IP_PROTO 0x80001601

#define OFPP_CONTROLLER 0xfffffffd
#define OFPP_FLOOD 0xfffffffb
#define OFPP_NORMAL 0xfffffffa
#define OFPP_ANY 0xffffffff

#define OFP_NO_BUFFER 0xffffffff

#pragma pack(push, 1)

typedef struct
{
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t xid;
} ofp_header_t;

typedef struct
{
    ofp_header_t header;
    /* HELLO has no body in OF1.3 (elements optional) */
} ofp_hello_t;

typedef struct
{
    uint16_t type;   /* OFPMT_OXM */
    uint16_t length; /* total match length including padding */
    /* OXM TLVs follow */
} ofp_match_t;

typedef struct
{
    ofp_header_t header;
    uint64_t cookie;
    uint64_t cookie_mask;
    uint8_t table_id;
    uint8_t command;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint16_t priority;
    uint32_t buffer_id;
    uint32_t out_port;
    uint32_t out_group;
    uint16_t flags;
    uint8_t pad[2];
    /* ofp_match follows, then instructions */
} ofp_flow_mod_t;

typedef struct
{
    uint16_t type;
    uint16_t len;
    uint8_t pad[4];
    /* actions follow */
} ofp_instruction_actions_t;

typedef struct
{
    uint16_t type;
    uint16_t len;
    uint32_t port;
    uint16_t max_len;
    uint8_t pad[6];
} ofp_action_output_t;

typedef struct
{
    uint16_t type; /* OFPAT_SET_FIELD */
    uint16_t len;
    /* OXM TLV follows */
} ofp_action_set_field_t;

typedef struct
{
    uint16_t type; /* OFPAT_DEC_NW_TTL */
    uint16_t len;
    uint8_t pad[4];
} ofp_action_dec_ttl_t;

typedef struct
{
    ofp_header_t header;
    uint8_t reason;
    uint8_t table_id;
    uint8_t pad[2];
    uint32_t cookie_high;
    uint32_t cookie_low;
    uint16_t total_len;
    uint16_t buffer_id_pad; /* actually part of data */
    /* match follows, then packet data */
} ofp_packet_in_t;

typedef struct
{
    uint16_t type; /* OFPIT_METER */
    uint16_t len;  /* 8 */
    uint32_t meter_id;
} ofp_instruction_meter_t;
#pragma pack(pop)

/* ── State ───────────────────────────────────────────────────────── */

#define MAX_OF_BRIDGES 8

typedef struct
{
    char bridge[64];
    int fd;
    int connected;
} of_conn_t;

static of_conn_t g_conns[MAX_OF_BRIDGES];
static uint32_t g_xid = 1;

/* Per-bridge epoll registration info */
static a2a_server_t *g_of_server[MAX_OF_BRIDGES]; /* parallel to g_conns */

/* Per-bridge MAC table populated by PACKET_IN */
#define OF_MAC_TABLE_MAX 1024

typedef struct
{
    char mac[18];
    uint32_t in_port;
    uint64_t learned_at_us;
    int valid;
} of_mac_entry_t;

static of_mac_entry_t g_mac_table[OF_MAC_TABLE_MAX];
static int g_mac_count = 0;

/* ── Connection management ───────────────────────────────────────── */

static of_conn_t *of_get_conn(const char *bridge)
{
    for (int i = 0; i < MAX_OF_BRIDGES; i++)
        if (g_conns[i].connected &&
            strcmp(g_conns[i].bridge, bridge) == 0)
            return &g_conns[i];
    return NULL;
}

static of_conn_t *of_alloc_conn(void)
{
    for (int i = 0; i < MAX_OF_BRIDGES; i++)
        if (!g_conns[i].connected)
            return &g_conns[i];
    return NULL;
}

/* Send a HELLO message and wait for peer HELLO */
static int of_do_hello(int fd)
{
    ofp_hello_t hello = {0};
    hello.header.version = OFP13_VERSION;
    hello.header.type = OFPT_HELLO;
    hello.header.length = htons(sizeof(hello));
    hello.header.xid = htonl(g_xid++);

    if (send(fd, &hello, sizeof(hello), MSG_NOSIGNAL) < 0)
    {
        LOG_E("OF", "HELLO send failed errno=%d", errno);
        return -1;
    }

    /* Read peer HELLO (blocking, short timeout via SO_RCVTIMEO) */
    ofp_hello_t peer_hello;
    ssize_t n = recv(fd, &peer_hello, sizeof(peer_hello), 0);
    if (n < (ssize_t)sizeof(ofp_header_t))
    {
        LOG_E("OF", "HELLO recv failed n=%zd", n);
        return -1;
    }
    if (peer_hello.header.version < OFP13_VERSION)
    {
        LOG_W("OF", "Peer OF version 0x%02x < 0x%02x",
              peer_hello.header.version, OFP13_VERSION);
        /* Continue anyway — OVS supports negotiation */
    }
    LOG_I("OF", "HELLO complete, peer version=0x%02x",
          peer_hello.header.version);
    return 0;
}

static int of_set_config(int fd)
{
    struct
    {
        ofp_header_t header;
        uint16_t flags;
        uint16_t miss_send_len;
    } __attribute__((packed)) cfg;

    memset(&cfg, 0, sizeof(cfg));

    cfg.header.version = OFP13_VERSION;
    cfg.header.type = OFPT_SET_CONFIG;
    cfg.header.length = htons(sizeof(cfg));
    cfg.header.xid = htonl(g_xid++);

    cfg.flags = htons(0); // OFPC_FRAG_NORMAL
    cfg.miss_send_len = htons(65535);

    if (send(fd, &cfg, sizeof(cfg), MSG_NOSIGNAL) < 0)
    {
        LOG_E("OF", "SET_CONFIG failed errno=%d", errno);
        return -1;
    }

    LOG_I("OF", "SET_CONFIG sent (miss_send_len=65535)");
    return 0;
}

/* Install a table-miss entry: priority=0, match=*, output=CONTROLLER */
static int of_install_table_miss(int fd, const char *bridge)
{
    /*
     * Build FLOW_MOD:
     *   table_id=0, command=ADD, priority=0,
     *   match=OXM (empty = match all),
     *   instruction=APPLY_ACTIONS(OUTPUT:CONTROLLER)
     */
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    int off = 0;

    /* ofp_flow_mod header placeholder */
    ofp_flow_mod_t *fm = (ofp_flow_mod_t *)buf;
    off += sizeof(ofp_flow_mod_t);

    fm->header.version = OFP13_VERSION;
    fm->header.type = OFPT_FLOW_MOD;
    fm->cookie = 0;
    fm->cookie_mask = 0;
    fm->table_id = 0;
    fm->command = OFPFC_ADD;
    fm->idle_timeout = 0;
    fm->hard_timeout = 0;
    fm->priority = 0; /* lowest priority = table miss */
    fm->buffer_id = htonl(OFP_NO_BUFFER);
    fm->out_port = htonl(OFPP_ANY);
    fm->out_group = htonl(0xffffffff);
    fm->flags = 0;

    /* Empty OXM match (matches everything) */
    ofp_match_t *match = (ofp_match_t *)(buf + off);
    match->type = htons(OFPMT_OXM);
    match->length = htons(4); /* header only, no TLVs */
    off += 4;
    /* Pad to 8-byte boundary */
    off += 4; /* 4-byte pad */

    /* Instruction: APPLY_ACTIONS */
    ofp_instruction_actions_t *inst =
        (ofp_instruction_actions_t *)(buf + off);
    int inst_off = off;
    off += sizeof(ofp_instruction_actions_t);

    /* Action: OUTPUT to CONTROLLER */
    ofp_action_output_t *act_out = (ofp_action_output_t *)(buf + off);
    act_out->type = htons(OFPAT_OUTPUT);
    act_out->len = htons(sizeof(ofp_action_output_t));
    act_out->port = htonl(OFPP_CONTROLLER);
    act_out->max_len = htons(0xffff); /* send full packet */
    off += sizeof(ofp_action_output_t);

    inst->type = htons(OFPIT_APPLY_ACTIONS);
    inst->len = htons(off - inst_off);

    fm->header.length = htons(off);

    if (send(fd, buf, off, MSG_NOSIGNAL) < 0)
    {
        LOG_E("OF", "[%s] table-miss FLOW_MOD failed errno=%d", bridge, errno);
        return -1;
    }
    LOG_I("OF", "[%s] table-miss entry installed (PACKET_IN controller mode)",
          bridge);
    return 0;
}

/* Called by epoll when the OpenFlow fd is readable.
 * Reads one OF message and dispatches it. */
static void of_epoll_handler(int fd, void *ud)
{
    /* Find which bridge this fd belongs to */
    const char *bridge = NULL;
    for (int i = 0; i < MAX_OF_BRIDGES; i++)
    {
        if (g_conns[i].connected && g_conns[i].fd == fd)
        {
            bridge = g_conns[i].bridge;
            break;
        }
    }
    if (!bridge)
        return;
    ovs_of_process_packet_in(bridge, fd);
}

/* Public: connect to bridge OpenFlow channel */
int ovs_of_connect(const char *bridge)
{
    of_conn_t *c = of_get_conn(bridge);
    if (c)
        return c->fd;

    c = of_alloc_conn();
    if (!c)
    {
        LOG_E("OF", "Connection table full");
        return -1;
    }

    char path[256];
    snprintf(path, sizeof(path),
             "/var/run/openvswitch/%s.mgmt", bridge);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        LOG_E("OF", "socket() failed errno=%d", errno);
        return -1;
    }

    /* Set receive timeout (2s) for HELLO negotiation */
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOG_E("OF", "connect %s failed errno=%d", path, errno);
        close(fd);
        return -1;
    }

    if (of_do_hello(fd) < 0)
    {
        close(fd);
        return -1;
    }

    if (of_set_config(fd) < 0)
    {
        close(fd);
        return -1;
    }

    /* Remove receive timeout — now non-blocking via epoll */
    tv.tv_sec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Set non-blocking for epoll integration */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Install table-miss entry */
    of_install_table_miss(fd, bridge);

    /* FIX B7: Install a dedicated ARP flood flow so ARP requests are
     * immediately flooded without waiting for the controller PACKET_OUT.
     * This ensures ARP works even if the controller PACKET_OUT is delayed.
     * Priority 1 (above table-miss priority=0, below learned MAC priority=10). */
    {
        ovs_flow_t arp_flow = {0};
        arp_flow.priority     = 1;
        arp_flow.idle_timeout = 0;   /* permanent */
        arp_flow.hard_timeout = 0;
        /* Match ARP frames (EtherType 0x0806) */
        snprintf(arp_flow.match,   sizeof(arp_flow.match),
                 "dl_type=0x0806");
        snprintf(arp_flow.actions, sizeof(arp_flow.actions),
                 "output:flood");
        ovs_of_add_flow(bridge, &arp_flow);
        LOG_I("OF", "[%s] ARP flood flow installed", bridge);
    }

    snprintf(c->bridge, sizeof(c->bridge), "%s", bridge);
    c->fd = fd;
    c->connected = 1;

    LOG_I("OF", "[%s] OpenFlow channel open fd=%d", bridge, fd);
    return fd;
}

/*
 * Register all open OpenFlow fds with the agent's epoll loop.
 * Must be called after ovs_of_connect() and a2a_server_create().
 * This is what makes PACKET_IN messages actually arrive.
 */
void ovs_of_register_epoll(a2a_server_t *server)
{
    if (!server)
        return;
    for (int i = 0; i < MAX_OF_BRIDGES; i++)
    {
        if (!g_conns[i].connected)
            continue;
        if (a2a_server_add_fd(server, g_conns[i].fd) == 0)
        {
            g_of_server[i] = server;
            a2a_server_add_ext_fd(server, g_conns[i].fd,
                                  of_epoll_handler, NULL);
            LOG_I("OF", "[%s] fd=%d registered with epoll",
                  g_conns[i].bridge, g_conns[i].fd);
        }
    }
}

void ovs_of_deregister_epoll(a2a_server_t *server)
{
    for (int i = 0; i < MAX_OF_BRIDGES; i++)
    {
        if (g_conns[i].connected && g_of_server[i] == server)
        {
            a2a_server_del_fd(server, g_conns[i].fd);
            g_of_server[i] = NULL;
        }
    }
}

/* ── OXM TLV builder helpers ─────────────────────────────────────── */

/*
 * Append an OXM TLV to buf at *off.
 * field: OXM header (with hasmask=0)
 * val:   field value bytes
 * len:   byte length of value
 */
static int oxm_put(uint8_t *buf, int *off, int bufsz,
                   uint32_t field_hdr, const uint8_t *val, int vlen)
{
    if (*off + 4 + vlen > bufsz)
        return -1;
    uint32_t hdr = htonl((field_hdr & ~0xFF) | (uint32_t)vlen);
    memcpy(buf + *off, &hdr, 4);
    *off += 4;
    memcpy(buf + *off, val, vlen);
    *off += vlen;
    return 0;
}

/* Pad *off to 8-byte boundary */
static void oxm_pad(uint8_t *buf, int *off)
{
    int pad = (8 - (*off % 8)) % 8;
    if (pad)
    {
        memset(buf + *off, 0, pad);
        *off += pad;
    }
}

/*
 * Parse "aa:bb:cc:dd:ee:ff" MAC string into 6-byte array.
 * Returns 0 on success, -1 on error.
 */
static int parse_mac(const char *str, uint8_t *out)
{
    unsigned a, b, c, d, e, f;
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) != 6)
        return -1;
    out[0] = (uint8_t)a;
    out[1] = (uint8_t)b;
    out[2] = (uint8_t)c;
    out[3] = (uint8_t)d;
    out[4] = (uint8_t)e;
    out[5] = (uint8_t)f;
    return 0;
}

/*
 * Parse "A.B.C.D" or "A.B.C.D/prefix" into network-byte-order uint32_t.
 * Sets *prefix_len (0-32).
 */
static int parse_ip_prefix(const char *str, uint32_t *ip, int *prefix_len)
{
    char tmp[48];
    strncpy(tmp, str, sizeof(tmp) - 1);
    char *slash = strchr(tmp, '/');
    *prefix_len = 32;
    if (slash)
    {
        *slash++ = '\0';
        *prefix_len = atoi(slash);
    }
    struct in_addr a;
    if (inet_pton(AF_INET, tmp, &a) != 1)
        return -1;
    *ip = a.s_addr; /* already network byte order */
    return 0;
}

/* ── Build a FLOW_MOD message from ovs_flow_t ────────────────────── */
/*
 * We support a subset of match strings that covers L2+L3 use cases:
 *   "ip,nw_dst=A.B.C.D/N"
 *   "dl_dst=aa:bb:cc:dd:ee:ff"
 *   "in_port=N,dl_type=0x0800"
 *
 * And action strings:
 *   "dec_ttl,mod_dl_dst:MAC,mod_dl_src:MAC,output:PORT"
 *   "output:PORT"
 *   "output:CONTROLLER"
 *   "meter:N,output:normal"
 */

static int build_flow_mod(const ovs_flow_t *flow, uint8_t command,
                          uint8_t *buf, int bufsz)
{
    memset(buf, 0, bufsz);
    int off = 0;

    /* ── ofp_flow_mod header (placeholder) ── */
    if (off + (int)sizeof(ofp_flow_mod_t) > bufsz)
        return -1;
    ofp_flow_mod_t *fm = (ofp_flow_mod_t *)buf;
    off += sizeof(ofp_flow_mod_t);
    fm->header.version = OFP13_VERSION;
    fm->header.type = OFPT_FLOW_MOD;
    fm->cookie = 0;
    fm->cookie_mask = 0;
    fm->table_id = 0;
    fm->command = command;
    fm->idle_timeout = htons(flow->idle_timeout);
    fm->hard_timeout = htons(flow->hard_timeout);
    fm->priority = htons(flow->priority);
    fm->buffer_id = htonl(OFP_NO_BUFFER);
    fm->out_port = htonl(OFPP_ANY);
    fm->out_group = htonl(0xffffffff);

    /* ── OXM match ── */
    int match_start = off;
    if (off + 4 > bufsz)
        return -1;
    ofp_match_t *match = (ofp_match_t *)(buf + off);
    match->type = htons(OFPMT_OXM);
    off += 4; /* header; length filled in later */

    /* Parse match string */
    char mstr[256];
    snprintf(mstr, sizeof(mstr), "%s", flow->match);

    /* ip / dl_type */
    if (strstr(mstr, "ip,") || strstr(mstr, ",ip") ||
        strcmp(mstr, "ip") == 0)
    {
        uint8_t eth_type[2] = {0x08, 0x00};
        oxm_put(buf, &off, bufsz, OXM_OF_ETH_TYPE, eth_type, 2);
    }
    else if (strstr(mstr, "dl_type=0x0800")) {
        uint8_t eth_type[2] = {0x08, 0x00};
        oxm_put(buf, &off, bufsz, OXM_OF_ETH_TYPE, eth_type, 2);
    } else if (strstr(mstr, "dl_type=0x0806")) {          /* ADD THIS */
        uint8_t eth_type[2] = {0x08, 0x06};
        oxm_put(buf, &off, bufsz, OXM_OF_ETH_TYPE, eth_type, 2);
    }

    /* in_port=N */
    char *p = strstr(mstr, "in_port=");
    if (p)
    {
        uint32_t port_no = (uint32_t)atoi(p + 8);
        uint32_t port_be = htonl(port_no);
        oxm_put(buf, &off, bufsz, OXM_OF_IN_PORT,
                (uint8_t *)&port_be, 4);
    }

    /* nw_dst=A.B.C.D or nw_dst=A.B.C.D/N */
    p = strstr(mstr, "nw_dst=");
    if (p)
    {
        uint32_t ip;
        int plen;
        if (parse_ip_prefix(p + 7, &ip, &plen) == 0)
        {
            if (plen == 32)
            {
                oxm_put(buf, &off, bufsz, OXM_OF_IPV4_DST,
                        (uint8_t *)&ip, 4);
            }
            else
            {
                /* masked — use OXM_OF_IPV4_DST with hasmask=1 */
                uint32_t mask = plen ? htonl(~0u << (32 - plen)) : 0;
                uint8_t val[8];
                memcpy(val, &ip, 4);
                memcpy(val + 4, &mask, 4);
                /* set hasmask bit in header */
                uint32_t hdr_m = htonl((OXM_OF_IPV4_DST & ~0xFF) | 0x100 | 8);
                if (off + 4 + 8 > bufsz)
                    return -1;
                memcpy(buf + off, &hdr_m, 4);
                off += 4;
                memcpy(buf + off, val, 8);
                off += 8;
            }
        }
    }

    /* dl_dst=MAC */
    p = strstr(mstr, "dl_dst=");
    if (p)
    {
        uint8_t mac[6];
        if (parse_mac(p + 7, mac) == 0)
            oxm_put(buf, &off, bufsz, OXM_OF_ETH_DST, mac, 6);
    }

    /* dl_src=MAC — used by POLICY_BLACKHOLE_MAC */
    p = strstr(mstr, "dl_src=");
    if (p)
    {
        uint8_t mac[6];
        if (parse_mac(p + 7, mac) == 0)
            oxm_put(buf, &off, bufsz, OXM_OF_ETH_SRC, mac, 6);
    }

    /* Finalise match length */
    int match_len = off - match_start;
    match->length = htons((uint16_t)match_len);

    /* Pad match to 8-byte boundary */
    oxm_pad(buf, &off);

    /* Parse action string here so meter block can reference it */
    char astr[256];
    snprintf(astr, sizeof(astr), "%s", flow->actions);

    /* ── Instruction: METER (if meter:N present in actions) ── */
    {
        char *mp = strstr(astr, "meter:");
        if (mp)
        {
            uint32_t meter_id = (uint32_t)atoi(mp + 6);
            if (off + (int)sizeof(ofp_instruction_meter_t) > bufsz)
                return -1;
            ofp_instruction_meter_t *mi =
                (ofp_instruction_meter_t *)(buf + off);
            mi->type = htons(OFPIT_METER);
            mi->len = htons(sizeof(ofp_instruction_meter_t));
            mi->meter_id = htonl(meter_id);
            off += sizeof(ofp_instruction_meter_t);
            LOG_D("OF", "Meter instruction: meter_id=%u", meter_id);
        }
    }

    /* ─────────────────────────────────────────────
     * DROP ACTION HANDLING
     * OpenFlow drop = NO instructions at all
     * ───────────────────────────────────────────── */
    if (strstr(astr, "drop") &&
        !strstr(astr, "output:") &&
        !strstr(astr, "dec_ttl") &&
        !strstr(astr, "mod_dl"))
    {
        LOG_I("OF", "Installing DROP flow (no actions)");

        /* No APPLY_ACTIONS instruction */
        fm->header.length = htons((uint16_t)off);

        return off;
    }

    /* ── Instruction: APPLY_ACTIONS ── */
    int inst_start = off;
    if (off + (int)sizeof(ofp_instruction_actions_t) > bufsz)
        return -1;
    ofp_instruction_actions_t *inst =
        (ofp_instruction_actions_t *)(buf + off);
    inst->type = htons(OFPIT_APPLY_ACTIONS);
    off += sizeof(ofp_instruction_actions_t);

    /* action string already parsed above (astr) */

    /* dec_ttl */
    if (strstr(astr, "dec_ttl"))
    {
        if (off + (int)sizeof(ofp_action_dec_ttl_t) > bufsz)
            return -1;
        ofp_action_dec_ttl_t *a = (ofp_action_dec_ttl_t *)(buf + off);
        a->type = htons(OFPAT_DEC_NW_TTL);
        a->len = htons(sizeof(*a));
        off += sizeof(*a);
    }

    /* mod_dl_dst:MAC */
    p = strstr(astr, "mod_dl_dst:");
    if (p)
    {
        uint8_t mac[6];
        if (parse_mac(p + 11, mac) == 0)
        {
            /* SET_FIELD with OXM_OF_ETH_DST */
            int sf_start = off;
            if (off + (int)sizeof(ofp_action_set_field_t) + 4 + 6 + 2 > bufsz)
                return -1;
            ofp_action_set_field_t *sf =
                (ofp_action_set_field_t *)(buf + off);
            sf->type = htons(OFPAT_SET_FIELD);
            off += sizeof(*sf);
            uint32_t oxm_hdr = htonl((OXM_OF_ETH_DST & ~0xFF) | 6);
            memcpy(buf + off, &oxm_hdr, 4);
            off += 4;
            memcpy(buf + off, mac, 6);
            off += 6;
            oxm_pad(buf, &off);
            sf->len = htons((uint16_t)(off - sf_start));
        }
    }

    /* mod_dl_src:MAC */
    p = strstr(astr, "mod_dl_src:");
    if (p)
    {
        uint8_t mac[6];
        if (parse_mac(p + 11, mac) == 0)
        {
            int sf_start = off;
            if (off + (int)sizeof(ofp_action_set_field_t) + 4 + 6 + 2 > bufsz)
                return -1;
            ofp_action_set_field_t *sf =
                (ofp_action_set_field_t *)(buf + off);
            sf->type = htons(OFPAT_SET_FIELD);
            off += sizeof(*sf);
            uint32_t oxm_hdr = htonl((OXM_OF_ETH_SRC & ~0xFF) | 6);
            memcpy(buf + off, &oxm_hdr, 4);
            off += 4;
            memcpy(buf + off, mac, 6);
            off += 6;
            oxm_pad(buf, &off);
            sf->len = htons((uint16_t)(off - sf_start));
        }
    }

    p = strstr(astr, "output:");
    if (p)
    {
        p += 7;
        uint32_t port_no;

        if (!strncmp(p, "normal", 6))
            port_no = OFPP_NORMAL;
        else if (!strncmp(p, "flood", 5))
            port_no = OFPP_FLOOD;
        else if (!strncmp(p, "CONTROLLER", 10))
            port_no = OFPP_CONTROLLER;
        else
        {
            int pnum = atoi(p);

            if (pnum <= 0)
            {
                LOG_W("OF", "Invalid output port %d in actions '%s', using NORMAL",
                      pnum, astr);
                port_no = OFPP_NORMAL;
            }
            else
            {
                port_no = (uint32_t)pnum;
            }
        }

        if (off + (int)sizeof(ofp_action_output_t) > bufsz)
            return -1;

        ofp_action_output_t *ao = (ofp_action_output_t *)(buf + off);
        ao->type = htons(OFPAT_OUTPUT);
        ao->len = htons(sizeof(*ao));
        ao->port = htonl(port_no);
        ao->max_len = htons(0xffff);
        off += sizeof(*ao);
    }

    /* Finalise instruction length */
    inst->len = htons((uint16_t)(off - inst_start));

    /* Finalise flow_mod total length */
    fm->header.length = htons((uint16_t)off);

    return off;
}

/*
 * of_reconnect() — close the dead fd, clear the connection slot,
 * then reconnect OpenFlow channel for the bridge.
 * Returns the new fd on success, -1 on failure.
 */
static int of_reconnect(const char *bridge)
{
    for (int i = 0; i < MAX_OF_BRIDGES; i++)
    {
        if (g_conns[i].connected &&
            strcmp(g_conns[i].bridge, bridge) == 0)
        {
            LOG_W("OF", "[%s] reconnecting OpenFlow fd=%d",
                  bridge, g_conns[i].fd);
            if (g_of_server[i])
            {
                a2a_server_del_fd(g_of_server[i], g_conns[i].fd);
            }
            close(g_conns[i].fd);
            g_conns[i].fd = -1;
            g_conns[i].connected = 0;
            break;
        }
    }
    int fd = ovs_of_connect(bridge);
    if (fd < 0)
    {
        LOG_E("OF", "[%s] reconnect failed", bridge);
        return -1;
    }
    /* Re-register with epoll if a server is available */
    for (int i = 0; i < MAX_OF_BRIDGES; i++)
    {
        if (g_conns[i].connected &&
            strcmp(g_conns[i].bridge, bridge) == 0 &&
            g_of_server[i])
        {
            a2a_server_add_fd(g_of_server[i], g_conns[i].fd);
            a2a_server_add_ext_fd(g_of_server[i],
                                  g_conns[i].fd,
                                  of_epoll_handler,
                                  NULL);
            break;
        }
    }
    return fd;
}

/* ── Public flow management API ──────────────────────────────────── */

int ovs_of_add_flow(const char *bridge, const ovs_flow_t *flow)
{
    int fd = ovs_of_connect(bridge);
    if (fd < 0)
    {
        LOG_E("OF", "[%s] not connected, cannot add flow", bridge);
        return -1;
    }

    uint8_t buf[1024];
    int len = build_flow_mod(flow, OFPFC_ADD, buf, sizeof(buf));
    if (len < 0)
    {
        LOG_E("OF", "[%s] build_flow_mod failed", bridge);
        return -1;
    }

    if (send(fd, buf, len, MSG_NOSIGNAL) < 0)
    {
        LOG_E("OF", "[%s] FLOW_MOD ADD send failed errno=%d", bridge, errno);
        if (errno == EPIPE || errno == ECONNRESET || errno == EBADF)
        {
            fd = of_reconnect(bridge);
            if (fd >= 0 && send(fd, buf, len, MSG_NOSIGNAL) == 0)
            {
                LOG_I("OF", "[%s] FLOW_MOD ADD succeeded after reconnect", bridge);
                return 0;
            }
        }
        return -1;
    }

    LOG_I("OF", "[%s] FLOW_MOD ADD priority=%u match=%s actions=%s",
          bridge, flow->priority, flow->match, flow->actions);
    return 0;
}

int ovs_of_del_flow(const char *bridge, const char *match)
{
    int fd = ovs_of_connect(bridge);
    if (fd < 0)
        return -1;

    ovs_flow_t flow = {0};
    strncpy(flow.match, match, sizeof(flow.match) - 1);
    flow.priority = 0; /* ignored for DELETE */

    uint8_t buf[512];
    int len = build_flow_mod(&flow, OFPFC_DELETE, buf, sizeof(buf));
    if (len < 0)
        return -1;

    if (send(fd, buf, len, MSG_NOSIGNAL) < 0)
    {
        LOG_E("OF", "[%s] FLOW_MOD DEL send failed errno=%d", bridge, errno);
        if (errno == EPIPE || errno == ECONNRESET || errno == EBADF)
        {
            fd = of_reconnect(bridge);
            if (fd >= 0 && send(fd, buf, len, MSG_NOSIGNAL) == 0)
            {
                LOG_I("OF", "[%s] FLOW_MOD DEL succeeded after reconnect", bridge);
                return 0;
            }
        }
        return -1;
    }

    LOG_I("OF", "[%s] FLOW_MOD DELETE match=%s", bridge, match);
    return 0;
}

int ovs_of_list_flows(const char *bridge, ovs_flow_t *out, int max)
{
    /* STATS_REQUEST for flow stats is complex; return in-memory table */
    (void)bridge;
    (void)out;
    (void)max;
    return 0;
}

int ovs_of_flush_mac(const char *bridge)
{
    /* Delete all flows at priority 10 (unicast forwarding tier) */
    ovs_flow_t flow = {0};
    strncpy(flow.match, "*", sizeof(flow.match) - 1);
    flow.priority = 10;
    return ovs_of_del_flow(bridge, "*");
}

/* ── PACKET_IN handler — real MAC learning ───────────────────────── */

/*
 * ovs_of_process_packet_in() is called by a2a_server_poll() when
 * the OpenFlow fd is readable.  It reads and processes PACKET_IN
 * messages, updating the in-memory MAC table and installing unicast
 * forwarding flows.
 */
static void mac_table_learn(const uint8_t *eth_src, uint32_t in_port,
                            const char *bridge)
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_src[0], eth_src[1], eth_src[2],
             eth_src[3], eth_src[4], eth_src[5]);

    if (eth_src[0] & 0x01)
        return;

    /* Skip packets arriving on OVS internal ports (OFPP_LOCAL, OFPP_ANY).
     * These are kernel-generated (OSPF, ARP for bridge IP, etc.) and must
     * not be forwarded or counted toward flood detection thresholds. */
    if (in_port == 0xFFFFFFFE || in_port == 0xFFFFFFFF)
    {
        LOG_D("OF", "[%s] skipping MAC learn on internal port %u", bridge, in_port);
        return;
    }

    uint64_t now = a2a_now_us();

    /* CHECK EXISTING */
    for (int i = 0; i < g_mac_count; i++)
    {
        if (strcmp(g_mac_table[i].mac, mac_str) == 0)
        {

            /* Only update if port changed */
            if (g_mac_table[i].in_port != in_port)
            {

                LOG_I("OF", "[%s] MAC moved: %s %u → %u",
                      bridge, mac_str,
                      g_mac_table[i].in_port, in_port);

                g_mac_table[i].in_port = in_port;

                /* reinstall flow ONLY on move */
                ovs_flow_t fwd = {0};
                fwd.priority = 10;
                fwd.idle_timeout = 300;

                snprintf(fwd.match, sizeof(fwd.match),
                         "dl_dst=%s", mac_str);
                snprintf(fwd.actions, sizeof(fwd.actions),
                         "output:%u", in_port);

                ovs_of_add_flow(bridge, &fwd);
            }

            g_mac_table[i].learned_at_us = now;
            return;
        }
    }

    /* NEW ENTRY ONLY */
    if (g_mac_count >= OF_MAC_TABLE_MAX)
        return;

    of_mac_entry_t *e = &g_mac_table[g_mac_count++];
    strncpy(e->mac, mac_str, sizeof(e->mac) - 1);
    e->in_port = in_port;
    e->learned_at_us = now;
    e->valid = 1;

    LOG_I("OF", "[%s] MAC learned: %s port=%u", bridge, mac_str, in_port);

    /* install flow ONLY ON FIRST LEARN */
    ovs_flow_t fwd = {0};
    fwd.priority = 10;
    fwd.idle_timeout = 300;

    snprintf(fwd.match, sizeof(fwd.match),
             "dl_dst=%s", mac_str);
    snprintf(fwd.actions, sizeof(fwd.actions),
             "output:%u", in_port);

    ovs_of_add_flow(bridge, &fwd);
}

static void of_send_packet_out_flood(int fd, uint32_t buffer_id,
                                     uint32_t in_port,
                                     const uint8_t *pkt_data, int pkt_len)
{
    /* If buffer_id is valid, use it (no need to resend packet data).
     * If OFP_NO_BUFFER, include packet data. */
    int data_len = (buffer_id == OFP_NO_BUFFER) ? pkt_len : 0;

    /* PACKET_OUT structure:
     *   ofp_header(8) + buffer_id(4) + in_port(4) + actions_len(2) + pad(6)
     *   + action (OUTPUT FLOOD, 16 bytes)
     *   + [packet data if no buffer]
     */
    int total = 8 + 4 + 4 + 2 + 6 + (int)sizeof(ofp_action_output_t) + data_len;
    if (total > 2048)
        return; /* safety */

    uint8_t buf[2048] = {0};
    int off = 0;

    ofp_header_t *hdr = (ofp_header_t *)buf;
    hdr->version = OFP13_VERSION;
    hdr->type = OFPT_PACKET_OUT;
    hdr->length = htons((uint16_t)total);
    hdr->xid = htonl(g_xid++);
    off += 8;

    uint32_t bid_be = htonl(buffer_id);
    memcpy(buf + off, &bid_be, 4);
    off += 4; /* buffer_id */

    uint32_t inp_be = htonl(in_port);
    memcpy(buf + off, &inp_be, 4);
    off += 4; /* in_port */

    uint16_t act_len = htons(sizeof(ofp_action_output_t));
    memcpy(buf + off, &act_len, 2);
    off += 2; /* actions_len */
    off += 6; /* pad */

    ofp_action_output_t *ao = (ofp_action_output_t *)(buf + off);
    ao->type = htons(OFPAT_OUTPUT);
    ao->len = htons(sizeof(*ao));
    ao->port = htonl(OFPP_FLOOD);
    ao->max_len = htons(0xffff);
    off += sizeof(*ao);

    if (data_len > 0)
    {
        memcpy(buf + off, pkt_data, data_len);
        off += data_len;
    }

    send(fd, buf, off, MSG_NOSIGNAL);
}

void ovs_of_process_packet_in(const char *bridge, int fd)
{
    uint8_t buf[2048];
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n <= 0)
        return;

    ofp_header_t *hdr = (ofp_header_t *)buf;
    if (hdr->version != OFP13_VERSION)
        return;
    if (hdr->type != OFPT_PACKET_IN)
        return;
    if (n < (ssize_t)sizeof(ofp_header_t))
        return;

    uint16_t total_len = ntohs(hdr->length);
    if (n < total_len)
        return;

    /* OF1.3 PACKET_IN fixed fields after header:
     *   buffer_id(4) + total_len(2) + reason(1) + table_id(1) + cookie(8) = 16 bytes */
    if (total_len < 24)
        return;

    uint32_t buffer_id;
    memcpy(&buffer_id, buf + 8, 4);
    buffer_id = ntohl(buffer_id);

    int match_off = 24;
    if (match_off + 4 > total_len)
        return;

    ofp_match_t *match = (ofp_match_t *)(buf + match_off);
    uint16_t mlen = ntohs(match->length);
    if (match_off + mlen > total_len)
        return;

    uint32_t in_port = OFPP_ANY;
    int oxm_off = match_off + 4;
    int oxm_end = match_off + (int)mlen;

    while (oxm_off + 4 <= oxm_end)
    {
        const uint8_t *oxm_bytes = buf + oxm_off;
        uint8_t vlen = oxm_bytes[3]; /* FIX B1 */
        uint16_t cls = ((uint16_t)oxm_bytes[0] << 8) | oxm_bytes[1];
        uint8_t field_byte = oxm_bytes[2];
        uint32_t field = ((uint32_t)cls << 16) |
                         ((uint32_t)(field_byte >> 1) << 9) |
                         ((uint32_t)(field_byte & 1) << 8);

        if (field == (OXM_OF_IN_PORT & ~0xFF) && vlen == 4)
        {
            uint32_t port_be;
            memcpy(&port_be, buf + oxm_off + 4, 4);
            in_port = ntohl(port_be);
        }
        oxm_off += 4 + vlen;
    }

    /* Packet data starts after match, padded to 8-byte boundary */
    int pkt_off = match_off + ((mlen + 7) & ~7);
    if (pkt_off + 14 > total_len)
        return;

    const uint8_t *pkt = buf + pkt_off;
    int pkt_len = total_len - pkt_off;

    /*  Flood the original frame immediately so ARP/unknown traffic
     * is not silently dropped at the controller. */
    if (in_port != OFPP_ANY)
    {
        of_send_packet_out_flood(fd, buffer_id, in_port,
                                 pkt, (buffer_id != OFP_NO_BUFFER) ? 0 : pkt_len);
    }

    /* Learn the source MAC */
    const uint8_t *eth_src = pkt + 6;
    mac_table_learn(eth_src, in_port, bridge);
}

/* Public accessor for ovs_interface.c */
int ovs_of_get_mac_table(ovs_mac_entry_t *out, int max)
{
    int count = 0;
    for (int i = 0; i < g_mac_count && count < max; i++)
    {
        if (!g_mac_table[i].valid)
            continue;
        if (g_mac_table[i].in_port == 0xFFFFFFFE ||
            g_mac_table[i].in_port == 0xFFFFFFFF)
            continue;
        strncpy(out[count].mac, g_mac_table[i].mac, 17);
        out[count].port = (int)g_mac_table[i].in_port;
        out[count].learned_at_us = g_mac_table[i].learned_at_us;
        count++;
    }
    return count;
}
