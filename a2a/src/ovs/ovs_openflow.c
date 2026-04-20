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
 *   - ECHO_REQUEST reply (controller liveness)
 *   - METER_MOD (ADD) for rate limiting
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

/* ── OpenFlow 1.3 wire constants ─────────────────────────────────── */

#define OFP13_VERSION 0x04
#define OFPT_HELLO 0
#define OFPT_ECHO_REQUEST 2
#define OFPT_ECHO_REPLY 3
#define OFPT_FEATURES_REQUEST 5
#define OFPT_FEATURES_REPLY 6
#define OFPT_SET_CONFIG 9
#define OFPT_PACKET_IN 10
#define OFPT_FLOW_MOD 14
#define OFPT_METER_MOD 29
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
#define OFPIT_METER 6

/* OXM field headers (class=OPENFLOW_BASIC=0x8000) */
#define OXM_OF_IN_PORT 0x80000000
#define OXM_OF_ETH_DST 0x80000606
#define OXM_OF_ETH_SRC 0x80000806
#define OXM_OF_ETH_TYPE 0x80000a02
#define OXM_OF_IPV4_DST 0x80001804
#define OXM_OF_IPV4_DST_W 0x80001908
#define OXM_OF_IP_PROTO 0x80001601

#define OFPP_CONTROLLER 0xfffffffd
#define OFPP_FLOOD 0xfffffffb
#define OFPP_NORMAL 0xfffffffa
#define OFPP_ANY 0xffffffff

#define OFP_NO_BUFFER 0xffffffff

/* Meter constants */
#define OFPMC_ADD 0
#define OFPMF_KBPS 1
#define OFPMBT_DROP 1

#pragma pack(push, 1)

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t xid;
} ofp_header_t;

typedef struct {
    ofp_header_t header;
} ofp_hello_t;

typedef struct {
    uint16_t type;
    uint16_t length;
} ofp_match_t;

typedef struct {
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
} ofp_flow_mod_t;

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t pad[4];
} ofp_instruction_actions_t;

typedef struct {
    uint16_t type;
    uint16_t len;
    uint32_t port;
    uint16_t max_len;
    uint8_t pad[6];
} ofp_action_output_t;

typedef struct {
    uint16_t type;
    uint16_t len;
} ofp_action_set_field_t;

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t pad[4];
} ofp_action_dec_ttl_t;

typedef struct {
    uint16_t type;
    uint16_t len;
    uint32_t meter_id;
} ofp_instruction_meter_t;

#pragma pack(pop)

/* ── State ───────────────────────────────────────────────────────── */

#define MAX_OF_BRIDGES 8

typedef struct {
    char bridge[64];
    int fd;
    int connected;
} of_conn_t;

static of_conn_t g_conns[MAX_OF_BRIDGES];
static uint32_t g_xid = 1;

static a2a_server_t *g_of_server[MAX_OF_BRIDGES];

#define OF_MAC_TABLE_MAX 1024

typedef struct {
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

static int of_do_hello(int fd)
{
    ofp_hello_t hello = {0};
    hello.header.version = OFP13_VERSION;
    hello.header.type = OFPT_HELLO;
    hello.header.length = htons(sizeof(hello));
    hello.header.xid = htonl(g_xid++);

    if (send(fd, &hello, sizeof(hello), MSG_NOSIGNAL) < 0) {
        LOG_E("OF", "HELLO send failed errno=%d", errno);
        return -1;
    }

    ofp_hello_t peer_hello;
    ssize_t n = recv(fd, &peer_hello, sizeof(peer_hello), 0);
    if (n < (ssize_t)sizeof(ofp_header_t)) {
        LOG_E("OF", "HELLO recv failed n=%zd", n);
        return -1;
    }
    if (peer_hello.header.version < OFP13_VERSION) {
        LOG_W("OF", "Peer OF version 0x%02x < 0x%02x",
              peer_hello.header.version, OFP13_VERSION);
    }
    LOG_I("OF", "HELLO complete, peer version=0x%02x",
          peer_hello.header.version);
    return 0;
}

static int of_set_config(int fd)
{
    struct {
        ofp_header_t header;
        uint16_t flags;
        uint16_t miss_send_len;
    } __attribute__((packed)) cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.header.version = OFP13_VERSION;
    cfg.header.type = OFPT_SET_CONFIG;
    cfg.header.length = htons(sizeof(cfg));
    cfg.header.xid = htonl(g_xid++);
    cfg.flags = htons(0);
    cfg.miss_send_len = htons(65535);

    if (send(fd, &cfg, sizeof(cfg), MSG_NOSIGNAL) < 0) {
        LOG_E("OF", "SET_CONFIG failed errno=%d", errno);
        return -1;
    }
    LOG_I("OF", "SET_CONFIG sent (miss_send_len=65535)");
    return 0;
}

static int of_install_table_miss(int fd, const char *bridge)
{
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    int off = 0;

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
    fm->priority = 0;
    fm->buffer_id = htonl(OFP_NO_BUFFER);
    fm->out_port = htonl(OFPP_ANY);
    fm->out_group = htonl(0xffffffff);
    fm->flags = 0;

    ofp_match_t *match = (ofp_match_t *)(buf + off);
    match->type = htons(OFPMT_OXM);
    match->length = htons(4);
    off += 4;
    off += 4; /* 8-byte pad */

    ofp_instruction_actions_t *inst =
        (ofp_instruction_actions_t *)(buf + off);
    int inst_off = off;
    off += sizeof(ofp_instruction_actions_t);

    ofp_action_output_t *act_out = (ofp_action_output_t *)(buf + off);
    act_out->type = htons(OFPAT_OUTPUT);
    act_out->len = htons(sizeof(ofp_action_output_t));
    act_out->port = htonl(OFPP_CONTROLLER);
    act_out->max_len = htons(0xffff);
    off += sizeof(ofp_action_output_t);

    inst->type = htons(OFPIT_APPLY_ACTIONS);
    inst->len = htons(off - inst_off);
    fm->header.length = htons(off);

    if (send(fd, buf, off, MSG_NOSIGNAL) < 0) {
        LOG_E("OF", "[%s] table-miss FLOW_MOD failed errno=%d", bridge, errno);
        return -1;
    }
    LOG_I("OF", "[%s] table-miss entry installed (PACKET_IN controller mode)",
          bridge);
    return 0;
}

static void of_epoll_handler(int fd, void *ud)
{
    (void)ud;
    const char *bridge = NULL;
    for (int i = 0; i < MAX_OF_BRIDGES; i++) {
        if (g_conns[i].connected && g_conns[i].fd == fd) {
            bridge = g_conns[i].bridge;
            break;
        }
    }
    if (!bridge)
        return;
    ovs_of_process_packet_in(bridge, fd);
}

int ovs_of_connect(const char *bridge)
{
    of_conn_t *c = of_get_conn(bridge);
    if (c)
        return c->fd;

    c = of_alloc_conn();
    if (!c) {
        LOG_E("OF", "Connection table full");
        return -1;
    }

    char path[256];
    snprintf(path, sizeof(path),
             "/var/run/openvswitch/%s.mgmt", bridge);

    char path2[256];
    snprintf(path2, sizeof(path2),
             "/var/run/openvswitch/%s.snoop", bridge);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_E("OF", "socket() failed errno=%d", errno);
        return -1;
    }

    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_W("OF", "connect %s failed errno=%d — checking if vswitchd is running",
              path, errno);
        /* Check if the socket file exists at all */
        struct stat st;
        if (stat(path, &st) != 0) {
            LOG_E("OF", "Socket %s does not exist — is ovs-vswitchd running?", path);
        }
        close(fd);
        return -1;
    }

    if (of_do_hello(fd) < 0) {
        close(fd);
        return -1;
    }

    if (of_set_config(fd) < 0) {
        close(fd);
        return -1;
    }

    tv.tv_sec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Store connection BEFORE installing flows so of_get_conn works
     * inside ovs_of_add_flow calls below (avoids recursive reconnects) */
    snprintf(c->bridge, sizeof(c->bridge), "%s", bridge);
    c->fd = fd;
    c->connected = 1;

    /* Install table-miss entry */
    of_install_table_miss(fd, bridge);

    /* Install ARP flood flow (priority=1) so ARP works without waiting
     * for controller PACKET_OUT round-trip */
    {
        ovs_flow_t arp_flow = {0};
        arp_flow.priority     = 1;
        arp_flow.idle_timeout = 0;
        arp_flow.hard_timeout = 0;
        snprintf(arp_flow.match,   sizeof(arp_flow.match),
                 "dl_type=0x0806");
        snprintf(arp_flow.actions, sizeof(arp_flow.actions),
                 "output:flood");
        ovs_of_add_flow(bridge, &arp_flow);
        LOG_I("OF", "[%s] ARP flood flow installed", bridge);
    }
    
    LOG_I("OF", "[%s] OpenFlow channel open fd=%d", bridge, fd);
    return fd;
}

void ovs_of_register_epoll(a2a_server_t *server)
{
    if (!server)
        return;
    for (int i = 0; i < MAX_OF_BRIDGES; i++) {
        if (!g_conns[i].connected)
            continue;
        if (a2a_server_add_fd(server, g_conns[i].fd) == 0) {
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
    for (int i = 0; i < MAX_OF_BRIDGES; i++) {
        if (g_conns[i].connected && g_of_server[i] == server) {
            a2a_server_del_fd(server, g_conns[i].fd);
            g_of_server[i] = NULL;
        }
    }
}

/* ── OXM TLV builder helpers ─────────────────────────────────────── */

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

static void oxm_pad(uint8_t *buf, int *off)
{
    int pad = (8 - (*off % 8)) % 8;
    if (pad) {
        memset(buf + *off, 0, pad);
        *off += pad;
    }
}

static int parse_mac(const char *str, uint8_t *out)
{
    unsigned a, b, c, d, e, f;
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) != 6)
        return -1;
    out[0]=(uint8_t)a; out[1]=(uint8_t)b; out[2]=(uint8_t)c;
    out[3]=(uint8_t)d; out[4]=(uint8_t)e; out[5]=(uint8_t)f;
    return 0;
}

static int parse_ip_prefix(const char *str, uint32_t *ip, int *prefix_len)
{
    char tmp[48];
    strncpy(tmp, str, sizeof(tmp) - 1);
    char *slash = strchr(tmp, '/');
    *prefix_len = 32;
    if (slash) {
        *slash++ = '\0';
        *prefix_len = atoi(slash);
    }
    struct in_addr a;
    if (inet_pton(AF_INET, tmp, &a) != 1)
        return -1;
    *ip = a.s_addr;
    return 0;
}

static int build_flow_mod(const ovs_flow_t *flow, uint8_t command,
                          uint8_t *buf, int bufsz)
{
    memset(buf, 0, bufsz);
    int off = 0;

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

    int match_start = off;
    if (off + 4 > bufsz)
        return -1;
    ofp_match_t *match = (ofp_match_t *)(buf + off);
    match->type = htons(OFPMT_OXM);
    off += 4;

    char mstr[256];
    snprintf(mstr, sizeof(mstr), "%s", flow->match);

    if (strstr(mstr, "ip,") || strstr(mstr, ",ip") ||
        strcmp(mstr, "ip") == 0) {
        uint8_t eth_type[2] = {0x08, 0x00};
        oxm_put(buf, &off, bufsz, OXM_OF_ETH_TYPE, eth_type, 2);
    } else if (strstr(mstr, "dl_type=0x0800")) {
        uint8_t eth_type[2] = {0x08, 0x00};
        oxm_put(buf, &off, bufsz, OXM_OF_ETH_TYPE, eth_type, 2);
    } else if (strstr(mstr, "dl_type=0x0806")) {
        uint8_t eth_type[2] = {0x08, 0x06};
        oxm_put(buf, &off, bufsz, OXM_OF_ETH_TYPE, eth_type, 2);
    }

    char *p = strstr(mstr, "in_port=");
    if (p) {
        uint32_t port_no = (uint32_t)atoi(p + 8);
        uint32_t port_be = htonl(port_no);
        oxm_put(buf, &off, bufsz, OXM_OF_IN_PORT,
                (uint8_t *)&port_be, 4);
    }

    p = strstr(mstr, "nw_dst=");
    if (p) {
        uint32_t ip;
        int plen;
        if (parse_ip_prefix(p + 7, &ip, &plen) == 0) {
            if (plen == 32) {
                oxm_put(buf, &off, bufsz, OXM_OF_IPV4_DST,
                        (uint8_t *)&ip, 4);
            } else {
                uint32_t mask = plen ? htonl(~0u << (32 - plen)) : 0;
                uint8_t val[8];
                memcpy(val, &ip, 4);
                memcpy(val + 4, &mask, 4);
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

    p = strstr(mstr, "dl_dst=");
    if (p) {
        uint8_t mac[6];
        if (parse_mac(p + 7, mac) == 0)
            oxm_put(buf, &off, bufsz, OXM_OF_ETH_DST, mac, 6);
    }

    p = strstr(mstr, "dl_src=");
    if (p) {
        uint8_t mac[6];
        if (parse_mac(p + 7, mac) == 0)
            oxm_put(buf, &off, bufsz, OXM_OF_ETH_SRC, mac, 6);
    }

    int match_len = off - match_start;
    match->length = htons((uint16_t)match_len);
    oxm_pad(buf, &off);

    char astr[256];
    snprintf(astr, sizeof(astr), "%s", flow->actions);

    /* Meter instruction (if meter:N in actions) */
    {
        char *mp = strstr(astr, "meter:");
        if (mp) {
            uint32_t meter_id = (uint32_t)atoi(mp + 6);
            if (off + (int)sizeof(ofp_instruction_meter_t) > bufsz)
                return -1;
            ofp_instruction_meter_t *mi =
                (ofp_instruction_meter_t *)(buf + off);
            mi->type = htons(OFPIT_METER);
            mi->len = htons(sizeof(ofp_instruction_meter_t));
            mi->meter_id = htonl(meter_id);
            off += sizeof(ofp_instruction_meter_t);
        }
    }

    /* DROP = no instructions */
    if (strstr(astr, "drop") &&
        !strstr(astr, "output:") &&
        !strstr(astr, "dec_ttl") &&
        !strstr(astr, "mod_dl")) {
        LOG_I("OF", "Installing DROP flow (no actions)");
        fm->header.length = htons((uint16_t)off);
        return off;
    }

    int inst_start = off;
    if (off + (int)sizeof(ofp_instruction_actions_t) > bufsz)
        return -1;
    ofp_instruction_actions_t *inst =
        (ofp_instruction_actions_t *)(buf + off);
    inst->type = htons(OFPIT_APPLY_ACTIONS);
    off += sizeof(ofp_instruction_actions_t);

    if (strstr(astr, "dec_ttl")) {
        if (off + (int)sizeof(ofp_action_dec_ttl_t) > bufsz)
            return -1;
        ofp_action_dec_ttl_t *a = (ofp_action_dec_ttl_t *)(buf + off);
        a->type = htons(OFPAT_DEC_NW_TTL);
        a->len = htons(sizeof(*a));
        off += sizeof(*a);
    }

    p = strstr(astr, "mod_dl_dst:");
    if (p) {
        uint8_t mac[6];
        if (parse_mac(p + 11, mac) == 0) {
            int sf_start = off;
            if (off + (int)sizeof(ofp_action_set_field_t) + 4 + 6 + 2 > bufsz)
                return -1;
            ofp_action_set_field_t *sf =
                (ofp_action_set_field_t *)(buf + off);
            sf->type = htons(OFPAT_SET_FIELD);
            off += sizeof(*sf);
            uint32_t oxm_hdr = htonl((OXM_OF_ETH_DST & ~0xFF) | 6);
            memcpy(buf + off, &oxm_hdr, 4); off += 4;
            memcpy(buf + off, mac, 6); off += 6;
            oxm_pad(buf, &off);
            sf->len = htons((uint16_t)(off - sf_start));
        }
    }

    p = strstr(astr, "mod_dl_src:");
    if (p) {
        uint8_t mac[6];
        if (parse_mac(p + 11, mac) == 0) {
            int sf_start = off;
            if (off + (int)sizeof(ofp_action_set_field_t) + 4 + 6 + 2 > bufsz)
                return -1;
            ofp_action_set_field_t *sf =
                (ofp_action_set_field_t *)(buf + off);
            sf->type = htons(OFPAT_SET_FIELD);
            off += sizeof(*sf);
            uint32_t oxm_hdr = htonl((OXM_OF_ETH_SRC & ~0xFF) | 6);
            memcpy(buf + off, &oxm_hdr, 4); off += 4;
            memcpy(buf + off, mac, 6); off += 6;
            oxm_pad(buf, &off);
            sf->len = htons((uint16_t)(off - sf_start));
        }
    }

    p = strstr(astr, "output:");
    if (p) {
        p += 7;
        uint32_t port_no;
        if (!strncmp(p, "normal", 6))
            port_no = OFPP_NORMAL;
        else if (!strncmp(p, "flood", 5))
            port_no = OFPP_FLOOD;
        else if (!strncmp(p, "CONTROLLER", 10))
            port_no = OFPP_CONTROLLER;
        else {
            int pnum = atoi(p);
            if (pnum <= 0) {
                LOG_W("OF", "Invalid port %d in '%s', using NORMAL", pnum, astr);
                port_no = OFPP_NORMAL;
            } else {
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

    inst->len = htons((uint16_t)(off - inst_start));
    fm->header.length = htons((uint16_t)off);
    return off;
}

static int of_reconnect(const char *bridge)
{
    for (int i = 0; i < MAX_OF_BRIDGES; i++) {
        if (g_conns[i].connected &&
            strcmp(g_conns[i].bridge, bridge) == 0) {
            LOG_W("OF", "[%s] reconnecting OpenFlow fd=%d",
                  bridge, g_conns[i].fd);
            if (g_of_server[i])
                a2a_server_del_fd(g_of_server[i], g_conns[i].fd);
            close(g_conns[i].fd);
            g_conns[i].fd = -1;
            g_conns[i].connected = 0;
            break;
        }
    }
    int fd = ovs_of_connect(bridge);
    if (fd < 0) {
        LOG_E("OF", "[%s] reconnect failed", bridge);
        return -1;
    }
    for (int i = 0; i < MAX_OF_BRIDGES; i++) {
        if (g_conns[i].connected &&
            strcmp(g_conns[i].bridge, bridge) == 0 &&
            g_of_server[i]) {
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

/* ── Meter management ────────────────────────────────────────────── */

/*
 * ovs_of_add_meter — Install an OpenFlow 1.3 METER_MOD ADD.
 * Creates a DROP meter that discards packets exceeding rate_kbps.
 * Called before installing a "meter:N,output:normal" flow.
 *
 * Wire format:
 *   ofp_header(8) + command(2) + flags(2) + meter_id(4)
 *   + band: type(2)+len(2)+rate(4)+burst(4)+pad(4) = 16 bytes
 */
int ovs_of_add_meter(const char *bridge, uint32_t meter_id,
                     uint32_t rate_kbps)
{
    int fd = ovs_of_connect(bridge);
    if (fd < 0)
        return -1;

    uint8_t buf[64] = {0};
    int off = 0;

    buf[0] = OFP13_VERSION;
    buf[1] = OFPT_METER_MOD;
    /* length at bytes 2-3, filled below */
    uint32_t xid = htonl(g_xid++);
    memcpy(buf + 4, &xid, 4);
    off = 8;

    uint16_t cmd   = htons(OFPMC_ADD);
    uint16_t flags = htons(OFPMF_KBPS);
    memcpy(buf + off, &cmd,   2); off += 2;
    memcpy(buf + off, &flags, 2); off += 2;
    uint32_t mid = htonl(meter_id);
    memcpy(buf + off, &mid, 4); off += 4;

    /* Band: DROP */
    uint16_t btype  = htons(OFPMBT_DROP);
    uint16_t blen   = htons(16);
    uint32_t brate  = htonl(rate_kbps);
    uint32_t bburst = htonl(rate_kbps / 10 < 1 ? 1 : rate_kbps / 10);
    memcpy(buf + off, &btype,  2); off += 2;
    memcpy(buf + off, &blen,   2); off += 2;
    memcpy(buf + off, &brate,  4); off += 4;
    memcpy(buf + off, &bburst, 4); off += 4;
    off += 4; /* pad to 16-byte band */

    uint16_t total = htons((uint16_t)off);
    memcpy(buf + 2, &total, 2);

    if (send(fd, buf, off, MSG_NOSIGNAL) < 0) {
        LOG_E("OF", "[%s] METER_MOD ADD failed errno=%d", bridge, errno);
        return -1;
    }
    LOG_I("OF", "[%s] Meter %u installed rate=%u kbps",
          bridge, meter_id, rate_kbps);
    return 0;
}

/* ── Public flow management API ──────────────────────────────────── */

int ovs_of_add_flow(const char *bridge, const ovs_flow_t *flow)
{
    int fd = ovs_of_connect(bridge);
    if (fd < 0) {
        LOG_E("OF", "[%s] not connected, cannot add flow", bridge);
        return -1;
    }

    uint8_t buf[1024];
    int len = build_flow_mod(flow, OFPFC_ADD, buf, sizeof(buf));
    if (len < 0) {
        LOG_E("OF", "[%s] build_flow_mod failed", bridge);
        return -1;
    }

    if (send(fd, buf, len, MSG_NOSIGNAL) < 0) {
        LOG_E("OF", "[%s] FLOW_MOD ADD send failed errno=%d", bridge, errno);
        if (errno == EPIPE || errno == ECONNRESET || errno == EBADF) {
            fd = of_reconnect(bridge);
            if (fd >= 0 && send(fd, buf, len, MSG_NOSIGNAL) == 0) {
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
    flow.priority = 0;

    uint8_t buf[512];
    int len = build_flow_mod(&flow, OFPFC_DELETE, buf, sizeof(buf));
    if (len < 0)
        return -1;

    if (send(fd, buf, len, MSG_NOSIGNAL) < 0) {
        LOG_E("OF", "[%s] FLOW_MOD DEL send failed errno=%d", bridge, errno);
        if (errno == EPIPE || errno == ECONNRESET || errno == EBADF) {
            fd = of_reconnect(bridge);
            if (fd >= 0 && send(fd, buf, len, MSG_NOSIGNAL) == 0)
                return 0;
        }
        return -1;
    }
    LOG_I("OF", "[%s] FLOW_MOD DELETE match=%s", bridge, match);
    return 0;
}

int ovs_of_list_flows(const char *bridge, ovs_flow_t *out, int max)
{
    (void)bridge; (void)out; (void)max;
    return 0;
}

int ovs_of_flush_mac(const char *bridge)
{
    return ovs_of_del_flow(bridge, "*");
}

/* ── PACKET_IN handler — real MAC learning ───────────────────────── */

static void mac_table_learn(const uint8_t *eth_src, uint32_t in_port,
                            const char *bridge)
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_src[0], eth_src[1], eth_src[2],
             eth_src[3], eth_src[4], eth_src[5]);

    if (eth_src[0] & 0x01)
        return; /* skip multicast/broadcast source */

    /* Skip OVS internal port MACs */
    if (in_port == 0xFFFFFFFE || in_port == 0xFFFFFFFF) {
        LOG_D("OF", "[%s] skipping MAC learn on internal port %u",
              bridge, in_port);
        return;
    }

    uint64_t now = a2a_now_us();

    for (int i = 0; i < g_mac_count; i++) {
        if (strcmp(g_mac_table[i].mac, mac_str) == 0) {
            if (g_mac_table[i].in_port != in_port) {
                LOG_I("OF", "[%s] MAC moved: %s %u → %u",
                      bridge, mac_str, g_mac_table[i].in_port, in_port);
                g_mac_table[i].in_port = in_port;

                ovs_flow_t fwd = {0};
                fwd.priority = 10;
                fwd.idle_timeout = 300;
                snprintf(fwd.match,   sizeof(fwd.match),
                         "dl_dst=%s", mac_str);
                snprintf(fwd.actions, sizeof(fwd.actions),
                         "output:%u", in_port);
                ovs_of_add_flow(bridge, &fwd);
            }
            g_mac_table[i].learned_at_us = now;
            return;
        }
    }

    if (g_mac_count >= OF_MAC_TABLE_MAX)
        return;

    of_mac_entry_t *e = &g_mac_table[g_mac_count++];
    strncpy(e->mac, mac_str, sizeof(e->mac) - 1);
    e->in_port = in_port;
    e->learned_at_us = now;
    e->valid = 1;

    LOG_I("OF", "[%s] MAC learned: %s port=%u", bridge, mac_str, in_port);

    ovs_flow_t fwd = {0};
    fwd.priority = 10;
    fwd.idle_timeout = 300;
    snprintf(fwd.match,   sizeof(fwd.match),   "dl_dst=%s", mac_str);
    snprintf(fwd.actions, sizeof(fwd.actions), "output:%u", in_port);
    ovs_of_add_flow(bridge, &fwd);
}

/*
 * PACKET_OUT flood uses dynamically allocated buffer to avoid
 * the 2048-byte stack overflow when pkt_len is large.
 */
static void of_send_packet_out_flood(int fd, uint32_t buffer_id,
                                     uint32_t in_port,
                                     const uint8_t *pkt_data, int pkt_len)
{
    (void)buffer_id;
    int data_len = pkt_len;
    buffer_id = OFP_NO_BUFFER;
    
    int base_total = 8 + 4 + 4 + 2 + 6 + (int)sizeof(ofp_action_output_t) + data_len;
    
    /* OpenFlow 1.3 messages MUST be padded to an 8-byte boundary */
    int pad_len = (8 - (base_total % 8)) % 8;
    int total = base_total + pad_len;

    if (total > 9216) return;

    uint8_t *buf = calloc(1, total);
    if (!buf) return;

    int off = 0;
    ofp_header_t *hdr = (ofp_header_t *)buf;
    hdr->version = OFP13_VERSION;
    hdr->type = OFPT_PACKET_OUT;
    hdr->length = htons((uint16_t)total);
    hdr->xid = htonl(g_xid++);
    off += 8;

    uint32_t bid_be = htonl(buffer_id);
    memcpy(buf + off, &bid_be, 4); off += 4;

    uint32_t inp_be = htonl(in_port);
    memcpy(buf + off, &inp_be, 4); off += 4;

    uint16_t act_len = htons(sizeof(ofp_action_output_t));
    memcpy(buf + off, &act_len, 2); off += 2;
    off += 6; /* pad */

    ofp_action_output_t *ao = (ofp_action_output_t *)(buf + off);
    ao->type = htons(OFPAT_OUTPUT);
    ao->len = htons(sizeof(*ao));
    ao->port = htonl(OFPP_FLOOD);
    ao->max_len = htons(0xffff);
    off += sizeof(*ao);

    if (data_len > 0) {
        memcpy(buf + off, pkt_data, data_len);
        off += data_len;
    }
    
    off += pad_len;

    send(fd, buf, off, MSG_NOSIGNAL);
    free(buf);
}
/*
 * ovs_of_process_packet_in — drain all readable OF messages from fd.
 * Handles: ECHO_REQUEST (reply immediately), PACKET_IN (MAC learn + flood).
 *
 * ECHO_REQUEST is now handled so OVS doesn't consider the
 * controller dead and sweep its flows.
 */
void ovs_of_process_packet_in(const char *bridge, int fd)
{
    for (;;) {
        uint8_t hdr_buf[8];
        ssize_t n = recv(fd, hdr_buf, 8, MSG_DONTWAIT | MSG_PEEK);
        if (n < 8) return;

        ofp_header_t *hdr = (ofp_header_t *)hdr_buf;
        if (hdr->version != OFP13_VERSION) {
            recv(fd, hdr_buf, 8, MSG_DONTWAIT);
            return;
        }

        uint16_t total_len = ntohs(hdr->length);
        if (total_len < 8) return;

        uint8_t *buf = malloc(total_len);
        if (!buf) return;

        n = recv(fd, buf, total_len, MSG_DONTWAIT);
        if (n < total_len) { free(buf); return; }

        ofp_header_t *msg_hdr = (ofp_header_t *)buf;

        if (msg_hdr->type == OFPT_ECHO_REQUEST) {
            ofp_header_t reply;
            reply.version = OFP13_VERSION;
            reply.type    = OFPT_ECHO_REPLY;
            reply.length  = htons(8);
            reply.xid     = msg_hdr->xid;
            send(fd, &reply, sizeof(reply), MSG_NOSIGNAL);
            free(buf);
            continue;
        }

        if (msg_hdr->type != OFPT_PACKET_IN || total_len < 24) {
            free(buf); continue;
        }

        int match_off = 24;
        if (match_off + 4 > total_len) { free(buf); continue; }

        ofp_match_t *match = (ofp_match_t *)(buf + match_off);
        uint16_t mlen = ntohs(match->length);
        if (match_off + mlen > total_len) { free(buf); continue; }

        uint32_t in_port = OFPP_ANY;
        int oxm_off = match_off + 4;
        int oxm_end = match_off + (int)mlen;

        while (oxm_off + 4 <= oxm_end) {
            const uint8_t *oxm_bytes = buf + oxm_off;
            uint8_t vlen = oxm_bytes[3];
            uint16_t cls = ((uint16_t)oxm_bytes[0] << 8) | oxm_bytes[1];
            uint8_t field_byte = oxm_bytes[2];
            uint32_t field = ((uint32_t)cls << 16) |
                             ((uint32_t)(field_byte >> 1) << 9) |
                             ((uint32_t)(field_byte & 1) << 8);

            if (field == (OXM_OF_IN_PORT & ~0xFF) && vlen == 4) {
                uint32_t port_be;
                memcpy(&port_be, buf + oxm_off + 4, 4);
                in_port = ntohl(port_be);
            }
            oxm_off += 4 + vlen;
        }

        /* STRICT OF1.3 COMPLIANCE: Match padded to 8 bytes, exactly 2 bytes padding */
        int pkt_off = match_off + ((mlen + 7) & ~7) + 2;

        if (pkt_off >= total_len) {
            free(buf); continue;
        }

        uint16_t frame_len;
        memcpy(&frame_len, buf + 12, 2);
        frame_len = ntohs(frame_len);

        const uint8_t *pkt = buf + pkt_off;
        int pkt_len = frame_len; 

        if (pkt_off + pkt_len > total_len) {
            pkt_len = total_len - pkt_off;
        }

        if (in_port != OFPP_ANY) {
            of_send_packet_out_flood(fd, OFP_NO_BUFFER, in_port, pkt, pkt_len);
        }

        if (pkt_len >= 14) {
            const uint8_t *eth_src = pkt + 6;
            mac_table_learn(eth_src, in_port, bridge);
        }

        free(buf);
    }
}
int ovs_of_get_mac_table(ovs_mac_entry_t *out, int max)
{
    int count = 0;
    for (int i = 0; i < g_mac_count && count < max; i++) {
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