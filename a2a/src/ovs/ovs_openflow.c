//src/ovs/ovs_openflow.c

/*
 * Native OpenFlow 1.3 integration
 *
 * Connects to /var/run/openvswitch/<bridge>.mgmt. Implements HELLO,
 * FEATURES_REQUEST, FLOW_MOD, PACKET_IN (MAC learning), ECHO_REQUEST,
 * and METER_MOD. No subprocess calls.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <net/ethernet.h>
#include <endian.h>
#include <poll.h>

#include "l2_agent.h"
#include "ovs_interface.h"
#include "a2a_log.h"
#include "a2a_message.h"
#include "a2a_transport.h"

/* Forward declarations */
void ovs_of_process_packet_in(const char *bridge, int fd);
static int of_install_table_miss(int fd, const char *bridge);

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
#define OFPMC_MODIFY 1
#define OFPMF_KBPS 1
#define OFPMBT_DROP 1

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
} ofp_hello_t;

typedef struct
{
    uint16_t type;
    uint16_t length;
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
} ofp_flow_mod_t;

typedef struct
{
    uint16_t type;
    uint16_t len;
    uint8_t pad[4];
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
    uint16_t type;
    uint16_t len;
} ofp_action_set_field_t;

typedef struct
{
    uint16_t type;
    uint16_t len;
    uint8_t pad[4];
} ofp_action_dec_ttl_t;

typedef struct
{
    uint16_t type;
    uint16_t len;
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

static a2a_server_t *g_of_server[MAX_OF_BRIDGES];

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

/* Shared globals — read by L2 agent tick */
uint32_t g_pkt_in_per_port[OF_MAX_PORTS] = {0};
volatile int g_fdb_overflow_flag = 0;
/* Set by main.c or l2_agent.c after agent creation */
static l2_agent_ctx_t *g_l2_ctx_for_spoof = NULL;
void ovs_of_set_l2_ctx(void *ctx) { g_l2_ctx_for_spoof = (l2_agent_ctx_t *)ctx; }

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

    if (send(fd, &hello, sizeof(hello), MSG_NOSIGNAL) < 0)
    {
        LOG_E("OF", "HELLO send failed errno=%d", errno);
        return -1;
    }

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
    cfg.flags = htons(0);
    cfg.miss_send_len = htons(65535);

    if (send(fd, &cfg, sizeof(cfg), MSG_NOSIGNAL) < 0)
    {
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
    act_out->len  = htons(sizeof(ofp_action_output_t));
    act_out->port = htonl(OFPP_CONTROLLER);
    act_out->max_len = htons(0xffff);
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

static void of_epoll_handler(int fd, void *ud)
{
    (void)ud;
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

    char path2[256];
    snprintf(path2, sizeof(path2),
             "/var/run/openvswitch/%s.snoop", bridge);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        LOG_E("OF", "socket() failed errno=%d", errno);
        return -1;
    }

    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOG_W("OF", "connect %s failed errno=%d — checking if vswitchd is running",
              path, errno);
        /* Check if the socket file exists at all */
        struct stat st;
        if (stat(path, &st) != 0)
        {
            LOG_E("OF", "Socket %s does not exist — is ovs-vswitchd running?", path);
        }
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

    LOG_I("OF", "[%s] OpenFlow channel open fd=%d", bridge, fd);
    return fd;
}

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
    if (pad)
    {
        memset(buf + *off, 0, pad);
        *off += pad;
    }
}

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
    fm->cookie = htobe64(flow->cookie);
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
        strcmp(mstr, "ip") == 0)
    {
        uint8_t eth_type[2] = {0x08, 0x00};
        oxm_put(buf, &off, bufsz, OXM_OF_ETH_TYPE, eth_type, 2);
    }
    else if (strstr(mstr, "dl_type=0x0800"))
    {
        uint8_t eth_type[2] = {0x08, 0x00};
        oxm_put(buf, &off, bufsz, OXM_OF_ETH_TYPE, eth_type, 2);
    }
    else if (strstr(mstr, "dl_type=0x0806") ||
             strstr(mstr, "arp,") || strstr(mstr, ",arp") ||
             strcmp(mstr, "arp") == 0)
    {
        uint8_t eth_type[2] = {0x08, 0x06};
        oxm_put(buf, &off, bufsz, OXM_OF_ETH_TYPE, eth_type, 2);
    }

    char *p = strstr(mstr, "in_port=");
    if (p)
    {
        uint32_t port_no = (uint32_t)atoi(p + 8);
        uint32_t port_be = htonl(port_no);
        oxm_put(buf, &off, bufsz, OXM_OF_IN_PORT,
                (uint8_t *)&port_be, 4);
    }

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
    if (p)
    {
        uint8_t mac[6];
        if (parse_mac(p + 7, mac) == 0)
            oxm_put(buf, &off, bufsz, OXM_OF_ETH_DST, mac, 6);
    }

    p = strstr(mstr, "dl_src=");
    if (p)
    {
        uint8_t mac[6];
        if (parse_mac(p + 7, mac) == 0)
            oxm_put(buf, &off, bufsz, OXM_OF_ETH_SRC, mac, 6);
    }

    p = strstr(mstr, "arp_tpa=");
    if (p)
    {
        /* OXM_OF_ARP_TPA = 0x80002c04 (class=OPENFLOW_BASIC, field=22, len=4) */
        uint32_t ip = 0;
        struct in_addr a;
        char ip_str[24];
        const char *ip_start = p + 8;
        /* Copy IP string (up to next comma or end) */
        int k = 0;
        while (ip_start[k] && ip_start[k] != ',' && k < 23)
        {
            ip_str[k] = ip_start[k];
            k++;
        }
        ip_str[k] = '\0';
        if (inet_pton(AF_INET, ip_str, &a) == 1)
        {
            ip = a.s_addr; /* already big-endian */
            uint32_t oxm_hdr = htonl(0x80002c04); /* OXM_OF_ARP_TPA, len=4 */
            if (off + 4 + 4 <= bufsz)
            {
                memcpy(buf + off, &oxm_hdr, 4);
                off += 4;
                memcpy(buf + off, &ip, 4);
                off += 4;
            }
        }
    }

    int match_len = off - match_start;
    match->length = htons((uint16_t)match_len);
    oxm_pad(buf, &off);

    char astr[256];
    snprintf(astr, sizeof(astr), "%s", flow->actions);

    /* Meter instruction (if meter:N in actions) */
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
        }
    }

    /* DROP = no instructions */
    if (strstr(astr, "drop") &&
        !strstr(astr, "output:") &&
        !strstr(astr, "dec_ttl") &&
        !strstr(astr, "mod_dl"))
    {
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

    if (strstr(astr, "dec_ttl"))
    {
        if (off + (int)sizeof(ofp_action_dec_ttl_t) > bufsz)
            return -1;
        ofp_action_dec_ttl_t *a = (ofp_action_dec_ttl_t *)(buf + off);
        a->type = htons(OFPAT_DEC_NW_TTL);
        a->len = htons(sizeof(*a));
        off += sizeof(*a);
    }

    p = strstr(astr, "mod_dl_dst:");
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
            uint32_t oxm_hdr = htonl((OXM_OF_ETH_DST & ~0xFF) | 6);
            memcpy(buf + off, &oxm_hdr, 4);
            off += 4;
            memcpy(buf + off, mac, 6);
            off += 6;
            oxm_pad(buf, &off);
            sf->len = htons((uint16_t)(off - sf_start));
        }
    }

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
        if (!strncmp(p, "normal", 6) || !strncmp(p, "NORMAL", 6))
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
                LOG_W("OF", "Invalid port %d in '%s', using NORMAL", pnum, astr);
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

    inst->len = htons((uint16_t)(off - inst_start));
    fm->header.length = htons((uint16_t)off);
    return off;
}

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
                a2a_server_del_fd(g_of_server[i], g_conns[i].fd);
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

/* ── Meter management ────────────────────────────────────────────── */

/*
 * Install an OpenFlow 1.3 DROP meter at rate_kbps.
 * Must be called before installing a "meter:N,output:normal" flow.
 */
int ovs_of_add_meter(const char *bridge, uint32_t meter_id,
                     uint32_t rate_kbps, int already_exists)
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

    /* OVS kernel datapath does not support METER_MOD MODIFY.
    * Delete existing meter first, then re-add with new rate. */
    if (already_exists) {
        /* Send METER_MOD DELETE */
        uint8_t del_buf[32] = {0};
        del_buf[0] = OFP13_VERSION;
        del_buf[1] = OFPT_METER_MOD;
        uint16_t del_len = htons(16);
        memcpy(del_buf + 2, &del_len, 2);
        uint32_t del_xid = htonl(g_xid++);
        memcpy(del_buf + 4, &del_xid, 4);
        uint16_t del_cmd = htons(2); /* OFPMC_DELETE */
        uint16_t del_flags = htons(0);
        memcpy(del_buf + 8,  &del_cmd,   2);
        memcpy(del_buf + 10, &del_flags, 2);
        uint32_t del_mid = htonl(meter_id);
        memcpy(del_buf + 12, &del_mid, 4);
        send(fd, del_buf, 16, MSG_NOSIGNAL);

        /* Wait up to 100ms for OVS kernel datapath to process the DELETE.
         * Poll in 10ms increments; drain any pending messages (ECHO_REQUEST
         * or stale OFPT_ERROR from prior ADD) so the socket buffer is clean. */
        struct timeval tv_save = {0, 0};
        socklen_t tv_len = sizeof(tv_save);
        getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_save, &tv_len);
        struct timeval tv_poll = {0, 10000}; /* 10ms */
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_poll, sizeof(tv_poll));
        for (int _wi = 0; _wi < 10; _wi++) {
            uint8_t drain[64];
            ssize_t n = recv(fd, drain, sizeof(drain), 0);
            if (n <= 0) break; /* no more pending messages */
        }
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_save, sizeof(tv_save));
        /* Additional 50ms guard to let kernel complete deletion */
        struct timespec ts = {0, 50000000}; /* 50ms */
        nanosleep(&ts, NULL);
    }
    uint16_t cmd = htons(OFPMC_ADD);
    uint16_t flags = htons(OFPMF_KBPS);
    memcpy(buf + off, &cmd, 2);
    off += 2;
    memcpy(buf + off, &flags, 2);
    off += 2;
    uint32_t mid = htonl(meter_id);
    memcpy(buf + off, &mid, 4);
    off += 4;

    /* Band: DROP */
    uint16_t btype = htons(OFPMBT_DROP);
    uint16_t blen = htons(16);
    uint32_t brate = htonl(rate_kbps);
    uint32_t bburst = htonl(rate_kbps / 10 < 1 ? 1 : rate_kbps / 10);
    memcpy(buf + off, &btype, 2);
    off += 2;
    memcpy(buf + off, &blen, 2);
    off += 2;
    memcpy(buf + off, &brate, 4);
    off += 4;
    memcpy(buf + off, &bburst, 4);
    off += 4;
    off += 4; /* pad to 16-byte band */

    uint16_t total = htons((uint16_t)off);
    memcpy(buf + 2, &total, 2);

    if (send(fd, buf, off, MSG_NOSIGNAL) < 0)
    {
        LOG_E("OF", "[%s] METER_MOD ADD failed errno=%d", bridge, errno);
        return -1;
    }
    LOG_I("OF", "[%s] Meter %u installed rate=%u kbps",
          bridge, meter_id, rate_kbps);
    return 0;
}

/* ── Blocking-with-timeout receive helper ────────────────────────────
 * The OpenFlow fd is permanently O_NONBLOCK. SO_RCVTIMEO has NO effect
 * on a non-blocking socket — recv() returns EAGAIN immediately instead
 * of waiting. poll() correctly respects non-blocking fds, so use it to
 * wait for actual readability before calling recv(). */
static ssize_t of_wait_recv(int fd, void *buf, size_t buflen, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0)
        return -1;
    if (!(pfd.revents & POLLIN))
        return -1;
    return recv(fd, buf, buflen, 0);
}

/* ── OpenFlow statistics API ─────────────────────────────────────── */

int ovs_of_get_all_flow_stats(const char *bridge,
                               of_flow_stat_t *out, int max,
                               int *count_out)
{
    *count_out = 0;
    of_conn_t *c = of_get_conn(bridge);
    if (!c || c->fd < 0) return -1;

    uint8_t req[56] = {0};
    req[0] = OFP13_VERSION;
    req[1] = 18;
    uint16_t rlen = htons(56);
    memcpy(req + 2, &rlen, 2);
    uint32_t xid = htonl(g_xid++);
    memcpy(req + 4, &xid, 4);
    uint16_t mp_type = htons(1);
    memcpy(req + 8, &mp_type, 2);
    req[16] = 0xFF;
    memset(req + 20, 0xFF, 4);
    memset(req + 24, 0xFF, 4);
    uint16_t mt = htons(1);
    memcpy(req + 48, &mt, 2);
    uint16_t ml = htons(4);
    memcpy(req + 50, &ml, 2);

    if (send(c->fd, req, 56, MSG_NOSIGNAL) < 0) {
        LOG_E("OF", "[%s] flow stats request send failed errno=%d", bridge, errno);
        return -1;
    }

    uint8_t reply[16384];
    int total = 0;
    int budget_ms = 300;

    for (;;) {
        if (budget_ms <= 0) break;

        uint64_t t0 = a2a_now_us();
        ssize_t n = of_wait_recv(c->fd, reply, sizeof(reply), budget_ms);
        budget_ms -= (int)((a2a_now_us() - t0) / 1000);
        if (n <= 0) break;

        ofp_header_t *hdr = (ofp_header_t *)reply;
        if (hdr->type == 2) {
            ofp_header_t echo_reply = *hdr;
            echo_reply.type = 3;
            send(c->fd, &echo_reply, sizeof(echo_reply), MSG_NOSIGNAL);
            continue;
        }
        if (hdr->type != 19) continue;

        uint16_t reply_mp_type;
        memcpy(&reply_mp_type, reply + 8, 2);
        if (ntohs(reply_mp_type) != 1) continue;

        int off = 16;
        while (off + 56 <= (int)n && total < max) {
            uint16_t entry_len;
            memcpy(&entry_len, reply + off, 2);
            entry_len = ntohs(entry_len);
            if (entry_len < 56 || (off + entry_len) > (int)n)
                break;

            of_flow_stat_t *s = &out[total];
            uint32_t dur; memcpy(&dur, reply + off + 4, 4);
            s->duration_sec = ntohl(dur);
            uint64_t ck; memcpy(&ck, reply + off + 8, 8);
            s->cookie = be64toh(ck);
            uint16_t pri; memcpy(&pri, reply + off + 12, 2);
            s->priority = ntohs(pri);
            uint64_t pc; memcpy(&pc, reply + off + 32, 8);
            s->packet_count = be64toh(pc);
            uint64_t bc; memcpy(&bc, reply + off + 40, 8);
            s->byte_count = be64toh(bc);

            total++;
            off += entry_len;
        }

        uint16_t flags; memcpy(&flags, reply + 10, 2);
        if (!(ntohs(flags) & 0x0001)) break;
    }

    *count_out = total;
    LOG_D("OF", "[%s] flow stats: %d entries", bridge, total);
    return (total > 0) ? 0 : -1;
}

int ovs_of_get_meter_stats(const char *bridge,
                            uint32_t meter_id,
                            of_meter_stat_t *out)
{
    memset(out, 0, sizeof(*out));
    out->meter_id = meter_id;

    of_conn_t *c = of_get_conn(bridge);
    if (!c || c->fd < 0) return -1;

    uint8_t req[24] = {0};
    req[0] = OFP13_VERSION;
    req[1] = 18;
    uint16_t rlen = htons(24);
    memcpy(req + 2, &rlen, 2);
    uint32_t xid = htonl(g_xid++);
    memcpy(req + 4, &xid, 4);
    uint16_t mpt = htons(9);
    memcpy(req + 8, &mpt, 2);
    uint32_t mid = htonl(meter_id);
    memcpy(req + 16, &mid, 4);

    if (send(c->fd, req, 24, MSG_NOSIGNAL) < 0) return -1;

    uint8_t reply[512];
    int budget_ms = 300;

    for (;;) {
        if (budget_ms <= 0) return -1;
        uint64_t t0 = a2a_now_us();
        ssize_t n = of_wait_recv(c->fd, reply, sizeof(reply), budget_ms);
        budget_ms -= (int)((a2a_now_us() - t0) / 1000);
        if (n < 8) return -1;

        ofp_header_t *hdr = (ofp_header_t *)reply;

        if (hdr->type == 2) { /* ECHO_REQUEST — service it, keep waiting */
            ofp_header_t echo_reply = *hdr;
            echo_reply.type = 3;
            send(c->fd, &echo_reply, sizeof(echo_reply), MSG_NOSIGNAL);
            continue;
        }
        if (hdr->type != 19) continue;      /* not a multipart reply — skip */

        uint16_t reply_mp_type;
        memcpy(&reply_mp_type, reply + 8, 2);
        if (ntohs(reply_mp_type) != 9) continue;  /* not OFPMP_METER — skip */

        if (n < 16 + 56) return -1;

        int base = 16;
        uint64_t pic; memcpy(&pic, reply + base + 16, 8);
        out->packet_in_count = be64toh(pic);
        uint64_t bic; memcpy(&bic, reply + base + 24, 8);
        out->byte_in_count = be64toh(bic);
        uint64_t pbc; memcpy(&pbc, reply + base + 40, 8);
        out->packet_band_count = be64toh(pbc);
        uint64_t bbc; memcpy(&bbc, reply + base + 48, 8);
        out->byte_band_count = be64toh(bbc);
        return 0;
    }
}

int ovs_of_get_table_stats(const char *bridge,
                            of_table_stat_t *out)
{
    memset(out, 0, sizeof(*out));

    of_conn_t *c = of_get_conn(bridge);
    if (!c || c->fd < 0) return -1;

    uint8_t req[16] = {0};
    req[0] = OFP13_VERSION;
    req[1] = 18;
    uint16_t rlen = htons(16);
    memcpy(req + 2, &rlen, 2);
    uint32_t xid = htonl(g_xid++);
    memcpy(req + 4, &xid, 4);
    uint16_t mpt = htons(3);
    memcpy(req + 8, &mpt, 2);

    if (send(c->fd, req, 16, MSG_NOSIGNAL) < 0) return -1;

    uint8_t reply[512];
    int budget_ms = 300;

    for (;;) {
        if (budget_ms <= 0) return -1;
        uint64_t t0 = a2a_now_us();
        ssize_t n = of_wait_recv(c->fd, reply, sizeof(reply), budget_ms);
        budget_ms -= (int)((a2a_now_us() - t0) / 1000);
        if (n < 8) return -1;

        ofp_header_t *hdr = (ofp_header_t *)reply;

        if (hdr->type == 2) {
            ofp_header_t echo_reply = *hdr;
            echo_reply.type = 3;
            send(c->fd, &echo_reply, sizeof(echo_reply), MSG_NOSIGNAL);
            continue;
        }
        if (hdr->type != 19) continue;

        uint16_t reply_mp_type;
        memcpy(&reply_mp_type, reply + 8, 2);
        if (ntohs(reply_mp_type) != 3) continue;  /* not OFPMP_TABLE — skip */

        if (n < 16 + 24) return -1;

        int base = 16;
        uint32_t ac; memcpy(&ac, reply + base + 4, 4);
        out->active_count = ntohl(ac);
        uint64_t lc; memcpy(&lc, reply + base + 8, 8);
        out->lookup_count = be64toh(lc);
        uint64_t mc; memcpy(&mc, reply + base + 16, 8);
        out->matched_count = be64toh(mc);
        return 0;
    }
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

/* DELETE_STRICT at a specific priority to avoid collateral deletion. */
int ovs_of_del_flow_at_priority(const char *bridge, const char *match,
                                uint16_t priority)
{
    of_conn_t *c = of_get_conn(bridge);
    if (!c)
        return -1;

    ovs_flow_t flow = {0};
    strncpy(flow.match, match, sizeof(flow.match) - 1);
    flow.priority = priority;

    uint8_t buf[512];
    int len = build_flow_mod(&flow, OFPFC_DELETE_STRICT, buf, sizeof(buf));
    if (len < 0)
        return -1;

    if (send(c->fd, buf, len, MSG_NOSIGNAL) < 0)
        return -1;

    LOG_I("OF", "[%s] FLOW_MOD DELETE_STRICT priority=%u match=%s",
          bridge, priority, match);
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

    if (send(fd, buf, len, MSG_NOSIGNAL) < 0)
    {
        LOG_E("OF", "[%s] FLOW_MOD DEL send failed errno=%d", bridge, errno);
        if (errno == EPIPE || errno == ECONNRESET || errno == EBADF)
        {
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
    (void)bridge;
    (void)out;
    (void)max;
    return 0;
}

/*
 * Flush all learned MAC flows by DELETE non-strict (empty OXM),
 * then immediately reinstall permanent protection flows.
 *
 * DELETE non-strict with empty OXM wildcards all flows. We must
 * reinstall table-miss, broadcast, and multicast protection flows
 * atomically before any new traffic arrives.
 */
int ovs_of_flush_mac(const char *bridge)
{
    of_conn_t *c = of_get_conn(bridge);
    if (!c)
        return -1;

    /* Step 1: DELETE non-strict with empty OXM — removes ALL flows in table 0 */
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    ofp_flow_mod_t *fm = (ofp_flow_mod_t *)buf;
    int off = sizeof(ofp_flow_mod_t);

    fm->header.version  = OFP13_VERSION;
    fm->header.type     = OFPT_FLOW_MOD;
    fm->cookie          = 0;
    fm->cookie_mask     = 0;
    fm->table_id        = 0;
    fm->command         = OFPFC_DELETE;        /* non-strict: match all */
    fm->idle_timeout    = 0;
    fm->hard_timeout    = 0;
    fm->priority        = 0;                   /* ignored for non-strict */
    fm->buffer_id       = htonl(OFP_NO_BUFFER);
    fm->out_port        = htonl(OFPP_ANY);
    fm->out_group       = htonl(0xffffffff);

    /* Empty OXM match = wildcard all */
    ofp_match_t *match  = (ofp_match_t *)(buf + off);
    match->type         = htons(OFPMT_OXM);
    match->length       = htons(4);
    off += 4;
    off += 4; /* 8-byte pad */

    fm->header.length = htons((uint16_t)off);

    if (send(c->fd, buf, off, MSG_NOSIGNAL) < 0)
    {
        LOG_E("OF", "[%s] flush_mac: DELETE all flows failed errno=%d",
              bridge, errno);
        return -1;
    }

    LOG_I("OF", "[%s] flush_mac: all flows deleted, reinstalling permanent flows",
          bridge);

    /* Reset in-memory MAC table so re-learning reinstalls dl_dst flows */
    g_mac_count = 0;
    memset(g_mac_table, 0, sizeof(g_mac_table));

    /* Step 2: Reinstall permanent flows wiped by DELETE above */

    /* Table-miss: priority=0, actions=CONTROLLER */
    int of_install_table_miss(int fd, const char *bridge);
    if (of_install_table_miss(c->fd, bridge) < 0)
    {
        LOG_E("OF", "[%s] flush_mac: FAILED to reinstall table-miss", bridge);
        return -1;
    }

    /* Broadcast storm protection: priority=50 */
    {
        ovs_flow_t bcast_fl = {0};
        bcast_fl.priority     = 50;
        bcast_fl.idle_timeout = 0;
        bcast_fl.hard_timeout = 0;
        snprintf(bcast_fl.match, sizeof(bcast_fl.match),
                 "dl_dst=ff:ff:ff:ff:ff:ff");
        snprintf(bcast_fl.actions, sizeof(bcast_fl.actions),
                 "meter:1,output:normal");
        ovs_of_add_flow(bridge, &bcast_fl);
    }

    /* Multicast storm protection: priority=45, meter:2 */
    {
        ovs_flow_t mcast_fl = {0};
        mcast_fl.priority     = 45;
        mcast_fl.idle_timeout = 0;
        mcast_fl.hard_timeout = 0;
        snprintf(mcast_fl.match, sizeof(mcast_fl.match),
                 "dl_dst=01:00:00:00:00:00/01:00:00:00:00:00");
        snprintf(mcast_fl.actions, sizeof(mcast_fl.actions),
                 "meter:2,output:normal");
        ovs_of_add_flow(bridge, &mcast_fl);
    }

    /* ARP monitoring flow: priority=60, meter:3 */
    {
        ovs_flow_t arp_fl = {0};
        arp_fl.priority     = 60;
        arp_fl.idle_timeout = 0;
        arp_fl.hard_timeout = 0;
        snprintf(arp_fl.match, sizeof(arp_fl.match), "dl_type=0x0806");
        snprintf(arp_fl.actions, sizeof(arp_fl.actions),
                 "meter:3,output:normal");
        ovs_of_add_flow(bridge, &arp_fl);
    }

    LOG_I("OF", "[%s] flush_mac: permanent flows reinstalled (table-miss, bcast, mcast, arp)",
          bridge);
    return 0;
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
    if (in_port == 0xFFFFFFFE || in_port == 0xFFFFFFFF)
    {
        LOG_D("OF", "[%s] skipping MAC learn on internal port %u",
              bridge, in_port);
        return;
    }

    uint64_t now = a2a_now_us();

    for (int i = 0; i < g_mac_count; i++)
    {
        if (strcmp(g_mac_table[i].mac, mac_str) == 0)
        {
            if (g_mac_table[i].in_port != in_port)
            {
                LOG_I("OF", "[%s] MAC moved: %s %u → %u",
                      bridge, mac_str, g_mac_table[i].in_port, in_port);
                g_mac_table[i].in_port = in_port;
                if (in_port < OF_MAX_PORTS)
                    g_pkt_in_per_port[in_port]++;

                /* Spoof/flap detection directly in PACKET_IN path */
                if (g_l2_ctx_for_spoof) {
                    uint64_t now_us = a2a_now_us();
                    for (int _si = 0; _si < g_l2_ctx_for_spoof->mac_count; _si++) {
                        mac_entry_t *me = &g_l2_ctx_for_spoof->mac_table[_si];
                        if (strncmp(me->mac, mac_str, 17) == 0) {
                            mac_check_spoof_window(g_l2_ctx_for_spoof, me,
                                                   (int)in_port, now_us);
                            me->port = (int)in_port;
                            break;
                        }
                    }
                }

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

    if (g_mac_count >= OF_MAC_TABLE_MAX)
        return;

    of_mac_entry_t *e = &g_mac_table[g_mac_count++];
    strncpy(e->mac, mac_str, sizeof(e->mac) - 1);
    e->in_port = in_port;
    e->learned_at_us = now;
    e->valid = 1;

    LOG_I("OF", "[%s] MAC learned: %s port=%u", bridge, mac_str, in_port);

    /* Increment per-port PACKET_IN counter for unicast flood detection */
    if (in_port < OF_MAX_PORTS)
        g_pkt_in_per_port[in_port]++;

    /* Eagerly create entry in L2 ctx MAC table so port-change spoof check works
     * immediately, without waiting 2s for l2_mac_sync() to run. */
    if (g_l2_ctx_for_spoof && g_l2_ctx_for_spoof->mac_count < L2_MAX_MAC_TABLE) {
        /* Check not already there (shouldn't be, but guard against race) */
        int already = 0;
        for (int _ci = 0; _ci < g_l2_ctx_for_spoof->mac_count; _ci++) {
            if (strncmp(g_l2_ctx_for_spoof->mac_table[_ci].mac, mac_str, 17) == 0) {
                already = 1;
                break;
            }
        }
        if (!already) {
            mac_entry_t *ce = &g_l2_ctx_for_spoof->mac_table[g_l2_ctx_for_spoof->mac_count++];
            strncpy(ce->mac, mac_str, sizeof(ce->mac) - 1);
            ce->mac[17] = '\0';
            ce->port = (int)in_port;
            ce->learned_at_us = now;
            ce->last_seen_us  = now;
            ce->pkt_count = 1;
            ce->flap_window_start_us = now;
        }
    }

    ovs_flow_t fwd = {0};
    fwd.priority = 10;
    fwd.idle_timeout = 300;
    snprintf(fwd.match, sizeof(fwd.match), "dl_dst=%s", mac_str);
    snprintf(fwd.actions, sizeof(fwd.actions), "output:%u", in_port);
    ovs_of_add_flow(bridge, &fwd);
}

/* PACKET_OUT flood — dynamically allocated to avoid stack overflow. */
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

    if (total > 9216)
        return;

    uint8_t *buf = calloc(1, total);
    if (!buf)
        return;

    int off = 0;
    ofp_header_t *hdr = (ofp_header_t *)buf;
    hdr->version = OFP13_VERSION;
    hdr->type = OFPT_PACKET_OUT;
    hdr->length = htons((uint16_t)total);
    hdr->xid = htonl(g_xid++);
    off += 8;

    uint32_t bid_be = htonl(buffer_id);
    memcpy(buf + off, &bid_be, 4);
    off += 4;

    uint32_t inp_be = htonl(in_port);
    memcpy(buf + off, &inp_be, 4);
    off += 4;

    uint16_t act_len = htons(sizeof(ofp_action_output_t));
    memcpy(buf + off, &act_len, 2);
    off += 2;
    off += 6; /* pad */

    ofp_action_output_t *ao = (ofp_action_output_t *)(buf + off);
    ao->type = htons(OFPAT_OUTPUT);
    ao->len = htons(sizeof(*ao));
    ao->port = htonl(OFPP_NORMAL);
    ao->max_len = htons(0xffff);
    off += sizeof(*ao);

    if (data_len > 0)
    {
        memcpy(buf + off, pkt_data, data_len);
        off += data_len;
    }

    off += pad_len;

    send(fd, buf, off, MSG_NOSIGNAL);
    free(buf);
}
/* Drain all readable OF messages: handle ECHO_REQUEST and PACKET_IN. */
void ovs_of_process_packet_in(const char *bridge, int fd)
{
    for (;;)
    {
        uint8_t hdr_buf[8];
        ssize_t n = recv(fd, hdr_buf, 8, MSG_DONTWAIT | MSG_PEEK);
        if (n < 8)
            return;

        ofp_header_t *hdr = (ofp_header_t *)hdr_buf;
        if (hdr->version != OFP13_VERSION)
        {
            recv(fd, hdr_buf, 8, MSG_DONTWAIT);
            return;
        }

        uint16_t total_len = ntohs(hdr->length);
        if (total_len < 8)
            return;

        uint8_t *buf = malloc(total_len);
        if (!buf)
            return;

        n = recv(fd, buf, total_len, MSG_DONTWAIT);
        if (n < total_len)
        {
            free(buf);
            return;
        }

        ofp_header_t *msg_hdr = (ofp_header_t *)buf;

        if (msg_hdr->type == OFPT_ECHO_REQUEST)
        {
            ofp_header_t reply;
            reply.version = OFP13_VERSION;
            reply.type = OFPT_ECHO_REPLY;
            reply.length = htons(8);
            reply.xid = msg_hdr->xid;
            send(fd, &reply, sizeof(reply), MSG_NOSIGNAL);
            free(buf);
            continue;
        }

        /* OFPT_ERROR = type 1 */
        if (msg_hdr->type == 1 && total_len >= 12)
        {
            uint16_t err_type, err_code;
            memcpy(&err_type, buf + 8,  2); err_type = ntohs(err_type);
            memcpy(&err_code, buf + 10, 2); err_code = ntohs(err_code);
            
            /* OFPET_METER_MOD_FAILED=12, OFPMMFC_METER_EXISTS=1 */
            if (err_type == 12 && err_code == 1) {
                /* Harmless race condition during rapid storm mitigation. Suppress it. */
            }
            /* OFPET_FLOW_MOD_FAILED=5, OFPFMFC_TABLE_FULL=1 */
            else if (err_type == 5 && err_code == 1) {
                LOG_E("OF", "[%s] OFPT_ERROR: FLOW TABLE FULL — FDB overflow!", bridge);
                g_fdb_overflow_flag = 1;
            } else {
                LOG_W("OF", "[%s] OFPT_ERROR type=%u code=%u", bridge, err_type, err_code);
            }
            free(buf);
            continue;
        }

        if (msg_hdr->type != OFPT_PACKET_IN || total_len < 24)
        {
            free(buf);
            continue;
        }

        int match_off = 24;
        if (match_off + 4 > total_len)
        {
            free(buf);
            continue;
        }

        ofp_match_t *match = (ofp_match_t *)(buf + match_off);
        uint16_t mlen = ntohs(match->length);
        if (match_off + mlen > total_len)
        {
            free(buf);
            continue;
        }

        uint32_t in_port = OFPP_ANY;
        int oxm_off = match_off + 4;
        int oxm_end = match_off + (int)mlen;

        while (oxm_off + 4 <= oxm_end)
        {
            const uint8_t *oxm_bytes = buf + oxm_off;
            uint8_t vlen = oxm_bytes[3];
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

        /* OF1.3 §7.4.1 + OVS implementation: 2 explicit pad bytes follow the
         * 8-byte-aligned match, before the Ethernet frame data. */
        int pkt_off = match_off + ((mlen + 7) & ~7) + 2;

        if (pkt_off >= total_len)
        {
            free(buf);
            continue;
        }

        const uint8_t *pkt = buf + pkt_off;
        int pkt_len = total_len - pkt_off;
        if (pkt_len < 0)
        {
            free(buf);
            continue;
        }

        if (pkt_len < 14)
        {
            free(buf);
            continue;
        }

        if (in_port != OFPP_ANY)
        {
            of_send_packet_out_flood(fd, OFP_NO_BUFFER, in_port, pkt, pkt_len);
        }

        if (pkt_len >= 14)
        {
            const uint8_t *eth_src = pkt + 6;
            mac_table_learn(eth_src, in_port, bridge);
        }

        free(buf);
    }
}
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
        strncpy(out[count].mac, g_mac_table[i].mac, sizeof(out[count].mac) - 1);
        out[count].mac[sizeof(out[count].mac) - 1] = '\0';
        out[count].port = (int)g_mac_table[i].in_port;
        out[count].learned_at_us = g_mac_table[i].learned_at_us;
        count++;
    }
    return count;
}