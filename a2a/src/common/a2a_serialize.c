#include "a2a_message.h"
#include "a2a_serialize.h"
#include <cjson/cJSON.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char *a2a_serialize(const a2a_message_t *msg) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddNumberToObject(root, "msg_id",       (double)msg->msg_id);
    cJSON_AddStringToObject(root, "src_agent",    msg->src_agent);
    cJSON_AddStringToObject(root, "dst_agent",    msg->dst_agent);
    cJSON_AddNumberToObject(root, "msg_type",     (double)msg->msg_type);
    cJSON_AddNumberToObject(root, "timestamp_us", (double)msg->timestamp_us);
    cJSON_AddStringToObject(root, "payload",      msg->payload);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

int a2a_deserialize(const char *json, a2a_message_t *msg) {
    cJSON *root = cJSON_Parse(json);
    if (!root) return -1;

    memset(msg, 0, sizeof(*msg));

    cJSON *item;
    item = cJSON_GetObjectItem(root, "msg_id");
    if (item) msg->msg_id = (uint32_t)item->valuedouble;

    item = cJSON_GetObjectItem(root, "src_agent");
    if (item) strncpy(msg->src_agent, item->valuestring, A2A_MAX_AGENT_ID - 1);

    item = cJSON_GetObjectItem(root, "dst_agent");
    if (item) strncpy(msg->dst_agent, item->valuestring, A2A_MAX_AGENT_ID - 1);

    item = cJSON_GetObjectItem(root, "msg_type");
    if (item) msg->msg_type = (a2a_msg_type_t)(int)item->valuedouble;

    item = cJSON_GetObjectItem(root, "timestamp_us");
    if (item) msg->timestamp_us = (uint64_t)item->valuedouble;

    item = cJSON_GetObjectItem(root, "payload");
    if (item) {
        strncpy(msg->payload, item->valuestring, A2A_MAX_PAYLOAD - 1);
        msg->payload_len = (uint32_t)strlen(msg->payload);
    }

    cJSON_Delete(root);
    return 0;
}

/* Example for l2_event — same pattern for all others */
int a2a_msg_set_l2_event(a2a_message_t *msg, const l2_event_payload_t *pl) {
    cJSON *j = cJSON_CreateObject();
    if (!j) return -1;
    cJSON_AddStringToObject(j, "mac",         pl->mac);
    cJSON_AddNumberToObject(j, "port",        pl->port);
    cJSON_AddStringToObject(j, "switch_id",   pl->switch_id);
    cJSON_AddNumberToObject(j, "pkt_count",   pl->pkt_count);
    cJSON_AddNumberToObject(j, "is_anomaly",  pl->is_anomaly);
    cJSON_AddNumberToObject(j, "anomaly_pps", pl->anomaly_pps);
    cJSON_AddStringToObject(j, "reason",      pl->reason);   /* ← ADD */
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return -1;
    strncpy(msg->payload, s, A2A_MAX_PAYLOAD - 1);
    msg->payload[A2A_MAX_PAYLOAD - 1] = '\0'; /* guarantee null termination */
    msg->payload_len = strlen(msg->payload);
    msg->msg_type    = MSG_L2_EVENT;
    free(s);
    return 0;
}

int a2a_msg_get_l2_event(const a2a_message_t *msg, l2_event_payload_t *pl) {
    cJSON *j = cJSON_Parse(msg->payload);
    if (!j) return -1;
    cJSON *item;
    memset(pl, 0, sizeof(*pl));
    if ((item = cJSON_GetObjectItem(j, "mac")))
        strncpy(pl->mac, item->valuestring, 17);
    if ((item = cJSON_GetObjectItem(j, "port")))
        pl->port = (int)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "switch_id")))
        strncpy(pl->switch_id, item->valuestring, A2A_MAX_AGENT_ID - 1);
    if ((item = cJSON_GetObjectItem(j, "pkt_count")))
        pl->pkt_count = (uint32_t)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "is_anomaly")))
        pl->is_anomaly = (int)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "anomaly_pps")))
        pl->anomaly_pps = (uint32_t)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "reason")))    /* ← ADD */
        strncpy(pl->reason, item->valuestring, 63);
    cJSON_Delete(j);
    return 0;
}

/* ── l3_event ────────────────────────────────────────────────────────── */
int a2a_msg_set_l3_event(a2a_message_t *msg, const l3_event_payload_t *pl) {
    cJSON *j = cJSON_CreateObject();
    if (!j) return -1;
    cJSON_AddStringToObject(j, "prefix",     pl->prefix);
    cJSON_AddStringToObject(j, "nexthop",    pl->nexthop);
    cJSON_AddStringToObject(j, "via_switch", pl->via_switch);
    cJSON_AddNumberToObject(j, "metric",     pl->metric);
    cJSON_AddNumberToObject(j, "is_withdraw",pl->is_withdraw);
    cJSON_AddStringToObject(j, "reason",     pl->reason);
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return -1;
    strncpy(msg->payload, s, A2A_MAX_PAYLOAD - 1);
    msg->payload[A2A_MAX_PAYLOAD - 1] = '\0'; /* guarantee null termination */
    msg->payload_len = strlen(msg->payload);
    msg->msg_type    = MSG_L3_EVENT;
    free(s);
    return 0;
}

int a2a_msg_get_l3_event(const a2a_message_t *msg, l3_event_payload_t *pl) {
    cJSON *j = cJSON_Parse(msg->payload);
    if (!j) return -1;
    cJSON *item;
    memset(pl, 0, sizeof(*pl));
    if ((item = cJSON_GetObjectItem(j, "prefix")))
        strncpy(pl->prefix,     item->valuestring, sizeof(pl->prefix) - 1);
    if ((item = cJSON_GetObjectItem(j, "nexthop")))
        strncpy(pl->nexthop,    item->valuestring, sizeof(pl->nexthop) - 1);
    if ((item = cJSON_GetObjectItem(j, "via_switch")))
        strncpy(pl->via_switch, item->valuestring, A2A_MAX_AGENT_ID - 1);
    if ((item = cJSON_GetObjectItem(j, "metric")))
        pl->metric = (int)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "is_withdraw")))
        pl->is_withdraw = (int)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "reason")))
        strncpy(pl->reason, item->valuestring, 63);
    cJSON_Delete(j);
    return 0;
}

/* ── register ────────────────────────────────────────────────────────── */
int a2a_msg_set_register(a2a_message_t *msg, const register_payload_t *pl) {
    cJSON *j = cJSON_CreateObject();
    if (!j) return -1;
    cJSON_AddStringToObject(j, "host",       pl->host);
    cJSON_AddNumberToObject(j, "port",       pl->port);
    cJSON_AddNumberToObject(j, "agent_type", pl->agent_type);
    cJSON_AddStringToObject(j, "switch_id",  pl->switch_id);
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return -1;
    strncpy(msg->payload, s, A2A_MAX_PAYLOAD - 1);
    msg->payload[A2A_MAX_PAYLOAD - 1] = '\0'; /* guarantee null termination */
    msg->payload_len = strlen(msg->payload);
    msg->msg_type    = MSG_REGISTER;
    free(s);
    return 0;
}

int a2a_msg_get_register(const a2a_message_t *msg, register_payload_t *pl) {
    cJSON *j = cJSON_Parse(msg->payload);
    if (!j) return -1;
    cJSON *item;
    memset(pl, 0, sizeof(*pl));
    if ((item = cJSON_GetObjectItem(j, "host")))
        strncpy(pl->host,      item->valuestring, A2A_MAX_HOST_LEN - 1);
    if ((item = cJSON_GetObjectItem(j, "port")))
        pl->port = (int)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "agent_type")))
        pl->agent_type = (int)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "switch_id")))
        strncpy(pl->switch_id, item->valuestring, A2A_MAX_AGENT_ID - 1);
    cJSON_Delete(j);
    return 0;
}

/* ── heartbeat ───────────────────────────────────────────────────────── */
int a2a_msg_set_heartbeat(a2a_message_t *msg, const heartbeat_payload_t *pl) {
    cJSON *j = cJSON_CreateObject();
    if (!j) return -1;
    cJSON_AddNumberToObject(j, "uptime_us",  (double)pl->uptime_us);
    cJSON_AddNumberToObject(j, "peer_count", pl->peer_count);
    cJSON_AddNumberToObject(j, "fsm_state",  pl->fsm_state);
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return -1;
    strncpy(msg->payload, s, A2A_MAX_PAYLOAD - 1);
    msg->payload[A2A_MAX_PAYLOAD - 1] = '\0'; /* guarantee null termination */
    msg->payload_len = strlen(msg->payload);
    msg->msg_type    = MSG_HEARTBEAT;
    free(s);
    return 0;
}

int a2a_msg_get_heartbeat(const a2a_message_t *msg, heartbeat_payload_t *pl) {
    cJSON *j = cJSON_Parse(msg->payload);
    if (!j) return -1;
    cJSON *item;
    memset(pl, 0, sizeof(*pl));
    if ((item = cJSON_GetObjectItem(j, "uptime_us")))
        pl->uptime_us = (uint64_t)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "peer_count")))
        pl->peer_count = (int)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "fsm_state")))
        pl->fsm_state = (int)item->valuedouble;
    cJSON_Delete(j);
    return 0;
}

/* ── flow_install ────────────────────────────────────────────────────── */
int a2a_msg_set_flow(a2a_message_t *msg, const flow_install_payload_t *pl) {
    cJSON *j = cJSON_CreateObject();
    if (!j) return -1;
    cJSON_AddStringToObject(j, "bridge",       pl->bridge);
    cJSON_AddNumberToObject(j, "priority",     pl->priority);
    cJSON_AddStringToObject(j, "match",        pl->match);
    cJSON_AddStringToObject(j, "actions",      pl->actions);
    cJSON_AddNumberToObject(j, "idle_timeout", pl->idle_timeout);
    cJSON_AddNumberToObject(j, "hard_timeout", pl->hard_timeout);
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return -1;
    strncpy(msg->payload, s, A2A_MAX_PAYLOAD - 1);
    msg->payload[A2A_MAX_PAYLOAD - 1] = '\0'; /* guarantee null termination */
    msg->payload_len = strlen(msg->payload);
    msg->msg_type    = MSG_FLOW_INSTALL;
    free(s);
    return 0;
}

int a2a_msg_get_flow(const a2a_message_t *msg, flow_install_payload_t *pl) {
    cJSON *j = cJSON_Parse(msg->payload);
    if (!j) return -1;
    cJSON *item;
    memset(pl, 0, sizeof(*pl));
    if ((item = cJSON_GetObjectItem(j, "bridge")))
        strncpy(pl->bridge,  item->valuestring, 63);
    if ((item = cJSON_GetObjectItem(j, "priority")))
        pl->priority = (uint16_t)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "match")))
        strncpy(pl->match,   item->valuestring, 255);
    if ((item = cJSON_GetObjectItem(j, "actions")))
        strncpy(pl->actions, item->valuestring, 255);
    if ((item = cJSON_GetObjectItem(j, "idle_timeout")))
        pl->idle_timeout = (uint32_t)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "hard_timeout")))
        pl->hard_timeout = (uint32_t)item->valuedouble;
    cJSON_Delete(j);
    return 0;
}

int a2a_msg_set_l2_anomaly(a2a_message_t *msg, const l2_anomaly_payload_t *pl) {
    cJSON *j = cJSON_CreateObject();
    if (!j) return -1;

    cJSON_AddNumberToObject(j, "anomaly_type", pl->anomaly_type);
    cJSON_AddNumberToObject(j, "port", pl->port);
    cJSON_AddStringToObject(j, "switch_id", pl->switch_id);
    cJSON_AddNumberToObject(j, "pps", pl->pps);
    cJSON_AddNumberToObject(j, "mac_count", pl->mac_count);
    cJSON_AddStringToObject(j, "mac", pl->mac);
    cJSON_AddStringToObject(j, "reason", pl->reason);

    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return -1;

    strncpy(msg->payload, s, A2A_MAX_PAYLOAD - 1);
    msg->payload[A2A_MAX_PAYLOAD - 1] = '\0';
    msg->payload_len = strlen(msg->payload);
    msg->msg_type = MSG_L2_ANOMALY;

    free(s);
    return 0;
}

int a2a_msg_get_l2_anomaly(const a2a_message_t *msg, l2_anomaly_payload_t *pl) {
    cJSON *j = cJSON_Parse(msg->payload);
    if (!j) return -1;

    memset(pl, 0, sizeof(*pl));
    cJSON *item;

    if ((item = cJSON_GetObjectItem(j, "anomaly_type")))
        pl->anomaly_type = item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "port")))
        pl->port = (int)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "switch_id")))
        strncpy(pl->switch_id, item->valuestring, A2A_MAX_AGENT_ID - 1);
    if ((item = cJSON_GetObjectItem(j, "pps")))
        pl->pps = item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "mac_count")))
        pl->mac_count = item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "mac")))
        strncpy(pl->mac, item->valuestring, 17);
    if ((item = cJSON_GetObjectItem(j, "reason")))
        strncpy(pl->reason, item->valuestring, 63);

    cJSON_Delete(j);
    return 0;
}


int a2a_msg_set_policy_cmd(a2a_message_t *msg, const policy_cmd_payload_t *pl) {
    cJSON *j = cJSON_CreateObject();
    if (!j) return -1;

    cJSON_AddNumberToObject(j, "policy_type", pl->policy_type);
    cJSON_AddNumberToObject(j, "port", pl->port);
    cJSON_AddStringToObject(j, "switch_id", pl->switch_id);
    cJSON_AddStringToObject(j, "mac", pl->mac);
    cJSON_AddNumberToObject(j, "rate_limit", pl->rate_limit);

    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return -1;

    strncpy(msg->payload, s, A2A_MAX_PAYLOAD - 1);
    msg->payload[A2A_MAX_PAYLOAD - 1] = '\0';
    msg->payload_len = strlen(msg->payload);
    msg->msg_type = MSG_POLICY_CMD;

    free(s);
    return 0;
}

int a2a_msg_set_peer_list(a2a_message_t *msg, const peer_list_payload_t *pl) {
    cJSON *j = cJSON_CreateObject();
    if (!j) return -1;

    cJSON_AddNumberToObject(j, "count", pl->count);

    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        cJSON_Delete(j);
        return -1;
    }

    for (int i = 0; i < pl->count; i++) {
        cJSON *p = cJSON_CreateObject();
        if (!p) continue;

        cJSON_AddStringToObject(p, "agent_id", pl->peers[i].agent_id);
        cJSON_AddStringToObject(p, "host",     pl->peers[i].host);
        cJSON_AddNumberToObject(p, "port",     pl->peers[i].port);
        cJSON_AddNumberToObject(p, "type",     pl->peers[i].agent_type);
        cJSON_AddStringToObject(p, "switch_id",pl->peers[i].switch_id);

        cJSON_AddItemToArray(arr, p);
    }

    cJSON_AddItemToObject(j, "peers", arr);

    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return -1;

    strncpy(msg->payload, s, A2A_MAX_PAYLOAD - 1);
    msg->payload[A2A_MAX_PAYLOAD - 1] = '\0';
    msg->payload_len = strlen(msg->payload);
    msg->msg_type = MSG_PEER_LIST;

    free(s);
    return 0;
}

int a2a_msg_get_peer_list(const a2a_message_t *msg, peer_list_payload_t *pl) {
    cJSON *j = cJSON_Parse(msg->payload);
    if (!j) return -1;

    memset(pl, 0, sizeof(*pl));

    cJSON *count = cJSON_GetObjectItem(j, "count");
    if (count) pl->count = (int)count->valuedouble;

    if (pl->count > PEER_LIST_MAX)
        pl->count = PEER_LIST_MAX;

    cJSON *arr = cJSON_GetObjectItem(j, "peers");
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(j);
        return -1;
    }

    for (int i = 0; i < pl->count; i++) {
        cJSON *p = cJSON_GetArrayItem(arr, i);
        if (!p) continue;

        cJSON *item;

        if ((item = cJSON_GetObjectItem(p, "agent_id")))
            strncpy(pl->peers[i].agent_id, item->valuestring, A2A_MAX_AGENT_ID - 1);

        if ((item = cJSON_GetObjectItem(p, "host")))
            strncpy(pl->peers[i].host, item->valuestring, A2A_MAX_HOST_LEN - 1);

        if ((item = cJSON_GetObjectItem(p, "port")))
            pl->peers[i].port = (int)item->valuedouble;

        if ((item = cJSON_GetObjectItem(p, "type")))
            pl->peers[i].agent_type = (int)item->valuedouble;

        if ((item = cJSON_GetObjectItem(p, "switch_id")))
            strncpy(pl->peers[i].switch_id, item->valuestring, A2A_MAX_AGENT_ID - 1);
    }

    cJSON_Delete(j);
    return 0;
}

int a2a_msg_get_policy_cmd(const a2a_message_t *msg, policy_cmd_payload_t *pl) {
    cJSON *j = cJSON_Parse(msg->payload);
    if (!j) return -1;

    memset(pl, 0, sizeof(*pl));
    cJSON *item;

    if ((item = cJSON_GetObjectItem(j, "policy_type")))
        pl->policy_type = item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "port")))
        pl->port = (int)item->valuedouble;
    if ((item = cJSON_GetObjectItem(j, "switch_id")))
        strncpy(pl->switch_id, item->valuestring, A2A_MAX_AGENT_ID - 1);
    if ((item = cJSON_GetObjectItem(j, "mac")))
        strncpy(pl->mac, item->valuestring, 17);
    if ((item = cJSON_GetObjectItem(j, "rate_limit")))
        pl->rate_limit = item->valuedouble;

    cJSON_Delete(j);
    return 0;
}