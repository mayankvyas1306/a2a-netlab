#ifndef A2A_DISCOVERY_H
#define A2A_DISCOVERY_H

#include "a2a_agent.h"

#define DISCOVERY_MAX_AGENTS 32

typedef struct {
    char         agent_id[A2A_MAX_AGENT_ID];
    agent_type_t type;
    char         switch_id[A2A_MAX_AGENT_ID];
    char         host[A2A_MAX_HOST_LEN];
    int          port;
    uint64_t     registered_at_us;
    int          alive;
} registry_entry_t;

typedef struct {
    registry_entry_t entries[DISCOVERY_MAX_AGENTS];
    int              count;
} agent_registry_t;

int  discovery_register(const char *agent_id, agent_type_t type,
                         const char *switch_id, const char *host, int port);
int  discovery_unregister(const char *agent_id);
int  discovery_load(agent_registry_t *reg);
int  discovery_find_by_type(agent_registry_t *reg, agent_type_t type,
                             char results[][A2A_MAX_AGENT_ID], int max);
void discovery_print(agent_registry_t *reg);
int  discovery_auto_connect(a2a_agent_t *agent, agent_registry_t *reg);

#endif
