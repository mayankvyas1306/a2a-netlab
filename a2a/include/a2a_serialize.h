#ifndef A2A_SERIALIZE_H
#define A2A_SERIALIZE_H

#include "a2a_message.h"

char *a2a_serialize(const a2a_message_t *msg);
int   a2a_deserialize(const char *json, a2a_message_t *msg);

#endif /* A2A_SERIALIZE_H */
