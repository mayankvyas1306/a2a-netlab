#!/bin/bash
# Create a flat L2 management network for A2A agent discovery
docker network create --driver bridge \
    --subnet 172.28.0.0/16 \
    a2a-mgmt 2>/dev/null || echo "a2a-mgmt already exists"

# Attach all agent containers to the mgmt network
for c in core1 core2 core3 core4 sw1 sw2 sw3 sw4 sw5 sw6 sw7 sw8; do
    docker network connect a2a-mgmt $c 2>/dev/null \
        && echo "Connected $c to a2a-mgmt" \
        || echo "$c already connected"
done
