#!/bin/bash
# Demonstrates: nexthop NUD_FAILED detection, route degradation, kernel-route fallback keeps connectivity, auto-restore
echo "=== NUD_FAILED NEXTHOP DEGRADATION ==="

echo "--- Current nexthop state (should be REACHABLE) ---"
docker exec core1 ip neigh show | grep "100.0.0.2"

echo "--- Forcing nexthop to FAILED state ---"
docker exec core1 ip neigh del 100.0.0.2 dev c1c2 2>/dev/null || true
docker exec core1 ip neigh add 100.0.0.2 dev c1c2 nud failed

sleep 2

echo "--- NUD_FAILED detection log ---"
docker exec core1 tail -20 /tmp/agent-core1.log | grep -E "NUD_FAILED|DEGRADED"

echo "--- Route table showing DEGRADED routes ---"
docker exec core1 pkill -USR1 a2a_agent
sleep 2
docker exec core1 tail -30 /tmp/agent-core1.log | grep "DEGRADED"

echo "--- Connectivity DURING degradation (kernel routes still work, 0% loss) ---"
docker exec host1 ping -c 3 20.0.0.1 -q | grep "packet loss"

echo "--- Triggering ARP re-resolution (restores nexthop naturally) ---"
docker exec core1 ping -c 2 100.0.0.2 -q >/dev/null

sleep 2

echo "--- Routes restored DEGRADED -> ACTIVE ---"
docker exec core1 tail -20 /tmp/agent-core1.log | grep "ACTIVE"

echo "--- Connectivity restored ---"
docker exec host1 ping -c 3 20.0.0.1 -q | grep "packet loss"

echo "=== DONE ==="