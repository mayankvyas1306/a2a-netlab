#!/bin/bash
# Demonstrates: link failure detection via OVSDB, automatic reroute, link restore
echo "=== LINK DOWN DETECTION & REROUTE ==="

echo "--- Baseline connectivity ---"
docker exec host1 ping -c 3 20.0.0.1 -q | grep "packet loss"

echo "--- Interface states (all up) ---"
docker exec sw1 ovs-vsctl list Interface | grep -E "^name|link_state" | paste - -

echo "--- Taking s1c1 (sw1 -> core1 uplink) DOWN ---"
docker exec sw1 ip link set s1c1 down

sleep 1

echo "--- Link DOWN detection log ---"
docker exec sw1 tail -30 /tmp/agent-sw1.log | grep -E "LINK DOWN|Uplink DOWN"
docker exec core1 tail -30 /tmp/agent-core1.log | grep -E "LINK_DOWN|reroute"

echo "--- Connectivity DURING link down (via sw2->core1, should still be 0% loss) ---"
docker exec host1 ping -c 5 20.0.0.1 -q | grep "packet loss"

echo "--- Restoring s1c1 ---"
docker exec sw1 ip link set s1c1 up

sleep 2

echo "--- Link RESTORED log ---"
docker exec sw1 tail -10 /tmp/agent-sw1.log | grep -E "RESTORED"

echo "--- Connectivity AFTER restore ---"
docker exec host1 ping -c 5 20.0.0.1 -q | grep "packet loss"

echo "=== DONE ==="