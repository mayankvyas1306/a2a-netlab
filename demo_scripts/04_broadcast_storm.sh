#!/bin/bash
# Demonstrates: storm detection, dynamic rate limiting, L3 coordination, connectivity preserved on uninvolved paths
echo "=== BROADCAST STORM DETECTION ==="

echo "--- Connectivity BEFORE storm ---"
docker exec host1 ping -c 3 20.0.0.1 -q | grep "packet loss"

echo "--- Launching broadcast flood from host1 (8 parallel streams, 8 sec) ---"
docker exec host1 bash -c \
  'for i in $(seq 1 8); do ping -f -c 2000 -b 10.0.0.255 >/dev/null 2>&1 & done; wait' &

echo "--- Waiting 10s for detection + rate limit to kick in ---"
sleep 10

echo "--- sw1 storm detection log (last 15 lines) ---"
docker exec sw1 tail -100 /tmp/agent-sw1.log | grep -E "STORM|Rate limit|CLEARED"

echo "--- core1 L3 decision log (last 15 lines) ---"
docker exec core1 tail -100 /tmp/agent-core1.log | grep -E "STORM|Decision|reroute|No alternate"

echo "--- Dynamic rate-limit meter installed on sw1 (meter:4) ---"
docker exec sw1 ovs-ofctl -O OpenFlow13 dump-meters br0 | grep -A1 "meter=4"

echo "--- Waiting for storm flood to finish ---"
wait

echo "--- Connectivity AFTER storm (must be 0% loss) ---"
docker exec host1 ping -c 5 20.0.0.1 -q | grep "packet loss"

echo ""
echo "--- A2A MESSAGE FLOW ---"
echo "[1] sw1 detects storm -> reports to L3 core1 AND its L2 peer sw2:"
docker exec sw1 grep -E "STORM DETECTED|Notified L2 peer" /tmp/agent-sw1.log | tail -4
echo "[2] core1 receives sw1's anomaly, decides, replies with a policy:"
docker exec core1 grep -E "anomaly from agent-l2-sw1|policy sent" /tmp/agent-core1.log | tail -4
echo "[3] sw1 applies the policy core1 sent back:"
docker exec sw1 grep -E "Policy received|Rate limit applied" /tmp/agent-sw1.log | tail -4
echo "[4] sw2 reacted to sw1's PEER notice directly — no L3 round-trip needed:"
docker exec sw2 grep "L2 peer anomaly from agent-l2-sw1" /tmp/agent-sw2.log | tail -4

echo "=== DONE ==="