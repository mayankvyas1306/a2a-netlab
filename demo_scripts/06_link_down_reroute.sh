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
sleep 7
docker exec host1 ping -c 5 20.0.0.1 > /dev/null 2>&1 &
docker exec host1 ping -c 5 20.0.0.1 > /dev/null 2>&1 &
docker exec host1 ping -c 5 20.0.0.1 > /dev/null 2>&1 &
docker exec host1 ping -c 5 20.0.0.1
docker exec host1 ping -c 5 20.0.0.1 -q | grep "packet loss"

echo "--- Restoring s1c1 ---"
docker exec sw1 ip link set s1c1 up

sleep 2

echo "--- Link RESTORED log ---"
docker exec sw1 tail -10 /tmp/agent-sw1.log | grep -E "RESTORED"

echo "--- Connectivity AFTER restore ---"
sleep 7
docker exec host1 ping -c 5 20.0.0.1 > /dev/null 2>&1 &
docker exec host1 ping -c 5 20.0.0.1 > /dev/null 2>&1 &
docker exec host1 ping -c 5 20.0.0.1 > /dev/null 2>&1 &
docker exec host1 ping -c 5 20.0.0.1
docker exec host1 ping -c 5 20.0.0.1 -q | grep "packet loss"
echo ""
echo "--- A2A MESSAGE FLOW: link failure propagates two ways at once ---"
echo "[1] sw1 -> L3 core1:"
docker exec core1 grep -E "anomaly from agent-l2-sw1 type=4|LINK_DOWN" /tmp/agent-core1.log | tail -4
echo "[2] sw1 -> sw2 (L2 peer), same event, independent path:"
docker exec sw2 grep "L2 peer anomaly from agent-l2-sw1: type=4" /tmp/agent-sw2.log | tail -2
echo "[3] On restore, both paths fire again with type=6 LINK_UP:"
docker exec core1 grep "type=6" /tmp/agent-core1.log | tail -2
docker exec sw2 grep "type=6" /tmp/agent-sw2.log | tail -2

echo "=== DONE ==="