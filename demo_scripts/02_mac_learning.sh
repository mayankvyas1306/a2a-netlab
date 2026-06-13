#!/bin/bash
# Demonstrates: L2 agent observes OVS MAC learning, flows installed
echo "=== MAC LEARNING ==="

echo "--- OVS flows before learned MACs ---"
docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0

echo "--- Generating traffic to trigger MAC learning ---"
docker exec host1 ping -c 3 10.0.0.2 -q
docker exec host3 ping -c 3 10.0.0.1 -q

sleep 1

echo "--- MAC table on sw1 (agent state dump via SIGUSR1) ---"
docker exec sw1 pkill -USR1 a2a_agent
sleep 2
docker exec sw1 tail -15 /tmp/agent-sw1.log | grep -A 10 "MAC Table"

echo "--- OVS flows showing learned MACs ---"
docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0

echo "=== DONE ==="