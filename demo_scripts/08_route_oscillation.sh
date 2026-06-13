#!/bin/bash
# Demonstrates: route oscillation detection, convergence timing measurement, L2 notification
echo "=== ROUTE OSCILLATION DETECTION ==="
echo "(This takes ~50-60 seconds)"

echo "--- Flapping c1c2 link 5 times ---"
for i in $(seq 1 5); do
  echo "Flap $i"
  docker exec core1 ip link set c1c2 down
  sleep 3
  docker exec core1 ip link set c1c2 up
  sleep 4
done

sleep 5

echo "--- Oscillation detected log ---"
docker exec core1 tail -100 /tmp/agent-core1.log | grep -E "OSCILLATION"

echo "--- L2 agents notified of oscillation ---"
docker exec sw1 tail -100 /tmp/agent-sw1.log | grep -E "anomaly_type.*2|oscillation"

echo "--- Convergence timing measurements ---"
docker exec core1 tail -100 /tmp/agent-core1.log | grep "CONVERGENCE"

echo "--- Final convergence statistics ---"
docker exec core1 pkill -USR1 a2a_agent
sleep 2
docker exec core1 tail -20 /tmp/agent-core1.log | grep -A 4 "Convergence Statistics"

echo "--- Connectivity AFTER oscillation (must be 0% loss, route count must stay 17) ---"
docker exec host9 ping -c 5 10.0.0.1 -q | grep "packet loss"

echo "=== DONE ==="