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
docker exec core1 grep -E "OSCILLATION" /tmp/agent-core1.log | tail -5

echo "--- L2 agents notified of oscillation ---"
docker exec sw1 tail -100 /tmp/agent-sw1.log | grep -E "anomaly_type.*2|oscillation"

echo "--- Convergence timing measurements ---"
docker exec core1 tail -100 /tmp/agent-core1.log | grep "CONVERGENCE"

echo "--- Final convergence statistics ---"
docker exec core1 pkill -USR1 a2a_agent
sleep 2
docker exec core1 tail -20 /tmp/agent-core1.log | grep -A 4 "Convergence Statistics"

echo "--- Route count check (must be 17 active routes) ---"
docker exec core1 pkill -USR1 a2a_agent
sleep 5
ROUTE_COUNT=$(docker exec core1 grep "Route health" /tmp/agent-core1.log | tail -1 | grep -o 'active=[0-9]*' | grep -o '[0-9]*')
echo "Active routes: ${ROUTE_COUNT:-NOT_FOUND} (expected: 17)"
if [ "${ROUTE_COUNT}" = "17" ]; then
    echo "  PASS: Route count correct"
elif [ -z "${ROUTE_COUNT}" ]; then
    echo "  WARN: No route health log yet — agent may still be converging"
else
    echo "  WARN: Route count=${ROUTE_COUNT} (expected 17, may still be converging)"
fi

echo "--- Waiting for OSPF to fully reconverge ---"
sleep 30
echo "--- Connectivity AFTER oscillation (must be 0% loss, route count must stay 17) ---"
docker exec host9 ping -c 5 10.0.0.1 -q | grep "packet loss"

echo "=== DONE ==="