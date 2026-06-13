#!/bin/bash
# Demonstrates: cross-subnet connectivity works end to end
echo "=== BASELINE CONNECTIVITY (must all be 0% loss) ==="
echo "--- host1 -> 20.0.0.1 (cross subnet) ---"
docker exec host1 ping -c 3 20.0.0.1 -q | grep "packet loss"

echo "--- host1 -> 30.0.0.1 (cross subnet) ---"
docker exec host1 ping -c 3 30.0.0.1 -q | grep "packet loss"

echo "--- host9 -> 10.0.0.1 (cross subnet) ---"
docker exec host9 ping -c 3 10.0.0.1 -q | grep "packet loss"

echo "=== DONE ==="