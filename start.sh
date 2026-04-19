#!/bin/bash
set -e

echo "========================================"
echo "Starting A2A Network Lab"
echo "========================================"

echo "Cleaning previous containers..."
docker ps -a --format '{{.Names}}' | grep -E '^host[0-9]+$'  | xargs -r docker rm -f
docker ps -a --format '{{.Names}}' | grep -E '^sw[0-9]+$'    | xargs -r docker rm -f
docker ps -a --format '{{.Names}}' | grep -E '^core[0-9]+$'  | xargs -r docker rm -f
docker ps -a --format '{{.Names}}' | grep -E '^r[0-9]+$'     | xargs -r docker rm -f

# Ensure a2a-mgmt network exists
docker network inspect a2a-mgmt >/dev/null 2>&1 || \
    docker network create --driver bridge --subnet 172.28.0.0/16 a2a-mgmt

echo "Creating 16 host containers..."
for i in {1..16}; do
    docker run -dit --name host$i --network a2a-mgmt --privileged hpe-netlab
done

echo "Creating 8 switch containers..."
for i in {1..8}; do
    docker run -dit --name sw$i --network a2a-mgmt --privileged hpe-netlab
done

echo "Creating 4 core + 4 transit router containers..."
for r in core1 core2 core3 core4 r1 r2 r3 r4; do
    docker run -dit --name $r --network a2a-mgmt --privileged hpe-netlab
done

sleep 3
echo "Building network topology..."
bash "$(dirname "$0")/network_setup.sh"


echo "Verifying FRR is up on all routers..."
sleep 5
for r in core1 core2 core3 core4 r1 r2 r3 r4; do
    docker exec $r service frr status >/dev/null 2>&1 \
        && echo "  $r: FRR OK" \
        || echo "  $r: FRR not running — check /var/log/frr/ inside container"
done
echo "Waiting for OSPF convergence (max 120s)..."
sleep 8  # Give FRR time to initialise after restart
MAX_RETRIES=40; COUNT=0; OSPF_READY=0
while [ $COUNT -lt $MAX_RETRIES ]; do
    C1=$(docker exec core1 vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -c "Full" | tr -d '\n')
    C2=$(docker exec core2 vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -c "Full" | tr -d '\n')
    C3=$(docker exec core3 vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -c "Full" | tr -d '\n')
    C4=$(docker exec core4 vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -c "Full" | tr -d '\n')
    TOT=$((C1 + C2 + C3 + C4))
    if [ "$TOT" -ge 4 ]; then
        echo "OSPF converged (neighbors: core1=$C1 core2=$C2 core3=$C3 core4=$C4)"
        OSPF_READY=1
        break
    fi
    echo "OSPF not ready yet ($COUNT/$MAX_RETRIES) — neighbors: $C1 $C2 $C3 $C4"
    sleep 3; COUNT=$((COUNT+1))
done
[ $OSPF_READY -eq 0 ] && echo "WARNING: OSPF did not converge in 120s — check frr logs"
echo "Network is UP."