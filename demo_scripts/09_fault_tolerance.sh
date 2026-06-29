#!/bin/bash
# Demonstrates: no single point of failure. Kills agent-l3-core2 entirely;
# shows sw3/sw4 detect the dead peer purely via missed heartbeats (no third
# party involved), shows OVS+OSPF forwarding survive completely untouched
# (the a2a layer is a supplementary anomaly-response layer, NOT the
# forwarding path — unlike a centralized SDN controller, whose death blacks
# out every switch it controls), then shows self-healing recovery.
echo "=== FAULT TOLERANCE: L3 AGENT CRASH (NO SINGLE POINT OF FAILURE) ==="

echo "--- Baseline: cross-subnet reachable via core2 ---"
docker exec host5 ping -c 3 10.0.0.1 -q | grep "packet loss"

echo "--- Killing agent-l3-core2 (simulated crash, SIGKILL) ---"
docker exec core2 pkill -9 a2a_agent

echo "--- Intra-subnet traffic on sw3 unaffected (pure OVS dataplane) ---"
sleep 1
docker exec host5 ping -c 3 -W 2 20.0.0.3 -q | grep "packet loss"

echo " --- forwarding is unaffected ---"
docker exec host5 ping -c 3 -W 2 10.0.0.1 -q | grep "packet loss"

echo "--- Waiting for heartbeat timeout on sw3/sw4 (15s window) ---"
sleep 17

echo "--- Peer timeout detected on sw3 — peer-to-peer, no third party told it ---"
docker exec sw3 tail -80 /tmp/agent-sw3.log | grep -E "peer TIMEOUT|peer timeout"

echo "--- Unaffected agents elsewhere keep heartbeating normally (no cascade) ---"
docker exec core1 tail -5 /tmp/agent-core1.log | grep "HB ok"

echo "--- Restarting agent-l3-core2 (recovery) ---"
CORE2_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' core2)
docker exec -d core2 bash -c \
  "nohup /usr/local/bin/a2a_agent --type l3 --id agent-l3-core2 --host $CORE2_IP --port 7700 --switch core2 --bridge br0 --real-ovs >/dev/null 2>/tmp/agent-core2.log </dev/null &"

echo "--- Waiting for sw3 to re-register (next discovery tick, ~5-8s) ---"
sleep 10

echo "--- Re-registration handshake on sw3 ---"
docker exec sw3 tail -30 /tmp/agent-sw3.log | grep -E "agent-l3-core2"

echo "--- Connectivity fully restored ---"
docker exec host5 ping -c 3 20.0.0.1 -q | grep "packet loss"

echo " --- forwarding is unaffected ---"
docker exec host5 ping -c 3 -W 2 10.0.0.1 -q | grep "packet loss"


echo "=== DONE ==="