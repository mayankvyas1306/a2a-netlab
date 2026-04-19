#!/bin/bash
set -e

log() { echo "[DEPLOY] $1"; }



# ─────────────────────────────────────────────────────────────
# Helper: get mgmt IP (172.28.x.x)
# ─────────────────────────────────────────────────────────────
get_mgmt_ip() {
    docker inspect -f '{{(index .NetworkSettings.Networks "a2a-mgmt").IPAddress}}' "$1"
}
# ─────────────────────────────────────────────────────────────
# Copy binary
# ─────────────────────────────────────────────────────────────


for i in {1..8}; do
    docker exec sw$i test -f /usr/local/bin/a2a_agent || {
        echo "ERROR: a2a_agent missing in sw$i"
        exit 1
    }
done

log "Using container-built a2a_agent (no copy needed)"

for c in core1 core2 core3 core4 sw1 sw2 sw3 sw4 sw5 sw6 sw7 sw8; do
    docker exec $c test -f /usr/local/bin/a2a_agent || {
        echo "ERROR: a2a_agent missing in $c"
        exit 1
    }
done

# ─────────────────────────────────────────────────────────────
# Assign IPs (your original network — keep for routing)
# ─────────────────────────────────────────────────────────────
log "Assigning data-plane IPs..."

assign_ip() {
    CONTAINER=$1
    IP=$2

    docker exec $CONTAINER ip link show br0 >/dev/null 2>&1 || {
        echo "[SKIP] $CONTAINER has no br0 (not a switch)"
        return
    }

    docker exec $CONTAINER ip addr add $IP dev br0 2>/dev/null || \
        echo "[WARN] $CONTAINER already has IP $IP"
}
# Switches
assign_ip sw1 10.0.0.251/24
assign_ip sw2 10.0.0.252/24
assign_ip sw3 20.0.0.251/24
assign_ip sw4 20.0.0.252/24
assign_ip sw5 30.0.0.251/24
assign_ip sw6 30.0.0.252/24
assign_ip sw7 40.0.0.251/24
assign_ip sw8 40.0.0.252/24

# Gateway IPs on core br0 (in case they were lost between network_setup and here)
assign_core_gw() {
    C=$1; IP=$2
    docker exec $C ip addr show br0 | grep -q "${IP%%/*}" 2>/dev/null || \
        docker exec $C ip addr add $IP dev br0 2>/dev/null || true
    log "$C: ensured gateway $IP on br0"
}
assign_core_gw core1 10.0.0.254/24
assign_core_gw core2 20.0.0.254/24
assign_core_gw core3 30.0.0.254/24
assign_core_gw core4 40.0.0.254/24

# ─────────────────────────────────────────────────────────────
# Get management IPs 
# ─────────────────────────────────────────────────────────────
log "Fetching management IPs..."

CORE1_IP=$(get_mgmt_ip core1)
CORE2_IP=$(get_mgmt_ip core2)
CORE3_IP=$(get_mgmt_ip core3)
CORE4_IP=$(get_mgmt_ip core4)

SW1_IP=$(get_mgmt_ip sw1)
SW2_IP=$(get_mgmt_ip sw2)
SW3_IP=$(get_mgmt_ip sw3)
SW4_IP=$(get_mgmt_ip sw4)
SW5_IP=$(get_mgmt_ip sw5)
SW6_IP=$(get_mgmt_ip sw6)
SW7_IP=$(get_mgmt_ip sw7)
SW8_IP=$(get_mgmt_ip sw8)

echo "[MGMT] core1=$CORE1_IP core2=$CORE2_IP core3=$CORE3_IP core4=$CORE4_IP"

log "Stopping old agents..."

for c in core1 core2 core3 core4 sw1 sw2 sw3 sw4 sw5 sw6 sw7 sw8; do
    docker exec $c pkill a2a_agent 2>/dev/null || true
done

start_agent() {
    local CONTAINER=$1
    local LOGFILE=$2
    shift 2
    # nohup + </dev/null ensures the agent survives bash -c exit and docker-exec detach.
    # Without nohup the process may receive SIGHUP when its parent bash exits.
    docker exec -d $CONTAINER bash -c \
        "nohup /usr/local/bin/a2a_agent $@ >/dev/null 2>$LOGFILE </dev/null &"
    echo "[DEPLOY] Started agent in $CONTAINER → logs: $LOGFILE"
}

log "Verifying OVS is running on all containers..."
OVS_OK=1
for c in core1 core2 core3 core4 sw1 sw2 sw3 sw4 sw5 sw6 sw7 sw8; do
    if ! docker exec $c test -f /var/run/openvswitch/ovs-vswitchd.pid 2>/dev/null; then
        echo "[ERROR] vswitchd not running in $c — attempting restart..."
        docker exec $c bash -c "
            ovs-vswitchd \
                --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
                --log-file=/var/log/openvswitch/ovs-vswitchd.log \
                --detach --no-chdir \
                unix:/var/run/openvswitch/db.sock
            sleep 2
        " || true
        if ! docker exec $c test -f /var/run/openvswitch/ovs-vswitchd.pid 2>/dev/null; then
            echo "[FATAL] Cannot restart vswitchd in $c. Run start.sh again."
            OVS_OK=0
        fi
    else
        echo "  $c: vswitchd OK"
    fi
done
[ "$OVS_OK" -eq 0 ] && echo "[ABORT] Fix OVS before deploying agents." && exit 1

log "Configuring OVS controller listeners..."
for c in core1 core2 core3 core4 sw1 sw2 sw3 sw4 sw5 sw6 sw7 sw8; do
    docker exec $c ovs-vsctl set-controller br0 \
        "punix:/var/run/openvswitch/br0.mgmt" 2>/dev/null || true
    docker exec $c ovs-vsctl set bridge br0 \
        protocols=OpenFlow13 2>/dev/null || true
done
log "OVS controllers configured"

# ─────────────────────────────────────────────────────────────
# Start L3 agents (USING MGMT IP)
# ─────────────────────────────────────────────────────────────
log "Starting L3 agents..."

start_agent core1 /tmp/agent-core1.log \
  "--type l3 --id agent-l3-core1 \
   --host $CORE1_IP --port 7700 --switch core1 --bridge br0 --real-ovs"

start_agent core2 /tmp/agent-core2.log \
  "--type l3 --id agent-l3-core2 \
   --host $CORE2_IP --port 7700 --switch core2 --bridge br0 --real-ovs"

start_agent core3 /tmp/agent-core3.log \
  "--type l3 --id agent-l3-core3 \
   --host $CORE3_IP --port 7700 --switch core3 --bridge br0 --real-ovs"

start_agent core4 /tmp/agent-core4.log \
  "--type l3 --id agent-l3-core4 \
   --host $CORE4_IP --port 7700 --switch core4 --bridge br0 --real-ovs"

sleep 2

# ─────────────────────────────────────────────────────────────
# Start L2 agents (USING MGMT IP + SEEDING)
# ─────────────────────────────────────────────────────────────
log "Starting L2 agents..."

start_agent sw1 /tmp/agent-sw1.log \
  "--type l2 --id agent-l2-sw1 \
   --host $SW1_IP --port 7701 \
   --l3-host $CORE1_IP --l3-port 7700 --switch sw1 --bridge br0 --real-ovs"

start_agent sw2 /tmp/agent-sw2.log \
  "--type l2 --id agent-l2-sw2 \
   --host $SW2_IP --port 7701 \
   --l3-host $CORE1_IP --l3-port 7700 --switch sw2 --bridge br0 --real-ovs"

start_agent sw3 /tmp/agent-sw3.log \
  "--type l2 --id agent-l2-sw3 \
   --host $SW3_IP --port 7701 \
   --l3-host $CORE2_IP --l3-port 7700 --switch sw3 --bridge br0 --real-ovs"

start_agent sw4 /tmp/agent-sw4.log \
  "--type l2 --id agent-l2-sw4 \
   --host $SW4_IP --port 7701 \
   --l3-host $CORE2_IP --l3-port 7700 --switch sw4 --bridge br0 --real-ovs"

start_agent sw5 /tmp/agent-sw5.log \
  "--type l2 --id agent-l2-sw5 \
   --host $SW5_IP --port 7701 \
   --l3-host $CORE3_IP --l3-port 7700 --switch sw5 --bridge br0 --real-ovs"

start_agent sw6 /tmp/agent-sw6.log \
  "--type l2 --id agent-l2-sw6 \
   --host $SW6_IP --port 7701 \
   --l3-host $CORE3_IP --l3-port 7700 --switch sw6 --bridge br0 --real-ovs"

start_agent sw7 /tmp/agent-sw7.log \
  "--type l2 --id agent-l2-sw7 \
   --host $SW7_IP --port 7701 \
   --l3-host $CORE4_IP --l3-port 7700 --switch sw7 --bridge br0 --real-ovs"

start_agent sw8 /tmp/agent-sw8.log \
  "--type l2 --id agent-l2-sw8 \
   --host $SW8_IP --port 7701 \
   --l3-host $CORE4_IP --l3-port 7700 --switch sw8 --bridge br0 --real-ovs"

sleep 3

# ─────────────────────────────────────────────────────────────
# Status
# ─────────────────────────────────────────────────────────────
echo ""
echo "=== AGENT STATUS ==="

for r in core1 core2 core3 core4; do
    COUNT=$(docker exec $r pgrep -c a2a_agent 2>/dev/null || echo 0)
    echo "  $r (L3): $COUNT process(es)"
done

for i in {1..8}; do
    COUNT=$(docker exec sw$i pgrep -c a2a_agent 2>/dev/null || echo 0)
    echo "  sw$i (L2): $COUNT process(es)"
done

echo ""
log "Deployment complete."