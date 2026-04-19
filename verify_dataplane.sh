#!/bin/bash
# verify_dataplane.sh — Run after start.sh + deploy_agents.sh to confirm
# the data plane is fully operational.

PASS=0; FAIL=0
chk() {
    if eval "$2" >/dev/null 2>&1; then
        echo "  PASS: $1"; PASS=$((PASS+1))
    else
        echo "  FAIL: $1"; FAIL=$((FAIL+1))
    fi
}

echo "=== DATA PLANE VERIFICATION ==="
echo ""

# ── OVS sanity ─────────────────────────────────────────────────────
echo "--- OVS Health ---"
for i in {1..8}; do
    chk "sw$i ovs-vswitchd running" \
        "docker exec sw$i test -f /var/run/openvswitch/ovs-vswitchd.pid"
done
for c in core1 core2 core3 core4; do
    chk "$c ovs-vswitchd running" \
        "docker exec $c test -f /var/run/openvswitch/ovs-vswitchd.pid"
done
echo ""

# ── Flow tables ────────────────────────────────────────────────────
echo "--- Flow Table Contents (after agents deploy) ---"
for i in 1 3 5 7; do
    N=$(docker exec sw$i ovs-ofctl dump-flows br0 2>/dev/null | grep -v "^NXST\|^OFPST" | wc -l)
    echo "  sw$i: $N flows in table"
    chk "sw$i has flows" "[ $N -gt 0 ]"
done
echo ""

# ── Intra-subnet ping ───────────────────────────────────────────────
echo "--- Intra-subnet Ping ---"
chk "host1 → host3 (10.0.0.1 → 10.0.0.3, same switch sw1)" \
    "docker exec host1 ping -c 3 -W 2 10.0.0.3"
chk "host1 → host4 (10.0.0.1 → 10.0.0.4, same switch sw1)" \
    "docker exec host1 ping -c 3 -W 2 10.0.0.4"
chk "host5 → host7 (20.0.0.1 → 20.0.0.3, same switch sw3)" \
    "docker exec host5 ping -c 3 -W 2 20.0.0.3"
echo ""

# ── Cross-switch intra-subnet ping ──────────────────────────────────
echo "--- Cross-switch Intra-subnet Ping (sw1 ↔ sw2) ---"
chk "host1 → host2 (10.0.0.1 → 10.0.0.2, sw1 → sw2)" \
    "docker exec host1 ping -c 3 -W 2 10.0.0.2"
echo ""

# ── Inter-subnet ping ───────────────────────────────────────────────
echo "--- Inter-subnet Ping (requires OSPF + L3 routing) ---"
chk "host1 → host5 (10.0.0.1 → 20.0.0.1)" \
    "docker exec host1 ping -c 3 -W 3 20.0.0.1"
chk "host1 → host9 (10.0.0.1 → 30.0.0.1)" \
    "docker exec host1 ping -c 3 -W 3 30.0.0.1"
chk "host1 → host13 (10.0.0.1 → 40.0.0.1)" \
    "docker exec host1 ping -c 3 -W 3 40.0.0.1"
echo ""

# ── MAC learning ────────────────────────────────────────────────────
echo "--- MAC Learning ---"
# Trigger traffic then check OVS FDB
docker exec host1 ping -c 2 -W 1 10.0.0.3 >/dev/null 2>&1 || true
sleep 1
MAC_COUNT=$(docker exec sw1 ovs-appctl fdb/show br0 2>/dev/null | grep -v "^port\|^---" | wc -l)
echo "  sw1 FDB entries: $MAC_COUNT"
chk "sw1 has learned MACs (>0 FDB entries)" "[ $MAC_COUNT -gt 0 ]"
echo ""

# ── Agent heartbeats ─────────────────────────────────────────────────
echo "--- A2A Agent Health ---"
for c in core1 core2 core3 core4; do
    chk "$c agent heartbeating" \
        "docker exec $c grep -q 'HB ok' /tmp/agent-$c.log"
done
for i in {1..8}; do
    chk "sw$i agent heartbeating" \
        "docker exec sw$i grep -q 'HB ok' /tmp/agent-sw$i.log"
done
echo ""

# ── Storm detection test ─────────────────────────────────────────────
echo "--- Storm Detection Test ---"
echo "  Sending flood traffic from host1 to trigger storm detection..."
# Use iperf3 UDP flood to host1 itself on the switch (flood at ~10kpps)
docker exec host1 bash -c "
    for i in \$(seq 1 5); do
        ping -f -c 500 -b 10.0.0.255 -W 1 &
    done
    wait
" 2>/dev/null || true
sleep 3
STORM_DETECTED=$(docker exec sw1 grep -c "STORM DETECTED\|storm_detected" /tmp/agent-sw1.log 2>/dev/null || echo 0)
echo "  sw1 storm events: $STORM_DETECTED"
# Note: storm detection requires actual high-PPS traffic through OVS

echo ""
echo "=== RESULTS: PASS=$PASS  FAIL=$FAIL ==="