#!/bin/bash
PASS=0; FAIL=0
chk() {
    if eval "$2" >/dev/null 2>&1; then
        echo "  PASS: $1"; PASS=$((PASS+1))
    else
        echo "  FAIL: $1"; FAIL=$((FAIL+1))
    fi
}
echo "=== AGENT VERIFICATION ==="
for r in core1 core2 core3 core4; do
    chk "$r has L3 agent" "docker exec $r pgrep a2a_agent"
done
for i in {1..8}; do
    chk "sw$i has L2 agent" "docker exec sw$i pgrep a2a_agent"
done
echo ""
# Use management network IPs — agents bind on the mgmt interface
get_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $1; }

CORE1_IP=$(get_ip core1)
CORE2_IP=$(get_ip core2)
CORE3_IP=$(get_ip core3)
CORE4_IP=$(get_ip core4)

chk "sw1 can reach core1:7700 (mgmt)" \
    "docker exec sw1 bash -c \"echo x | nc -w2 $CORE1_IP 7700\""
chk "sw3 can reach core2:7700 (mgmt)" \
    "docker exec sw3 bash -c \"echo x | nc -w2 $CORE2_IP 7700\""
chk "sw5 can reach core3:7700 (mgmt)" \
    "docker exec sw5 bash -c \"echo x | nc -w2 $CORE3_IP 7700\""
chk "sw7 can reach core4:7700 (mgmt)" \
    "docker exec sw7 bash -c \"echo x | nc -w2 $CORE4_IP 7700\""

# Also verify log files exist and are non-empty
for c in core1 core2 core3 core4; do
    chk "$c agent log non-empty" \
        "docker exec $c test -s /tmp/agent-$c.log"
done
for i in {1..8}; do
    chk "sw$i agent log non-empty" \
        "docker exec sw$i test -s /tmp/agent-sw$i.log"
done
echo ""
echo "RESULT: PASS=$PASS  FAIL=$FAIL"