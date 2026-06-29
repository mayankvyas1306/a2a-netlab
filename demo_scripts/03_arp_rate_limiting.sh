echo "--- Sending 1M ARP frames (to trigger DYNAMIC A2A detection, bypassing static meter test separately) ---"
# Temporarily disable static ARP meter cap to let dynamic agent detection fire
docker exec sw1 ovs-ofctl -O OpenFlow13 mod-flows br0 "priority=60,arp,actions=output:normal"
docker exec host1 python3 -c "
import socket, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(('h1s1', 0))
frame = bytes.fromhex(
    'ffffffffffff' +
    'aabbccddeeff' +
    '0806' +
    '00010800060400019999999999990a000001' +
    '0000000000000a000002' +
    '0000' * 9
)
t0 = time.time()
count = 0
while time.time() - t0 < 4:
    s.send(frame)
    count += 1
print(f'Sent {count} ARP frames = {count//4} pps')
s.close()
" 2>/dev/null

sleep 2

echo "--- A2A: dynamic ARP-storm anomaly + policy response ---"
docker exec sw1 grep -E "ARP STORM|ARP storm" /tmp/agent-sw1.log | tail -5
docker exec core1 grep "ARP_STORM" /tmp/agent-core1.log | tail -5

# Restore static meter flow
docker exec sw1 ovs-ofctl -O OpenFlow13 mod-flows br0 "priority=60,arp,actions=meter:3,output:normal"