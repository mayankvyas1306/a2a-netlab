#!/bin/bash

echo ""
echo "=== ARP RATE LIMITING ==="
echo "--- ARP rate-limit flow (permanent, priority=60) ---"
docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0 \
  | grep "priority=60"

echo "--- ARP meter (meter:3, 128 kbps cap) ---"
docker exec sw1 ovs-ofctl -O OpenFlow13 dump-meters br0

echo "--- Sending 1M ARP frames ---"
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
echo "--- ARP flow packet count after flood ---"
docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0 \
  | grep "priority=60"

echo "--- Connectivity maintained after ARP flood ---"
docker exec host1 ping -c 3 20.0.0.1 -q 2>/dev/null | grep "packet loss"

echo "=== DONE ==="