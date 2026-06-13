#!/bin/bash

# Demonstrates: MAC spoof detection, blackhole flow install, L3 confirmation
echo "=== MAC SPOOF DETECTION ==="

echo "--- Setting identical MAC on host1 and host3 ---"
docker exec host1 ip link set h1s1 address aa:bb:cc:dd:ee:ff

docker exec host3 ip link set h3s1 address aa:bb:cc:dd:ee:ff

echo "--- Clearing any pre-existing flows for this MAC (both src and dst) ---"

docker exec sw1 ovs-ofctl -O OpenFlow13 del-flows br0 "dl_src=aa:bb:cc:dd:ee:ff" 2>/dev/null

docker exec sw1 ovs-ofctl -O OpenFlow13 del-flows br0 "dl_dst=aa:bb:cc:dd:ee:ff" 2>/dev/null

sleep 1

echo "=== No flows for spoof MAC yet ==="

docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0 | grep "aa:bb:cc:dd:ee:ff" || echo "(none)"

echo "=== Sequential alternating frames ==="

for i in 1 2 3; do

  docker exec host1 python3 -c "

import socket

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)

s.bind(('h1s1',0))

s.send(bytes.fromhex('021411b3a44a'+'aabbccddeeff'+'88b5'+'00'*46))

"

  sleep 0.15

  docker exec host3 python3 -c "

import socket

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)

s.bind(('h3s1',0))

s.send(bytes.fromhex('021411b3a44a'+'aabbccddeeff'+'88b5'+'00'*46))

"

  sleep 0.15

done

sleep 2

echo "=== Spoof detection ==="

docker exec sw1 grep -E "MAC SPOOF|blackholed|MAC moved" /tmp/agent-sw1.log | tail -8

echo "=== Blackhole flow installed ==="

docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0
docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0 | grep "priority=300"

echo "=== L3 confirmation ==="

docker exec core1 grep "BLACKHOLE_MAC" /tmp/agent-core1.log | tail -3

echo "=== Restoring original MACs ==="

docker exec host1 ip link set h1s1 address 02:01:01:01:01:01

docker exec host3 ip link set h3s1 address 02:03:03:03:03:03

docker exec sw1 ovs-ofctl -O OpenFlow13 del-flows br0 "dl_src=aa:bb:cc:dd:ee:ff"

docker exec sw1 ovs-ofctl -O OpenFlow13 del-flows br0 "dl_dst=aa:bb:cc:dd:ee:ff"

sleep 2

echo "=== Flows ==="

docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0
docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0 | grep "priority=300"

echo "=== Connectivity restored ==="

docker exec host1 ping -c 3 10.0.0.2 -q 2>/dev/null | grep "packet loss"

echo "=== DONE ==="
