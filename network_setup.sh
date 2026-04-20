#!/bin/bash
set -e
log()  { echo "[NET] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

echo "STEP 1: CREATING NETWORK LINKS"
create_link() {
    C1=$1; I1=$2; C2=$3; I2=$4
    PID1=$(docker inspect -f '{{.State.Pid}}' $C1 2>/dev/null) || fail "Cannot get PID for $C1"
    PID2=$(docker inspect -f '{{.State.Pid}}' $C2 2>/dev/null) || fail "Cannot get PID for $C2"
    ip link add $I1 type veth peer name $I2
    ip link set $I1 netns $PID1
    ip link set $I2 netns $PID2
    nsenter -t $PID1 -n ip link set $I1 up
    nsenter -t $PID2 -n ip link set $I2 up
    log "Linked $C1:$I1 <-> $C2:$I2"
}

create_link host1 h1s1 sw1 s1h1
create_link host2 h2s2 sw2 s2h2
create_link host3 h3s1 sw1 s1h3
create_link host4 h4s1 sw1 s1h4
create_link host5 h5s3 sw3 s3h5
create_link host6 h6s4 sw4 s4h6
create_link host7 h7s3 sw3 s3h7
create_link host8 h8s3 sw3 s3h8
create_link host9  h9s5  sw5 s5h9
create_link host10 h10s6 sw6 s6h10
create_link host11 h11s5 sw5 s5h11
create_link host12 h12s5 sw5 s5h12
create_link host13 h13s7 sw7 s7h13
create_link host14 h14s8 sw8 s8h14
create_link host15 h15s7 sw7 s7h15
create_link host16 h16s7 sw7 s7h16
create_link sw1 s1s2 sw2 s2s1
create_link sw3 s3s4 sw4 s4s3
create_link sw5 s5s6 sw6 s6s5
create_link sw7 s7s8 sw8 s8s7
create_link sw1 s1c1 core1 c1s1
create_link sw3 s3c2 core2 c2s3
create_link sw5 s5c3 core3 c3s5
create_link sw7 s7c4 core4 c4s7
create_link core1 c1c2 core2 c2c1
create_link core2 c2c3 core3 c3c2
create_link core3 c3c4 core4 c4c3
create_link core1 c1r1 r1 r1c1
create_link core2 c2r2 r2 r2c2
create_link core3 c3r3 r3 r3c3
create_link core4 c4r4 r4 r4c4
create_link r1 r1r2 r2 r2r1
create_link r2 r2r3 r3 r3r2
create_link r3 r3r4 r4 r4r3
create_link r4 r4r1 r1 r1r4


echo "STEP 2: CONFIGURING OVS SWITCHES"
configure_ovs_switch() {
    SW=$1
    log "Configuring OVS on $SW"
    docker exec $SW bash -c "
        mkdir -p /var/run/openvswitch /etc/openvswitch /var/log/openvswitch

        # Stop any existing instances cleanly
        ovs-appctl exit 2>/dev/null || true
        pkill ovsdb-server 2>/dev/null || true
        pkill ovs-vswitchd 2>/dev/null || true
        sleep 1
        rm -f /var/run/openvswitch/*.pid /var/run/openvswitch/*.ctl
        rm -f /var/run/openvswitch/db.sock

        # Create fresh DB
        ovsdb-tool create /etc/openvswitch/conf.db \
            /usr/share/openvswitch/vswitch.ovsschema

        # Start OVSDB server
        ovsdb-server \
            /etc/openvswitch/conf.db \
            --remote=punix:/var/run/openvswitch/db.sock \
            --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
            --pidfile=/var/run/openvswitch/ovsdb-server.pid \
            --log-file=/var/log/openvswitch/ovsdb-server.log \
            --detach --no-chdir
        sleep 1

        ovs-vsctl --no-wait init

        # Start vswitchd — force userspace datapath to avoid
        # conflict with host kernel OVS module
        ovs-vswitchd \
            --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
            --log-file=/var/log/openvswitch/ovs-vswitchd.log \
            --detach --no-chdir \
            unix:/var/run/openvswitch/db.sock

        # Wait until vswitchd is ready (up to 10s)
        for i in \$(seq 1 10); do
            ovs-vsctl show >/dev/null 2>&1 && break
            sleep 1
        done

        ovs-vsctl add-br br0
        ovs-vsctl set bridge br0 fail-mode=standalone
        ovs-vsctl set bridge br0 datapath_type=netdev
    "
    #  use fail-mode=standalone so basic L2 forwarding works even before
    # the A2A agent connects. The agent installs higher-priority flows on top.
    for iface in $(docker exec $SW ls /sys/class/net | grep -v -E '^(lo|br0|ovs-system|eth0|ovs-netdev)$'); do
        docker exec $SW bash -c "ip link set $iface up; ovs-vsctl --if-exists del-port br0 $iface; ovs-vsctl add-port br0 $iface"
        log "$SW: added port $iface"
    done
    docker exec $SW ip link set br0 up
      # Verify vswitchd is still alive after all port additions
    if ! docker exec $SW test -f /var/run/openvswitch/ovs-vswitchd.pid; then
        log "WARNING: vswitchd died in $SW during port setup — check /var/log/openvswitch/ovs-vswitchd.log"
    else
        local FLOW_COUNT
        FLOW_COUNT=$(docker exec $SW ovs-ofctl -O OpenFlow13 dump-flows br0 2>/dev/null | grep -c "actions" || echo 0)
        log "$SW: br0 UP, vswitchd alive, $FLOW_COUNT flows"
    fi
}
for i in {1..8}; do configure_ovs_switch sw$i; done

# Core routers need OVS only for the A2A agent (OVSDB monitoring + flow install).
# Their transit interfaces (cXcY, cXrY) MUST stay as plain kernel L3 interfaces
# so OSPF hello packets are processed by the kernel IP stack.
configure_ovs_core() {
    CORE=$1
    ACCESS_IF=$2
    GW_IP=$3
    log "Configuring OVS on $CORE (access-only: $ACCESS_IF)"
    docker exec $CORE bash -c "
        mkdir -p /var/run/openvswitch /etc/openvswitch /var/log/openvswitch

        ovs-appctl exit 2>/dev/null || true
        pkill ovsdb-server 2>/dev/null || true
        pkill ovs-vswitchd 2>/dev/null || true
        sleep 1
        rm -f /var/run/openvswitch/*.pid /var/run/openvswitch/*.ctl
        rm -f /var/run/openvswitch/db.sock

        ovsdb-tool create /etc/openvswitch/conf.db \
            /usr/share/openvswitch/vswitch.ovsschema

        ovsdb-server \
            /etc/openvswitch/conf.db \
            --remote=punix:/var/run/openvswitch/db.sock \
            --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
            --pidfile=/var/run/openvswitch/ovsdb-server.pid \
            --log-file=/var/log/openvswitch/ovsdb-server.log \
            --detach --no-chdir
        sleep 1

        ovs-vsctl --no-wait init

        ovs-vswitchd \
            --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
            --log-file=/var/log/openvswitch/ovs-vswitchd.log \
            --detach --no-chdir \
            unix:/var/run/openvswitch/db.sock

        for i in \$(seq 1 10); do
            ovs-vsctl show >/dev/null 2>&1 && break
            sleep 1
        done

        ovs-vsctl add-br br0
        ovs-vsctl set bridge br0 fail-mode=standalone
        ovs-vsctl set bridge br0 datapath_type=netdev
    "
    docker exec $CORE bash -c "
        ip link set $ACCESS_IF up
        ovs-vsctl --if-exists del-port br0 $ACCESS_IF
        ovs-vsctl add-port br0 $ACCESS_IF
    "
    docker exec $CORE ip link set br0 up
    docker exec $CORE bash -c "
        ip addr del $GW_IP dev br0 2>/dev/null || true
        for i in 1 2 3; do
            ip addr add $GW_IP dev br0 && break
            sleep 1
        done
    "
    log "$CORE: gateway $GW_IP assigned to br0"
}
configure_ovs_core core1 c1s1 10.0.0.254/24
configure_ovs_core core2 c2s3 20.0.0.254/24
configure_ovs_core core3 c3s5 30.0.0.254/24
configure_ovs_core core4 c4s7 40.0.0.254/24

echo "STEP 3: CONFIGURING IPs"
docker exec host1  bash -c "ip addr add 10.0.0.1/24  dev h1s1"
docker exec host2  bash -c "ip addr add 10.0.0.2/24  dev h2s2"
docker exec host3  bash -c "ip addr add 10.0.0.3/24  dev h3s1"
docker exec host4  bash -c "ip addr add 10.0.0.4/24  dev h4s1"
docker exec host5  bash -c "ip addr add 20.0.0.1/24  dev h5s3"
docker exec host6  bash -c "ip addr add 20.0.0.2/24  dev h6s4"
docker exec host7  bash -c "ip addr add 20.0.0.3/24  dev h7s3"
docker exec host8  bash -c "ip addr add 20.0.0.4/24  dev h8s3"
docker exec host9  bash -c "ip addr add 30.0.0.1/24  dev h9s5"
docker exec host10 bash -c "ip addr add 30.0.0.2/24  dev h10s6"
docker exec host11 bash -c "ip addr add 30.0.0.3/24  dev h11s5"
docker exec host12 bash -c "ip addr add 30.0.0.4/24  dev h12s5"
docker exec host13 bash -c "ip addr add 40.0.0.1/24  dev h13s7"
docker exec host14 bash -c "ip addr add 40.0.0.2/24  dev h14s8"
docker exec host15 bash -c "ip addr add 40.0.0.3/24  dev h15s7"
docker exec host16 bash -c "ip addr add 40.0.0.4/24  dev h16s7"
docker exec core1 bash -c "ip addr add 100.0.0.1/30  dev c1c2"
docker exec core2 bash -c "ip addr add 100.0.0.2/30  dev c2c1"
docker exec core2 bash -c "ip addr add 100.0.0.5/30  dev c2c3"
docker exec core3 bash -c "ip addr add 100.0.0.6/30  dev c3c2"
docker exec core3 bash -c "ip addr add 100.0.0.9/30  dev c3c4"
docker exec core4 bash -c "ip addr add 100.0.0.10/30 dev c4c3"
docker exec core1 bash -c "ip addr add 100.0.1.1/30  dev c1r1"
docker exec r1    bash -c "ip addr add 100.0.1.2/30  dev r1c1"
docker exec core2 bash -c "ip addr add 100.0.1.5/30  dev c2r2"
docker exec r2    bash -c "ip addr add 100.0.1.6/30  dev r2c2"
docker exec core3 bash -c "ip addr add 100.0.1.9/30  dev c3r3"
docker exec r3    bash -c "ip addr add 100.0.1.10/30 dev r3c3"
docker exec core4 bash -c "ip addr add 100.0.1.13/30 dev c4r4"
docker exec r4    bash -c "ip addr add 100.0.1.14/30 dev r4c4"
docker exec r1 bash -c "ip addr add 100.0.2.1/30  dev r1r2"
docker exec r2 bash -c "ip addr add 100.0.2.2/30  dev r2r1"
docker exec r2 bash -c "ip addr add 100.0.2.5/30  dev r2r3"
docker exec r3 bash -c "ip addr add 100.0.2.6/30  dev r3r2"
docker exec r3 bash -c "ip addr add 100.0.2.9/30  dev r3r4"
docker exec r4 bash -c "ip addr add 100.0.2.10/30 dev r4r3"
docker exec r4 bash -c "ip addr add 100.0.2.13/30 dev r4r1"
docker exec r1 bash -c "ip addr add 100.0.2.14/30 dev r1r4"


# Ensure all transit (inter-core + uplink) interfaces are UP as kernel L3.
for PAIR in core1:c1c2 core1:c1r1 core2:c2c1 core2:c2c3 core2:c2r2 \
            core3:c3c2 core3:c3c4 core3:c3r3 core4:c4c3 core4:c4r4; do
    C="${PAIR%%:*}"; IF="${PAIR##*:}"
    docker exec $C ip link set $IF up 2>/dev/null || true
done
for PAIR in r1:r1c1 r1:r1r2 r1:r1r4 r2:r2c2 r2:r2r1 r2:r2r3 \
            r3:r3c3 r3:r3r2 r3:r3r4 r4:r4c4 r4:r4r3 r4:r4r1; do
    R="${PAIR%%:*}"; IF="${PAIR##*:}"
    docker exec $R ip link set $IF up 2>/dev/null || true
done

echo "STEP 4: IP FORWARDING"
for r in core1 core2 core3 core4 r1 r2 r3 r4; do
    docker exec $r sysctl -w net.ipv4.ip_forward=1 > /dev/null
done

echo "STEP 5: OSPF"
configure_ospf() {
    R=$1; RID=$2
    docker exec $R bash -c "cat > /etc/frr/frr.conf << 'OSPFEOF'
frr version 8
hostname $R
service integrated-vtysh-config
router ospf
 router-id $RID
 network 0.0.0.0/0 area 0
 passive-interface default
 no passive-interface c1s1
 no passive-interface c2s3
 no passive-interface c3s5
 no passive-interface c4s7
 no passive-interface br0
 no passive-interface c1c2
 no passive-interface c2c1
 no passive-interface c2c3
 no passive-interface c3c2
 no passive-interface c3c4
 no passive-interface c4c3
 no passive-interface c1r1
 no passive-interface c2r2
 no passive-interface c3r3
 no passive-interface c4r4
 no passive-interface r1c1
 no passive-interface r2c2
 no passive-interface r3c3
 no passive-interface r4c4
 no passive-interface r1r2
 no passive-interface r2r1
 no passive-interface r2r3
 no passive-interface r3r2
 no passive-interface r3r4
 no passive-interface r4r3
 no passive-interface r4r1
 no passive-interface r1r4
OSPFEOF"
    docker exec $R sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons
    docker exec $R sed -i 's/zebra=no/zebra=yes/' /etc/frr/daemons
    docker exec $R service frr restart
    log "OSPF on $R (id=$RID)"
}
configure_ospf core1 1.1.1.1
configure_ospf core2 2.2.2.2
configure_ospf core3 3.3.3.3
configure_ospf core4 4.4.4.4
configure_ospf r1    11.11.11.11
configure_ospf r2    22.22.22.22
configure_ospf r3    33.33.33.33
configure_ospf r4    44.44.44.44

echo "STEP 6: DEFAULT GATEWAYS"
for i in {1..4};   do docker exec host$i  ip route replace default via 10.0.0.254; done
for i in {5..8};   do docker exec host$i  ip route replace default via 20.0.0.254; done
for i in {9..12};  do docker exec host$i  ip route replace default via 30.0.0.254; done
for i in {13..16}; do docker exec host$i  ip route replace default via 40.0.0.254; done

echo "NETWORK SETUP COMPLETE"