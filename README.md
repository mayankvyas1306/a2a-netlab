# A2A NetLab: Distributed Agent-to-Agent Network Control System

---

## What is this project?

This project builds a **distributed network control system** where each network device runs its own intelligent agent. These agents talk to each other using a custom **A2A (Agent-to-Agent) protocol** built from scratch in C.

Instead of one central controller managing everything, **each switch and router has its own agent** that makes decisions locally and coordinates with neighbors. Think of it like every intersection having its own smart traffic light that communicates with nearby intersections — no central traffic command center.

The system handles real network events: MAC learning, broadcast storms, link failures, and agent crashes — all **without any central coordinator**.

---

## Why was this built?

Traditional SDN (Software Defined Networking) depends on a single central controller. If that controller fails, the entire network loses intelligence.

This project proves that **distributed agents can do the same job** — with better resilience. Key properties:

- No single point of failure — each agent makes its own decisions
- Even if 3 out of 4 L3 agents crash, the remaining one keeps its switches working
- Each agent is lightweight (under 5MB RAM), written in C, runs directly on the device
- The system detects link failures, traffic storms, and agent crashes and **automatically recovers** from all of them

---

## Project Structure

```
a2a-netlab/
├── a2a/                          ← All C source code
│   ├── src/
│   │   ├── main.c                ← Program entry point, argument parsing, main event loop
│   │   ├── agent_core/
│   │   │   ├── a2a_agent.c       ← Core agent: peer table, message dispatch, lifecycle
│   │   │   ├── a2a_fsm.c         ← Finite State Machine engine (9 states, 12 events)
│   │   │   ├── a2a_heartbeat.c   ← Peer liveness detection and recovery
│   │   │   └── a2a_event.c       ← Ring-buffer event queue (256 slots)
│   │   ├── a2a_messaging/
│   │   │   ├── a2a_transport.c   ← TCP server using epoll (receives messages)
│   │   │   ├── a2a_connpool.c    ← TCP connection pool (sends messages, reuses connections)
│   │   │   └── a2a_framing.c     ← 4-byte length-prefix message framing
│   │   ├── common/
│   │   │   ├── a2a_serialize.c   ← JSON encode/decode for all message types
│   │   │   └── a2a_log.c         ← Timestamped leveled logging (DEBUG/INFO/WARN/ERROR)
│   │   ├── l2_agent/
│   │   │   └── l2_agent.c        ← L2 switch agent (MAC learning, storm detection, link failover)
│   │   ├── l3_agent/
│   │   │   ├── l3_agent.c        ← L3 router agent (routing, reroute, policy dispatch)
│   │   │   └── l3_netlink.c      ← Linux kernel route/ARP/neighbor monitoring via Netlink
│   │   └── ovs/
│   │       ├── ovs_openflow.c    ← Native binary OpenFlow 1.3 (flow install, PACKET_IN, METER_MOD)
│   │       ├── ovs_ovsdb.c       ← OVSDB JSON-RPC monitor (port stats, link state shadow table)
│   │       └── ovs_interface.c   ← OVS backend abstraction (real vs mock selection)
│   ├── include/                  ← All header files
│   │   ├── a2a_agent.h
│   │   ├── a2a_message.h         
│   │   ├── a2a_fsm.h
│   │   ├── a2a_event.h
│   │   ├── a2a_transport.h
│   │   ├── a2a_connpool.h
│   │   ├── a2a_heartbeat.h
│   │   ├── a2a_log.h
│   │   ├── a2a_serialize.h
│   │   ├── a2a_framing.h
│   │   ├── a2a_discovery.h
│   │   ├── l2_agent.h
│   │   ├── l3_agent.h
│   │   └── ovs_interface.h
│   ├── tests/
│   │   ├── test_serialize.c      ← Unit test: JSON encode/decode roundtrip
│   │   ├── test_transport.c      ← Unit test: TCP ping/pong between two agents
│   │   └── test_integration.c    ← Integration test: L2+L3 registration handshake
│   └── CMakeLists.txt            ← Build configuration
├── Dockerfile                    ← Container image (Ubuntu 22.04 + OVS + FRR + agent binary)
├── demo_scripts/                 ← Standalone scripts 
|   ├── 01_baseline_connectivity.sh
|   ├── 02_mac_learning.sh
|   ├── 03_arp_rate_limiting.sh
|   ├── 04_broadcast_storm.sh
|   ├── 05_mac_spoof_detection.sh
|   ├── 06_link_down_reroute.sh
|   └── 07_nud_failed_degradation.sh
├── start.sh                      ← Start all 28 containers and build topology
├── deploy_agents.sh              ← Start all 12 agents across containers
├── network_setup.sh              ← Create veth links, configure OVS, assign IPs, start OSPF
├── setup_mgmt_net.sh             ← Create Docker management network (172.28.0.0/16)
├── verify_agents.sh              ← Check all 12 agents are running and reachable
└── verify_dataplane.sh           ← Test network connectivity and agent health
```

---

## Technology Stack

| Technology | What it is | Why used here |
|---|---|---|
| **C language** | Low-level systems programming | Lightweight, fast, no garbage collector, under 5MB RAM per agent |
| **Docker** | Container platform | Each network device runs in its own isolated container |
| **Open vSwitch (OVS)** | Software-based network switch | Acts as the virtual switch/router in each container |
| **OpenFlow 1.3** | Protocol to program flows in OVS | Used to install/remove/modify forwarding rules directly via binary socket |
| **OVSDB** | OVS configuration database | Used to monitor port link state and interface statistics |
| **Netlink** | Linux kernel interface for network events | L3 agent subscribes to route changes, ARP updates, link state changes |
| **OSPF via FRR** | Dynamic routing protocol | Automatically propagates routes between core routers |
| **JSON over TCP** | A2A message format | Human-readable, easy to debug, reliable delivery |
| **epoll** | Linux event notification | Single-threaded non-blocking event loop — same architecture as nginx and Redis |
| **cJSON** | Lightweight C JSON library | Serializes and deserializes all A2A protocol messages |

---

## Network Topology

```
Subnet 10.0.0.0/24                    Subnet 20.0.0.0/24
────────────────────                   ────────────────────
host1 (10.0.0.1) ─┐                    host5 (20.0.0.1) ─┐
host3 (10.0.0.3) ─┤ ── sw1 ─┐          host7 (20.0.0.3) ─┤ ── sw3 ─┐
host4 (10.0.0.4) ─┘         ├── core1  host8 (20.0.0.4) ─┘         ├── core2
host2 (10.0.0.2) ──── sw2 ──┘          host6 (20.0.0.2) ──── sw4 ──┘

Subnet 30.0.0.0/24                    Subnet 40.0.0.0/24
────────────────────                   ────────────────────
host9  (30.0.0.1) ─┐                  host13 (40.0.0.1) ─┐
host11 (30.0.0.3) ─┤── sw5 ─┐         host15 (40.0.0.3) ─┤── sw7 ─┐
host12 (30.0.0.4) ─┘         ├── core3 host16 (40.0.0.4) ─┘         ├── core4
host10 (30.0.0.2) ──── sw6 ──┘         host14 (40.0.0.2) ──── sw8 ──┘

Core router ring:
core1 ──(100.0.0.0/30)── core2 ──(100.0.0.4/30)── core3 ──(100.0.0.8/30)── core4

Transit router ring (for redundant paths):
r1 ──── r2 ──── r3 ──── r4 ──── r1 (loop)
each connected to its core router (core1↔r1, core2↔r2, core3↔r3, core4↔r4)
```

**Total containers: 28**
- 16 host containers (actual end-point machines)
- 8 switch containers (sw1 through sw8, each running OVS)
- 4 core router containers (core1 through core4, running OVS + OSPF)
- 4 transit router containers (r1 through r4, running OSPF only)

Each pair of switches shares one core router. sw1 and sw2 both connect to core1. core1 holds the gateway IP 10.0.0.254/24 on its OVS bridge.

---

##  Agent Deployment

**12 agents total** — same compiled binary `a2a_agent`, different startup flags:

- **8 L2 agents** — one per switch (sw1-sw8), listen on port **7701**
- **4 L3 agents** — one per core router (core1-core4), listen on port **7700**

```bash
# L3 agent on core1
/usr/local/bin/a2a_agent --type l3 --id agent-l3-core1 \
  --host <core1-mgmt-ip> --port 7700 --switch core1 --bridge br0 --real-ovs

# L2 agent on sw1 (seeded with core1's address for discovery)
/usr/local/bin/a2a_agent --type l2 --id agent-l2-sw1 \
  --host <sw1-mgmt-ip> --port 7701 \
  --l3-host <core1-mgmt-ip> --l3-port 7700 --switch sw1 --bridge br0 --real-ovs
```

L3 agents start first. L2 agents register with their core router, then discover
sibling switches via `MSG_PEER_LIST`.

---

##  A2A Protocol — Wire Format

Every message: **4-byte big-endian length prefix + JSON body**
[4 bytes: body length][JSON message body]

```json
{
  "msg_id": 42,
  "src_agent": "agent-l2-sw1",
  "dst_agent": "agent-l3-core1",
  "msg_type": 40,
  "timestamp_us": 1716099712000,
  "payload": "{...}"
}
```

### Message Types
| ID | Name | Direction | Purpose |
|---|---|---|---|
| 3 | MSG_REGISTER | any→any | "I exist, here's my info" |
| 4 | MSG_REGISTER_ACK | any→any | "Got your registration" |
| 5 | MSG_HEARTBEAT | any→any | "I'm alive" (every 3s) |
| 6 | MSG_PEER_LIST | any→any | "Here are other peers I know" |
| 10 | MSG_L2_EVENT | L2→L3 | General switch event |
| 11 | MSG_L3_EVENT | L3→L3/L2 | Route advertised/withdrawn |
| 20 | MSG_FLOW_INSTALL | L3→L2 | "Install this OpenFlow rule" |
| 30 | MSG_TOPOLOGY | L3→L2 | "Route changed, update records" |
| 40 | MSG_L2_ANOMALY | L2→L3 | "I detected a problem" |
| 41 | MSG_POLICY_CMD | L3→L2 | "Apply this fix" |

### Anomaly Types (inside MSG_L2_ANOMALY)
| Type | Meaning | L3 Response |
|---|---|---|
| 1 (STORM) | Broadcast storm, pps ≥ 1000 | Reroute + rate-limit |
| 2 (ROUTE_OSCILLATION, sent L3→L2) | Route flapping detected | Notify peers |
| 3 (MAC_SPOOF) | Same MAC seen on different port | Send BLACKHOLE_MAC |
| 4 (LINK_DOWN) | Port link went down | Reroute around switch |
| 5 (STORM_CLEAR) | pps dropped below ~100 | Restore port |
| 6 (LINK_UP) | Port link restored | Restore routes for switch |

### Policy Types (inside MSG_POLICY_CMD)
| Type | What L2 does |
|---|---|
| 1 - RATE_LIMIT | Install OpenFlow meter, cap traffic |
| 2 - ISOLATE_PORT | Drop traffic from port (never on uplinks) |
| 3 - BLACKHOLE_MAC | Drop flow matching `dl_src=<MAC>` |
| 4 - RESTORE_PORT | Remove meter/flow, restore normal |
| 5 - FLUSH_PORT | Delete all learned flows |

---

## State Machine (FSM) — How Agents Progress

Every agent has a **9-state, 12-event FSM**. All 108 state+event combinations are pre-registered at startup. Invalid transitions are logged and counted but never crash the agent.

```
States: INIT → DISCOVERY → REGISTERING → ACTIVE ↔ RECEIVING
                                            ↑              ↓
                                         DEGRADED <---- PEER_TIMEOUT
                                         ERROR    <---- any error
                                         SHUTDOWN <---- SIGTERM
```

**Normal startup flow:**

```
INIT
  → (START event) → DISCOVERY
  → (seed peer address given via --l3-host) → PEER_DISCOVERED event queued
  → REGISTERING (action: send MSG_REGISTER to seed peer)
  → (MSG_REGISTER_ACK received) → ACTIVE
  → (MSG_L2_ANOMALY received) → RECEIVING (action: process message)
  → (PROCESSING_DONE) → ACTIVE
```

**FSM events:**

| Event | What triggers it |
|---|---|
| START | Agent creation, fired once at startup |
| PEER_DISCOVERED | New peer found (via seed address or PEER_LIST) |
| REGISTERED | MSG_REGISTER_ACK received |
| MSG_RECEIVED | Any inbound A2A message arrives on TCP socket |
| PROCESSING_DONE | Message handler finished, return to ACTIVE |
| HEARTBEAT_TICK | Every 3 seconds from main loop timer |
| PEER_TIMEOUT | Peer missed 5 consecutive heartbeats (15 seconds) |
| OVS_EVENT | PACKET_IN, link-down, or anomaly from OVS/OVSDB |
| ERROR | Unrecoverable error |
| SHUTDOWN | SIGTERM or SIGINT received |

---

## L2 Agent — Full Responsibility Table

| Responsibility | Mechanism |
|---|---|
| MAC learning | Receives PACKET_IN via OpenFlow socket → installs FLOW_MOD (priority=10, idle_timeout=300, `dl_dst=<MAC>` → `output:<port>`) |
| Storm detection | Polls port stats every 50ms via OVSDB → calculates pps. ≥1000 pps = storm, <200 pps = cleared |
| Storm mitigation | Installs METER_MOD (dynamic rate cap) + flow `in_port=<port> → meter:4,output:normal` |
| MAC flood detection | Counts distinct MACs per port per 2s window, alert if >50 |
| MAC spoof detection | Tracks port-per-MAC; if a MAC moves to a different port → reports MAC_SPOOF |
| Link failure detection | OVSDB monitor pushes link state change in <1ms |
| Link failover | Flushes MAC table, reinstalls table-miss + permanent flows, floods via remaining ports |
| Alerting | Sends typed `MSG_L2_ANOMALY` to all known L3 peers |

---

## L3 Agent — Full Responsibility Table

| Responsibility | Mechanism |
|---|---|
| Route monitoring | Subscribes to kernel via Netlink (`RTM_NEWROUTE`/`RTM_DELROUTE`) |
| OVS flow installation | Installs IP forwarding flows: `dec_ttl + mod_dl_dst + mod_dl_src + output:<port>` |
| ARP resolution | Listens for `RTM_NEWNEIGH`, caches nexthop MACs, reinstalls flows once ARP resolves |
| Anomaly handling | Receives `MSG_L2_ANOMALY`, decides action per anomaly type |
| Route failover | Finds alternate route, withdraws old flow, installs new flow |
| NUD_FAILED handling | Marks routes DEGRADED when nexthop unreachable; auto-restores when ARP re-resolves |
| Route oscillation detection | If a prefix has 2+ withdrawals + 2+ installs within 60s → flags oscillation, measures convergence time |
| Policy dispatch | Sends `MSG_POLICY_CMD` (rate-limit / blackhole / restore) back to L2 agents |

---
## How to Build

```bash
# 1. Clone or copy the project
cd ~/a2a-netlab

# 2. Build the Docker image (takes ~60-100 seconds the first time)
docker build --no-cache -t hpe-netlab .

# Expected last line:
# naming to docker.io/library/hpe-netlab
```

The Dockerfile:
- Starts from Ubuntu 22.04
- Installs: iproute2, iputils-ping, openvswitch-switch, frr, libcjson-dev, gcc, cmake
- Copies `a2a/` source into the image
- Compiles with CMake → produces `/usr/local/bin/a2a_agent`
- The same image is used for all 28 containers

---

## How to Build & Run

### Prerequisites
- Ubuntu 22.04 (or compatible Linux with Docker)
- Docker installed, sudo access
- ~4GB free RAM (28 containers)

### Step 1 — Clone
```bash
git clone https://github.com/<your-username>/a2a-netlab.git
cd a2a-netlab
```

### Step 2 — Build the agent image ( first time)
```bash
docker build --no-cache -t hpe-netlab .
```
Expected last line: `naming to docker.io/library/hpe-netlab`

### Step 3 — Start the topology ( minutes)
```bash
sudo bash start.sh
```
This creates all 28 containers, builds veth links, configures OVS, starts OSPF,
and waits for OSPF convergence.

Expected last lines:
OSPF converged (neighbors: core1=2 core2=3 core3=3 core4=2)

Network is UP.

### Step 4 — Deploy all 12 agents
```bash
bash deploy_agents.sh
```
Expected: all 12 containers show `1 process(es)`.

### Step 5 — Wait for registration
```bash
sleep 15
```

### Step 6 — Verify
```bash
bash verify_agents.sh
bash verify_dataplane.sh
```

---

## Running the Demo Scripts

The `demo_scripts/` folder contains one standalone script per use case — run them
in order, independently:

```bash
chmod +x demo_scripts/*.sh

bash demo_scripts/01_baseline_connectivity.sh
bash demo_scripts/02_mac_learning.sh
bash demo_scripts/03_arp_rate_limiting.sh
bash demo_scripts/04_broadcast_storm.sh
bash demo_scripts/05_mac_spoof_detection.sh
bash demo_scripts/06_link_down_reroute.sh
bash demo_scripts/07_nud_failed_degradation.sh
bash demo_scripts/08_route_oscillation.sh
```

---

## Monitoring & Debugging

```bash
# Live agent log (any container)
docker exec sw1 tail -f /tmp/agent-sw1.log
docker exec core1 tail -f /tmp/agent-core1.log

# Trigger a full state dump (route table, peer table, MAC table, stats)
docker exec core1 pkill -SIGUSR1 a2a_agent
docker exec core1 tail -30 /tmp/agent-core1.log

# Watch OVS flows live
watch -n 3 "docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0"

# Watch kernel routes
watch -n 2 "docker exec core1 ip route show"

# Watch all anomalies + decisions on a core router
docker exec core1 tail -f /tmp/agent-core1.log | \
  grep -E "anomaly|Decision|STORM|LINK|reroute|DEGRADED|OSCILLATION"
```

### What healthy logs look like
Heartbeat (every ~15s in log, sent every 3s)
[HB] [agent-l2-sw1] → agent-l3-core1 HB ok (uptime=300s peers=2)
MAC learning
[OF] [br0] MAC learned: aa:bb:cc:dd:00:01 port=3
Storm → reroute → rate-limit
[L2] STORM DETECTED port=2 pps=12500

[L3] anomaly from agent-l2-sw1 type=1 port=2 pps=12500

[L3] Decision: STORM → reroute + rate limit

[L2] Rate limit applied on port 2
MAC spoof → blackhole
[L3] anomaly from agent-l2-sw1 type=3 port=3 pps=3

[L3] Sent BLACKHOLE_MAC for <mac> to switch sw1
Link down → reroute
[OVSDB] LINK DOWN: if=s1c1 ofport=1

[L3] Decision: LINK_DOWN → reroute
Route oscillation
[L3] ROUTE OSCILLATION DETECTED: 100.0.0.0/30 (2 withdrawals + 2 installs in 60s)

---

##  Shutdown / Cleanup

```bash
# Graceful agent stop (prints final stats)
for c in core1 core2 core3 core4 sw1 sw2 sw3 sw4 sw5 sw6 sw7 sw8; do
  docker exec $c pkill -TERM a2a_agent 2>/dev/null || true
done

# Full container cleanup
docker rm -f $(docker ps -aq) 2>/dev/null

# Or just re-run start.sh — it cleans automatically
sudo bash start.sh
```

---
