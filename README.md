# A2A NetLab: Distributed Agent-to-Agent Network Control System

---

## What is this project?

This project builds a **distributed network control system** where each network device runs its own intelligent agent. These agents talk to each other using a custom **A2A (Agent-to-Agent) protocol** built from scratch in C.

Instead of one central controller managing everything, **each switch and router runs its own agent** that makes decisions locally and coordinates with neighbors — like every intersection having its own smart traffic light that talks to nearby intersections, instead of one city-wide traffic command center.

The system detects and reacts to real network events in real time: MAC learning, broadcast storms, ARP storms, MAC spoofing, link failures, nexthop failures, route oscillation, and agent crashes — all without any central coordinator, using nothing but live OVS/OVSDB/OpenFlow state and Linux kernel Netlink events.

---

## Why was this built?

Traditional SDN (Software Defined Networking) depends on a single central controller. If that controller fails, the entire network loses intelligence.

This project tests whether **distributed peer agents can do the same job with better resilience**:

- No single controller failure can black out the whole network — each agent decides independently for its own switch/router.
- Even if an L3 core agent crashes, its L2 children detect the loss via missed heartbeats (peer-to-peer, no third party involved) and the underlying OVS/OSPF dataplane keeps forwarding traffic untouched.
- Each agent is lightweight (a few MB RAM), written in C, compiled once, and deployed identically to every device.
- The system detects failures and traffic anomalies and **automatically remediates** — reroute, rate-limit, blackhole, isolate — without a human or a central brain in the loop.

**NOTE:** Core1 specifically still is a single point of failure for its own subnet subtree (10.0.0.0/24, served by sw1/sw2) — if core1 dies, its L2 children lose their only L3 path until it restarts. This contradicts a broad "zero SPOF" claim and should be disclosed as-is during evaluation, not hidden.

# Project Directory Structure

```text
a2a-netlab/
├── a2a/                                   # Complete C implementation of the A2A distributed agent framework
│   ├── src/                               # All source (.c) files
│   │   ├── main.c                         # Program entry point, argument parsing, initialization, and main event loop
│   │   │
│   │   ├── agent_core/                    # Core agent framework shared by L2 and L3 agents
│   │   │   ├── a2a_agent.c                # Agent lifecycle, peer table management, message dispatch, and initialization
│   │   │   ├── a2a_fsm.c                  # Finite State Machine engine (9 states, 12 events)
│   │   │   ├── a2a_heartbeat.c            # Peer heartbeat transmission, timeout detection, and recovery
│   │   │   └── a2a_event.c                # Ring-buffer event queue implementation (256 event slots)
│   │   │
│   │   ├── a2a_messaging/                 # Reliable Agent-to-Agent communication layer
│   │   │   ├── a2a_transport.c            # TCP server using epoll for receiving messages
│   │   │   ├── a2a_connpool.c             # Outgoing TCP connection pool with connection reuse
│   │   │   └── a2a_framing.c              # 4-byte length-prefixed message framing protocol
│   │   │
│   │   ├── common/                        # Utilities shared by all agents
│   │   │   ├── a2a_serialize.c            # JSON serialization/deserialization for all protocol messages
│   │   │   ├── a2a_log.c                  # Timestamped leveled logging (DEBUG/INFO/WARN/ERROR)
│   │   │   └── a2a_metrics.c              # Runtime metrics collection and JSON dump (SIGUSR1 trigger)
│   │   │
│   │   ├── l2_agent/                      # Layer-2 switch agent implementation
│   │   │   └── l2_agent.c                 # MAC learning, storm detection, spoof detection, flooding detection, and link failover
│   │   │
│   │   ├── l3_agent/                      # Layer-3 router agent implementation
│   │   │   ├── l3_agent.c                 # Routing decisions, anomaly handling, rerouting, policy engine, and failover
│   │   │   └── l3_netlink.c               # Linux Netlink interface for route, ARP, neighbor, and link monitoring
│   │   │
│   │   └── ovs/                           # Open vSwitch integration layer
│   │       ├── ovs_openflow.c             # Native OpenFlow 1.3 implementation (flows, meters, PACKET_IN, statistics)
│   │       ├── ovs_ovsdb.c                # OVSDB JSON-RPC monitor for port status and interface statistics
│   │       └── ovs_interface.c            # Backend abstraction for real OVS and mock OVS implementations
│   │
│   ├── include/                           # All project header (.h) files
│   │
│   ├── tests/                             # Unit tests, integration tests, and deployment verification scripts
│   │   ├── test_serialize.c               # Unit test for JSON encode/decode round-trip validation
│   │   ├── test_transport.c               # Unit test for TCP communication between two agents
│   │   ├── test_integration.c             # Integration test for L2-L3 agent registration and handshake
│   │   ├── verify_agents.sh               # Verifies all 12 A2A agents are running and mutually reachable
│   │   └── verify_dataplane.sh            # Verifies network connectivity, MAC learning, routing, and overall dataplane health
│   │
│   └── CMakeLists.txt                     # CMake build configuration for compiling the complete A2A project
│
├── Dockerfile                             # Docker image definition (Ubuntu 22.04 + OVS + FRR + A2A agent)
│
├── initial_scripts/                       # One-time scripts used to create and initialize the complete network topology
│   ├── start.sh                           # Creates all 32 Docker containers and starts the entire network topology
│   ├── deploy_agents.sh                   # Launches all 12 A2A agents inside their respective containers
│   └── network_setup.sh                   # Creates veth links, configures OVS bridges, assigns IPs, and starts OSPF
│
└── demo_scripts/                          # Standalone demonstration scripts showcasing every implemented feature
    ├── 01_baseline_connectivity.sh        # Verifies end-to-end network connectivity before demonstrations
    ├── 02_mac_learning.sh                 # Demonstrates dynamic MAC learning and OpenFlow rule installation
    ├── 03_arp_rate_limiting.sh            # Demonstrates ARP storm detection and automatic rate limiting
    ├── 04_broadcast_storm.sh              # Demonstrates broadcast storm detection and mitigation
    ├── 05_mac_spoof_detection.sh          # Demonstrates MAC spoof detection and automatic blackholing
    ├── 06_link_down_reroute.sh            # Demonstrates automatic rerouting after a link failure
    ├── 07_nud_failed_degradation.sh       # Demonstrates nexthop failure (NUD_FAILED) detection and route degradation
    ├── 08_route_oscillation.sh            # Demonstrates route oscillation detection and convergence handling
    ├── 09_fault_tolerance.sh              # Demonstrates peer heartbeat recovery and distributed fault tolerance
    └── 99_shutdown.sh                     # Gracefully stops all agents and cleans up the demonstration environment
```

## Technology Stack

| Technology | What it is | Why used here |
|---|---|---|
| **C language** | Low-level systems programming | Lightweight, fast, no garbage collector, small RAM footprint per agent |
| **Docker** | Container platform | Each network device (host/switch/router) runs in its own isolated container |
| **Open vSwitch (OVS)** | Software-based network switch | Acts as the virtual switch/router in each container |
| **OpenFlow 1.3** | Protocol to program flows in OVS | Installs/removes/modifies forwarding rules directly over a raw binary socket — no `ovs-ofctl` subprocess calls |
| **OVSDB** | OVS configuration database | Monitored via JSON-RPC to track port link state and interface statistics |
| **Netlink** | Linux kernel networking interface | L3 agent subscribes to route changes, ARP/neighbor updates, link state changes directly from the kernel |
| **OSPF via FRR** | Dynamic routing protocol | Automatically propagates routes between the 4 core routers and 4 transit routers |
| **JSON over TCP** | A2A message format | Human-readable, easy to debug, delivered over reliable length-prefixed TCP framing |
| **epoll** | Linux event notification | Single-threaded, non-blocking event loop — the same architecture pattern used by nginx and Redis |
| **cJSON** | Lightweight C JSON library | Serializes and deserializes every A2A protocol message |

---

## Network Topology
```
Subnet 10.0.0.0/24                      Subnet 20.0.0.0/24
────────────────────                   ────────────────────
host1 (10.0.0.1) ─┐                      host5 (20.0.0.1) ─┐
host3 (10.0.0.3) ─┤ ── sw1 ─┐            host7 (20.0.0.3) ─┤ ── sw3 ─┐
host4 (10.0.0.4) ─┘         ├── core1    host8 (20.0.0.4) ─┘         ├── core2
host2 (10.0.0.2) ──── sw2 ──┘            host6 (20.0.0.2) ──── sw4 ──┘

Subnet 30.0.0.0/24                      Subnet 40.0.0.0/24
────────────────────                   ────────────────────
host9  (30.0.0.1) ─┐                    host13 (40.0.0.1) ─┐
host11 (30.0.0.3) ─┤ ── sw5 ─┐           host15 (40.0.0.3)─┤ ── sw7 ─┐
host12 (30.0.0.4) ─┘         ├── core3  host16 (40.0.0.4) ─┘         ├── core4
host10 (30.0.0.2) ──── sw6 ──┘          host14 (40.0.0.2) ──── sw8 ──┘

Core router ring (OSPF, direct kernel L3 links):
core1 ──(100.0.0.0/30)── core2 ──(100.0.0.4/30)── core3 ──(100.0.0.8/30)── core4

Transit router ring (OSPF-only, provides an alternate path around the core ring):
r1 ──── r2 ──── r3 ──── r4 ──── r1 (loop)

each connected to its matching core router (core1↔r1, core2↔r2, core3↔r3, core4↔r4)
```
**Total containers: 32**
- 16 host containers — the end-point machines
- 8 switch containers (sw1–sw8) — each running OVS + an L2 agent
- 4 core router containers (core1–core4) — running OVS + OSPF (FRR) + an L3 agent
- 4 transit router containers (r1–r4) — running OSPF only (FRR), no A2A agent — they exist purely to give the core ring a redundant path, which is what Demo 08 exercises

Each pair of switches shares one core router. sw1 and sw2 both connect to core1. core1 holds the gateway IP 10.0.0.254/24 on its OVS bridge.

---

## Agent Deployment

**12 A2A agents total** — same compiled binary `a2a_agent`, different startup flags. The 4 transit routers (r1–r4) run FRR/OSPF only and carry no agent — they're plain routers, intentionally.

- **8 L2 agents** — one per switch (sw1–sw8), listen on port **7701**
- **4 L3 agents** — one per core router (core1–core4), listen on port **7700**

```bash
# L3 agent on core1
/usr/local/bin/a2a_agent --type l3 --id agent-l3-core1 \
  --host <core1-mgmt-ip> --port 7700 --switch core1 --bridge br0 --real-ovs

# L2 agent on sw1 (seeded with core1's address for discovery)
/usr/local/bin/a2a_agent --type l2 --id agent-l2-sw1 \
  --host <sw1-mgmt-ip> --port 7701 \
  --l3-host <core1-mgmt-ip> --l3-port 7700 --switch sw1 --bridge br0 --real-ovs
```

L3 agents start first. L2 agents register with their seeded core router over TCP, then discover sibling switches and other core routers via `MSG_PEER_LIST` propagation — no static peer configuration beyond the one initial seed address.

---

## A2A Protocol — Wire Format

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
| 6 | MSG_PEER_LIST | any→any | "Here are other peers I know about" |
| 10 | MSG_L2_EVENT | L2→L3 | General switch event |
| 11 | MSG_L3_EVENT | L3→L2/L3 | Route advertised/withdrawn |
| 20 | MSG_FLOW_INSTALL | L3→L2 | "Install this OpenFlow rule" |
| 30 | MSG_TOPOLOGY | L3→L2 | "Route changed, update your records" |
| 31 | MSG_ANOMALY | L3→any | "I detected a network-wide anomaly" (route oscillation) |
| 40 | MSG_L2_ANOMALY | L2→L3, L2→L2 | "I detected a problem" |
| 41 | MSG_POLICY_CMD | L3→L2 | "Apply this remediation" |
| 99 | MSG_ERROR | any→any | Error signaling |

### L2 Anomaly Types (inside MSG_L2_ANOMALY)
| Type | Meaning | L3 Response |
|---|---|---|
| 1 STORM | Broadcast/multicast storm confirmed | Reroute around switch + rate-limit |
| 2 ROUTE_OSCILLATION | (sent L3→L2 as MSG_ANOMALY, not MSG_L2_ANOMALY) | Notify peers |
| 3 MAC_SPOOF | Same MAC seen on ≥3 different ports within 10s | Send BLACKHOLE_MAC to reporting switch + propagate to L2 peers |
| 4 LINK_DOWN | Port link went down | Reroute around switch (link-failure path: also repairs kernel routes + sends GARP) |
| 5 STORM_CLEAR | pps dropped below clear threshold for ≥10s | Restore port |
| 6 LINK_UP | Port link restored | Restore routes for switch |
| 7 ARP_STORM | ARP pps above threshold | Rate-limit the ARP meter |
| 8 MAC_FLAP | A MAC moved ports repeatedly in 30s | Mild rate-limit, or "loop suspected" log if ≥5 MACs flapping at once |
| 9 FDB_OVERFLOW | OVS flow table nearing capacity | Logged for operator awareness (no automated remediation) |
| 10 UNICAST_FLOOD | Excessive PACKET_IN rate on one port | Reroute around switch + rate-limit |

### Policy Types (inside MSG_POLICY_CMD)
| Type | What L2 does |
|---|---|
| 1 RATE_LIMIT | Install/update an OpenFlow meter, cap traffic on the port |
| 2 ISOLATE_PORT | Drop traffic from the port — refused and downgraded to rate-limit if the port is an uplink, to avoid killing routing |
| 3 BLACKHOLE_MAC | Drop flow matching `dl_src=<MAC>` |
| 4 RESTORE_PORT | Remove meter/isolation flow, restore normal forwarding |
| 5 FLUSH_PORT | Delete all learned flows on the port |

---

## State Machine (FSM) — How Agents Progress

Every agent runs a **9-state, 12-event FSM**. All 108 state×event combinations are pre-registered at startup with a safe default (unregistered = log and ignore, never crash).
States: INIT → DISCOVERY → REGISTERING → ACTIVE ↔ RECEIVING
↑
PEER_TIMEOUT (stays ACTIVE, triggers reroute)
ERROR    ← any unrecoverable condition
SHUTDOWN ← SIGTERM/SIGINT

**Normal startup flow:**
INIT
→ (START event) → DISCOVERY
→ (seed peer address given via --l3-host) → PEER_DISCOVERED event queued
→ REGISTERING (action: send MSG_REGISTER to seed peer)
→ (MSG_REGISTER_ACK received) → ACTIVE
→ (MSG_L2_ANOMALY / any message received) → RECEIVING (action: process message)
→ (PROCESSING_DONE) → ACTIVE

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
| MAC learning | Receives PACKET_IN via raw OpenFlow socket → installs FLOW_MOD (priority=10, idle_timeout=300, `dl_dst=<MAC>` → `output:<port>`) |
| Storm detection | Polls OVS flow-stats (broadcast/multicast counters) every 500ms → computes pps. ≥1000 pps confirmed-broadcast = storm, <200 pps sustained for 10s = cleared |
| Storm mitigation | Installs an OpenFlow meter (dynamic rate cap) + a flow `in_port=<port> → meter:4,output:normal` |
| ARP storm detection | Same flow-stat polling path, tracks ARP-tagged packet rate separately (priority=60 flow) |
| MAC flood detection | Counts distinct MACs per port per 2s window, alerts above 50 |
| MAC spoof detection | Sliding 10s window tracking port changes per MAC; ≥3 port changes = alert, blackholes and notifies both L3 and L2 peers |
| Unicast flood detection | Tracks PACKET_IN rate per port over 500ms |
| FDB/table overflow detection | Polls OVS table stats every 5s, alerts above 80% capacity |
| Link failure detection | OVSDB monitor pushes link state change events in under 1ms, plus a 50ms poll-based backup path |
| Link failover | Flushes learned MAC flows, reinstalls table-miss + protection flows, floods via the inter-switch port, redirects kernel default route to the neighbor switch as a fallback path |
| Alerting | Sends typed `MSG_L2_ANOMALY` to all known L3 peers, and to L2 peers for anomaly types that affect shared paths (storm, spoof, link state) |

---

## L3 Agent — Full Responsibility Table

| Responsibility | Mechanism |
|---|---|
| Route monitoring | Subscribes to the kernel via Netlink (`RTM_NEWROUTE`/`RTM_DELROUTE`), ignoring its own management-plane interface's routes |
| OVS flow installation | Installs IP forwarding flows: `dec_ttl + mod_dl_dst + mod_dl_src + output:<port>`, falling back to `output:NORMAL` for kernel-only transit interfaces |
| ARP resolution | Listens for `RTM_NEWNEIGH`/`RTM_DELNEIGH`, caches nexthop MACs, reinstalls flows once ARP resolves |
| Anomaly handling | Receives `MSG_L2_ANOMALY`, rate-limited per (source, anomaly type) to 1 action per 2s, decides remediation per anomaly type |
| Route failover (link-down) | Finds an alternate route avoiding the failed switch, withdraws the old flow, installs the alternate, repairs the kernel route table, and sends a gratuitous ARP so hosts don't wait out their ARP cache timeout |
| Route failover (traffic anomaly) | Reroutes at the flow level only — deliberately skips kernel route repair and GARP for STORM/FLOOD anomalies, since those aren't real link failures and repairing kernel routes on every traffic spike would corrupt routing state |
| NUD_FAILED handling | Marks the exact affected route DEGRADED and looks for a real alternate for that specific route — does **not** reuse the generic switch-wide reroute path, since a nexthop failure isn't a switch/link failure |
| Route oscillation detection | If a prefix has ≥4 combined withdrawals+installs within 60s → flags oscillation, notifies all peers, measures convergence time |
| Blackhole / subnet isolation detection | Polls per-route flow packet counters every 10s; flags a route DEGRADED if it had traffic and then went silent for 30s with ARP unreachable |
| Policy dispatch | Sends `MSG_POLICY_CMD` (rate-limit / blackhole / restore) back to the reporting L2 agent |

---

## How to Build

```bash
cd ~/a2a-netlab

# Build the Docker image (first build takes ~5-8 minutes; apt install is the slow part)
docker build --no-cache -t hpe-netlab .

# Expected last line:
# naming to docker.io/library/hpe-netlab
```

The Dockerfile:
- Starts from Ubuntu 22.04
- Installs: iproute2, iputils-ping, iputils-arping, openvswitch-switch, frr, libcjson-dev, gcc, cmake
- Copies `a2a/` source into the image
- Compiles with CMake → produces `/usr/local/bin/a2a_agent`
- The same image is used for all 32 containers

---

## How to Build & Run

### Prerequisites
- Ubuntu 22.04 (or compatible Linux with Docker)
- Docker installed, sudo access
- ~4-5GB free RAM (32 containers)

### Step 1 — Clone
```bash
git clone https://github.com/mayankvyas1306/a2a-netlab.git
cd a2a-netlab
```

### Step 2 — Build the agent image (first time)
```bash
docker build --no-cache -t hpe-netlab .
```

### Step 3 — Start the topology (a few minutes)
```bash
sudo bash initial_scripts/start.sh
```
This creates all 32 containers, builds veth links, configures OVS, starts OSPF, and waits for OSPF convergence.

Expected last lines:
OSPF converged (neighbors: core1=2 core2=3 core3=3 core4=2)
Network is UP.

### Step 4 — Deploy all 12 agents
```bash
bash initial_scripts/deploy_agents.sh
```
Expected: all 12 agent containers (core1-4, sw1-8) show `1 process(es)`.

### Step 5 — Wait for registration
```bash
sleep 15
```

### Step 6 — Verify
```bash
bash tests/verify_agents.sh
bash tests/verify_dataplane.sh
```

---

## Running the Demo Scripts

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
bash demo_scripts/09_fault_tolerance.sh
```

To stop everything cleanly:
```bash
bash demo_scripts/99_shutdown.sh
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
```
Heartbeat (every ~15s in log, sent every 3s)
[HB] [agent-l2-sw1] → agent-l3-core1 HB ok (uptime=300s peers=2)
MAC learning
[OF] [br0] MAC learned: aa:bb:cc:dd:00:01 port=3
Storm → reroute → rate-limit
[L2] STORM DETECTED port=2 pps=12500
[L3] anomaly from agent-l2-sw1 type=1 port=2 pps=12500
[L3] Decision: STORM → rate limit
[L2] Rate limit applied on port 2
MAC spoof → blackhole
[L3] anomaly from agent-l2-sw1 type=3 port=3 pps=3
[L3] Sent BLACKHOLE_MAC for <mac> to switch sw1
Link down → reroute
[OVSDB] LINK DOWN: if=s1c1 ofport=1
[L3] Decision: LINK_DOWN → reroute
Route oscillation
[L3] ROUTE OSCILLATION DETECTED: 100.0.0.0/30 (X withdrawals + Y installs in 60s)
```


## Shutdown / Cleanup

```bash
# Graceful agent stop (prints final stats)
bash demo_scripts/99_shutdown.sh

# Full container cleanup
docker rm -f $(docker ps -aq) 2>/dev/null

# Or just re-run start.sh — it cleans automatically
sudo bash initial_scripts/start.sh
```
