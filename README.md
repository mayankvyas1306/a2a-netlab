# README — A2A NetLab: Distributed Agent-to-Agent Network Control System

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
│   │   ├── a2a_message.h         ← Message types, payload structs, helper functions
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
host1 (10.0.0.1) ─┐                   host5 (20.0.0.1) ─┐
host3 (10.0.0.3) ─┤── sw1 ─┐          host7 (20.0.0.3) ─┤── sw3 ─┐
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

## Agent Deployment

**12 agents total** — one per node that needs network intelligence:

- **8 L2 agents** — one on each switch (sw1 through sw8), listening on port **7701**
- **4 L3 agents** — one on each core router (core1 through core4), listening on port **7700**

All agents are the same compiled binary (`a2a_agent`) launched with different arguments. A2A communication runs over a dedicated **management network** (172.28.0.0/16) — completely separate from data traffic.

**How agents are started (example):**

```bash
# L3 agent on core1
/usr/local/bin/a2a_agent --type l3 --id agent-l3-core1 \
  --host 172.28.x.x --port 7700 --switch core1 --bridge br0 --real-ovs

# L2 agent on sw1, seeded with core1's address to bootstrap discovery
/usr/local/bin/a2a_agent --type l2 --id agent-l2-sw1 \
  --host 172.28.x.x --port 7701 \
  --l3-host 172.28.x.x --l3-port 7700 --switch sw1 --bridge br0 --real-ovs
```

---

## Agent Types — What Each One Does

### L2 Agent (runs on sw1 through sw8)

| Responsibility | Mechanism |
|---|---|
| MAC learning | Receives PACKET_IN from OVS via OpenFlow socket, installs FLOW_MOD per learned MAC |
| Storm detection | Polls port statistics every 50ms via OVSDB, calculates packets-per-second |
| Storm mitigation | Installs OpenFlow METER_MOD (rate-limiting) and metered flow when storm detected |
| Link failure detection | OVSDB monitor pushes link state changes to agent in under 1ms |
| Link failover | Flushes MAC table, finds inter-switch port, redirects kernel default route |
| MAC flood detection | Counts distinct MACs per port per 2s window, alerts if above 50 |
| MAC spoof detection | Tracks port-per-MAC; detects and reports when MAC moves to a different port |
| Alerting | Sends typed L2_ANOMALY messages to all known L3 peers via A2A |

### L3 Agent (runs on core1 through core4)

| Responsibility | Mechanism |
|---|---|
| Route monitoring | Subscribes to Linux kernel via Netlink (RTM_NEWROUTE, RTM_DELROUTE) |
| OVS flow installation | Installs IP forwarding flows with dec_ttl + MAC rewrite + port output |
| ARP resolution | Listens for RTM_NEWNEIGH events, caches next-hop MACs, reinstalls flows when ARP resolves |
| Anomaly handling | Receives L2_ANOMALY messages, makes routing decisions per anomaly type |
| Route failover | Finds alternate routes and reinstalls OVS flows when a switch fails |
| Policy dispatch | Sends POLICY_CMD messages (rate-limit, blackhole, restore) back to L2 agents |
| Peer recovery | Detects agent crashes via heartbeat timeout, triggers reroute, recovers when peer restarts |

---

## A2A Protocol — How Agents Talk to Each Other

### Wire Format

Every message is JSON wrapped with a **4-byte big-endian length prefix**:

```
[4 bytes: message body length in big-endian][JSON message body]
```

The receiver reads exactly 4 bytes first to know how many bytes to read for the body. This handles partial TCP reads correctly.

### Message Structure

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

| Type ID | Name | Direction | Purpose |
|---|---|---|---|
| 3 | MSG_REGISTER | any → any | "I exist, here is my address, type, and switch" |
| 4 | MSG_REGISTER_ACK | any → any | "I received your registration" |
| 5 | MSG_HEARTBEAT | any → any | "I am still alive" (every 3 seconds) |
| 6 | MSG_PEER_LIST | any → any | "Here are the other peers I know about" |
| 10 | MSG_L2_EVENT | L2 → L3 | General L2 switch event |
| 11 | MSG_L3_EVENT | L3 → L3/L2 | Route advertisement or withdrawal |
| 20 | MSG_FLOW_INSTALL | L3 → L2 | "Install this OpenFlow rule on your switch" |
| 30 | MSG_TOPOLOGY | L3 → L2 | "This route changed, update your records" |
| 40 | MSG_L2_ANOMALY | L2 → L3 | "I detected storm/flood/spoof/link-down on my switch" |
| 41 | MSG_POLICY_CMD | L3 → L2 | "Apply rate-limit / restore port / blackhole MAC" |

### Anomaly Types (inside MSG_L2_ANOMALY payload)

| Type | Meaning | L3 Response |
|---|---|---|
| L2_ANOMALY_STORM | Broadcast storm detected (pps ≥ 500) | Reroute + send POLICY_RATE_LIMIT |
| L2_ANOMALY_FLOOD | MAC flood (>50 distinct MACs per port) | Reroute + send POLICY_RATE_LIMIT |
| L2_ANOMALY_MAC_SPOOF | MAC moved to different port | Send POLICY_BLACKHOLE_MAC |
| L2_ANOMALY_LINK_DOWN | Port link went down | Reroute around failed switch |
| L2_ANOMALY_STORM_CLEAR | Storm traffic dropped below 100 pps | Send POLICY_RESTORE_PORT |

### Policy Types (inside MSG_POLICY_CMD payload)

| Type | What L2 does |
|---|---|
| POLICY_RATE_LIMIT | Install OpenFlow meter, cap traffic to specified kbps |
| POLICY_ISOLATE_PORT | Drop all traffic from port (refuses to isolate uplink ports) |
| POLICY_BLACKHOLE_MAC | Install drop flow matching dl_src=MAC |
| POLICY_RESTORE_PORT | Remove rate-limit meter and flow, restore port to normal |
| POLICY_FLUSH_PORT | Delete all learned flows from OVS bridge |

---

## State Machine (FSM) — How Agents Progress

Every agent has a **9-state, 12-event FSM**. All 108 state+event combinations are pre-registered at startup. Invalid transitions are logged and counted but never crash the agent.

```
States: INIT → DISCOVERY → REGISTERING → ACTIVE ↔ RECEIVING
                                            ↑              ↓
                                         DEGRADED ←── PEER_TIMEOUT
                                         ERROR ←──── any error
                                         SHUTDOWN ←── SIGTERM
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

## Peer Discovery — How Agents Find Each Other

No central directory. No broadcast. Pure seed-based peer-to-peer discovery:

1. L2 agent starts with `--l3-host` and `--l3-port` pointing to its core router
2. L2 sends MSG_REGISTER to the seed address
3. L3 receives MSG_REGISTER, adds L2 to its peer table, sends MSG_REGISTER_ACK + MSG_PEER_LIST
4. MSG_PEER_LIST contains all peers the L3 agent currently knows
5. L2 discovers sibling switches (e.g., sw2 alongside sw1) from that list
6. L2 sends MSG_REGISTER to each newly discovered peer
7. All agents in a group reach full mutual registration within 1 second of startup

Every 5 seconds, the main loop re-triggers PEER_DISCOVERED for any peer that has not yet confirmed two-way communication. This handles startup races automatically.

---

## Heartbeat — How Agent Failures are Detected

| Parameter | Value |
|---|---|
| Send interval | Every 3 seconds |
| Timeout threshold | 15 seconds (5 missed heartbeats) |
| Dead peer retry interval | Every 30 seconds (throttled reconnect probes) |
| Log verbosity | Every 5th heartbeat (every 15 seconds) to avoid log spam |

**Detailed flow:**

```
Every 3s:
  → send MSG_HEARTBEAT to all known peers (alive and dead)
  → dead peers are throttled: only probe once per 30s
  → check every peer's last_heartbeat_us timestamp
  → if age > 15s: mark alive=0, push PEER_TIMEOUT event
  → PEER_TIMEOUT action: mark dead, evict TCP connection, trigger reroute

When heartbeat arrives from a peer:
  → update last_heartbeat_us to now
  → if peer was dead: mark alive=1, push PEER_DISCOVERED event
  → PEER_DISCOVERED action: send MSG_REGISTER to re-establish protocol state
```

The heartbeat uses `last_heartbeat_us` from **received** heartbeats — not from outbound sends. A failed send does not trigger a timeout. This prevents false timeouts when your own TCP stack has a transient issue.

---

## MAC Learning — Detailed Flow

1. Unknown destination packet arrives at OVS switch
2. OVS has no flow matching that destination MAC → sends PACKET_IN to the L2 agent via OpenFlow socket
3. Agent's `ovs_of_process_packet_in()` extracts the source MAC and input port from the OXM fields
4. Agent calls `mac_table_learn()`: looks up MAC in in-memory table, installs a FLOW_MOD if new
   - FLOW_MOD: `priority=10, idle_timeout=300, match=dl_dst=<MAC>, action=output:<port>`
5. Agent sends PACKET_OUT flood so the original packet is not dropped
6. Future packets to that MAC are forwarded by OVS hardware with no agent involvement
7. If a MAC appears on a different port than previously recorded: MAC SPOOF anomaly is reported to L3

**MAC table limits:**
- Maximum 256 entries (soft limit in `l2_agent_ctx_t`)
- In-memory table in `ovs_openflow.c` supports up to 1024 entries
- Entries age out after 300 seconds of no activity
- The aging code explicitly deletes the matching `dl_dst` OVS flow when evicting an entry

---

## Storm Detection — Detailed Flow

**Polling cycle (every 50ms):**

1. For each known port, call `ovs_get_port_stats()` → reads from OVSDB shadow table
2. Calculate `pps = (rx_packets_delta) / elapsed_time`
3. Compare against thresholds:
   - `pps ≥ 1000` → storm detected
   - `pps < 200` → storm cleared
4. On first storm detection: set `storm_active=1`, call `l2_report_anomaly()`, push `A2A_EV_ANOMALY`
5. On storm clear: set `storm_active=0`, send `L2_ANOMALY_STORM_CLEAR` to all L3 peers

**Rate limiting response from L3:**

```
L3 receives L2_ANOMALY_STORM:
  1. Calls l3_reroute_around() — finds alternate routes that don't use the stormy switch
  2. Calls l3_send_policy() with POLICY_RATE_LIMIT and the reported pps value

L2 receives POLICY_RATE_LIMIT:
  1. Calls ovs_of_add_meter() — installs OpenFlow METER_MOD (DROP meter at pps × 200 kbps)
  2. Installs flow: in_port=<storm port>, action=meter:1,output:normal
  3. OVS hardware drops excess packets at line rate

Storm clears (pps < 100):
  L2 sends L2_ANOMALY_STORM_CLEAR → L3 sends POLICY_RESTORE_PORT → L2 removes meter flow
```

**Baseline broadcast protection (always active, separate from storm response):**

Meter 1 (1500 kbps) is installed at agent startup via `ovs_of_add_meter()`. It applies to all broadcast and multicast traffic permanently, independent of storm detection.

---

## Link Failure and Recovery — Complete Flow

### When a switch's uplink to its core router goes down

```
PHYSICAL LINK GOES DOWN (e.g., interface s1c1 in sw1 container)

L2 agent on sw1 (detects via OVSDB monitor, under 1ms):
  1. OVSDB shadow table updates link_up=0 for s1c1
  2. ovsdb_process_update() pushes A2A_EV_OVS_LINK_DOWN into event queue
  3. FSM dispatches to on_ovs_event() → calls l2_handle_link_down()
  4. l2_handle_link_down() calls l2_report_anomaly(L2_ANOMALY_LINK_DOWN)
  5. MSG_L2_ANOMALY sent to all alive L3 peers

L3 agent on core1 (receives anomaly):
  1. l3_handle_l2_anomaly() sees anomaly_type=LINK_DOWN
  2. Calls l3_reroute_around(failed_switch="sw1", port=-1)
  3. l3_reroute_around() scans route table for routes via sw1
  4. find_alternate() finds a route to the same prefix via sw2
  5. withdraw_route_flow() deletes the old OVS flow
  6. install_route_flow() installs new OVS flow via sw2's path
  7. notify_l2_peers_topology() sends MSG_TOPOLOGY to all L2 agents

Result: data plane restored via sw2 path within ~13ms of failure
```

### When the link comes back up

```
PHYSICAL LINK RESTORED

L2 agent detects via OVSDB (link_up=1):
  1. link_state_cache shows was_up=0, now_up=1
  2. check_link_state_changes() logs "Link UP: s1c1"
  (L2 does not auto-restore — restoration is driven by the L3 agent's
   route re-verification on the next heartbeat tick)

L3 agent on next heartbeat_tick:
  1. Scans route table for DEGRADED routes
  2. If via_switch peer is now alive again, route state returns to ACTIVE
  3. install_route_flow() reinstalls the original path
```

---

## OVS Integration — How Agents Control the Switch

### OpenFlow Channel (`ovs_openflow.c`)

- Connects to `/var/run/openvswitch/br0.mgmt` Unix socket
- Performs HELLO handshake and SET_CONFIG (miss_send_len=65535) at startup
- Installs table-miss entry: all unmatched packets → send to controller (PACKET_IN)
- Handles incoming PACKET_IN: extracts OXM fields, learns MACs, sends PACKET_OUT flood
- Handles ECHO_REQUEST: replies with ECHO_REPLY so OVS does not remove controller flows
- `build_flow_mod()` constructs binary OpenFlow 1.3 FLOW_MOD messages from match/action strings
- `ovs_of_add_meter()` constructs binary METER_MOD ADD messages for rate limiting
- **No popen(), no ovs-ofctl subprocess — pure binary socket communication**

### OVSDB Channel (`ovs_ovsdb.c`)

- Connects to `/var/run/openvswitch/db.sock` Unix socket
- Sends a JSON-RPC monitor subscription for three tables: Port, Interface, Bridge
- Maintains an in-memory shadow table (`g_ifaces[128]`) with per-interface stats and state
- `ovsdb_process_update()` parses both the initial full-state response and incremental updates
- Link-down events are detected by comparing `was_up` vs current `link_up` in shadow table
- `ovsdb_get_port_stats()` serves storm detection polling without any system call
- `ovsdb_get_ofport()` maps interface names to OpenFlow port numbers for flow installation
- `ovsdb_set_admin_state()` sends a JSON-RPC transact mutation to bring a port up or down

### Netlink Channel (`l3_netlink.c`, L3 agents only)

- Creates a `NETLINK_ROUTE` socket subscribed to four groups: IPV4_ROUTE, LINK, IPV4_IFADDR, NEIGH
- Registered with the agent's epoll loop — processes events asynchronously as they arrive
- RTM_NEWROUTE / RTM_DELROUTE: calls `l3_add_route()` or `l3_withdraw_route()`
- RTM_NEWNEIGH: updates the in-memory ARP cache; reinstalls OVS flows for any route whose next-hop just got resolved
- RTM_NEWLINK with IFF_UP clear: calls `l3_reroute_around()` for the affected interface
- Initial route dump via RTM_GETROUTE at startup populates the route table from the kernel

---

## Route Table and Flow Installation

The L3 agent maintains an in-memory route table (`route_entry_t routes[128]`). Each entry tracks:

- `prefix` — destination network (e.g., "10.0.0.0/24")
- `nexthop` — next-hop IP address
- `egress_ifname` — kernel interface name (e.g., "c1s1", "br0")
- `via_switch` — which agent manages the path to this prefix
- `metric` — route cost (lower is better)
- `state` — ACTIVE, DEGRADED, or WITHDRAWN
- `is_local` — whether this route was learned from the local kernel

**Flow installation logic:**

1. If `egress_ifname` is not in OVS (e.g., transit interfaces c1c2, c1r1): install `output:NORMAL` and let the kernel handle it
2. If the interface is in OVS and ARP is resolved: install full L3 forwarding action:
   `dec_ttl, mod_dl_dst:<nexthop_mac>, mod_dl_src:<local_mac>, output:<ofport>`
3. If ARP is not yet resolved: install `output:NORMAL` as fallback; reinstall with full action when RTM_NEWNEIGH arrives

---

## Connection Pool (`a2a_connpool.c`)

All outbound A2A messages go through a connection pool instead of opening a new TCP connection per message:

- Pool holds up to 64 connections keyed by "host:port"
- On send: finds existing connection or opens a new one with 50ms connect timeout
- On send failure: evicts the connection, waits 50ms for TCP RST to clear, retries once
- `conn_pool_evict_peer()` closes only the dead peer's connection — never disrupts healthy peers
- `conn_pool_gc()` evicts connections idle for more than 60 seconds
- `pool_alloc()` evicts the oldest entry when the pool is full (LRU)

---

## Event Queue (`a2a_event.c`)

Each agent has a ring-buffer event queue with 256 slots. Events are pushed by:

- TCP message arrival → `A2A_EV_MSG_RECEIVED`
- OVSDB link-down detection → `A2A_EV_OVS_LINK_DOWN`
- OpenFlow PACKET_IN → MAC learning → `A2A_EV_OVS_MAC_LEARNED`
- Heartbeat timer → `A2A_EV_HEARTBEAT_TICK`
- Peer timeout detection → `A2A_EV_PEER_TIMEOUT`
- Seed peer address at startup → `A2A_EV_PEER_DISCOVERED`

The main loop drains the entire queue on every iteration: `while (event_queue_pop(&eq, &ev) == 0) fsm_process(agent, &ev)`. Events dropped when the queue is full are counted in `agent->events_dropped`.

---

## Main Event Loop (`main.c`)

Single-threaded. No threads anywhere. Same architecture as nginx and Redis.

```
while (running):
  1. epoll_wait(5ms) — handles TCP accepts, inbound messages, OVSDB updates,
                       OpenFlow PACKET_IN, and Netlink route changes all in one call
  2. Check heartbeat timer (every 3s) — push A2A_EV_HEARTBEAT_TICK
  3. Check discovery retry timer (every 5s) — re-trigger PEER_DISCOVERED for unconfirmed peers
  4. Drain event queue — process all queued events through the FSM
  5. Call l2_agent_tick() or l3_agent_tick() — periodic port polling, MAC sync
  6. Connection pool GC (every 30s) — evict idle connections, compact peer table
  7. Handle SIGUSR1 — print state dump: FSM state, peer table, route table, MAC table
```

All external fds (OVSDB socket, OpenFlow socket, Netlink socket) are registered with the same epoll instance as the TCP server. One `epoll_wait` call drives all I/O.

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

## How to Start the Network

```bash
# Step 1: Start all 28 containers and build the topology (takes ~3-5 minutes)
sudo bash start.sh

# What this does:
# - Removes any old containers
# - Creates 16 host, 8 switch, 4 core, 4 transit router containers
# - Creates veth pairs between containers (virtual network cables)
# - Configures OVS on each switch and router container
# - Assigns IP addresses to all interfaces
# - Starts OSPF via FRR on all 8 routers
# - Waits for OSPF to converge (at least 4 Full neighbors across core routers)

# Expected last lines:
# OSPF converged (neighbors: core1=2 core2=3 core3=3 core4=2)
# Network is UP.

# Step 2: Deploy all 12 agents
bash deploy_agents.sh

# What this does:
# - Verifies OVS is running in all 12 agent containers
# - Configures OVS controller listener (punix:.../br0.mgmt) on all containers
# - Sets OpenFlow protocol to 1.3 on all bridges
# - Starts L3 agents first (core1-core4)
# - Waits 2 seconds for L3 agents to initialize
# - Starts L2 agents (sw1-sw8), each seeded with its core router's mgmt IP
# - Reports process count per container

# Expected last lines:
# core1 (L3): 1 process(es)
# sw1 (L2): 1 process(es)
# ... (all 12 show 1 process)

# Step 3: Wait 30 seconds for OSPF routes to populate + agents to register
sleep 30
```

---

## How to Verify Everything is Working

```bash
# Verify all agents are running and reachable
bash verify_agents.sh

# Full data plane verification (ping tests, MAC learning, flow table check)
bash verify_dataplane.sh

# Check specific agent log (live)
docker exec sw1 tail -f /tmp/agent-sw1.log
docker exec core1 tail -f /tmp/agent-core1.log
```

---

## Demo Scenarios

### Baseline connectivity

```bash
# Intra-subnet (same switch)
docker exec host1 ping -c 3 10.0.0.3
# Expected: 0% loss, ttl=64

# Cross-subnet (through core router)
docker exec host1 ping -c 3 20.0.0.1
# Expected: 0% loss, ttl=62

# Far cross-subnet (4 hops)
docker exec host1 ping -c 3 40.0.0.1
# Expected: 0% loss, ttl=60
```

### Link failure and reroute

```bash
# Bring down sw1's uplink to core1
docker exec sw1 ip link set s1c1 down
echo "Link failed at $(date)"
sleep 3

# Verify reroute happened
docker exec core1 ip route show | grep "10.0.0"
# Expected: route now goes via sw2 path (c1s2 or similar)

# Traffic still works
docker exec host1 ping -c 3 20.0.0.1

# Restore the link
docker exec sw1 ip link set s1c1 up
sleep 18

# Verify original route restored
docker exec core1 ip route show | grep "10.0.0"
```

### Storm detection

```bash
# Send broadcast flood from host1
docker exec host1 ping -b -c 500 -i 0.001 10.0.0.255 &

# Watch storm detection in sw1 log
docker exec sw1 grep "STORM DETECTED\|storm_detected" /tmp/agent-sw1.log | tail -5

# Watch L3 response in core1 log
docker exec core1 grep "Decision: STORM\|policy sent" /tmp/agent-core1.log | tail -3

# After flood ends, verify cleanup
sleep 5
docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0 | grep "meter:2" | wc -l
# Expected: 0 (rate-limit flow removed after storm clears)
```

### Agent crash and recovery

```bash
# Kill the sw2 agent
docker exec sw2 pkill -f a2a_agent
echo "sw2 agent killed at $(date)"

# Wait for timeout detection (15 seconds)
sleep 20
docker exec core1 grep "peer TIMEOUT.*sw2" /tmp/agent-core1.log | tail -1
# Expected: "peer TIMEOUT: agent-l2-sw2 (last seen 15.7s ago)"

# Restart the agent
SW2_IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "a2a-mgmt").IPAddress}}' sw2)
CORE1_IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "a2a-mgmt").IPAddress}}' core1)
docker exec -d sw2 /usr/local/bin/a2a_agent --type l2 --id agent-l2-sw2 \
  --switch sw2 --bridge br0 --host $SW2_IP --port 7701 \
  --l3-host $CORE1_IP --l3-port 7700

# Verify recovery
sleep 10
docker exec core1 grep "peer RECOVERED\|re-registered" /tmp/agent-core1.log | tail -1
```

---

## How to Monitor

```bash
# Watch all anomalies and decisions on core1
docker exec core1 tail -f /tmp/agent-core1.log | \
  grep -E "anomaly|Decision|STORM|LINK|reroute|repair|restored"

# Watch MAC learning on sw1
docker exec sw1 tail -f /tmp/agent-sw1.log | grep "MAC learned"

# Watch heartbeats on sw1 (logged every 15 seconds)
docker exec sw1 tail -f /tmp/agent-sw1.log | grep "HB ok"

# Watch OVS flows on sw1 in real time
watch -n 3 "docker exec sw1 ovs-ofctl -O OpenFlow13 dump-flows br0"

# Watch kernel routing table on core1
watch -n 2 "docker exec core1 ip route show | grep '10.0.0'"

# Trigger a state dump from a running agent (prints route table, peer table, stats)
docker exec core1 pkill -SIGUSR1 a2a_agent
docker exec core1 grep "STATE DUMP\|Route health" /tmp/agent-core1.log | tail -20

# Watch route health across all core routers
watch -n 10 'for c in core1 core2 core3 core4; do
  echo -n "$c: "; docker exec $c grep "Route health" /tmp/agent-$c.log | tail -1
done'
```

**What to look for in logs:**

```
# Healthy heartbeat (every 15s)
[12:34:56.789][INFO ][HB] [agent-l2-sw1] → agent-l3-core1 HB ok (uptime=300s peers=2)

# Successful MAC learning
[12:34:57.001][INFO ][OF] [br0] MAC learned: aa:bb:cc:dd:00:01 port=3

# Storm detection and L3 response
[12:35:01.045][WARN ][L2] STORM DETECTED port=2 pps=12500
[12:35:01.089][INFO ][L3] [core1] anomaly from agent-l2-sw1 type=1 port=2 pps=12500
[12:35:01.090][INFO ][L3] Decision: STORM → reroute + rate limit
[12:35:01.091][INFO ][L3] [core1] policy sent → agent-l2-sw1 type=3 port=2

# Link failure handling
[12:36:00.001][WARN ][OVSDB] LINK DOWN: if=s1c1 ofport=1
[12:36:00.002][ERROR][L2] Link DOWN on port 1 — notifying L3 peers
[12:36:00.015][INFO ][L3] Decision: LINK_DOWN → reroute

# Peer timeout and recovery
[12:40:15.000][WARN ][HB] [agent-l3-core1] peer TIMEOUT: agent-l2-sw2 (last seen 15.7s ago)
[12:40:45.000][INFO ][HB] [agent-l3-core1] peer RECOVERED: agent-l2-sw2

# Shutdown statistics
[INFO ][STATS] send_failures=8 events_dropped=0 fsm_invalid=0 msgs_sent=270 msgs_recv=287
```

---

## How to Stop Everything

```bash
# Gracefully stop all agents (they print final stats on SIGTERM)
for c in core1 core2 core3 core4 sw1 sw2 sw3 sw4 sw5 sw6 sw7 sw8; do
  docker exec $c pkill -TERM a2a_agent 2>/dev/null || true
done

# Full reset (removes all containers)
docker rm -f $(docker ps -aq) 2>/dev/null

# Or re-run start.sh which cleans and rebuilds everything
sudo bash start.sh
```

---
