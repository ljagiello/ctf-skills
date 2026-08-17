# ICS / SCADA / OT Protocol Testing Quickstart

ICS challenges run small simulated plants (reactors, water treatment, factories) with one of the standard OT/SCADA protocols. The objective string is usually broadcast as part of a "shutdown" / "alarm" / "meltdown" event that the operator triggers by adversely manipulating actuators or violating safety thresholds.

## Protocol identification (ports + DNA)

| Protocol | Port(s) | Library | DNA in source/Dockerfile |
|---------|---------|---------|--------------------------|
| Modbus TCP | 502 | `pymodbus` | `from pymodbus.server.sync import StartTcpServer` |
| Siemens S7 | 102 | `python-snap7` | `import snap7` |
| DNP3 | 20000 | `pydnp3`, `opendnp3` | `from pydnp3 import opendnp3` |
| EtherNet/IP / CIP | 44818 (TCP) + 2222 (UDP) | `cpppo` | `from cpppo.server.enip` |
| OPC-UA | 4840 (typical) | `opcua` (FreeOpcUa) / `asyncua` | `from opcua import Server` / `from asyncua import Server` |
| MQTT | 1883 / 8883 (TLS) | `paho-mqtt` | `from paho.mqtt import client` |
| BACnet | 47808 (UDP) | `bacpypes` | `from bacpypes` |

## Generic attack flow

1. **Read source first**. Identify protocol, security policy, and which variables are *writable from outside*. Almost always one role (Anonymous / public broker / unauth Modbus) has write access to a "safety" register that the simulator's control loop tries to keep stable.
2. **Enumerate writable nodes / coils / topics**. Use the protocol's discovery / browse / SUBSCRIBE feature.
3. **Identify safety thresholds**. The challenge usually models a physical system (temperature, pressure, fluid level) with a control loop that tries to keep readings inside a range. The target string is broadcast when a threshold is breached.
4. **Override the control loop**. Single-shot writes are typically reset within ~1s by the plant model. Need a *sustained write loop* (every 100-500ms) to overpower the controller.
5. **Listen for the broadcast**. The target string often appears in a single update message at the moment of the failure event — a parallel listener (Socket.IO, WebSocket, MQTT subscribe, or repeated reads) is required because the broadcast is brief.

## OPC-UA specific gotchas

- Servers often advertise `Basic256Sha256` + `SignAndEncrypt` security policies (looks secure) but accept *any self-signed client cert* (no trust list). Generate a fresh cert with `openssl` or `opcua.crypto.uacrypto.generate_self_signed_cert()` and connect.
- Anonymous identity is frequently allowed *and* given UAL=3 (write) on namespaces it shouldn't have. Browse `Objects` and `WriteValue` on each variable; permission errors come back synchronously.
- `asyncua` and `opcua` both work; `asyncua` is more responsive for the sustained-write loop pattern.
- Enumerate the address space by recursively walking `Objects`, reading each variable's value + node class. Writable nodes are the targets:

  ```python
  from asyncua import Client          # URL e.g. opc.tcp://<TARGET>:4840/<path>/
  async with Client(url=URL) as c:
      async def walk(n, d=0, seen=set()):
          if n.nodeid.to_string() in seen or d > 6: return
          seen.add(n.nodeid.to_string())
          if str(await n.read_node_class()) == "NodeClass.Variable":
              print("  "*d, (await n.read_browse_name()).Name, "=", await n.read_value())
          for ch in await n.get_children(): await walk(ch, d+1, seen)
      await walk(c.nodes.objects)
  ```
- Impact isn't only a physical broadcast/meltdown. Writable OT nodes can drive a **host-side privileged controller** (often root) into a maintenance/override/test state that grants **OS-level** access — a window-gated `/etc/sudoers.d` rule, a privileged service restart, a script run as root. After flipping the relevant nodes (e.g. a mode/override flag + a value past a safety threshold via a calibration-offset node), check the host for newly granted sudo rights or triggered root actions, not just a flag in a broadcast.

## Modbus specific gotchas

- Holding Registers (function code 03/06/16) and Coils (01/05/15) are usually unauth-writable.
- Some challenges add a *fake* authentication layer in a wrapper protocol — bypass by speaking raw Modbus directly to the underlying port.
- Some sims have multiple slave IDs; enumerate slave_id 1..255 with `read_holding_registers` and pick the one that returns valid data.

## Worked example — OPC-UA reactor sim with empty trust list

When you encounter a FreeOpcUa OPC-UA server with empty trust list + Anonymous-write to a top-level namespace: generate a self-signed RSA-2048 client cert, browse `Objects` to enumerate writable safety actuators (control rods, coolant pumps, ECCS, SCRAM), run a sustained ~400ms write loop while a parallel WebSocket listener captures the broadcast (e.g. `reactor_update`). Typical breach time ~30s as the controller fights back.

## Anti-patterns
- Don't try to "exploit" the authentication if the source clearly shows Anonymous=write — the lesson is **the policy itself**, not bypass.
- Don't single-shot writes — the simulator will revert them; you need sustained pressure on the actuators.
- Don't ignore parallel broadcast channels (Socket.IO, MQTT, WebSocket); the target string often shows up there, not in the protocol response.
