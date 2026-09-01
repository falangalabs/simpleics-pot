# Architecture

```text
untrusted Modbus client
          |
          v
bounded TCP session and PyModbus parser
          |
          v
validated register-map adapter <-> deterministic wet-well model
          |
          v
versioned JSON event on the `simpleics_pot.event` logger -> stdout
```

## Trust boundaries

The network client controls all bytes entering the Modbus parser. The parser
and adapter are therefore not treated as a sandbox. The intended outer
boundary is a dedicated VM or host; the non-root read-only container adds a
second boundary.

The runtime has no administrative endpoint, shell, upload handler, outbound
client or destination credential. Process state is synthetic and exists only
in memory. Restarting the process resets the example cell.

## Protocol boundary

PyModbus provides Modbus TCP framing and PDU implementations. A small pinned
integration layer attaches peer, transaction and session context, limits
active connections and buffered requests, and closes idle or incomplete
sessions. The process adapter exposes only addresses defined by the checked-in
register map.

## Process boundary

The model is deterministic and performs no network or filesystem access.
Commands, actuator feedback and derived process values are separate. Valid
writes can therefore produce observable delayed effects without controlling a
real device.

## Telemetry boundary

Application telemetry is best-effort and must never break the Modbus path.
The two shipped shipping tools (`tools/forward_events.py`,
`tools/build_stix_bundle.py`) are separate processes that read the pot's
output; the runtime still holds no outbound client and no destination
credential, and a collector outage cannot change how the pot answers Modbus.
Each event is one JSON object emitted as a single log record on the
`simpleics_pot.event` logger, so the stdout line carries the usual timestamp,
level and logger name before it. A consumer parses the JSON that follows,
not the whole line -- see docs/EVENTS.md. Collection, retention and transport are
operator-owned external concerns; the runtime does not initiate them.
