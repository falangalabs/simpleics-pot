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
versioned JSONL event -> stdout / bounded local container log
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
Each event is a single JSON line. Collection, retention and transport are
operator-owned external concerns; the runtime does not initiate them.
