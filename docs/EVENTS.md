# JSONL event contract

Every handled read or write produces one `modbus_transaction` JSON object on
the `simpleics_pot.event` logger. The current schema version is `1.2.0`.

Important fields:

| Field | Meaning |
|---|---|
| `observed_at` | UTC observation time |
| `sensor_sequence` | process-local monotonic event sequence |
| `session_id` | random identifier shared by one TCP connection |
| `source_ip`, `source_port` | transport peer observed by the server |
| `transaction_id` | Modbus transaction identifier |
| `function_code` | received Modbus function code |
| `operation` | `read`, `write` or `unknown` |
| `area`, `address`, `count` | addressed Modbus range |
| `register_keys` | known semantic points in the range |
| `requested_values` | normalized write values, when applicable |
| `response_values` | semantic values served by a read |
| `before`, `after` | affected values around a successful write |
| `result`, `exception_code` | outcome and Modbus exception |

Sanitized example:

```json
{"address":43,"after":{"pump_speed_setpoint":8000},"area":"holding_register","before":{"pump_speed_setpoint":6800},"count":1,"event_type":"modbus_transaction","function_code":6,"operation":"write","protocol":"modbus_tcp","register_keys":["pump_speed_setpoint"],"requested_values":[8000],"result":"ok","schema_version":"1.2.0","source_ip":"127.0.0.1","transport_context":"pymodbus_request_handler","unit_id":7}
```

The real event also contains unique IDs, timestamps, sequence, source port and
transaction ID. Consumers must tolerate additional fields in later compatible
schema revisions and must treat source addresses as untrusted personal or
security-relevant data according to their jurisdiction and policy.

## Getting the events out

Two tools ship with the pot. Neither runs inside it: the decoy prints, they
read what it printed. That is what keeps the runtime free of an outbound
client and a destination credential, so a visitor who takes the container
finds nothing in it that reaches your network.

### Stream to a collector

```bash
docker compose logs -f --no-log-prefix | \
    python3 tools/forward_events.py --host 10.0.0.5 --port 514
```

One RFC 5424 syslog message per event, with the JSON object as the message and
the event id as the message id, so a collector can deduplicate. There is no
default destination and no credential; syslog was chosen because every
collector already speaks it.

It is unauthenticated, and over UDP unencrypted and lossy. On a link you
control to a collector you control that is the usual trade. Anywhere else,
use `--protocol tcp` into a local relay and let the relay handle transport
security. Do not add credentials to the forwarder to solve this -- put a relay
in front of it.

The forwarder never blocks the pot. A collector that is down, slow or absent
costs dropped events, counted and reported on stderr, never a stalled Modbus
reply. `--max-events-per-second` is a sustained ceiling with a one-second
burst allowance, so a scanner's rapid requests are forwarded rather than
thinned.

### Package for collection

```bash
docker compose logs --no-log-prefix | \
    python3 tools/build_stix_bundle.py --output-dir /var/lib/simpleics-drop
```

A STIX 2.1 bundle per run, written whole and then moved into place so a
collector arriving mid-write never reads half a file. **How the bundle leaves
the host is yours to build** -- rsync, scp, a pull from your collector, a
copy to removable media. The pot deliberately does not do it.

Each source that spoke Modbus becomes:

| Object | Carries |
|---|---|
| `ipv4-addr` / `ipv6-addr` | the address, with a deterministic id so bundles merge |
| `observed-data` | first seen, last seen, how many events |
| `indicator` | the address as a STIX pattern, the function codes it used |

There is **no verdict, score or threat classification**, because nothing in
this edition computes one. A label invented at packaging time would be a guess
wearing a standard's clothes. What the observations mean is the consumer's
call.

Sources that are not globally routable -- your own testing, the LAN, loopback,
and the documentation ranges -- are left out unless you pass
`--include-non-global`. Publishing them is how a honeypot ends up distributing
a map of the people who run it.

### Or neither

Both tools are optional. The events are ordinary log records; a log agent
pointed at the container's stdout works just as well. Keep collection outside
the honeypot process, do not mount collector credentials into the decoy
container, and do not let a logging outage block Modbus handling.
