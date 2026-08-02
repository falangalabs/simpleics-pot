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
{"address":5,"after":{"pump_speed_setpoint":8000},"area":"holding_register","before":{"pump_speed_setpoint":6800},"count":1,"event_type":"modbus_transaction","function_code":6,"operation":"write","protocol":"modbus_tcp","register_keys":["pump_speed_setpoint"],"requested_values":[8000],"result":"ok","schema_version":"1.2.0","source_ip":"127.0.0.1","transport_context":"pymodbus_request_handler","unit_id":7}
```

The real event also contains unique IDs, timestamps, sequence, source port and
transaction ID. Consumers must tolerate additional fields in later compatible
schema revisions and must treat source addresses as untrusted personal or
security-relevant data according to their jurisdiction and policy.

## Connector pattern

Keep collection outside the honeypot process. Consume stdout through the
container runtime's logging interface or a local log agent. Do not mount
collector credentials into the decoy container and do not let a logging outage
block Modbus handling.
