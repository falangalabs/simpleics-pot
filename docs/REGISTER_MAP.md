# Synthetic register map

`config/register_map.v1.json` is the source of truth for the fictional device
identity, Unit ID, addressing, scaling, bounds, defaults and write policy.

The built-in wet-well model expects the documented semantic keys. Operators
may safely change the explicitly synthetic identity and values within the
validated bounds, but renaming or adding process keys requires corresponding
model code and tests. Run the validator after every edit:

```bash
python3 tools/validate_register_map.py
```

Addresses in the JSON document are zero-based Modbus PDU offsets. The
four/five-digit references are informational notation for human readers.

Writable points are deliberately limited to:

- AUTO/MANUAL control mode;
- level setpoint;
- pump speed setpoint;
- manual pump command;
- inlet valve command;
- alarm acknowledge pulse.

Input registers and discrete inputs are process feedback and are read-only.
Invalid ranges or values return Modbus exceptions without partially applying a
multi-write.
