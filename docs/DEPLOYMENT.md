# Deployment guide

## Safe local evaluation

`docker compose up --build` publishes the decoy only on
`127.0.0.1:1502`. Validate it locally before considering any wider exposure.

## Public exposure checklist

There is no universal one-command safe Internet deployment. Before changing
the bind address, provide all of the following independently of the container:

- a dedicated disposable VM or host with no production route;
- key-only management restricted by source address or a private management
  path;
- host or upstream firewall allowing only the intended Modbus port;
- default-deny egress and no real credentials or OT data on the decoy;
- bounded CPU, memory, PIDs, connections and local logs;
- an application-independent firewall kill switch;
- evidence copied outside the decoy according to local policy;
- monitoring for disk pressure, restarts and unexpected listeners;
- an incident and rebuild procedure tested before exposure.

After those controls are implemented, an operator can explicitly choose a
wider host bind in a local `.env` file:

```text
SIMPLEICS_BIND_IP=0.0.0.0
SIMPLEICS_PORT=1502
```

Port `1502` avoids privileged binding and is convenient behind a separately
managed firewall or relay. Mapping directly to the standard Modbus port may
require host-specific privilege or packet-filter configuration and is outside
this portable example.

## Verification

From an authorized external network, scan the intended target and confirm that
only explicitly approved ports are visible. Then perform a harmless FC3 read,
confirm a corresponding JSON event, exercise the firewall kill switch, and
verify that the endpoint becomes unreachable without stopping the management
path.

Never run offensive tests against systems you do not own or lack explicit
permission to assess.
