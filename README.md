# SimpleICS Pot

SimpleICS Pot is a small, stateful Modbus TCP honeypot for defensive research.
It emulates a synthetic wet-well pump controller instead of exposing a static
banner or a flat register array. Reads return a changing process state, valid
writes affect that process, actuator feedback is delayed, and every handled
transaction produces a structured JSON event.

> **Safety:** Run Internet-facing honeypots only on a dedicated host or VM with
> no route to production systems. The included Compose profile binds to
> loopback by default. It is an application example, not a complete perimeter.

## Why it is different

- deterministic process simulation with level, flows, pump current and alarms;
- coherent AUTO/MANUAL control, setpoints, commands and feedback;
- Modbus reads FC1-FC4 and bounded writes FC5, FC6, FC15 and FC16;
- validated register ranges and atomic rejection of invalid multi-writes;
- session, transaction and peer context in versioned JSONL telemetry;
- connection, pending-request, buffer, idle and incomplete-frame limits;
- synthetic and configurable device identity in one register-map document;
- non-root, read-only, capability-free container profile;
- no credentials, outbound integrations, web UI or administrative endpoint;
- optional syslog forwarder and STIX 2.1 packager, both outside the decoy.

## Quick start

Requirements: Docker Engine with the Compose plugin.

```bash
docker compose up --build
```

The default listener is available only at `127.0.0.1:1502`. In another
terminal, run the included authorized-target demonstration:

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --require-hashes -r requirements-build.lock
.venv/bin/python examples/modbus_demo.py
```

To stop and remove the container:

```bash
docker compose down
```

See [Deployment](docs/DEPLOYMENT.md) before changing the bind address.

## Process model

The included community profile is a fictional compact lift-station controller,
deliberately distinct from any private deployment. Its 21
points cover coils, discrete inputs, holding registers and input registers.
For example, an authorized client can switch to MANUAL, issue a pump command,
observe delayed run feedback, and then see discharge flow, motor current and
tank level respond coherently.

Events are log records on the `simpleics_pot.event` logger. To ship them,
see [Getting the events out](docs/EVENTS.md#getting-the-events-out) --
a syslog forwarder and a STIX 2.1 packager are included, and both run
beside the pot rather than inside it.

The complete address table and scaling rules are in
[`config/register_map.v1.json`](config/register_map.v1.json). The identity is
explicitly synthetic and must not imitate a real vendor or deployed asset.
Before Internet exposure, create your own fictional identity and process
profile; do not copy identifiers or measurements from real equipment.

## Event output and connectors

Events are emitted as one compact JSON object per log line. Docker keeps a
bounded local log by default. Operators can connect any local log collector to
stdout or the Docker logging interface; the honeypot itself has no outbound
sender or destination credential.

See [Event contract](docs/EVENTS.md) for fields and a sanitized example.

## Local development

Python 3.11 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-build.lock
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --no-build-isolation --no-deps -e .
.venv/bin/python tools/validate_register_map.py
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

The CLI is loopback-only unless the operator explicitly acknowledges a wider
bind:

```bash
.venv/bin/simpleics-pot
```

## Project scope

This release intentionally contains only the Modbus decoy, process model,
local structured telemetry contract, tests and a constrained container
profile. It does not perform attribution, scan clients, enrich addresses,
publish threat intelligence or send data over the network.

## Contributing and security

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md) first. Do not submit real credentials, real OT data,
packet captures or details of a live sensor deployment.

Licensed under the [Apache License 2.0](LICENSE). Dependency attribution is in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
