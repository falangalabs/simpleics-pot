# Contributing

Thank you for helping improve defensive ICS research.

## Before opening a pull request

1. Keep all identities, process values and examples synthetic.
2. Do not add credentials, external senders, phone-home behavior, active
   scanning, exploit code or intentional remote-code-execution paths.
3. Preserve loopback-only defaults and fail-closed validation.
4. Add tests for protocol, state, resource or telemetry changes.
5. Run the complete local test command from the README.

Small focused changes are preferred. A protocol change should describe its
wire behavior, process effect, telemetry effect and failure behavior.

## Good contribution areas

- additional malformed-frame regression cases;
- interoperability tests with standard Modbus clients;
- safer container and deployment defaults;
- documentation and synthetic process realism;
- bounded observability and event-schema improvements;
- accessibility and reproducibility improvements.

Use a private security advisory for vulnerabilities. General bugs and feature
requests can use normal issues without including live sensor data.
