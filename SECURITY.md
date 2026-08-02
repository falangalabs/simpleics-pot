# Security Policy

## Supported versions

Only the latest published release receives security fixes during the initial
project phase.

## Reporting a vulnerability

Use the repository's private **Security → Advisories → Report a
vulnerability** workflow. Do not open a public issue for an unpatched
vulnerability and do not include attacker addresses, credentials, packet
captures or live deployment details.

Please include the affected version, preconditions, minimal reproduction,
impact and a suggested remediation if available. Test only systems you own or
are explicitly authorized to assess.

## Deployment boundary

Every Modbus client is untrusted. A public sensor must run on a dedicated VM or
host with no route to production, no real credentials or OT data, default-deny
egress, resource limits, bounded logs, a firewall-level kill switch and an
independent evidence strategy. The container is defense in depth, not the
outer security boundary.

The supplied Compose file deliberately binds to loopback. Changing that bind
does not by itself create a safe public deployment.
