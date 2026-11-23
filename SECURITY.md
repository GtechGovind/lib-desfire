# Security

Use the dashboard only on a trusted local workstation. It binds to loopback and
requires an exact local origin and session token for command submission. It is
not a remotely accessible service and does not provide user accounts or remote
authorization. Do not expose it through a proxy, tunnel or public listener.

Saved keys are held only in process memory and erased on removal or shutdown.
The application does not provide encrypted persistent key storage, locked memory,
hardware-backed key isolation or protection from a privileged local process.
Responses and exported activity can contain card application data. Review them
before sharing, even when request arguments and key fields are excluded.

Raw traffic can change selection, authentication and persistent data. After raw
traffic, reconnect before using typed commands. A lost response does not prove a
write failed: resolve the card state before considering another operation.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/GtechGovind/lib-desfire/security/advisories/new).
The current development line is 0.2.x; report the exact version or commit.
Maintainers review reports as availability permits; there is no guaranteed
response time or security audit certification.

Do not post credentials, card dumps, protected traffic, personal identifiers or
working exploit details in a public issue. Use the hosting platform's private
vulnerability-reporting facility when enabled, or request a private reporting
channel from the maintainers without including the sensitive details.

Include the affected version, platform, expected and observed behavior, and a
minimal reproduction using synthetic data. Keep production keys and private
deployment information out of the report.
