# Changelog

## 0.1.0a1

- Package the persistent ntfy outbox, bounded retries and readback verification.
- Make service-health checks optional and configurable.
- Add a copy-only Linux installer with a staging mode and disabled timers.
- Provide an optional, explicitly configured Linksys observation driver.
- Provide private Windows owner-PID snapshots and exact-endpoint manual review.
- Preserve evidence and fixed approval expiry through a portable SQLite helper.

This alpha does not implement continuous whole-network flow collection,
automatic connection blocking, single-session approvals or universal router/OS
support. A server delivery receipt does not prove that a phone displayed a push.
