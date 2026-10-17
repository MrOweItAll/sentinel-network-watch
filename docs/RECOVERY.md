# Recovery and maintenance

Keep a local console or a separately tested administrative connection available before enabling timers. Sentinel does not manage SSH, firewall, household DNS or the router configuration. Stopping its jobs does not require changing those systems.

## Autonomous hub recovery

The hub's authenticated browser interface is local to `http://127.0.0.1:8765/`. The normal desktop launcher contains no secret and does not run as root. Use the separate dashboard credentials created at native setup; the Ubuntu administrator password is not automatically a dashboard password. Do not put a password/token in the URL, a desktop entry or a public issue.

Inspect only the hub lifecycle, or stop its worker/UI without touching legacy services:

```sh
systemctl status sentinel-hub.service --no-pager
sudo systemctl disable --now sentinel-hub-watchdog.timer sentinel-hub.service
sudo systemctl stop sentinel-hub-watchdog.service
```

This intentionally pauses both the hub and its independent watchdog so planned maintenance does not look like an unattended failure. It preserves `/etc/sentinel-hub` and `/var/lib/sentinel-hub`, including pending review items and the hub's own durable alert outbox. It does not stop Docker, AdGuard, the existing router collector, the original alert timer, SSH or networking. No process kill/firewall block follows from rejecting a review item.

For a manual filesystem backup, keep the hub and watchdog stopped during a consistent backup of both hub directories, plus the exact public release and any separately retained ntfy config. Authentication hashes, raw observations, cases and outbox state are sensitive; encrypt the external backup and keep it out of Git. Do not copy only a live SQLite file, delete sidecars to force a clean state, merge older state into a running queue or discard pending alerts. An old restored outbox can produce duplicate delivery; server cache readback is not proof of new client receipt.

For a password problem, retain a console or trusted administrative connection. Preserve the old root-private auth file, then use the exact release's reviewed native setup/recovery procedure to create a replacement password hash. Do not delete case/state databases, make auth files world-readable, add passwordless sudo or expose the dashboard on the LAN to regain access. The installer will not overwrite a differing auth/config file.

For an unknown host/network/router-binding gap, pause review and verify the actual device, gateway and source context locally. Do not overwrite the original binding to make old approvals match, import a different network's router feed, or interpret missing telemetry as safe traffic. Reassess new network/source identity explicitly. Standalone Windows history is separate and does not automatically approve Linux observations.

For code/unit recovery, preserve the old package and all three hub/watchdog unit files plus consistent private state, compare the reviewed new files, and replace only explicitly selected paths. `install.py --hub-only` deliberately leaves differing original alert/router units alone and still refuses differing hub/package files. Restore compatible stopped state if a schema changed; do not silently roll a database backward while the worker runs.

Once configuration/authentication, evidence gaps and local UI access are understood, test one foreground instance while the unit is disabled. Then stop it and explicitly resume:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-hub.service sentinel-hub-watchdog.timer
```

The unit discards raw stdout/stderr; systemd still exposes lifecycle/exit status. Use the local authenticated dashboard and private reports for operational detail, and keep those details out of public issues. Timers/units that existed before the hub retain their own recovery procedures below.

## Encrypted hub backup and download

For a normal online hub backup, log into the local dashboard and use **Encrypted backup**: enter matching hidden passphrases of at least 16 characters, choose **Create encrypted backup**, then **Download encrypted backup**. GnuPG at `/usr/bin/gpg` is an optional prerequisite and is not installed by Sentinel. Keep the passphrase independently; do not enter it in a command, URL, issue or chat. The application does not retain it in configuration.

This operation coordinates with the hub lock and uses SQLite backup snapshots, so the hub need not be stopped for its own archive. It preserves every hub network case, imported evidence origins, decisions and absolute expiries, own alert outbox, hub configuration/authentication, configured ntfy dependency, package code and all three hub/watchdog units. Nested backup archives are excluded. The private `.tar.gpg` remains under `/var/lib/sentinel-hub/backups`; the authenticated download serves only a validated generated encrypted file. Temporary plaintext is removed on normal completion/failure, with no claim of secure SSD erasure.

A successful result verifies encrypted-content authentication and manifest member hashes. It **does not restore files**, verify a restored application, prove an independent off-host copy or provide a full-system backup. Legacy AdGuard/router/alerts and OS/SSH identity are listed as missing. Recreate the launcher/desktop entry from the matching reviewed source. Copy the downloaded archive to protected independent storage, verify that copy and its recovery passphrase, then plan an isolated restore before marking any broader backup gate complete. A local archive on the same SSD cannot protect against loss of that SSD.

There is no restore UI or generic extraction endpoint. For recovery, retain the original archive and evidence, stop the hub/watchdog as above, review the exact release and archive privately, and restore into an isolated destination first. Do not merge an older snapshot into running state, overwrite original host/network bindings or inherit endpoint permissions on a new network. Restored pending alerts can duplicate notifications. Preserve compatible code/state and validate local UI, source gaps, queue counts and subscriber receipt before resuming production operation.

The hub retains the latest 10,000 completed observation IDs it generated for replay detection, plus unfinished intake records. Imported IDs, relationship aggregates/counts, evidence, decisions and pending notices are preserved. Linux replay older than that ID window cannot be detected; unknown endpoint/local/UID buckets remain unapprovable. Bounded run history and replay compaction are not permission to delete unreviewed cases. No automatic archive retention/deletion policy is supplied; review free space and preserve backups until an explicit retention decision.

## Stop only Sentinel's scheduled work

```sh
sudo systemctl disable --now sentinel-router.timer sentinel-alerts.timer
sudo systemctl stop sentinel-router.service sentinel-alerts.service
```

These commands stop collection/publishing and preserve state and configuration. Check `systemctl status` for both services before copying SQLite files. Do not delete databases to clear an error: an unverified queued event or unacknowledged collector notice may still need delivery.

## Diagnose without exposing credentials

```sh
sentinel-network-watch doctor
sudo sentinel-network-watch alerts status
sudo sentinel-network-watch router status
sudo journalctl -u sentinel-alerts.service -u sentinel-router.service --since today
```

Router status may report a missing state before the first collection. Keep diagnostic output local: generic status is designed to omit secrets, while case reads/exports and raw router records contain private endpoints. Do not attach configs, databases, tokens, topics or complete captures to public issues. An alert status marked verified proves server cache readback, not client receipt.

For authentication failures, check the ntfy account/token read and publish permissions using the server's administration tools, then privately correct the config with `sudoedit`. Preserve ownership root:root and mode 0600. Sentinel retries authentication errors at bounded hourly intervals; a repaired config is loaded by the next invocation. Never put a replacement token in a command argument, URL, issue or chat.

For a router identity/profile error, stop its timer and confirm the exact supported hardware/firmware and explicitly configured gateway. Do not disable the guard or guess credentials. A telemetry gap, empty log window or missing endpoint is not evidence that traffic is safe or malicious.

## Backup and restore

After stopping both services, copy these directories into a protected backup owned by the administrator:

- `/etc/sentinel-alerts` and `/var/lib/sentinel-alerts`
- `/etc/sentinel-router` and `/var/lib/sentinel-router`, if used
- The reviewed source release and any local deployment changes

Use a backup tool that preserves ownership and private modes. Backups contain credentials, intent IDs and endpoint history; choose encryption/access controls and sync behavior deliberately. Copy the entire stopped state directory, including any SQLite sidecars that remain; do not copy only a live database file. Do not merge restored databases with newer live state or assume pending intents have already been delivered.

For restore, keep timers disabled, restore one consistent stopped snapshot with root ownership and private directories/files, then inspect local status. Run one explicit tick/collection only when ready for external requests. Duplicate notifications can occur after restoring old pending state. Personally test client receipt before re-enabling the timers.

For Windows/manual review, close all processes using the case before backing up its entire directory. Preserve its private ACL and identity context. On another PC, create a new device actor and verify evidence again; approval records are historical decisions, not permission automatically inherited by a new machine. Synced copies may conflict, so preserve both versions and reconcile deliberately rather than overwriting one blindly.

## Update or remove code

The installer deliberately refuses to overwrite differing files. For an update, stop Sentinel jobs, preserve code/units plus the private directories above, review the new release and its tests, and compare the changed files before an administrator deliberately replaces them. There is no unattended self-update or database migration guarantee in this alpha. Retain the previous release so code can be restored together with compatible stopped state if needed.

To remove scheduling, disable the two timers first. You may then remove the four Sentinel unit files, launcher and package directory **after verifying their exact paths and ownership**, followed by `sudo systemctl daemon-reload`. This repository supplies no recursive deletion command. Preserve private configuration/state/backups until their retention is explicitly decided; uninstalling code need not erase evidence.

After any deliberate code/unit change:

```sh
sudo systemctl daemon-reload
sudo sentinel-network-watch alerts status
```

Test an explicit operation and client receipt again, then enable only the timers you intend to run. A host that is powered off or unable to run its timer cannot alert about its own failure; reliable external dead-man monitoring is a separate system.
