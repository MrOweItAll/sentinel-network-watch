# Recovery and maintenance

Keep a local console or a separately tested administrative connection available before enabling timers. Sentinel does not manage SSH, firewall, household DNS or the router configuration. Stopping its jobs does not require changing those systems.

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
