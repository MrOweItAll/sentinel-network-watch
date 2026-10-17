# Installation and configuration

## Requirements and installation paths

Python 3.10+ and its standard library are sufficient for collection, review and alerts. Optional encrypted hub backups additionally require a separately installed `/usr/bin/gpg`; Sentinel does not install it. The host publisher is intended for Linux with systemd; the copy installer requires Linux root. The installer does not run apt, pip, Docker, systemctl, or network commands. Keep the distribution's system Python intact; [Ubuntu's Python guidance](https://ubuntu.com/developers/docs/howto/python-setup/) describes isolated environments for additional packages.

Run from a reviewed checkout or extracted release:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
sudo python3 install.py
sentinel-network-watch --version
sentinel-network-watch doctor
```

| Path | Contents |
| --- | --- |
| `/opt/sentinel-network-watch/sentinel_watch` | Curated Python modules |
| `/usr/local/bin/sentinel-network-watch` | Python launcher |
| `/etc/systemd/system/sentinel-{alerts,router}.{service,timer}` | Disabled deployment units |
| `/etc/systemd/system/sentinel-hub.service` | Disabled autonomous worker/local UI service |
| `/etc/systemd/system/sentinel-hub-watchdog.{service,timer}` | Disabled independent liveness/alert-retry units |
| `/usr/share/applications/sentinel-hub.desktop` | Normal-user browser launcher; no embedded secret |
| `/usr/share/sentinel-network-watch/examples` | Public placeholders only |
| `/etc/sentinel-alerts`, `/etc/sentinel-router` | Private config directories; no config created |
| `/var/lib/sentinel-alerts`, `/var/lib/sentinel-router` | Private persistent state |
| `/etc/sentinel-hub`, `/var/lib/sentinel-hub` | Private hub config/auth and independent state/outbox |

The installer accepts identical existing files and refuses differing files, symlinks/reparse points, or unsafe private directories. It does not merge an existing installation. A copied unit file does not imply the corresponding timer is active. Existing installations must be reviewed before changing files; see [recovery](RECOVERY.md).

For an offline staging copy, including on Windows:

```sh
python3 install.py --prefix ./staging-root
python3 ./staging-root/usr/local/bin/sentinel-network-watch doctor
```

All installed paths are contained inside that prefix; no system commands run. This is a file-layout test, not an operational systemd installation.

## Autonomous hub and local dashboard

The hub is a separate long-running service. It collects at a configured 60-second interval and presents normal review/report pages on **127.0.0.1:8765 only**. No ChatGPT session is required after setup. The root service reads process/socket identity evidence and optional existing router state; it cannot repair networking, change firewall/DNS/router policy, execute shell commands from the UI or turn a review approval into enforcement.

For an existing Sentinel installation, preserve its current alert/router units:

```sh
sudo python3 install.py --hub-only
```

This copies the curated package, hub/watchdog units, desktop launcher and public examples; it creates only the hub's private config/state directories. It does not inspect or replace the original alert/router unit paths, change their private configuration/state, run a package manager, reload systemd, start a browser or enable anything. Existing differing package/launcher/hub files still cause a refusal before any new file is written. Review an update/migration rather than forcing replacement.

On a clean host, the default full copy also installs the standalone alert/router units, still disabled. Configure the publisher using `init-config` if needed; an existing private `/etc/sentinel-alerts/config.json` can be read without being copied into hub state. The hub creates its own outbox under `/var/lib/sentinel-hub/alerts`; it does not write the legacy alert outbox or poll the router itself. If router input is selected, the separately scheduled router collector remains responsible for producing that source state.

Initialize at a native local terminal:

```sh
sudo sentinel-network-watch hub init --config /etc/sentinel-hub/config.json --network-label 'Home' --alerts-config /etc/sentinel-alerts/config.json
```

Optional arguments include `--state-dir /var/lib/sentinel-hub` and `--router-state-dir /var/lib/sentinel-router`. Initialization derives the local host/network binding and requests a separate dashboard password through hidden local entry. Never silently reuse the administrator password, put credentials in arguments/environment variables, or commit the generated configuration/auth/state. The username defaults to `sentinel`. The auth file is `/etc/sentinel-hub/dashboard-auth.json`, root-owned mode 0600, holding a salted PBKDF2-SHA256 hash rather than plaintext. Hub directories are private mode 0700.

`examples/hub.json.example` illustrates the keys but intentionally contains a zero network UUID and invalid identity placeholders. A real initialization must replace those with verified bindings; loading that unconfigured sample must fail. Preserve the original binding on migration. A different host/network needs new verified attribution rather than automatically inheriting old approvals. Router import must not reuse a household's feed after a gateway/network change; investigate a binding gap instead of bypassing it.

Run a single foreground `hub serve --config /etc/sentinel-hub/config.json` while the systemd unit is disabled, then open `http://127.0.0.1:8765/` from the same host. Alternatively use the installed application-menu entry. It runs only `xdg-open` with that fixed loopback URL. A remote Windows browser's localhost is its own machine, and no SSH tunnel or LAN listener is created by this installation.

The normal UI uses the separate password, session cookies and CSRF protection for mutations. Its existing-service summary reports local state without granting service control. The AdGuard link opens its separate local interface at `http://127.0.0.1:3000`, with separate credentials. Loopback is not per-user isolation; keep the password/auth file private even on a shared machine. The UI exposes bounded review operations, not a root command executor. Review both source identity and evidence before choosing an explicit endpoint duration. Device/binary recognition alone is not an endpoint grant or a suppression rule. Saved case IDs are scoped to their source/network; copying another machine's case is not authorization on this host.

The unit runs as root to correlate other users' `/proc` socket FD/executable ownership. Its only retained capabilities are `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` for those read operations; it has no `NET_ADMIN` or `NET_RAW`. Its filesystem is read-only except hub state, home directories remain read-only for executable hashing, and `/proc` uses the default host view. Private devices/temp, no-new-privileges and other systemd restrictions remain enabled. Configuration/legacy router state are read-only; dashboard authentication does not grant arbitrary root operations. Inspect the unit before deployment on a system with different `/proc` or security policies; unavailable attribution must remain an explicit gap.

Linux evidence is a non-atomic TCP4/TCP6 snapshot in the collector's current network namespace. It includes established peer rows and listening bindings, not UDP peers, namespace traversal, initiation direction, scripts/arguments/environment, payloads or complete history. Collection bounds include rows/PIDs/FDs/hash bytes/time; short-lived or inaccessible/racing/shared owners can be missed or remain unknown. Optional router history has its own bounded-window/schema limits. Observation counts are not sessions, requests or byte totals. Run history is bounded summary history. The newest 10,000 completed hub-owned replay IDs are retained, with unfinished intake records kept for crash recovery. Imported observation IDs, case aggregates, cumulative sightings, decisions and pending notices are preserved. Router watermarks avoid re-counting unchanged retained rows after compaction; Linux replay older than the ID window cannot be detected. Unattributed endpoint/local/UID buckets are explicitly unapprovable and may contain different processes. Capacity limits produce a gap; they are not permission to delete unreviewed cases. Verify retained gaps/capacity status in the UI rather than interpreting an empty page as an all-clear.

After the foreground/UI/alert checks pass, stop that process, then explicitly enable the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-hub.service sentinel-hub-watchdog.timer
systemctl status sentinel-hub.service sentinel-hub-watchdog.timer --no-pager
```

The independent watchdog checks hub freshness and service state and retries the hub's durable alert outbox on a separate minute timer. It can report a stopped/stale hub while the host and Internet still work; it cannot report complete host, power or Internet loss. Pause its own timer/service deliberately during intentional hub maintenance and resume afterward.

Do not run the foreground and systemd instances concurrently. Closing the browser does not stop the service. The host must remain awake; complete power/Internet loss cannot be announced during the outage without a separate outside observer. No reboot, package installation or network policy change is performed by these hub setup tools.

### Optional encrypted hub backup

The dashboard includes an **Encrypted backup** form. It requires [GnuPG](https://gnupg.org/documentation/manuals/gnupg24/gpg.1.html) at `/usr/bin/gpg`; installing that dependency is a separate administrator action. Collection, review and alerts work without it.

1. Log in locally and enter the same new passphrase of at least 16 characters in both hidden fields. Keep it separately; losing it prevents recovery of the archive.
2. Choose **Create encrypted backup**. The backend locks hub activity, snapshots all hub SQLite databases through the backup API, encrypts the archive and verifies decryption authentication and member hashes. The passphrase is not put in a URL, command argument, log or configuration file.
3. When creation succeeds, choose **Download encrypted backup**. Only that generated encrypted archive is downloadable through an authenticated same-origin request; no arbitrary file path, plaintext archive or restore action is exposed.
4. Verify an independent protected copy and perform an isolated restore test separately. The downloaded archive contains private authentication, ntfy configuration and endpoint history; keep it out of Git.

Archives are created under `/var/lib/sentinel-hub/backups`. They include hub config/auth, all hub network cases/imported origins, its own outbox, configured ntfy credentials, package code and hub/watchdog units. Legacy AdGuard/router/alert code/config/state and OS/SSH identity are excluded, and the result lists missing components. `integrity_verified` can be true while restore verification, off-host-copy verification and full-system completeness remain false. Local archives share the host's failure risks. See [recovery and retention](RECOVERY.md#encrypted-hub-backup-and-download).

For a CLI-only install, use a new virtual environment in your chosen development directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/sentinel-network-watch doctor
```

Windows equivalents are `py -3 -m venv .venv`, `.\.venv\Scripts\python.exe -m pip install .`, and `.\.venv\Scripts\sentinel-network-watch.exe doctor`. The build backend may need to be downloaded by pip. A virtual environment is [not portable between machines](https://docs.python.org/3/library/venv.html); recreate it at its destination. Do not combine a pip installation with the systemd copy layout unless you understand which launcher is executing.

## ntfy configuration and first test

Choose an ntfy server with valid HTTPS, create a private topic and grant the required read/write access. Subscribe in your own client first. Tokens are sent in an Authorization header, not a URL query. A hard-to-guess topic is not equivalent to enforced access control. See the official [ntfy authentication documentation](https://docs.ntfy.sh/publish/#access-tokens).

```sh
sudo sentinel-network-watch init-config
```

The prompts hide the topic and optional token. The root-owned file `/etc/sentinel-alerts/config.json` is created exclusively with mode 0600, inside a private directory. No topic or token argument is supported and no request is sent during initialization. Existing files are preserved. The conceptual schema is:

```json
{
  "base_url": "https://ntfy.example.com",
  "topic": "REPLACE_WITH_PRIVATE_TOPIC",
  "token": "REPLACE_WITH_ACCESS_TOKEN_IF_REQUIRED",
  "health_profile": "outbox"
}
```

The placeholder server/topic/token are examples, not working credentials. Use the hidden prompts rather than pasting actual secrets into shell commands or scripts. An HTTPS origin has no path, query, fragment or embedded credentials. Omit `token` when the server does not require authentication.

```sh
sudo sentinel-network-watch alerts status
sudo sentinel-network-watch alerts enqueue-test
sudo sentinel-network-watch alerts tick
sudo sentinel-network-watch alerts status
```

Status performs no network request. A tick observes health and attempts at most one due queued event. Cache verification can lag publishing, so a pending readback is retried without reposting an already accepted message. Network ambiguity is reconciled through readback before a later publish retry; duplicate delivery remains possible. HTTP authentication errors back off for an hour; rate limits respect bounded Retry-After/backoff. No tight-loop retry is necessary.

Personally confirm the generic test notification in your subscribed client. A verified cache ID is not an acknowledgement from your phone. Android background settings and iOS push delivery, especially with self-hosting, require separate client/server configuration described in the [ntfy subscription documentation](https://docs.ntfy.sh/subscribe/phone/).

After testing and agreeing on recovery:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-alerts.timer
systemctl status sentinel-alerts.timer
sudo sentinel-network-watch alerts status
```

### Existing AdGuard Home profile

The default `outbox` profile checks the writable state filesystem only. To opt into checks for services already installed:

```sh
sudo sentinel-network-watch init-config --health-profile adguard
```

For an existing config, use `sudoedit /etc/sentinel-alerts/config.json`, preserving root ownership and mode 0600. Set `health_profile` to `adguard`; optional `container_name`, `dns_port` and `web_port` default to `sentinel-adguard`, 1053 and 3000. Ports must be integers 1–65535. Checks inspect Docker service/container state, perform loopback TCP/UDP DNS probes and a loopback HTTP probe. Docker access from this root service is privileged; install this profile only on a host whose Docker daemon and selected container you administer. Sentinel does not install the services, change DNS, or add Docker group members. [Docker's official Ubuntu guide](https://docs.docker.com/engine/install/ubuntu/) covers its separate installation and firewall caveats.

## Optional router collector

Only the exact profile `linksys-ea7300-v2-2.0.4.216940` is supported. Confirm the model, hardware version and firmware before attempting collection. Other models/firmware fail the identity guard. There is no general-purpose router discovery or authentication bypass.

If the router administrator has separately enabled router logging, create a private config:

```sh
sudo install -m 0600 examples/router.json.example /etc/sentinel-router/config.json
sudoedit /etc/sentinel-router/config.json
```

Replace `192.0.2.1` with your explicitly selected gateway IP literal. The example uses a documentation address and will not discover your gateway. Do not place a router password in this file. Exact keys are `gateway` and optional `profile`. No network settings are changed by collection.

With a working alert configuration already present:

```sh
sudo sentinel-network-watch router collect
sudo sentinel-network-watch router status
```

`collect` performs one bounded read-only pass and durably hands generic notices to the alert outbox. `status` reads local state. Log history is finite and polling can miss events; records are observations, not session counts. Unknown transport, missing peer fields and unauthenticated device labels cannot establish endpoint permission. Initial inventory is a baseline, not a trusted-device approval. Raw observations stay private, with bounded retention/capacity; telemetry gaps are reported rather than silently asserted complete.

Only after validating that pass, explicitly enable collection:

```sh
sudo systemctl enable --now sentinel-router.timer
systemctl status sentinel-router.timer
```

The collector does not alter router logging settings, firewall, DNS, DHCP or port forwarding. Do not expose the router management interface to the Internet.

## Windows snapshot and manual review

Use Windows Python 3.10+ in a checkout or virtual environment. From a checkout in PowerShell, make the source package available in this terminal:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
py -3 -m sentinel_watch doctor
py -3 -m sentinel_watch init-case --directory "$env:LOCALAPPDATA\SentinelWatchCase"
py -3 -m sentinel_watch windows-snapshot --case-dir "$env:LOCALAPPDATA\SentinelWatchCase" --output "$env:LOCALAPPDATA\SentinelWatchCase\snapshot-001.json"
```

The case directory must be new. Initialization restricts Windows access to the current user and SYSTEM; POSIX cases use owner-only permissions. Output must be a new file inside that verified case directory. Avoid a synced case location unless you accept possible upload by your own sync client. Windows capture uses native IP Helper owner tables and does not install a driver or service. TCP state is a current observation, not proof of connection initiation. UDP capture via `--include-udp` lists local bindings, not remote peers. Captures alone do not establish a verified application path/hash/publisher identity.

Review ingestion is explicit and **not** an automatic conversion from raw snapshots. Build a JSON list matching `examples/review-input.json.example` from evidence you have verified; place it inside the private case folder. The example contains synthetic documentation addresses and should never be treated as an approval recommendation. For a case folder already initialized:

```powershell
py -3 -m sentinel_watch review --case-dir "$env:LOCALAPPDATA\SentinelWatchCase" --db "$env:LOCALAPPDATA\SentinelWatchCase\review.sqlite3" ingest --input "$env:LOCALAPPDATA\SentinelWatchCase\observations.json"
py -3 -m sentinel_watch review --case-dir "$env:LOCALAPPDATA\SentinelWatchCase" --db "$env:LOCALAPPDATA\SentinelWatchCase\review.sqlite3" status
py -3 -m sentinel_watch review --case-dir "$env:LOCALAPPDATA\SentinelWatchCase" --db "$env:LOCALAPPDATA\SentinelWatchCase\review.sqlite3" read --id C0001
```

Read details privately, then decide one exact relationship at a time. An example 24-hour decision (only after independently reviewing that particular record) is:

```powershell
py -3 -m sentinel_watch review --case-dir "$env:LOCALAPPDATA\SentinelWatchCase" --db "$env:LOCALAPPDATA\SentinelWatchCase\review.sqlite3" decide --id C0001 --decision approve --scope-endpoint --expires-seconds 86400
```

Duration is explicit per decision; there is no default approval duration. `--until-revoked` is a separate deliberate choice. Approval applies to exact actor, application context, record kind, transport, address and port. It does not authorize arbitrary traffic by an application, infer inbound permission, or enforce a firewall rule. Unknown/incomplete transport records cannot be approved. Interpreter/process-lifetime identity and ordinary binary identity must be constructed carefully by the evidence producer; this toolkit does not guess them. Never transplant another machine's actor/application identity to inherit its approvals.
