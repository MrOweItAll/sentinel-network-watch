# Sentinel Network Watch

An alpha, standard-library Python toolkit with an autonomous Linux review hub, a local authenticated dashboard, durable ntfy alerts, and optional router observations. After native setup, use the normal desktop/browser interface; ChatGPT is not required to collect observations, view reports or review pending items. MIT licensed. Python 3.10 or newer is required.

The default Linux health profile checks the alert outbox filesystem. An optional profile checks an **already installed** Docker/AdGuard Home service. The optional router collector supports the explicitly identified Linksys EA7300 v2 firmware profile below. Windows tools capture current owner-PID tables and support a local manual review queue.

This is partial telemetry. Linux collection observes TCP peers/listeners in the collector's current network namespace; optional router import reads an existing collector's bounded private history. It does not see every household connection, inspect encrypted content, determine whether a connection is malicious, or block traffic. A port number is a protocol hint, not permission. Windows snapshot ingestion remains a separate explicit workflow.

## Autonomous Linux hub

Install from a reviewed release on a Linux/systemd host. The installer is copy-only and leaves every service/timer disabled. On a host with existing Sentinel alert/router units, use `sudo python3 install.py --hub-only` to preserve those units; see [installation](docs/INSTALL.md#autonomous-hub-and-local-dashboard).

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
sudo python3 install.py
```

If no private ntfy configuration exists yet, create it with `sudo sentinel-network-watch init-config`, using the hidden native topic/token prompts. Existing credentials are preserved. Then initialize the hub and a **separate dashboard password**, locally:

```sh
sudo sentinel-network-watch hub init --config /etc/sentinel-hub/config.json --network-label 'Home' --alerts-config /etc/sentinel-alerts/config.json
```

Initialization records the local network/host binding and writes root-private configuration and password-hash files. The zero-UUID JSON example is deliberately unconfigured and must not be used as a live config. Add `--router-state-dir /var/lib/sentinel-router` only for a separately configured existing collector whose identity/coverage you have checked. No router logging, DNS or firewall setting is changed.

Test one foreground hub instance while its service is disabled:

```sh
sudo sentinel-network-watch hub serve --config /etc/sentinel-hub/config.json
```

Open **Sentinel Network Watch** from the Ubuntu application menu, or browse to `http://127.0.0.1:8765/` on that same Linux desktop. Log in with the dashboard credentials chosen during setup. The launcher carries no token, password or sudo command. Review the displayed source/network, existing-service summary, collection gaps and pending items; approvals require an explicit scope and duration and do not change the firewall. A listener binding is not proof of incoming reachability. The local AdGuard link, if applicable, opens `http://127.0.0.1:3000` and still requires AdGuard's separate login.

After checking local operation and generic alert delivery, stop the foreground instance with Ctrl+C and enable the persistent service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-hub.service sentinel-hub-watchdog.timer
systemctl status sentinel-hub.service sentinel-hub-watchdog.timer --no-pager
```

The hub works without the browser or ChatGPT open while the host is awake. Its 60-second worker and UI share private hub state; generic alerts use the hub's own durable outbox. An independent watchdog timer checks hub freshness/service state and retries the same hub outbox even if the hub service stops. It cannot report during whole-host, power or Internet loss; an outside observer is still needed. Existing alert/router timers and their state are separate. The dashboard is authenticated and loopback-only, has no shell/sudo/apply endpoint, and must not be exposed through a tunnel, LAN bind or router forwarding rule. See [recovery](docs/RECOVERY.md#autonomous-hub-recovery).

Unattributed Linux snapshots use explicit endpoint/local-address/port/UID observation buckets. A bucket may contain different processes and is never an application or session identity; it cannot be recognized or approved. Its latest evidence retains the original capture context. Known application contexts and imported historical cases keep their original identities. To bound repeat metadata, the hub retains the newest 10,000 completed observation-ID hashes that it generated itself, plus any unfinished intake records; status reports the compaction count. Relationship first/last sightings, cumulative observation counts, latest evidence, decisions, recognitions and pending notices remain. Imported observation IDs are protected. Router watermarks prevent unchanged retained rows being re-counted after ID compaction; Linux replay older than the retained ID window cannot be detected. These counts are observations, not sessions. The 50,000-relationship/200 MiB database caps still produce a visible collection gap rather than deleting unreviewed evidence.

### Local encrypted backups

In the dashboard's **Encrypted backup** section, enter and confirm a new passphrase of at least 16 characters, choose **Create encrypted backup**, then **Download encrypted backup**. This optional feature requires a separately installed `/usr/bin/gpg`; the installer does not install it. Keep the passphrase separately and never put it in a URL, command or repository.

The hub snapshots its databases under its activity lock and verifies the encrypted archive's authentication and member hashes before offering the download. The archive includes hub configuration/authentication, all hub network cases and preserved imported evidence, its own alert outbox, configured ntfy credentials, code and hub/watchdog units. It remains a **local, partial backup**: downloading does not verify an off-host copy, integrity verification is not a tested restore, and legacy AdGuard/router/alert services plus OS/SSH identity are excluded. There is no restore endpoint. Move a copy to independent protected storage and test restoration in isolation; see [recovery](docs/RECOVERY.md#encrypted-hub-backup-and-download).

## Standalone alert publisher (optional)

Download and extract the repository ZIP, or clone it:

```sh
git clone https://github.com/mroweitall/sentinel-network-watch.git
cd sentinel-network-watch
PYTHONPATH=src python3 -m unittest discover -s tests
sudo python3 install.py
sentinel-network-watch doctor
```

The copy-only installer installs the package, launcher, examples and systemd units. It runs no package manager, Docker command, network request or systemctl command. It creates **no credentials** and leaves the timers disabled. It refuses to overwrite differing existing files. See [installation details](docs/INSTALL.md) before installing on a host that already uses these paths.

Create a topic on an ntfy server you trust, configure its access permissions, then subscribe to that server and topic in your ntfy client. If authentication is required, the publisher needs both publish and subscription/read permission for cache verification. Enter secrets in the local terminal:

```sh
sudo sentinel-network-watch init-config
sudo sentinel-network-watch alerts status
sudo sentinel-network-watch alerts enqueue-test
sudo sentinel-network-watch alerts tick
sudo sentinel-network-watch alerts status
```

`init-config` prompts for an HTTPS origin and hides the topic and optional token. It makes no network request. `enqueue-test` only queues an intent; `tick` explicitly contacts your configured ntfy server and processes at most one due event. The first tick also queues a generic boot notice. If cache readback is pending, allow the retry interval to pass before another tick. Check your client and personally confirm receipt. Server acceptance or cache verification does **not** prove phone delivery.

When the test and local recovery procedure are satisfactory, explicitly enable recurring alerts:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-alerts.timer
systemctl list-timers sentinel-alerts.timer
```

The timer runs about once per minute. Alerts contain generic categories rather than device names or endpoint details. The outbox preserves pending work across restarts; uncertain publish outcomes can still produce duplicates because the upstream publish API has no exactly-once guarantee. See [ntfy delivery behavior](https://docs.ntfy.sh/subscribe/api/) and [recovery](docs/RECOVERY.md).

## Optional features

- **Existing AdGuard Home:** select `adguard` during `init-config` with `--health-profile adguard`, or privately edit your existing config. Defaults expect container `sentinel-adguard`, loopback DNS port 1053 and loopback HTTP port 3000. This project does not install Docker or AdGuard Home, or change DNS. See [configuration](docs/INSTALL.md#existing-adguard-home-profile).
- **Router observations:** explicitly configure a gateway only for profile `linksys-ea7300-v2-2.0.4.216940`, test one collection, then separately enable its timer. Collection uses fixed read-only JNAP actions with no router credentials. Router logging must already be enabled by its administrator; Sentinel never enables it. The finite log window omits transport, source port, byte counts and reliable flow identity. It cannot establish full coverage. See [router setup](docs/INSTALL.md#optional-router-collector).
- **Windows capture and review:** use the Python CLI from a checkout or an isolated virtual environment. No Windows monitoring service is installed. The snapshot contains private addresses/PIDs, not verified application signatures or a complete traffic history. See [Windows instructions](docs/INSTALL.md#windows-snapshot-and-manual-review).

## Scope and privacy

| Component | Intended scope | Important limit |
| --- | --- | --- |
| Autonomous hub/local dashboard | Linux with systemd, configured host/network binding | Current namespace TCP snapshots and optional retained router data; no full-flow or household-wide guarantee |
| Alert publisher/systemd units | Linux with systemd; Ubuntu-focused | No automatic dependency installation; optional checks require existing services |
| Router collector | Exact documented profile, explicitly configured | Partial retained observations, not complete flows or IDS |
| Windows snapshot | Native Windows TCP/optional UDP owner tables | Point-in-time; UDP rows are bindings with no remote peer |
| Standalone manual review CLI | Local Python CLI, Linux/Windows tests | Explicit ingest; approval records intent only and does not enforce firewall rules |

This is an alpha with synthetic offline tests; those tests do not certify arbitrary hardware, router firmware or mobile delivery. macOS deployment is unverified. Read [SECURITY.md](SECURITY.md), [installation](docs/INSTALL.md) and [recovery](docs/RECOVERY.md). Keep configs, SQLite databases, endpoint exports and backups out of public repositories. An owner-only ACL does not prevent a sync client running as that owner from uploading files.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
python3 install.py --prefix ./staging-root
python3 ./staging-root/usr/local/bin/sentinel-network-watch doctor
```

The staging prefix must be a dedicated directory, never `/`. Staging copies do not activate services. Optional pip/virtual-environment installation provides the CLI only; systemd deployment uses `install.py`. Contributions should use synthetic fixtures and document telemetry gaps. Report security issues using [SECURITY.md](SECURITY.md); do not attach real configurations or captures.
