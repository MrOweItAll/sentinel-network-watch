# Sentinel Network Watch

An alpha, standard-library Python toolkit for a durable ntfy alert outbox, optional router observations, and manual review of exact network endpoints. MIT licensed. Python 3.10 or newer is required.

The default Linux health profile checks the alert outbox filesystem. An optional profile checks an **already installed** Docker/AdGuard Home service. The optional router collector supports the explicitly identified Linksys EA7300 v2 firmware profile below. Windows tools capture current owner-PID tables and support a local manual review queue.

This is partial telemetry. It does not see every household connection, inspect encrypted content, determine whether a connection is malicious, or block traffic. A port number is a protocol hint, not permission. Continuous connection intake into the review queue is not implemented.

## Quick start on Ubuntu with systemd

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
| Alert publisher/systemd units | Linux with systemd; Ubuntu-focused | No automatic dependency installation; optional checks require existing services |
| Router collector | Exact documented profile, explicitly configured | Partial retained observations, not complete flows or IDS |
| Windows snapshot | Native Windows TCP/optional UDP owner tables | Point-in-time; UDP rows are bindings with no remote peer |
| Manual review queue | Local Python CLI, Linux/Windows tests | Approval records intent only; no firewall enforcement or automatic intake |

This is an alpha with synthetic offline tests; those tests do not certify arbitrary hardware, router firmware or mobile delivery. macOS deployment is unverified. Read [SECURITY.md](SECURITY.md), [installation](docs/INSTALL.md) and [recovery](docs/RECOVERY.md). Keep configs, SQLite databases, endpoint exports and backups out of public repositories. An owner-only ACL does not prevent a sync client running as that owner from uploading files.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
python3 install.py --prefix ./staging-root
python3 ./staging-root/usr/local/bin/sentinel-network-watch doctor
```

The staging prefix must be a dedicated directory, never `/`. Staging copies do not activate services. Optional pip/virtual-environment installation provides the CLI only; systemd deployment uses `install.py`. Contributions should use synthetic fixtures and document telemetry gaps. Report security issues using [SECURITY.md](SECURITY.md); do not attach real configurations or captures.
