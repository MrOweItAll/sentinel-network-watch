# Installation and configuration

## Requirements and installation paths

Python 3.10+ and its standard library are sufficient. The host publisher is intended for Linux with systemd; the copy installer requires Linux root. The installer does not run apt, pip, Docker, systemctl, or network commands. Keep the distribution's system Python intact; [Ubuntu's Python guidance](https://ubuntu.com/developers/docs/howto/python-setup/) describes isolated environments for additional packages.

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
| `/usr/share/sentinel-network-watch/examples` | Public placeholders only |
| `/etc/sentinel-alerts`, `/etc/sentinel-router` | Private config directories; no config created |
| `/var/lib/sentinel-alerts`, `/var/lib/sentinel-router` | Private persistent state |

The installer accepts identical existing files and refuses differing files, symlinks/reparse points, or unsafe private directories. It does not merge an existing installation. A copied unit file does not imply the corresponding timer is active. Existing installations must be reviewed before changing files; see [recovery](RECOVERY.md).

For an offline staging copy, including on Windows:

```sh
python3 install.py --prefix ./staging-root
python3 ./staging-root/usr/local/bin/sentinel-network-watch doctor
```

All installed paths are contained inside that prefix; no system commands run. This is a file-layout test, not an operational systemd installation.

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
