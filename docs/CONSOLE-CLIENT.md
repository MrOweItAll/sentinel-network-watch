# Dedicated Sentinel desktop app

`sentinel_watch.console_client` is an optional Linux single-site client for the existing HTTPS console. It has Home, Reload and connection status, with no URL bar, tabs or general browsing. Sign in with the existing **dashboard** username/password; it never requests the Ubuntu administrator password. This source addition does not install the app or change the server, household DNS, router or browser trust stores.

Run it as the ordinary desktop user, through a separately reviewed launcher:

```text
python -m sentinel_watch.console_client
```

It requires a separately installed, pinned PySide6/Qt **6.10.x** runtime with QtWebEngine. Normal CLI/library tests do not need Qt. Do not run the web engine as root, disable its sandbox, add Chromium/debug flags or use a proxy/certificate-error workaround. Runtime installation and actual sandboxed engine acceptance remain separate checks.

Before creating `QApplication`, the launcher sets `QT_QUICK_BACKEND=software` only in its own process. This CPU Qt Quick scene-graph backend does not disable the Chromium sandbox or change TLS validation. It is not a claim that every engine component avoids the GPU. Alternate engine executable paths, Chromium flags, debugging and proxy environment overrides are rejected.

An administrator must prepare `/etc/sentinel-console-client` as a root-owned directory without group/other write access. Its fixed, root-owned regular files are:

- `config.json`: exactly `schema_version` (integer 1), `origin` (canonical HTTPS RFC1918 IPv4 origin with explicit port 8443 and no trailing path), and `ca_der_sha256` (64 lowercase hex characters).
- `ca.der`: the **one public approved CA certificate** in DER form, matching that fingerprint. No CA private key, dashboard verifier or password belongs here.

Both files must have one hard link and no group/other write access; 0644 is appropriate for this non-secret configuration. There are no CLI/environment URL, CA-path or credential overrides. A changed server address/certificate needs deliberate administrator review.

The app verifies the complete DER bytes and fingerprint, decodes exactly one X509 certificate, and adds it only to its own profile's CA database alongside normal roots. It uses the configured builder's `createProfile('')`, then requires `isOffTheRecord()` and the exact additional CA before loading. It never accepts certificate errors or creates per-host exceptions. System and Firefox/iPhone trust remain unchanged. See the official [Qt 6.10 profile-builder API](https://doc.qt.io/qtforpython-6.10/PySide6/QtWebEngineCore/QWebEngineProfileBuilder.html) and [certificate-error rejection API](https://doc.qt.io/qtforpython-6.10/PySide6/QtWebEngineCore/QWebEngineCertificateError.html).

Navigation and HTTP/resource requests are limited to the exact configured HTTPS origin. Other schemes/hosts/ports, redirects outside the origin, new windows, uploads, unknown protocols and requested device/filesystem permissions are denied. The app exposes no shell or enforcement controls. These are web-request restrictions, **not an OS network sandbox**: Qt 6.10 does not document a complete WebRTC data-channel disable setting. Only the trusted Sentinel page is loaded; engine security updates and server CSP still matter.

User state is under `~/.local/share/sentinel-console-client`, owned by the desktop user with mode 0700 and umask 077. Cookies/cache/permissions are nonpersistent; Qt/Chromium can still create transient files. Each run uses a private temporary profile path, with best-effort cleanup only after the view/page/profile are destroyed. An interrupted process may leave private transient files; no zero-disk claim is made.

The console's Download report button can save only a same-origin JSON blob from its own page, with a known declared size between 1 byte and 4 MiB. Downloads stage privately, receive-size checks cancel oversized transfers, and the completed file is independently checked for owner/link/size, valid JSON and exactly `snapshot`/`annotations` top-level objects. Publication uses a generated filename and exclusive creation in the user's private `reports` subfolder, never a suggested remote filename or overwrite. Reports contain private network observations; keep them out of Git and shared folders. Other downloads and full-page saves are blocked.

Pure policy tests cover origin confusion, forbidden schemes, download bounds, CA envelopes/fingerprints, file metadata, report schema and no-overwrite publication. Actual engine TLS, navigation/subresource denial, report export and a human login/rendering check must pass before recording this app as accepted. The internal `create_window(...)` factory supports isolated loopback fixtures only in trusted Python test code; the shipped launcher always reads the fixed root configuration.

The optional actual-engine runner also requires `cryptography`. From the source checkout, run as an ordinary Linux user with the supported system Qt packages:

```sh
QT_QUICK_BACKEND=software python3 -I -B tests/linux_console_client_acceptance.py --module-root ./src --report /tmp/sentinel-client-engine-test.json
```

Choose a new report filename on subsequent runs; existing files are never overwritten. The runner uses temporary synthetic loopback certificates and accounts, rejects unsafe engine flags, and contacts no production console. Its image is synthetic; human acceptance of the actual desktop remains a separate check. Runtime seccomp, capabilities and profile-label observations describe the tested process; they do not establish complete OS network or namespace isolation.
