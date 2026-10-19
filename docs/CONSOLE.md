# Private network console

This alpha console operates without ChatGPT. A systemd timer collects a bounded observation snapshot every 30 seconds; the browser refreshes its view every 10 seconds while visible. Existing Sentinel router collection and notification services remain separate.

The console shows current TCP sockets and listeners on the Linux host, retained Linksys router observations, reported device inventory, source health, and actual Linux interface byte counters. Search, direction/source/review filters, durable review notes and a JSON report download are included. The view and download state their limits. Router history is capped at 500 exported observations per snapshot, alongside up to 500 local entries; it is not a complete flow recorder. Existing router evidence remains in its original database under its existing retention policy.

Unknown connections require review even when their device is recognized. Recognition in this console is a recorded assessment of that observation identity. It does not create an endpoint permission, inherit historical approvals, or change traffic. Review changes are journalled locally. There is no automatic enforcement, endpoint kill, process termination or blocking API.

## Interpret the evidence

Incoming/outgoing router labels are retained log labels, not proof that a connection is active or was accepted. iMac socket endpoints do not establish the initiator. A listening socket does not establish external reachability. Device names are router reports; addresses can be reassigned. Alias matches are time bounded and explicitly provisional.

Interface counters measure this host's traffic, including local traffic. They are neither per-application nor household totals. Rates require two compatible samples; reboot, interface identity, gateway context, clock or counter resets invalidate the previous baseline. Missing measurements remain unavailable. Never add bridge and physical interface counters indiscriminately.

Encrypted traffic hides its contents from a passive monitor. An unfamiliar domain, IP owner, geographic label or large upload is a reason to investigate, not proof of spyware or a data leak. Large-upload detection requires a suitable byte source and a reviewed baseline. No outside IP-reputation or geolocation service is queried by this console.

For an iPhone, Apple's **App Privacy Report** supplies complementary app/domain and sensitive-permission history. Enable it at Settings → Privacy & Security → App Privacy Report. Collection begins after enabling it. It does not establish upload contents or per-app byte totals, and this version does not automatically ingest the report. [Apple documentation](https://support.apple.com/en-ie/102188)

## Security and deployment boundary

`sentinel-console.service` runs as the non-login `sentinelconsole` account with no Linux capabilities or sudo access. Its HTTPS listener binds one configured IPv4 address and port 8443; it accepts only the configured home CIDR. Exact Host/Origin validation, Secure/HttpOnly/SameSite cookies, CSRF checks, bounded requests/workers, session expiry and login limits are enforced. It has no router credentials, administrator password, arbitrary file or command endpoint.

`sentinel-console-feed.service` is a separate root worker. It reads only local socket metadata, interface statistics and existing router evidence, then atomically publishes a bounded credential-free file. The root-owned feed directory is mode 0750 and snapshot mode 0640, readable by the console group but not writable by it. The web process cannot read the original private router or alert directories. The worker makes no router requests or DNS lookups and reads no process arguments, environments or payloads.

Feed configuration is root-private and binds a network UUID to the expected IPv4 default gateway and MAC hint. A changed/unavailable binding pauses connection export; review identities include network context. A MAC hint is not cryptographic authentication and does not defend against an attacker already able to impersonate the gateway. A new network requires explicit onboarding; old permissions must not transfer automatically.

TLS private keys and the salted dashboard verifier remain private local files. Use a separate dashboard password. Enrol the exact local CA deliberately on each client and verify its identity through a trusted channel. Never bypass a browser warning, expose this service through port forwarding, or use the Ubuntu sudo password as the dashboard password. Local certificate expiry and address changes need a planned renewal/reconfiguration; this alpha does not silently change either.

## Operation and recovery

Check `systemctl status sentinel-console.service sentinel-console-feed.timer` and `systemctl status sentinel-router.timer sentinel-alerts.timer` locally. A stale or missing feed must be investigated; it is not evidence of no traffic. The service journal uses fixed errors and does not log passwords or request bodies. Existing ntfy delivery remains independently configured and must be tested separately from dashboard access.

The new console's private state is `/var/lib/sentinel-console`, its filtered observation handoff is `/var/lib/sentinel-console-feed`, and configuration is under `/etc/sentinel-console` and `/etc/sentinel-console-feed`. Preserve the review database and its audit table. Back up private state only into a separately protected, preferably encrypted destination; code repositories do not substitute for a state backup. CA and TLS keys must never enter a public repository.

To withdraw access, stop/disable the console service and feed timer, then remove only the host-firewall rule created for this listener. Preserve state and original Sentinel services. Do not reset the router or alter household DNS. Remove the enrolled CA from clients if permanently retiring this deployment. Before any migration, re-check the network, address, interface, certificate, firewall scope and adapter capabilities.

The service units are templates, not a universal unattended installer: they require a reviewed user/group, file ownership, authentication, TLS and root-private network configuration. See [capabilities and future router contracts](CONSOLE-CAPABILITIES.md) before selecting replacement equipment or enabling control. No specific future router plugin is shipped yet.

Developers can run `python3 -B tests/linux_console_acceptance.py --source-root /absolute/path/to/src` as a non-root Linux user. It uses synthetic records, a temporary certificate/verifier and loopback port 8443, verifies real HTTPS authentication and review behavior, and removes only its own temporary material. It refuses an occupied port and never changes production services. The Linux CI jobs run this check separately from offline unit tests.
