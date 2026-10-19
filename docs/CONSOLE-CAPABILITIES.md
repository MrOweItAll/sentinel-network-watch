# Console capabilities and router adapters

**Status: alpha contracts; additional gateway integrations are proposed.** A console can display only the evidence its configured sources supply. This document does not claim a newly connected router, complete household visibility or an installed enforcement feature. No replacement router model has been selected here.

## What the current sources can establish

The existing EA7300 v2 / `2.0.4.216940` profile collects device inventory and bounded retained router logs through reviewed read-only JNAP actions. The saved vendor Troubleshooting code requests a window starting at 1 with at most 255 rows. Incoming/outgoing vendor labels are observations, not proof of initiation, acceptance, blocking or a distinct session. Its traffic-log schema does not establish transport, source port, event duration or per-flow byte counts. Empty or missing rows do not prove there was no traffic.

The inspected `GetNetworkConnections` data describes device/link associations, including `negotiatedMbps`, wireless band and signal. A negotiated link rate is not measured Internet consumption. Linksys documents upload/download usage on **models supporting that option**; this does not verify the feature or an export API on this exact firmware. A generic action named `GetConnections`, a NAT-table export and per-flow counters remain unverified. Absence from one inspected UI module does not establish that every firmware module lacks them. [Linksys Network Map documentation](https://support.linksys.com/kb/article/1802-hk/)

The EA7300 manual documents website/schedule controls, traffic prioritization and firewall settings. Those are not evidence of a programmable, exact per-flow block API. Do not repurpose port forwarding or IPv6 inbound exceptions as outbound blocking. [EA7300 manual](https://downloads.linksys.com/downloads/userguide/EA7300_UG_INTL.pdf), [Linksys Security tool](https://support.linksys.com/kb/article/3004-cn/)

An endpoint snapshot describes that host and its observation namespace. It can miss short connections and inaccessible owners. Router evidence alone cannot verify the application executable on another device. Application recognition, endpoint permission and enforcement remain separate decisions.

## Visibility depends on placement

An ordinary switched LAN port does not receive all other devices' unicast traffic. A configured mirror/SPAN port or network TAP can provide copies of traffic traversing selected paths; it cannot copy traffic that never crosses those paths. A passive mirror provides observation, not automatic prevention. [Cisco switching and SPAN explanation](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-6500-series-switches/10570-41.html)

For an integrated Wi-Fi router, mirroring an external wired switch can miss internal Wi-Fi traffic. A WAN-side sensor loses original IPv4 device identity through NAT unless reliable translation metadata is also available. A future gateway can observe routed Internet/inter-VLAN traffic, while same-LAN or same-AP exchanges can still bypass it. Coverage needs controlled wired, Wi-Fi, guest, IPv4 and IPv6 tests, including loss/sampling checks. No topology change is performed by this package. [Zeek sensor-placement guidance](https://docs.zeek.org/en/current/about/monitoring.html)

## Pure adapter contract

`sentinel_watch.router_adapter` supplies validation types and protocols only. It performs no discovery, HTTP request, credential read, package installation, file write or router operation. No concrete router plugin is included.

- `CapabilityState`: `verified`, `unverified` or `unsupported`. Omitted capabilities are unverified. Verified means a tested API/schema contract, not perfect coverage or trustworthy device labels.
- `AdapterConfig`: disabled by default, with a separately disabled enforcement flag. A configured `NetworkContext` binds a network UUID, source ID and gateway fingerprint. `validate_batch` rejects mismatched batches or nested records. The fingerprint's construction/authentication must be reviewed; matching a saved hint is not cryptographic device authentication. Never overwrite an origin binding to inherit approvals on another network.
- `FlowTuple` and `FlowRecord`: ordered source/destination addresses and ports, explicit transport, source observation/flow IDs, observation time, measurement scope and point, direction **and its basis**, independent initiator evidence, and optional NAT translation. Unknowns remain unknown. TCP established state or a vendor label alone cannot establish the initiator. Unscoped link-local IPv6 is retained as incomplete evidence.
- `FlowCounters`: source-to-destination and reverse-direction octets/packets relative to the ordered tuple, a counter epoch, `cumulative` versus `delta` mode, measurement window, sampling status and IP/link/payload/unknown octet scope. Missing values are `None`, not zero. `counter_delta` requires the same context, flow, tuple, observation point, epoch and scope; decreases require a new reviewed epoch. A cumulative window starts at the same time throughout that epoch. Plugins must not recycle a flow ID across different flow lifetimes. It never guesses wraparound, sums cumulative snapshots or extrapolates sampled counts. Flow records are not automatically sessions. [IPFIX flow/counter standard](https://www.rfc-editor.org/rfc/rfc7011.html)
- `ObservationBatch`: schema version 1, bounded records, fixed gap codes and explicit unknown/true/false internal Wi-Fi visibility. IPv6, NAT and measured octet fields require their respective verified capabilities before intake. Gaps and unknown coverage must remain visible.

The protocol is `ReadOnlyRouterAdapter.collect(expected_context) -> ObservationBatch`; its consumer calls `validate_batch(batch, config)` before use. These records do not automatically become application approvals or firewall rules.

## Future control and purchase gates

`EnforcementAdapter` defines a separate future `plan / apply / verify / rollback` contract. The shipped `DisabledEnforcement` refuses all four operations. `require_enforcement` provides necessary pure gates only: opt-in, matching context, verified capabilities, explicit approval and usable gateway evidence. Passing it neither proves authorization nor installs a rule.

A real backend must present the exact rule and expiry, preserve existing rules/configuration, bind approval to that plan, apply only its owned change, read back and test IPv4/IPv6 effects, and provide rollback by its own receipt. Existing-connection handling, reboot persistence, operator access and recovery must be tested separately. A device-level grant is not an application-level grant; historical incomplete router rows must not inherit endpoint approvals.

Before selecting any router, verify its **local** API and exact firmware: flow tuples and byte/counter semantics, IPv6 coverage, NAT mapping, internal Wi-Fi/guest visibility, authentication/least privilege, export loss limits and supported rule control/rollback. A cloud dashboard, device count, Wi-Fi speed or marketing security label does not establish those capabilities. Linksys has announced withdrawal of Smart WiFi cloud services for affected models including EA7300 v2, reinforcing the need to verify local integration rather than depend on old cloud instructions. [Official Linksys notice](https://support.linksys.com/kb/article/9634-en/)

IP registrant, ASN and approximate geolocation describe network infrastructure. They do not identify the person using a connection, prove a device's physical location or establish intent. Shared hosting, VPNs, proxies and changing addresses can make such attribution uncertain. Treat owner/location labels as context for review, never proof of safety or malice. Encrypted traffic metadata alone cannot prove what a stream contains. [MaxMind's IP-geolocation limitations](https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy)
