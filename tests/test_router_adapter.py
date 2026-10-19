"""Pure synthetic adapter contracts: no router, network, files or enforcement."""
from dataclasses import replace
import unittest

from sentinel_watch import router_adapter as a


CONTEXT = a.NetworkContext("12345678-1234-4234-8234-123456789abc", "fixture-gateway", "a" * 64)
VERIFIED = a.CapabilityState.VERIFIED


def flow(**changes):
    value = a.FlowRecord(CONTEXT, "observation:1", "flow:1", 100,
        a.FlowTuple("192.0.2.10", "198.51.100.20", 49152, 443, "TCP"),
        "internet_gateway", "lan-before-nat")
    return replace(value, **changes)


def counts(value, **changes):
    return a.FlowCounters("boot:one", "cumulative", "ip_octets", 10, value,
        source_octets=value * 10, destination_octets=value * 20, **changes)


class AdapterContractTests(unittest.TestCase):
    def test_unconfigured_disabled_defaults_and_unknown_capabilities(self):
        batch = a.ObservationBatch(CONTEXT, a.Capabilities(), 100)
        with self.assertRaisesRegex(a.AdapterError, "E_ADAPTER_DISABLED"):
            a.validate_batch(batch, a.AdapterConfig())
        with self.assertRaisesRegex(a.AdapterError, "E_ADAPTER_UNCONFIGURED"):
            a.validate_batch(batch, a.AdapterConfig(enabled=True))
        self.assertEqual(a.Capabilities().flow_records, a.CapabilityState.UNVERIFIED)

    def test_capability_states_reject_unknown_or_accidental_boolean_claims(self):
        self.assertEqual(a.Capabilities.from_mapping({"flow_records":"unsupported"}).flow_records,
                         a.CapabilityState.UNSUPPORTED)
        for obj in ({"flow_records":True}, {"made_up_feature":"verified"}, {"flow_records":"maybe"}):
            with self.assertRaisesRegex(a.AdapterError, "E_CAPABILITY"):
                a.Capabilities.from_mapping(obj)

    def test_matching_context_and_explicit_partial_coverage_are_retained(self):
        record = flow()
        batch = a.ObservationBatch(CONTEXT, a.Capabilities(flow_records=VERIFIED), 101,
                                   (record,), ("E_SOURCE_PARTIAL",), internal_wifi_visible=None)
        self.assertIs(a.validate_batch(batch, a.AdapterConfig(CONTEXT, True)), batch)
        self.assertIsNone(batch.internal_wifi_visible)
        self.assertEqual(record.direction, "unknown")
        self.assertEqual(record.initiator, "unknown")

    def test_all_context_dimensions_fence_even_a_copied_source_profile(self):
        config = a.AdapterConfig(CONTEXT, True)
        for changed in (replace(CONTEXT, gateway_fingerprint="b"*64),
                        replace(CONTEXT, source_id="other-source"),
                        replace(CONTEXT, network_id="22345678-1234-4234-8234-123456789abc")):
            with self.assertRaisesRegex(a.AdapterError, "E_NETWORK_CONTEXT"):
                a.validate_batch(a.ObservationBatch(changed, a.Capabilities(), 100), config)
            with self.assertRaisesRegex(a.AdapterError, "E_NETWORK_CONTEXT"):
                a.validate_batch(a.ObservationBatch(CONTEXT, a.Capabilities(flow_records=VERIFIED), 100,
                                                   (flow(context=changed),)), config)

    def test_flow_and_octet_features_require_verified_contracts(self):
        config = a.AdapterConfig(CONTEXT, True)
        with self.assertRaisesRegex(a.AdapterError, "E_FLOW_CAPABILITY"):
            a.validate_batch(a.ObservationBatch(CONTEXT, a.Capabilities(), 100, (flow(),)), config)
        with self.assertRaisesRegex(a.AdapterError, "E_COUNTER_CAPABILITY"):
            a.validate_batch(a.ObservationBatch(CONTEXT, a.Capabilities(flow_records=VERIFIED), 100,
                                               (flow(counters=counts(50)),)), config)

    def test_ipv6_and_nat_contracts_cannot_be_inferred_from_ipv4_success(self):
        config = a.AdapterConfig(CONTEXT, True)
        endpoint = a.FlowTuple("2001:db8::10", "2001:db8:1::20", 49152, 443, "TCP")
        with self.assertRaisesRegex(a.AdapterError, "E_IPV6_CAPABILITY"):
            a.validate_batch(a.ObservationBatch(CONTEXT, a.Capabilities(flow_records=VERIFIED), 100,
                                               (flow(endpoint=endpoint),)), config)
        with self.assertRaisesRegex(a.AdapterError, "E_NAT_CAPABILITY"):
            a.validate_batch(a.ObservationBatch(CONTEXT, a.Capabilities(flow_records=VERIFIED), 100,
                                               (flow(translated_endpoint=flow().endpoint),)), config)

    def test_missing_transport_ports_and_scoped_ipv6_remain_incomplete(self):
        self.assertFalse(a.FlowTuple(None, "198.51.100.20", None, None, "unknown").complete_endpoint)
        self.assertFalse(a.FlowTuple(None, "198.51.100.20", None, 443, "unknown").complete_endpoint)
        self.assertFalse(a.FlowTuple("192.0.2.10", "198.51.100.20", 0, 443, "TCP").complete_endpoint)
        self.assertFalse(a.FlowTuple("fe80::1", "fe80::2", 1, 2, "TCP").complete_endpoint)
        with self.assertRaisesRegex(a.AdapterError, "E_ADDRESS"):
            a.FlowTuple("fe80::1%eth0", "fe80::2", 1, 2, "TCP")

    def test_mixed_families_invalid_ports_and_nonfinite_times_fail(self):
        with self.assertRaisesRegex(a.AdapterError, "E_ADDRESS_FAMILY"):
            a.FlowTuple("192.0.2.10", "2001:db8::1", 1, 2, "TCP")
        for port in (True, -1, 65536):
            with self.assertRaisesRegex(a.AdapterError, "E_PORT"):
                a.FlowTuple("192.0.2.10", "198.51.100.20", port, 443, "TCP")
        for value in (True, float("nan"), float("inf"), -1, 10**1000):
            with self.assertRaisesRegex(a.AdapterError, "E_OBSERVATION_TIME"):
                flow(observed_at=value)

    def test_initiator_requires_separate_evidence_and_direction_basis(self):
        with self.assertRaisesRegex(a.AdapterError, "E_INITIATOR"):
            flow(initiator="source")
        with self.assertRaisesRegex(a.AdapterError, "E_DIRECTION"):
            flow(direction="outbound")
        self.assertEqual(flow(initiator="source", initiator_basis="handshake").initiator, "source")

    def test_counter_delta_is_measured_not_sampling_extrapolation_or_missing_zero(self):
        previous = flow(observed_at=60, counters=counts(50, sampled=True))
        current = flow(observation_id="observation:2", observed_at=70, counters=counts(60, sampled=True))
        delta = a.counter_delta(previous, current)
        self.assertEqual(delta["source_octets"], 100)
        self.assertEqual(delta["destination_octets"], 200)
        self.assertIsNone(delta["source_packets"])
        self.assertIsNone(delta["destination_packets"])

    def test_epoch_decrease_scope_and_delta_mode_cannot_be_silently_combined(self):
        previous = flow(observed_at=60, counters=counts(50))
        current = flow(observed_at=70, counters=counts(60))
        for changed, code in ((replace(current.counters, epoch="boot:two"), "E_COUNTER_EPOCH"),
                (replace(current.counters, source_octets=1), "E_COUNTER_RESET_REQUIRED"),
                (replace(current.counters, octet_scope="payload_octets"), "E_COUNTER_SCOPE"),
                (replace(current.counters, sampled=True), "E_COUNTER_SCOPE"),
                (replace(current.counters, mode="delta"), "E_COUNTER_MODE"),
                (replace(current.counters, window_end=40), "E_COUNTER_TIME")):
            with self.assertRaisesRegex(a.AdapterError, code):
                a.counter_delta(previous, replace(current, counters=changed))

    def test_counter_tuple_context_and_observation_point_fence(self):
        previous = flow(counters=counts(50))
        current = flow(counters=counts(60))
        for changed in (replace(current, flow_id="flow:other"),
                        replace(current, observation_point="wan-after-nat"),
                        replace(current, context=replace(CONTEXT, source_id="other-source")),
                        replace(current, endpoint=replace(current.endpoint, destination_port=8443))):
            with self.assertRaisesRegex(a.AdapterError, "E_COUNTER_CONTEXT"):
                a.counter_delta(previous, changed)

    def test_gap_codes_do_not_accept_private_arbitrary_text(self):
        for gaps in (("a private endpoint or password",), ({},)):
            with self.assertRaisesRegex(a.AdapterError, "E_GAP"):
                a.ObservationBatch(CONTEXT, a.Capabilities(), 100, gaps=gaps)

    def test_batch_schema_version_is_explicit_and_not_a_boolean(self):
        for version in (True, 0, 2, "1"):
            with self.assertRaisesRegex(a.AdapterError, "E_SCHEMA_VERSION"):
                a.ObservationBatch(CONTEXT, a.Capabilities(), 100, schema_version=version)

    def test_shipped_enforcer_denies_every_operation(self):
        for name in ("plan", "apply", "verify", "rollback"):
            with self.assertRaisesRegex(a.AdapterError, "E_ENFORCEMENT_DISABLED"):
                getattr(a.DisabledEnforcement(), name)({})

    def test_enforcement_requires_optin_approval_capability_and_real_gateway_tuple(self):
        record = flow(direction="outbound", direction_basis="interface")
        config = a.AdapterConfig(CONTEXT, True)
        caps = a.Capabilities(flow_records=VERIFIED, firewall_control=VERIFIED)
        with self.assertRaisesRegex(a.AdapterError, "E_ENFORCEMENT_DISABLED"):
            a.require_enforcement(config, caps, record, explicit_approval=True)
        config = replace(config, enforcement_enabled=True)
        with self.assertRaisesRegex(a.AdapterError, "E_APPROVAL_REQUIRED"):
            a.require_enforcement(config, caps, record)
        with self.assertRaisesRegex(a.AdapterError, "E_ENFORCEMENT_UNVERIFIED"):
            a.require_enforcement(config, a.Capabilities(), record, explicit_approval=True)
        for changed in (flow(), replace(record, direction_basis="vendor_label"),
                        replace(record, measurement_scope="retained_router_log"),
                        replace(record, measurement_scope="unknown")):
            with self.assertRaisesRegex(a.AdapterError, "E_ENFORCEMENT_EVIDENCE"):
                a.require_enforcement(config, caps, changed, explicit_approval=True)
        self.assertIsNone(a.require_enforcement(config, caps, record, explicit_approval=True))
        # Passing necessary pure gates still creates no implementation or rule.


if __name__ == "__main__":
    unittest.main()
