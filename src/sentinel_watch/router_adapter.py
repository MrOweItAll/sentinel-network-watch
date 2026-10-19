"""Router adapter contracts and pure validation; no discovery, network or file I/O.

No router implementation ships here. Verified capability means a tested source
contract, never complete coverage, trustworthy device names or traffic permission.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
import ipaddress
import math
import re
from typing import Mapping, Protocol
import uuid

SCHEMA_VERSION = 1

class AdapterError(ValueError):
    """Only fixed codes; never include a private endpoint or vendor response."""


def _need(ok, code):
    if not ok:
        raise AdapterError(code)


def _identifier(value, limit=128):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,%d}" % (limit - 1), value))


def _time(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except (OverflowError, TypeError):
        return False


class CapabilityState(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class Capabilities:
    inventory: CapabilityState = CapabilityState.UNVERIFIED
    flow_records: CapabilityState = CapabilityState.UNVERIFIED
    directional_octets: CapabilityState = CapabilityState.UNVERIFIED
    ipv6_flows: CapabilityState = CapabilityState.UNVERIFIED
    nat_mappings: CapabilityState = CapabilityState.UNVERIFIED
    firewall_control: CapabilityState = CapabilityState.UNVERIFIED

    def __post_init__(self):
        _need(all(isinstance(getattr(self, f.name), CapabilityState) for f in fields(self)), "E_CAPABILITY")

    @classmethod
    def from_mapping(cls, value):
        _need(isinstance(value, dict) and set(value) <= {f.name for f in fields(cls)}, "E_CAPABILITY")
        try:
            return cls(**{k: CapabilityState(v) for k, v in value.items()})
        except (ValueError, TypeError):
            raise AdapterError("E_CAPABILITY") from None


@dataclass(frozen=True)
class NetworkContext:
    network_id: str
    source_id: str
    gateway_fingerprint: str

    def __post_init__(self):
        try:
            valid = isinstance(self.network_id, str) and str(uuid.UUID(self.network_id)) == self.network_id
        except (ValueError, AttributeError):
            valid = False
        _need(valid and self.network_id != str(uuid.UUID(int=0)), "E_NETWORK_ID")
        _need(_identifier(self.source_id), "E_SOURCE_ID")
        _need(isinstance(self.gateway_fingerprint, str) and
              bool(re.fullmatch(r"[0-9a-f]{64}", self.gateway_fingerprint)), "E_GATEWAY_BINDING")


@dataclass(frozen=True)
class AdapterConfig:
    expected_context: NetworkContext | None = None
    enabled: bool = False
    enforcement_enabled: bool = False

    def __post_init__(self):
        _need(type(self.enabled) is bool and type(self.enforcement_enabled) is bool, "E_CONFIG")
        _need(self.expected_context is None or isinstance(self.expected_context, NetworkContext), "E_CONFIG")

    def require_context(self, observed):
        _need(self.enabled, "E_ADAPTER_DISABLED")
        _need(self.expected_context is not None, "E_ADAPTER_UNCONFIGURED")
        _need(isinstance(observed, NetworkContext) and observed == self.expected_context, "E_NETWORK_CONTEXT")


@dataclass(frozen=True)
class FlowTuple:
    source_address: str | None
    destination_address: str | None
    source_port: int | None
    destination_port: int | None
    transport: str

    def __post_init__(self):
        _need(self.transport in ("TCP", "UDP", "ICMP", "ICMPV6", "unknown"), "E_TRANSPORT")
        versions = []
        for name in ("source_address", "destination_address"):
            value = getattr(self, name)
            if value is not None:
                try:
                    _need(isinstance(value, str) and "%" not in value, "E_ADDRESS")
                    address = ipaddress.ip_address(value)
                except (ValueError, TypeError):
                    raise AdapterError("E_ADDRESS") from None
                object.__setattr__(self, name, str(address))
                versions.append(address.version)
        _need(len(set(versions)) <= 1, "E_ADDRESS_FAMILY")
        for value in (self.source_port, self.destination_port):
            _need(value is None or type(value) is int and 0 <= value <= 65535, "E_PORT")
        if self.transport in ("ICMP", "ICMPV6"):
            _need(self.source_port is None and self.destination_port is None, "E_PORT")
        _need(self.transport != "ICMPV6" or not versions or versions[0] == 6, "E_ADDRESS_FAMILY")
        _need(self.transport != "ICMP" or not versions or versions[0] == 4, "E_ADDRESS_FAMILY")

    @property
    def complete_endpoint(self):
        # Port zero is retained as evidence, but never an approvable endpoint.
        return (self.transport in ("TCP", "UDP") and self.source_address is not None
                and self.destination_address is not None and self.source_port is not None
                and self.destination_port is not None and self.source_port > 0 and self.destination_port > 0
                and not any(ipaddress.ip_address(a).version == 6 and ipaddress.ip_address(a).is_link_local
                            for a in (self.source_address, self.destination_address)))


COUNTER_FIELDS = ("source_octets", "destination_octets", "source_packets", "destination_packets")


@dataclass(frozen=True)
class FlowCounters:
    """source_* travels source-to-destination; destination_* is the reverse.

    Neither label means uploader, initiator or a person. Cumulative window_start
    stays fixed for an epoch. Delta records already describe their own window.
    """
    epoch: str
    mode: str
    octet_scope: str
    window_start: float
    window_end: float
    source_octets: int | None = None
    destination_octets: int | None = None
    source_packets: int | None = None
    destination_packets: int | None = None
    sampled: bool | None = None

    def __post_init__(self):
        _need(_identifier(self.epoch), "E_COUNTER_EPOCH")
        _need(self.mode in ("cumulative", "delta"), "E_COUNTER_MODE")
        _need(self.octet_scope in ("ip_octets", "link_octets", "payload_octets", "unknown"), "E_COUNTER_SCOPE")
        _need(_time(self.window_start) and _time(self.window_end) and self.window_start <= self.window_end, "E_COUNTER_TIME")
        _need(self.sampled is None or type(self.sampled) is bool, "E_COUNTER_SAMPLING")
        for name in COUNTER_FIELDS:
            value = getattr(self, name)
            _need(value is None or type(value) is int and 0 <= value < 2 ** 64, "E_COUNTER_VALUE")


SCOPES = ("internet_gateway", "routed_lan", "mirrored_segment", "endpoint_namespace", "retained_router_log", "unknown")


@dataclass(frozen=True)
class FlowRecord:
    context: NetworkContext
    observation_id: str
    flow_id: str
    observed_at: float
    endpoint: FlowTuple
    measurement_scope: str
    observation_point: str
    direction: str = "unknown"
    direction_basis: str = "unknown"
    initiator: str = "unknown"
    initiator_basis: str = "unknown"
    counters: FlowCounters | None = None
    translated_endpoint: FlowTuple | None = None

    def __post_init__(self):
        _need(isinstance(self.context, NetworkContext), "E_NETWORK_CONTEXT")
        _need(_identifier(self.observation_id) and _identifier(self.flow_id), "E_FLOW_ID")
        _need(_time(self.observed_at), "E_OBSERVATION_TIME")
        _need(isinstance(self.endpoint, FlowTuple), "E_FLOW_TUPLE")
        _need(self.measurement_scope in SCOPES and _identifier(self.observation_point), "E_MEASUREMENT_SCOPE")
        _need(self.direction in ("inbound", "outbound", "local", "unknown") and
              self.direction_basis in ("interface", "handshake", "vendor_label", "unknown"), "E_DIRECTION")
        _need(self.direction == "unknown" or self.direction_basis != "unknown", "E_DIRECTION")
        _need(self.initiator in ("source", "destination", "unknown"), "E_INITIATOR")
        _need(self.initiator_basis in ("handshake", "gateway_event", "unknown") and
              (self.initiator == "unknown" or self.initiator_basis != "unknown"), "E_INITIATOR")
        _need(self.counters is None or isinstance(self.counters, FlowCounters), "E_COUNTER_VALUE")
        _need(self.translated_endpoint is None or isinstance(self.translated_endpoint, FlowTuple), "E_NAT_MAPPING")


GAPS = frozenset({"E_SOURCE_PARTIAL", "E_EXPORT_LOSS", "E_COUNTER_RESET", "E_LIMIT",
                  "E_IDENTITY_UNVERIFIED", "E_IPV6_UNVERIFIED", "E_TIME_UNKNOWN"})


@dataclass(frozen=True)
class ObservationBatch:
    context: NetworkContext
    capabilities: Capabilities
    observed_at: float
    flows: tuple[FlowRecord, ...] = ()
    gaps: tuple[str, ...] = ()
    internal_wifi_visible: bool | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _need(type(self.schema_version) is int and self.schema_version == SCHEMA_VERSION, "E_SCHEMA_VERSION")
        _need(isinstance(self.context, NetworkContext) and isinstance(self.capabilities, Capabilities), "E_BATCH")
        _need(_time(self.observed_at), "E_OBSERVATION_TIME")
        _need(type(self.flows) is tuple and len(self.flows) <= 50000
              and all(isinstance(f, FlowRecord) for f in self.flows), "E_BATCH")
        _need(type(self.gaps) is tuple and len(self.gaps) <= len(GAPS)
              and all(isinstance(g, str) and g in GAPS for g in self.gaps), "E_GAP")
        _need(self.internal_wifi_visible is None or type(self.internal_wifi_visible) is bool, "E_BATCH")


def validate_batch(batch: ObservationBatch, config: AdapterConfig) -> ObservationBatch:
    """Fence intake before use; capability verification is not a coverage claim."""
    _need(isinstance(batch, ObservationBatch) and isinstance(config, AdapterConfig), "E_BATCH")
    config.require_context(batch.context)
    for flow in batch.flows:
        _need(flow.context == batch.context, "E_NETWORK_CONTEXT")
        _need(batch.capabilities.flow_records is CapabilityState.VERIFIED, "E_FLOW_CAPABILITY")
        if flow.counters is not None and (flow.counters.source_octets is not None or
                                          flow.counters.destination_octets is not None):
            _need(batch.capabilities.directional_octets is CapabilityState.VERIFIED, "E_COUNTER_CAPABILITY")
        endpoints = (flow.endpoint, flow.translated_endpoint)
        if any(e is not None and any(a is not None and ipaddress.ip_address(a).version == 6
               for a in (e.source_address, e.destination_address)) for e in endpoints):
            _need(batch.capabilities.ipv6_flows is CapabilityState.VERIFIED, "E_IPV6_CAPABILITY")
        if flow.translated_endpoint is not None:
            _need(batch.capabilities.nat_mappings is CapabilityState.VERIFIED, "E_NAT_CAPABILITY")
    return batch


def counter_delta(previous: FlowRecord, current: FlowRecord) -> dict[str, int | None]:
    """Measured differences only; never extrapolate sampling or guess resets/wraps."""
    _need(isinstance(previous, FlowRecord) and isinstance(current, FlowRecord), "E_FLOW_TUPLE")
    _need((previous.context, previous.flow_id, previous.endpoint, previous.translated_endpoint,
           previous.measurement_scope, previous.observation_point) ==
          (current.context, current.flow_id, current.endpoint, current.translated_endpoint,
           current.measurement_scope, current.observation_point), "E_COUNTER_CONTEXT")
    a, b = previous.counters, current.counters
    _need(a is not None and b is not None and a.mode == b.mode == "cumulative", "E_COUNTER_MODE")
    _need(a.epoch == b.epoch, "E_COUNTER_EPOCH")
    _need((a.octet_scope, a.sampled, a.window_start) == (b.octet_scope, b.sampled, b.window_start), "E_COUNTER_SCOPE")
    _need(current.observed_at >= previous.observed_at and b.window_end >= a.window_end, "E_COUNTER_TIME")
    result = {}
    for name in COUNTER_FIELDS:
        before, after = getattr(a, name), getattr(b, name)
        _need(before is None or after is None or after >= before, "E_COUNTER_RESET_REQUIRED")
        result[name] = None if before is None or after is None else after - before
    return result


class ReadOnlyRouterAdapter(Protocol):
    def collect(self, expected_context: NetworkContext) -> ObservationBatch:
        """Implement only reviewed reads, then validate_batch before intake."""
        ...


class EnforcementAdapter(Protocol):
    """Future separate privileged backend; this protocol implements no control."""
    def plan(self, flow: FlowRecord, *, expires_at: float | None) -> Mapping[str, object]: ...
    def apply(self, plan: Mapping[str, object], *, approval_id: str) -> Mapping[str, object]: ...
    def verify(self, receipt: Mapping[str, object]) -> Mapping[str, object]: ...
    def rollback(self, receipt: Mapping[str, object]) -> Mapping[str, object]: ...


class DisabledEnforcement:
    """Safe shipped default, including when no concrete plugin is configured."""
    def plan(self, *args, **kwargs):
        raise AdapterError("E_ENFORCEMENT_DISABLED")
    apply = plan
    verify = plan
    rollback = plan


def require_enforcement(config: AdapterConfig, capabilities: Capabilities,
                        flow: FlowRecord, *, explicit_approval: bool = False):
    """Necessary gates only, not authorization evidence or an implementation."""
    _need(isinstance(config, AdapterConfig) and isinstance(capabilities, Capabilities)
          and isinstance(flow, FlowRecord), "E_ENFORCEMENT_INPUT")
    config.require_context(flow.context)
    _need(config.enforcement_enabled, "E_ENFORCEMENT_DISABLED")
    _need(explicit_approval is True, "E_APPROVAL_REQUIRED")
    _need(capabilities.firewall_control is CapabilityState.VERIFIED
          and capabilities.flow_records is CapabilityState.VERIFIED, "E_ENFORCEMENT_UNVERIFIED")
    validate_batch(ObservationBatch(flow.context, capabilities, flow.observed_at, (flow,)), config)
    _need(flow.endpoint.complete_endpoint and flow.direction in ("inbound", "outbound")
          and flow.direction_basis in ("interface", "handshake")
          and flow.measurement_scope in ("internet_gateway", "routed_lan"), "E_ENFORCEMENT_EVIDENCE")
