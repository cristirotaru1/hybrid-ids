"""Causal version 2 source history with protocol and TCP outcome counts."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import groupby

from ids_ml.flows import TCP_ACK, TCP_SYN, Flow, TerminationReason
from ids_ml.history import (
    DEFAULT_WINDOW_SECONDS,
    NANOSECONDS_PER_SECOND,
    HistoryCalculationError,
    SourceHistoryFeatures,
    is_failed_connection,
    is_tcp_attempt,
)


@dataclass(frozen=True, slots=True)
class SourceHistoryFeaturesV2(SourceHistoryFeatures):
    """Version 1 history plus protocol-local and resolved TCP counts."""

    same_protocol_flows_last_10s: int
    tcp_attempts_last_10s: int
    failed_tcp_connections_last_10s: int


@dataclass(frozen=True, slots=True)
class FlowWithHistoryV2:
    """A flow paired with causal version 2 source-history features."""

    flow: Flow
    history: SourceHistoryFeaturesV2


def calculate_source_history_v2(
    flows: Iterable[Flow], window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> list[FlowWithHistoryV2]:
    """Attach causal version 2 history to start-ordered flows."""
    if window_seconds <= 0:
        raise HistoryCalculationError("history window must be positive")

    ordered_flows = list(flows)
    _validate_flow_order(ordered_flows)
    window_ns = window_seconds * NANOSECONDS_PER_SECOND
    recent_by_source: dict[str, deque[Flow]] = defaultdict(deque)
    enriched: list[FlowWithHistoryV2] = []

    for start_ns, simultaneous_flows in groupby(
        ordered_flows, key=lambda flow: flow.start_timestamp_ns
    ):
        current_group = list(simultaneous_flows)
        cutoff_ns = start_ns - window_ns

        for flow in current_group:
            recent = recent_by_source[flow.forward_endpoint.ip]
            while recent and recent[0].start_timestamp_ns <= cutoff_ns:
                recent.popleft()
            enriched.append(
                FlowWithHistoryV2(
                    flow=flow,
                    history=_features_for_v2(recent, flow, start_ns, window_seconds),
                )
            )

        # Flows with identical starts must not become one another's history.
        for flow in current_group:
            recent_by_source[flow.forward_endpoint.ip].append(flow)

    return enriched


def _features_for_v2(
    recent: deque[Flow],
    current_flow: Flow,
    current_start_ns: int,
    window_seconds: int,
) -> SourceHistoryFeaturesV2:
    destination_ips = {flow.backward_endpoint.ip for flow in recent}
    destination_ports = {
        flow.backward_endpoint.port
        for flow in recent
        if flow.backward_endpoint.port is not None
    }
    resolved_tcp_attempts = [
        flow for flow in recent if _tcp_attempt_resolved_by(flow, current_start_ns)
    ]
    failed_tcp_connections = sum(
        is_failed_connection(flow) for flow in resolved_tcp_attempts
    )
    failed_rate = (
        failed_tcp_connections / len(resolved_tcp_attempts)
        if resolved_tcp_attempts
        else 0.0
    )
    same_protocol_flows = sum(
        flow.key.protocol is current_flow.key.protocol for flow in recent
    )

    return SourceHistoryFeaturesV2(
        flows_last_10s=len(recent),
        unique_dst_ips_last_10s=len(destination_ips),
        unique_dst_ports_last_10s=len(destination_ports),
        connection_rate_last_10s=len(recent) / window_seconds,
        failed_connection_rate_last_10s=failed_rate,
        same_protocol_flows_last_10s=same_protocol_flows,
        tcp_attempts_last_10s=len(resolved_tcp_attempts),
        failed_tcp_connections_last_10s=failed_tcp_connections,
    )


def _validate_flow_order(flows: list[Flow]) -> None:
    if any(not flow.packets for flow in flows):
        raise HistoryCalculationError("every flow must contain at least one packet")
    if any(
        current.start_timestamp_ns < previous.start_timestamp_ns
        for previous, current in zip(flows, flows[1:], strict=False)
    ):
        raise HistoryCalculationError("flows must be ordered by start timestamp")


def _tcp_attempt_resolved_by(flow: Flow, timestamp_ns: int) -> bool:
    if not is_tcp_attempt(flow):
        return False
    accepted_before_current = any(
        packet.timestamp_ns <= timestamp_ns
        and packet.tcp_flags & TCP_SYN
        and packet.tcp_flags & TCP_ACK
        for packet in flow.backward_packets
    )
    refused_before_current = (
        flow.termination_reason is TerminationReason.TCP_RST
        and flow.end_timestamp_ns <= timestamp_ns
    )
    return accepted_before_current or refused_before_current
