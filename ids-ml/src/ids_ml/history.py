"""Causal source-host history features over a fixed preceding window."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import groupby

from ids_ml.flows import TCP_ACK, TCP_SYN, Flow, TerminationReason
from ids_ml.packets import IPProtocol

NANOSECONDS_PER_SECOND = 1_000_000_000
DEFAULT_WINDOW_SECONDS = 10


@dataclass(frozen=True, slots=True)
class SourceHistoryFeatures:
    """Recent behavior of the current flow's initiating source host."""

    flows_last_10s: int
    unique_dst_ips_last_10s: int
    unique_dst_ports_last_10s: int
    connection_rate_last_10s: float
    failed_connection_rate_last_10s: float


@dataclass(frozen=True, slots=True)
class FlowWithHistory:
    """A flow paired with source history available when that flow started."""

    flow: Flow
    history: SourceHistoryFeatures


class HistoryCalculationError(ValueError):
    """Raised when flows violate the source-history calculation contract."""


def calculate_source_history(
    flows: Iterable[Flow], window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> list[FlowWithHistory]:
    """Attach causal, preceding-window source history to start-ordered flows."""
    if window_seconds <= 0:
        raise HistoryCalculationError("history window must be positive")

    ordered_flows = list(flows)
    _validate_flow_order(ordered_flows)
    window_ns = window_seconds * NANOSECONDS_PER_SECOND
    recent_by_source: dict[str, deque[Flow]] = defaultdict(deque)
    enriched: list[FlowWithHistory] = []

    for start_ns, simultaneous_flows in groupby(
        ordered_flows, key=lambda flow: flow.start_timestamp_ns
    ):
        current_group = list(simultaneous_flows)
        cutoff_ns = start_ns - window_ns

        for flow in current_group:
            source_ip = flow.forward_endpoint.ip
            recent = recent_by_source[source_ip]
            while recent and recent[0].start_timestamp_ns <= cutoff_ns:
                recent.popleft()
            enriched.append(
                FlowWithHistory(
                    flow=flow,
                    history=_features_for(recent, start_ns, window_seconds),
                )
            )

        # Same-timestamp flows must not see one another as prior history.
        for flow in current_group:
            recent_by_source[flow.forward_endpoint.ip].append(flow)

    return enriched


def is_failed_connection(flow: Flow) -> bool:
    """Return whether a completed TCP attempt meets the v1 failure definition."""
    if not is_tcp_attempt(flow):
        return False
    backward_syn_ack = any(
        packet.tcp_flags & TCP_SYN and packet.tcp_flags & TCP_ACK
        for packet in flow.backward_packets
    )
    return not backward_syn_ack and flow.termination_reason in {
        TerminationReason.TCP_RST,
        TerminationReason.IDLE_TIMEOUT,
    }


def _features_for(
    recent: deque[Flow], current_start_ns: int, window_seconds: int
) -> SourceHistoryFeatures:
    destination_ips = {flow.backward_endpoint.ip for flow in recent}
    destination_ports = {
        flow.backward_endpoint.port
        for flow in recent
        if flow.backward_endpoint.port is not None
    }
    resolved_attempts = [
        flow
        for flow in recent
        if is_tcp_attempt(flow) and flow.end_timestamp_ns <= current_start_ns
    ]
    failed_attempts = sum(is_failed_connection(flow) for flow in resolved_attempts)
    failed_rate = failed_attempts / len(resolved_attempts) if resolved_attempts else 0.0

    return SourceHistoryFeatures(
        flows_last_10s=len(recent),
        unique_dst_ips_last_10s=len(destination_ips),
        unique_dst_ports_last_10s=len(destination_ports),
        connection_rate_last_10s=len(recent) / window_seconds,
        failed_connection_rate_last_10s=failed_rate,
    )


def is_tcp_attempt(flow: Flow) -> bool:
    """Return whether the forward direction contains a bare TCP SYN."""
    return flow.key.protocol is IPProtocol.TCP and any(
        packet.tcp_flags & TCP_SYN and not packet.tcp_flags & TCP_ACK
        for packet in flow.forward_packets
    )


def _validate_flow_order(flows: list[Flow]) -> None:
    if any(not flow.packets for flow in flows):
        raise HistoryCalculationError("every flow must contain at least one packet")
    if any(
        current.start_timestamp_ns < previous.start_timestamp_ns
        for previous, current in zip(flows, flows[1:], strict=False)
    ):
        raise HistoryCalculationError("flows must be ordered by start timestamp")
