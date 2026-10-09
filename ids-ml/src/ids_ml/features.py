"""Version 1 numerical features calculated from completed flows."""

from __future__ import annotations

import math
from dataclasses import dataclass

from ids_ml.flows import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Flow
from ids_ml.packets import IPProtocol

NANOSECONDS_PER_SECOND = 1_000_000_000


@dataclass(frozen=True, slots=True)
class FlowFeatures:
    """Model-ready flow-level features from data contract version 1."""

    flow_duration: float
    forward_packet_count: int
    backward_packet_count: int
    total_packet_count: int
    forward_bytes: int
    backward_bytes: int
    total_bytes: int
    mean_packet_size: float
    std_packet_size: float
    packets_per_second: float
    bytes_per_second: float
    syn_count: int
    ack_count: int
    rst_count: int
    fin_count: int
    src_port: int
    dst_port: int
    protocol: int
    inter_arrival_mean: float
    inter_arrival_std: float


class FeatureCalculationError(ValueError):
    """Raised when a supplied flow cannot produce trustworthy features."""


def calculate_flow_features(flow: Flow) -> FlowFeatures:
    """Calculate deterministic version 1 features for one completed flow."""
    _validate_flow(flow)

    duration_ns = flow.end_timestamp_ns - flow.start_timestamp_ns
    duration_seconds = duration_ns / NANOSECONDS_PER_SECOND

    forward_sizes = [packet.ip_total_length for packet in flow.forward_packets]
    backward_sizes = [packet.ip_total_length for packet in flow.backward_packets]
    all_sizes = [packet.ip_total_length for packet in flow.packets]

    forward_bytes = sum(forward_sizes)
    backward_bytes = sum(backward_sizes)
    total_bytes = sum(all_sizes)
    total_packet_count = len(flow.packets)

    if duration_seconds == 0:
        packets_per_second = 0.0
        bytes_per_second = 0.0
    else:
        packets_per_second = total_packet_count / duration_seconds
        bytes_per_second = total_bytes / duration_seconds

    inter_arrivals = [
        (current.timestamp_ns - previous.timestamp_ns) / NANOSECONDS_PER_SECOND
        for previous, current in zip(flow.packets, flow.packets[1:], strict=False)
    ]

    tcp_flags = (
        [packet.tcp_flags for packet in flow.packets]
        if flow.key.protocol is IPProtocol.TCP
        else []
    )

    return FlowFeatures(
        flow_duration=duration_seconds,
        forward_packet_count=len(flow.forward_packets),
        backward_packet_count=len(flow.backward_packets),
        total_packet_count=total_packet_count,
        forward_bytes=forward_bytes,
        backward_bytes=backward_bytes,
        total_bytes=total_bytes,
        mean_packet_size=_mean(all_sizes),
        std_packet_size=_population_std(all_sizes),
        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,
        syn_count=_flag_count(tcp_flags, TCP_SYN),
        ack_count=_flag_count(tcp_flags, TCP_ACK),
        rst_count=_flag_count(tcp_flags, TCP_RST),
        fin_count=_flag_count(tcp_flags, TCP_FIN),
        src_port=flow.forward_endpoint.port or 0,
        dst_port=flow.backward_endpoint.port or 0,
        protocol=int(flow.key.protocol),
        inter_arrival_mean=_mean(inter_arrivals),
        inter_arrival_std=_population_std(inter_arrivals),
    )


def _mean(values: list[int] | list[float]) -> float:
    if not values:
        return 0.0
    return math.fsum(values) / len(values)


def _population_std(values: list[int] | list[float]) -> float:
    if not values:
        return 0.0
    mean = _mean(values)
    variance = math.fsum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance)


def _flag_count(flags: list[int], mask: int) -> int:
    return sum(bool(value & mask) for value in flags)


def _validate_flow(flow: Flow) -> None:
    if not flow.packets:
        raise FeatureCalculationError("a flow must contain at least one packet")
    if len(flow.forward_packets) + len(flow.backward_packets) != len(flow.packets):
        raise FeatureCalculationError(
            "forward and backward packet counts must partition the flow"
        )
    if any(
        current.timestamp_ns < previous.timestamp_ns
        for previous, current in zip(flow.packets, flow.packets[1:], strict=False)
    ):
        raise FeatureCalculationError("flow packets must be in timestamp order")
    if any(packet.protocol is not flow.key.protocol for packet in flow.packets):
        raise FeatureCalculationError("all packets must match the flow protocol")
