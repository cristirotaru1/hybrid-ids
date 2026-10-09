"""Deterministic bidirectional flow grouping for packet schema version 1."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from ids_ml.packets import IPProtocol, PacketRecord

TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10
TCP_FIN = 0x01


@dataclass(frozen=True, order=True, slots=True)
class Endpoint:
    """One side of a transport conversation."""

    ip: str
    port: int | None


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Direction-independent identity shared by both sides of a flow."""

    protocol: IPProtocol
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    icmp_type_group: int | None = None
    icmp_code: int | None = None
    icmp_identifier: int | None = None


class TerminationReason(StrEnum):
    """Reason a grouped flow stopped accepting packets."""

    CAPTURE_END = "capture_end"
    IDLE_TIMEOUT = "idle_timeout"
    TCP_FIN = "tcp_fin"
    TCP_RST = "tcp_rst"


@dataclass(frozen=True, slots=True)
class Flow:
    """One completed bidirectional flow with initiator-relative direction."""

    key: FlowKey
    forward_endpoint: Endpoint
    backward_endpoint: Endpoint
    packets: tuple[PacketRecord, ...]
    forward_packets: tuple[PacketRecord, ...]
    backward_packets: tuple[PacketRecord, ...]
    termination_reason: TerminationReason

    @property
    def start_timestamp_ns(self) -> int:
        return self.packets[0].timestamp_ns

    @property
    def end_timestamp_ns(self) -> int:
        return self.packets[-1].timestamp_ns


@dataclass(frozen=True, slots=True)
class FlowTimeouts:
    """Idle timeouts expressed exactly as integer nanoseconds."""

    tcp_ns: int = 120_000_000_000
    udp_ns: int = 30_000_000_000
    icmp_ns: int = 10_000_000_000

    def for_protocol(self, protocol: IPProtocol) -> int:
        if protocol is IPProtocol.TCP:
            return self.tcp_ns
        if protocol is IPProtocol.UDP:
            return self.udp_ns
        return self.icmp_ns


class FlowBuilderError(ValueError):
    """Raised when packet records violate the flow-builder contract."""


@dataclass(slots=True)
class _ActiveFlow:
    key: FlowKey
    forward_endpoint: Endpoint
    backward_endpoint: Endpoint
    packets: list[PacketRecord] = field(default_factory=list)
    forward_packets: list[PacketRecord] = field(default_factory=list)
    backward_packets: list[PacketRecord] = field(default_factory=list)
    forward_fin_seen: bool = False
    backward_fin_seen: bool = False
    terminal_reason: TerminationReason | None = None

    @property
    def last_timestamp_ns(self) -> int:
        return self.packets[-1].timestamp_ns

    def add(self, packet: PacketRecord) -> None:
        source = _source_endpoint(packet)
        self.packets.append(packet)
        if source == self.forward_endpoint:
            self.forward_packets.append(packet)
            if packet.protocol is IPProtocol.TCP and packet.tcp_flags & TCP_FIN:
                self.forward_fin_seen = True
        elif source == self.backward_endpoint:
            self.backward_packets.append(packet)
            if packet.protocol is IPProtocol.TCP and packet.tcp_flags & TCP_FIN:
                self.backward_fin_seen = True
        else:
            raise FlowBuilderError(
                f"packet {packet.packet_index}: endpoints do not match active flow"
            )

    def finish(self, reason: TerminationReason) -> Flow:
        return Flow(
            key=self.key,
            forward_endpoint=self.forward_endpoint,
            backward_endpoint=self.backward_endpoint,
            packets=tuple(self.packets),
            forward_packets=tuple(self.forward_packets),
            backward_packets=tuple(self.backward_packets),
            termination_reason=reason,
        )


def build_flows(
    packets: Iterable[PacketRecord],
    timeouts: FlowTimeouts | None = None,
    *,
    linger_terminated_tcp: bool = False,
) -> list[Flow]:
    """Group capture-ordered packets into deterministic bidirectional flows."""
    timeout_config = timeouts or FlowTimeouts()
    _validate_timeouts(timeout_config)
    active: dict[FlowKey, _ActiveFlow] = {}
    completed: list[Flow] = []
    previous_timestamp_ns: int | None = None

    for packet in packets:
        _validate_packet(packet)
        if (
            previous_timestamp_ns is not None
            and packet.timestamp_ns < previous_timestamp_ns
        ):
            raise FlowBuilderError(
                f"packet {packet.packet_index}: timestamp precedes the previous packet"
            )
        previous_timestamp_ns = packet.timestamp_ns

        expired_keys = [
            key
            for key, flow in active.items()
            if packet.timestamp_ns - flow.last_timestamp_ns
            > timeout_config.for_protocol(key.protocol)
        ]
        for expired_key in expired_keys:
            expired_flow = active.pop(expired_key)
            completed.append(
                expired_flow.finish(
                    expired_flow.terminal_reason or TerminationReason.IDLE_TIMEOUT
                )
            )

        key = flow_key(packet)
        current = active.get(key)

        if current is None:
            forward = _initiator_endpoint(packet)
            backward = _other_endpoint(packet, forward)
            current = _ActiveFlow(key, forward, backward)
            active[key] = current

        if (
            linger_terminated_tcp
            and current.terminal_reason is not None
            and _is_bare_syn(packet)
        ):
            completed.append(current.finish(current.terminal_reason))
            forward = _initiator_endpoint(packet)
            backward = _other_endpoint(packet, forward)
            current = _ActiveFlow(key, forward, backward)
            active[key] = current

        clean_close_was_pending = current.forward_fin_seen and current.backward_fin_seen
        if clean_close_was_pending and _is_bare_syn(packet):
            completed.append(current.finish(TerminationReason.TCP_FIN))
            forward = _initiator_endpoint(packet)
            backward = _other_endpoint(packet, forward)
            current = _ActiveFlow(key, forward, backward)
            active[key] = current
            clean_close_was_pending = False

        current.add(packet)
        termination = _tcp_termination(packet, clean_close_was_pending)
        if termination is not None:
            if linger_terminated_tcp:
                current.terminal_reason = termination
            else:
                completed.append(current.finish(termination))
                del active[key]

    completed.extend(flow.finish(_capture_end_reason(flow)) for flow in active.values())
    completed.sort(
        key=lambda flow: (flow.start_timestamp_ns, flow.packets[0].packet_index)
    )
    return completed


def flow_key(packet: PacketRecord) -> FlowKey:
    """Return the canonical direction-independent key for *packet*."""
    source = _source_endpoint(packet)
    destination = _destination_endpoint(packet)
    endpoint_a, endpoint_b = sorted((source, destination), key=_endpoint_sort_key)

    if packet.protocol is not IPProtocol.ICMP:
        return FlowKey(packet.protocol, endpoint_a, endpoint_b)

    is_echo = packet.icmp_type in {0, 8}
    return FlowKey(
        packet.protocol,
        endpoint_a,
        endpoint_b,
        icmp_type_group=8 if is_echo else packet.icmp_type,
        icmp_code=packet.icmp_code,
        icmp_identifier=packet.icmp_identifier if is_echo else None,
    )


def _source_endpoint(packet: PacketRecord) -> Endpoint:
    return Endpoint(packet.src_ip, packet.src_port)


def _destination_endpoint(packet: PacketRecord) -> Endpoint:
    return Endpoint(packet.dst_ip, packet.dst_port)


def _initiator_endpoint(packet: PacketRecord) -> Endpoint:
    if packet.protocol is IPProtocol.ICMP and packet.icmp_type == 0:
        return _destination_endpoint(packet)
    if (
        packet.protocol is IPProtocol.TCP
        and packet.tcp_flags & TCP_SYN
        and packet.tcp_flags & TCP_ACK
    ):
        return _destination_endpoint(packet)
    return _source_endpoint(packet)


def _other_endpoint(packet: PacketRecord, endpoint: Endpoint) -> Endpoint:
    source = _source_endpoint(packet)
    return _destination_endpoint(packet) if endpoint == source else source


def _endpoint_sort_key(endpoint: Endpoint) -> tuple[int, int]:
    return int(ipaddress.IPv4Address(endpoint.ip)), endpoint.port or -1


def _tcp_termination(
    packet: PacketRecord, clean_close_was_pending: bool
) -> TerminationReason | None:
    if packet.protocol is not IPProtocol.TCP:
        return None
    if packet.tcp_flags & TCP_RST:
        return TerminationReason.TCP_RST
    if clean_close_was_pending:
        return TerminationReason.TCP_FIN
    return None


def _is_bare_syn(packet: PacketRecord) -> bool:
    return (
        packet.protocol is IPProtocol.TCP
        and bool(packet.tcp_flags & TCP_SYN)
        and not bool(packet.tcp_flags & TCP_ACK)
    )


def _capture_end_reason(flow: _ActiveFlow) -> TerminationReason:
    if flow.terminal_reason is not None:
        return flow.terminal_reason
    if flow.forward_fin_seen and flow.backward_fin_seen:
        return TerminationReason.TCP_FIN
    return TerminationReason.CAPTURE_END


def _validate_packet(packet: PacketRecord) -> None:
    if packet.protocol in {IPProtocol.TCP, IPProtocol.UDP}:
        if packet.src_port is None or packet.dst_port is None:
            raise FlowBuilderError(
                f"packet {packet.packet_index}: {packet.protocol.name} requires ports"
            )
    elif packet.icmp_type is None or packet.icmp_code is None:
        raise FlowBuilderError(
            f"packet {packet.packet_index}: ICMP requires type and code"
        )


def _validate_timeouts(timeouts: FlowTimeouts) -> None:
    if timeouts.tcp_ns <= 0 or timeouts.udp_ns <= 0 or timeouts.icmp_ns <= 0:
        raise FlowBuilderError("all idle timeouts must be positive")
