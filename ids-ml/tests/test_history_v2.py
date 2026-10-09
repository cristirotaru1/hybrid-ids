"""Hand-checkable tests for causal version 2 source-history features."""

from ids_ml.flows import Endpoint, Flow, FlowKey, TerminationReason
from ids_ml.history_v2 import calculate_source_history_v2
from ids_ml.packets import IPProtocol, PacketRecord

SECOND = 1_000_000_000


def _flow(
    index: int,
    start_seconds: int,
    protocol: IPProtocol,
    *,
    destination_ip: str = "10.0.0.2",
    destination_port: int | None = None,
    backward_flags: int | None = None,
    backward_seconds: int | None = None,
    termination: TerminationReason = TerminationReason.CAPTURE_END,
) -> Flow:
    source = Endpoint("10.0.0.1", 40_000 + index if destination_port else None)
    destination = Endpoint(destination_ip, destination_port)
    forward = PacketRecord(
        packet_index=index,
        timestamp_ns=start_seconds * SECOND,
        src_ip=source.ip,
        dst_ip=destination.ip,
        protocol=protocol,
        ip_total_length=40,
        src_port=source.port,
        dst_port=destination.port,
        tcp_flags=0x02 if protocol is IPProtocol.TCP else 0,
        icmp_type=8 if protocol is IPProtocol.ICMP else None,
        icmp_code=0 if protocol is IPProtocol.ICMP else None,
        icmp_identifier=index if protocol is IPProtocol.ICMP else None,
    )
    packets = [forward]
    backward_packets: tuple[PacketRecord, ...] = ()
    if backward_flags is not None and backward_seconds is not None:
        backward = PacketRecord(
            packet_index=index + 100,
            timestamp_ns=backward_seconds * SECOND,
            src_ip=destination.ip,
            dst_ip=source.ip,
            protocol=protocol,
            ip_total_length=40,
            src_port=destination.port,
            dst_port=source.port,
            tcp_flags=backward_flags,
        )
        packets.append(backward)
        backward_packets = (backward,)
    return Flow(
        key=FlowKey(protocol, source, destination),
        forward_endpoint=source,
        backward_endpoint=destination,
        packets=tuple(packets),
        forward_packets=(forward,),
        backward_packets=backward_packets,
        termination_reason=termination,
    )


def test_counts_same_protocol_and_only_observable_tcp_outcomes() -> None:
    refused = _flow(
        0,
        0,
        IPProtocol.TCP,
        destination_port=65_000,
        backward_flags=0x14,
        backward_seconds=1,
        termination=TerminationReason.TCP_RST,
    )
    accepted = _flow(
        1,
        2,
        IPProtocol.TCP,
        destination_port=22,
        backward_flags=0x12,
        backward_seconds=3,
        termination=TerminationReason.TCP_FIN,
    )
    future_refusal = _flow(
        2,
        4,
        IPProtocol.TCP,
        destination_port=443,
        backward_flags=0x14,
        backward_seconds=8,
        termination=TerminationReason.TCP_RST,
    )
    current = _flow(3, 5, IPProtocol.TCP, destination_port=22)

    history = calculate_source_history_v2([refused, accepted, future_refusal, current])[
        3
    ].history

    assert history.flows_last_10s == 3
    assert history.same_protocol_flows_last_10s == 3
    assert history.tcp_attempts_last_10s == 2
    assert history.failed_tcp_connections_last_10s == 1
    assert history.failed_connection_rate_last_10s == 0.5


def test_same_protocol_count_does_not_mix_protocols() -> None:
    udp = _flow(0, 0, IPProtocol.UDP, destination_port=9999)
    icmp = _flow(1, 1, IPProtocol.ICMP)
    current_udp = _flow(2, 2, IPProtocol.UDP, destination_port=9999)

    history = calculate_source_history_v2([udp, icmp, current_udp])[2].history

    assert history.flows_last_10s == 2
    assert history.same_protocol_flows_last_10s == 1
    assert history.tcp_attempts_last_10s == 0
    assert history.failed_tcp_connections_last_10s == 0


def test_same_timestamp_flows_remain_invisible_to_each_other() -> None:
    first = _flow(0, 1, IPProtocol.UDP, destination_port=9999)
    second = _flow(1, 1, IPProtocol.UDP, destination_port=9999)

    histories = calculate_source_history_v2([first, second])

    assert histories[0].history.flows_last_10s == 0
    assert histories[1].history.flows_last_10s == 0
    assert histories[0].history.same_protocol_flows_last_10s == 0
    assert histories[1].history.same_protocol_flows_last_10s == 0
