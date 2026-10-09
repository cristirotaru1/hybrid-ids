"""Hand-checkable tests for version 2 protocol-semantic flow features."""

from ids_ml.features_v2 import (
    NOT_APPLICABLE,
    calculate_flow_features_v2,
)
from ids_ml.flows import Endpoint, Flow, FlowKey, TerminationReason
from ids_ml.packets import IPProtocol, PacketRecord

SECOND = 1_000_000_000


def _packet(
    index: int,
    seconds: int,
    source: Endpoint,
    destination: Endpoint,
    protocol: IPProtocol,
    *,
    tcp_flags: int = 0,
    icmp_type: int | None = None,
    icmp_code: int | None = None,
) -> PacketRecord:
    return PacketRecord(
        packet_index=index,
        timestamp_ns=seconds * SECOND,
        src_ip=source.ip,
        dst_ip=destination.ip,
        protocol=protocol,
        ip_total_length=40,
        src_port=source.port,
        dst_port=destination.port,
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )


def test_marks_explicitly_refused_tcp_attempt() -> None:
    client = Endpoint("10.0.0.1", 50_000)
    server = Endpoint("10.0.0.2", 65_000)
    syn = _packet(0, 0, client, server, IPProtocol.TCP, tcp_flags=0x02)
    rst_ack = _packet(1, 1, server, client, IPProtocol.TCP, tcp_flags=0x14)
    flow = Flow(
        key=FlowKey(IPProtocol.TCP, client, server),
        forward_endpoint=client,
        backward_endpoint=server,
        packets=(syn, rst_ack),
        forward_packets=(syn,),
        backward_packets=(rst_ack,),
        termination_reason=TerminationReason.TCP_RST,
    )

    features = calculate_flow_features_v2(flow)

    assert features.current_tcp_failed == 1
    assert features.rst_count == 1
    assert features.icmp_type_group == NOT_APPLICABLE
    assert features.icmp_code == NOT_APPLICABLE
    assert features.icmp_is_error == 0


def test_reset_after_syn_ack_is_not_a_failed_connection() -> None:
    client = Endpoint("10.0.0.1", 50_000)
    server = Endpoint("10.0.0.2", 22)
    syn = _packet(0, 0, client, server, IPProtocol.TCP, tcp_flags=0x02)
    syn_ack = _packet(1, 1, server, client, IPProtocol.TCP, tcp_flags=0x12)
    reset = _packet(2, 2, client, server, IPProtocol.TCP, tcp_flags=0x14)
    flow = Flow(
        key=FlowKey(IPProtocol.TCP, client, server),
        forward_endpoint=client,
        backward_endpoint=server,
        packets=(syn, syn_ack, reset),
        forward_packets=(syn, reset),
        backward_packets=(syn_ack,),
        termination_reason=TerminationReason.TCP_RST,
    )

    assert calculate_flow_features_v2(flow).current_tcp_failed == 0


def test_distinguishes_icmp_echo_from_destination_unreachable() -> None:
    client = Endpoint("10.0.0.1", None)
    server = Endpoint("10.0.0.2", None)
    echo = _packet(
        0,
        0,
        client,
        server,
        IPProtocol.ICMP,
        icmp_type=8,
        icmp_code=0,
    )
    unreachable = _packet(
        1,
        1,
        server,
        client,
        IPProtocol.ICMP,
        icmp_type=3,
        icmp_code=3,
    )
    echo_flow = Flow(
        key=FlowKey(IPProtocol.ICMP, client, server, 8, 0, 7),
        forward_endpoint=client,
        backward_endpoint=server,
        packets=(echo,),
        forward_packets=(echo,),
        backward_packets=(),
        termination_reason=TerminationReason.CAPTURE_END,
    )
    error_flow = Flow(
        key=FlowKey(IPProtocol.ICMP, client, server, 3, 3, None),
        forward_endpoint=server,
        backward_endpoint=client,
        packets=(unreachable,),
        forward_packets=(unreachable,),
        backward_packets=(),
        termination_reason=TerminationReason.CAPTURE_END,
    )

    echo_features = calculate_flow_features_v2(echo_flow)
    error_features = calculate_flow_features_v2(error_flow)

    assert (echo_features.icmp_type_group, echo_features.icmp_code) == (8, 0)
    assert echo_features.icmp_is_error == 0
    assert (error_features.icmp_type_group, error_features.icmp_code) == (3, 3)
    assert error_features.icmp_is_error == 1
