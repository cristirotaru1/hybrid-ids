"""Hand-checkable tests for version 1 flow-level features."""

import math

import pytest

from ids_ml.features import FeatureCalculationError, calculate_flow_features
from ids_ml.flows import Endpoint, Flow, FlowKey, TerminationReason
from ids_ml.packets import IPProtocol, PacketRecord

SECOND = 1_000_000_000


def _tcp_packet(
    index: int,
    seconds: int,
    src: Endpoint,
    dst: Endpoint,
    size: int,
    flags: int,
) -> PacketRecord:
    return PacketRecord(
        packet_index=index,
        timestamp_ns=seconds * SECOND,
        src_ip=src.ip,
        dst_ip=dst.ip,
        protocol=IPProtocol.TCP,
        ip_total_length=size,
        src_port=src.port,
        dst_port=dst.port,
        tcp_flags=flags,
    )


def test_calculates_hand_checkable_bidirectional_tcp_features() -> None:
    client = Endpoint("10.0.0.1", 50_000)
    server = Endpoint("10.0.0.2", 22)
    first = _tcp_packet(0, 0, client, server, 40, 0x02)
    second = _tcp_packet(1, 1, server, client, 60, 0x12)
    third = _tcp_packet(2, 4, client, server, 100, 0x11)
    flow = Flow(
        key=FlowKey(IPProtocol.TCP, client, server),
        forward_endpoint=client,
        backward_endpoint=server,
        packets=(first, second, third),
        forward_packets=(first, third),
        backward_packets=(second,),
        termination_reason=TerminationReason.CAPTURE_END,
    )

    features = calculate_flow_features(flow)

    assert features.flow_duration == 4.0
    assert features.forward_packet_count == 2
    assert features.backward_packet_count == 1
    assert features.total_packet_count == 3
    assert features.forward_bytes == 140
    assert features.backward_bytes == 60
    assert features.total_bytes == 200
    assert features.mean_packet_size == pytest.approx(200 / 3)
    assert features.std_packet_size == pytest.approx(math.sqrt(5600 / 9))
    assert features.packets_per_second == 0.75
    assert features.bytes_per_second == 50.0
    assert features.syn_count == 2
    assert features.ack_count == 2
    assert features.rst_count == 0
    assert features.fin_count == 1
    assert features.src_port == 50_000
    assert features.dst_port == 22
    assert features.protocol == 6
    assert features.inter_arrival_mean == 2.0
    assert features.inter_arrival_std == 1.0


def test_single_icmp_packet_uses_documented_zero_values() -> None:
    source = Endpoint("10.0.0.1", None)
    destination = Endpoint("10.0.0.2", None)
    packet = PacketRecord(
        packet_index=0,
        timestamp_ns=5 * SECOND,
        src_ip=source.ip,
        dst_ip=destination.ip,
        protocol=IPProtocol.ICMP,
        ip_total_length=84,
        icmp_type=8,
        icmp_code=0,
        icmp_identifier=7,
        icmp_sequence=1,
    )
    flow = Flow(
        key=FlowKey(IPProtocol.ICMP, source, destination, 8, 0, 7),
        forward_endpoint=source,
        backward_endpoint=destination,
        packets=(packet,),
        forward_packets=(packet,),
        backward_packets=(),
        termination_reason=TerminationReason.CAPTURE_END,
    )

    features = calculate_flow_features(flow)

    assert features.flow_duration == 0.0
    assert features.packets_per_second == 0.0
    assert features.bytes_per_second == 0.0
    assert features.std_packet_size == 0.0
    assert features.inter_arrival_mean == 0.0
    assert features.inter_arrival_std == 0.0
    assert features.src_port == 0
    assert features.dst_port == 0
    assert features.protocol == 1
    assert features.syn_count == 0
    assert features.ack_count == 0
    assert features.rst_count == 0
    assert features.fin_count == 0


def test_rejects_flow_with_packets_out_of_timestamp_order() -> None:
    client = Endpoint("10.0.0.1", 50_000)
    server = Endpoint("10.0.0.2", 22)
    later = _tcp_packet(0, 2, client, server, 40, 0x02)
    earlier = _tcp_packet(1, 1, server, client, 40, 0x12)
    flow = Flow(
        key=FlowKey(IPProtocol.TCP, client, server),
        forward_endpoint=client,
        backward_endpoint=server,
        packets=(later, earlier),
        forward_packets=(later,),
        backward_packets=(earlier,),
        termination_reason=TerminationReason.CAPTURE_END,
    )

    with pytest.raises(FeatureCalculationError, match="timestamp order"):
        calculate_flow_features(flow)
