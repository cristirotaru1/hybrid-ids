"""Tests for deterministic bidirectional flow grouping."""

from ids_ml.flows import (
    Endpoint,
    FlowTimeouts,
    TerminationReason,
    build_flows,
    flow_key,
)
from ids_ml.packets import IPProtocol, PacketRecord

SECOND = 1_000_000_000


def _packet(
    index: int,
    seconds: int,
    src_ip: str,
    dst_ip: str,
    protocol: IPProtocol,
    *,
    src_port: int | None = None,
    dst_port: int | None = None,
    tcp_flags: int = 0,
    icmp_type: int | None = None,
    icmp_identifier: int | None = None,
) -> PacketRecord:
    return PacketRecord(
        packet_index=index,
        timestamp_ns=seconds * SECOND,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        ip_total_length=40,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
        icmp_code=0 if protocol is IPProtocol.ICMP else None,
        icmp_identifier=icmp_identifier,
        icmp_sequence=index if protocol is IPProtocol.ICMP else None,
    )


def test_tcp_reverse_packets_share_key_and_preserve_syn_initiator() -> None:
    syn = _packet(
        0,
        0,
        "10.10.0.2",
        "10.10.0.3",
        IPProtocol.TCP,
        src_port=50_000,
        dst_port=22,
        tcp_flags=0x02,
    )
    syn_ack = _packet(
        1,
        1,
        "10.10.0.3",
        "10.10.0.2",
        IPProtocol.TCP,
        src_port=22,
        dst_port=50_000,
        tcp_flags=0x12,
    )
    ack = _packet(
        2,
        2,
        "10.10.0.2",
        "10.10.0.3",
        IPProtocol.TCP,
        src_port=50_000,
        dst_port=22,
        tcp_flags=0x10,
    )

    assert flow_key(syn) == flow_key(syn_ack)
    flow = build_flows([syn, syn_ack, ack])[0]

    assert flow.forward_endpoint == Endpoint("10.10.0.2", 50_000)
    assert [packet.packet_index for packet in flow.forward_packets] == [0, 2]
    assert [packet.packet_index for packet in flow.backward_packets] == [1]
    assert flow.termination_reason is TerminationReason.CAPTURE_END


def test_tcp_closes_after_fin_from_both_directions() -> None:
    packets = [
        _packet(
            0,
            0,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x02,
        ),
        _packet(
            1,
            1,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x11,
        ),
        _packet(
            2,
            2,
            "10.0.0.2",
            "10.0.0.1",
            IPProtocol.TCP,
            src_port=22,
            dst_port=50_000,
            tcp_flags=0x11,
        ),
        _packet(
            3,
            3,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x02,
        ),
    ]

    flows = build_flows(packets)

    assert [len(flow.packets) for flow in flows] == [3, 1]
    assert flows[0].termination_reason is TerminationReason.TCP_FIN
    assert flows[1].termination_reason is TerminationReason.CAPTURE_END


def test_tcp_final_ack_stays_in_cleanly_closed_flow() -> None:
    packets = [
        _packet(
            0,
            0,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x11,
        ),
        _packet(
            1,
            1,
            "10.0.0.2",
            "10.0.0.1",
            IPProtocol.TCP,
            src_port=22,
            dst_port=50_000,
            tcp_flags=0x11,
        ),
        _packet(
            2,
            2,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x10,
        ),
    ]

    flow = build_flows(packets)[0]

    assert [packet.packet_index for packet in flow.packets] == [0, 1, 2]
    assert flow.termination_reason is TerminationReason.TCP_FIN


def test_tcp_syn_ack_seen_first_recovers_initiator_direction() -> None:
    syn_ack = _packet(
        0,
        0,
        "10.0.0.2",
        "10.0.0.1",
        IPProtocol.TCP,
        src_port=22,
        dst_port=50_000,
        tcp_flags=0x12,
    )

    flow = build_flows([syn_ack])[0]

    assert flow.forward_endpoint == Endpoint("10.0.0.1", 50_000)
    assert flow.backward_endpoint == Endpoint("10.0.0.2", 22)
    assert flow.forward_packets == ()
    assert flow.backward_packets == (syn_ack,)


def test_tcp_rst_closes_immediately() -> None:
    rst = _packet(
        0,
        0,
        "10.0.0.2",
        "10.0.0.1",
        IPProtocol.TCP,
        src_port=22,
        dst_port=50_000,
        tcp_flags=0x04,
    )

    flow = build_flows([rst])[0]

    assert flow.termination_reason is TerminationReason.TCP_RST


def test_v2_tcp_terminal_linger_keeps_late_teardown_in_original_flow() -> None:
    packets = [
        _packet(
            0,
            0,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x02,
        ),
        _packet(
            1,
            1,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x04,
        ),
        _packet(
            2,
            2,
            "10.0.0.2",
            "10.0.0.1",
            IPProtocol.TCP,
            src_port=22,
            dst_port=50_000,
            tcp_flags=0x11,
        ),
        _packet(
            3,
            3,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x04,
        ),
    ]

    flow = build_flows(packets, linger_terminated_tcp=True)[0]

    assert [packet.packet_index for packet in flow.packets] == [0, 1, 2, 3]
    assert flow.forward_endpoint == Endpoint("10.0.0.1", 50_000)
    assert flow.backward_endpoint == Endpoint("10.0.0.2", 22)
    assert flow.termination_reason is TerminationReason.TCP_RST


def test_v2_tcp_terminal_linger_starts_new_flow_on_bare_syn() -> None:
    packets = [
        _packet(
            0,
            0,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x04,
        ),
        _packet(
            1,
            1,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.TCP,
            src_port=50_000,
            dst_port=22,
            tcp_flags=0x02,
        ),
    ]

    flows = build_flows(packets, linger_terminated_tcp=True)

    assert [len(flow.packets) for flow in flows] == [1, 1]
    assert flows[0].termination_reason is TerminationReason.TCP_RST
    assert flows[1].termination_reason is TerminationReason.CAPTURE_END


def test_udp_reverse_packets_group_until_idle_timeout() -> None:
    packets = [
        _packet(
            0, 0, "10.0.0.1", "10.0.0.2", IPProtocol.UDP, src_port=40_000, dst_port=9999
        ),
        _packet(
            1,
            20,
            "10.0.0.2",
            "10.0.0.1",
            IPProtocol.UDP,
            src_port=9999,
            dst_port=40_000,
        ),
        _packet(
            2,
            51,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.UDP,
            src_port=40_000,
            dst_port=9999,
        ),
    ]

    flows = build_flows(packets)

    assert [len(flow.packets) for flow in flows] == [2, 1]
    assert flows[0].termination_reason is TerminationReason.IDLE_TIMEOUT
    assert flows[1].termination_reason is TerminationReason.CAPTURE_END


def test_icmp_echo_reply_uses_request_source_as_forward_and_ids_split_flows() -> None:
    reply_seen_first = _packet(
        0,
        0,
        "10.0.0.2",
        "10.0.0.1",
        IPProtocol.ICMP,
        icmp_type=0,
        icmp_identifier=7,
    )
    request = _packet(
        1,
        1,
        "10.0.0.1",
        "10.0.0.2",
        IPProtocol.ICMP,
        icmp_type=8,
        icmp_identifier=7,
    )
    different_ping_process = _packet(
        2,
        2,
        "10.0.0.1",
        "10.0.0.2",
        IPProtocol.ICMP,
        icmp_type=8,
        icmp_identifier=8,
    )

    flows = build_flows([reply_seen_first, request, different_ping_process])

    assert [len(flow.packets) for flow in flows] == [2, 1]
    assert flows[0].forward_endpoint == Endpoint("10.0.0.1", None)
    assert [packet.packet_index for packet in flows[0].forward_packets] == [1]
    assert [packet.packet_index for packet in flows[0].backward_packets] == [0]


def test_custom_timeout_is_applied() -> None:
    packets = [
        _packet(
            0,
            0,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.ICMP,
            icmp_type=8,
            icmp_identifier=7,
        ),
        _packet(
            1,
            2,
            "10.0.0.2",
            "10.0.0.1",
            IPProtocol.ICMP,
            icmp_type=0,
            icmp_identifier=7,
        ),
    ]

    flows = build_flows(packets, FlowTimeouts(icmp_ns=SECOND))

    assert [len(flow.packets) for flow in flows] == [1, 1]
    assert flows[0].termination_reason is TerminationReason.IDLE_TIMEOUT


def test_different_later_flow_advances_idle_timeout_clock() -> None:
    udp = _packet(
        0,
        0,
        "10.0.0.1",
        "10.0.0.2",
        IPProtocol.UDP,
        src_port=40_000,
        dst_port=9999,
    )
    later_icmp = _packet(
        1,
        31,
        "10.0.0.3",
        "10.0.0.4",
        IPProtocol.ICMP,
        icmp_type=8,
        icmp_identifier=7,
    )

    flows = build_flows([udp, later_icmp])

    assert flows[0].termination_reason is TerminationReason.IDLE_TIMEOUT
    assert flows[1].termination_reason is TerminationReason.CAPTURE_END
