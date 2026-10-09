"""Hand-checkable tests for causal 10-second source-history features."""

import pytest

from ids_ml.flows import Endpoint, Flow, FlowKey, TerminationReason
from ids_ml.history import (
    HistoryCalculationError,
    calculate_source_history,
    is_failed_connection,
)
from ids_ml.packets import IPProtocol, PacketRecord

SECOND = 1_000_000_000


def _flow(
    index: int,
    start_seconds: int,
    source_ip: str,
    destination_ip: str,
    protocol: IPProtocol,
    *,
    source_port: int | None = None,
    destination_port: int | None = None,
    backward_flags: int | None = None,
    termination: TerminationReason = TerminationReason.CAPTURE_END,
    duration_seconds: int = 0,
) -> Flow:
    source = Endpoint(source_ip, source_port)
    destination = Endpoint(destination_ip, destination_port)
    forward_flags = 0x02 if protocol is IPProtocol.TCP else 0
    forward = PacketRecord(
        packet_index=index,
        timestamp_ns=start_seconds * SECOND,
        src_ip=source_ip,
        dst_ip=destination_ip,
        protocol=protocol,
        ip_total_length=40,
        src_port=source_port,
        dst_port=destination_port,
        tcp_flags=forward_flags,
        icmp_type=8 if protocol is IPProtocol.ICMP else None,
        icmp_code=0 if protocol is IPProtocol.ICMP else None,
        icmp_identifier=index if protocol is IPProtocol.ICMP else None,
    )
    packets = [forward]
    backward_packets: tuple[PacketRecord, ...] = ()
    if backward_flags is not None:
        backward = PacketRecord(
            packet_index=index + 100,
            timestamp_ns=(start_seconds + duration_seconds) * SECOND,
            src_ip=destination_ip,
            dst_ip=source_ip,
            protocol=protocol,
            ip_total_length=40,
            src_port=destination_port,
            dst_port=source_port,
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


def test_tracks_only_prior_same_source_flows_inside_open_window() -> None:
    flows = [
        _flow(
            0,
            0,
            "10.0.0.1",
            "10.0.0.2",
            IPProtocol.UDP,
            source_port=40_000,
            destination_port=53,
        ),
        _flow(
            1,
            5,
            "10.0.0.1",
            "10.0.0.3",
            IPProtocol.UDP,
            source_port=40_001,
            destination_port=80,
        ),
        _flow(
            2,
            9,
            "10.0.0.9",
            "10.0.0.8",
            IPProtocol.UDP,
            source_port=40_002,
            destination_port=443,
        ),
        _flow(3, 10, "10.0.0.1", "10.0.0.3", IPProtocol.ICMP),
    ]

    enriched = calculate_source_history(flows)
    history = enriched[3].history

    assert history.flows_last_10s == 1
    assert history.unique_dst_ips_last_10s == 1
    assert history.unique_dst_ports_last_10s == 1
    assert history.connection_rate_last_10s == 0.1
    assert history.failed_connection_rate_last_10s == 0.0


def test_same_timestamp_flows_do_not_see_each_other() -> None:
    first = _flow(0, 1, "10.0.0.1", "10.0.0.2", IPProtocol.ICMP)
    second = _flow(1, 1, "10.0.0.1", "10.0.0.3", IPProtocol.ICMP)

    histories = calculate_source_history([first, second])

    assert histories[0].history.flows_last_10s == 0
    assert histories[1].history.flows_last_10s == 0


def test_failed_connection_rate_uses_only_resolved_tcp_attempts() -> None:
    failed = _flow(
        0,
        0,
        "10.0.0.1",
        "10.0.0.2",
        IPProtocol.TCP,
        source_port=50_000,
        destination_port=22,
        backward_flags=0x14,
        termination=TerminationReason.TCP_RST,
        duration_seconds=1,
    )
    successful = _flow(
        1,
        2,
        "10.0.0.1",
        "10.0.0.3",
        IPProtocol.TCP,
        source_port=50_001,
        destination_port=443,
        backward_flags=0x12,
        termination=TerminationReason.TCP_FIN,
        duration_seconds=1,
    )
    unresolved_at_current_start = _flow(
        2,
        3,
        "10.0.0.1",
        "10.0.0.4",
        IPProtocol.TCP,
        source_port=50_002,
        destination_port=80,
        backward_flags=0x12,
        termination=TerminationReason.TCP_FIN,
        duration_seconds=10,
    )
    current = _flow(3, 5, "10.0.0.1", "10.0.0.5", IPProtocol.ICMP)

    histories = calculate_source_history(
        [failed, successful, unresolved_at_current_start, current]
    )

    assert is_failed_connection(failed)
    assert not is_failed_connection(successful)
    assert histories[3].history.flows_last_10s == 3
    assert histories[3].history.failed_connection_rate_last_10s == 0.5


def test_capture_end_without_syn_ack_is_unknown_not_failed() -> None:
    incomplete = _flow(
        0,
        0,
        "10.0.0.1",
        "10.0.0.2",
        IPProtocol.TCP,
        source_port=50_000,
        destination_port=22,
    )

    assert not is_failed_connection(incomplete)


def test_rejects_flows_out_of_start_order() -> None:
    later = _flow(0, 2, "10.0.0.1", "10.0.0.2", IPProtocol.ICMP)
    earlier = _flow(1, 1, "10.0.0.1", "10.0.0.2", IPProtocol.ICMP)

    with pytest.raises(HistoryCalculationError, match="start timestamp"):
        calculate_source_history([later, earlier])
