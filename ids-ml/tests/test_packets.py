"""Tests for the version 1 offline packet parser."""

import socket
import struct
from pathlib import Path

import pytest

from ids_ml.packets import (
    IPProtocol,
    MalformedPacketError,
    UnsupportedLinkTypeError,
    iter_pcap_packets,
)


def _ethernet(payload: bytes, ether_type: int = 0x0800) -> bytes:
    return b"\x00" * 12 + struct.pack("!H", ether_type) + payload


def _ipv4(
    payload: bytes,
    protocol: int,
    *,
    src: str = "10.10.0.2",
    dst: str = "10.10.0.3",
    flags_fragment: int = 0,
) -> bytes:
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(payload),
            1,
            flags_fragment,
            64,
            protocol,
            0,
            socket.inet_aton(src),
            socket.inet_aton(dst),
        )
        + payload
    )


def _tcp(src_port: int, dst_port: int, flags: int) -> bytes:
    return struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 0x50, flags, 0, 0, 0)


def _udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def _icmp(icmp_type: int, identifier: int, sequence: int) -> bytes:
    return struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence)


def _write_pcap(
    path: Path, frames: list[tuple[int, int, bytes]], linktype: int = 1
) -> None:
    with path.open("wb") as capture:
        capture.write(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262_144, linktype)
        )
        for seconds, microseconds, frame in frames:
            capture.write(
                struct.pack("<IIII", seconds, microseconds, len(frame), len(frame))
            )
            capture.write(frame)


def test_parses_tcp_udp_and_icmp_and_ignores_out_of_scope_frames(
    tmp_path: Path,
) -> None:
    tcp_frame = _ethernet(_ipv4(_tcp(50_000, 22, 0x12), IPProtocol.TCP))
    udp_frame = _ethernet(_ipv4(_udp(45_875, 9_999, b"hello"), IPProtocol.UDP))
    icmp_frame = _ethernet(_ipv4(_icmp(8, 0x1234, 7), IPProtocol.ICMP))
    arp_frame = _ethernet(b"\x00" * 28, ether_type=0x0806)
    other_ipv4_frame = _ethernet(_ipv4(b"payload", 99))
    fixture = tmp_path / "tiny_ipv4.pcap"
    _write_pcap(
        fixture,
        [
            (1, 1, tcp_frame),
            (2, 2, arp_frame),
            (3, 3, udp_frame),
            (4, 4, other_ipv4_frame),
            (5, 5, icmp_frame),
        ],
    )

    records = list(iter_pcap_packets(fixture))

    assert [record.packet_index for record in records] == [0, 2, 4]
    assert records[0].timestamp_ns == 1_000_001_000
    assert records[0].src_ip == "10.10.0.2"
    assert records[0].dst_ip == "10.10.0.3"
    assert records[0].protocol is IPProtocol.TCP
    assert records[0].ip_total_length == 40
    assert records[0].src_port == 50_000
    assert records[0].dst_port == 22
    assert records[0].tcp_flags == 0x12

    assert records[1].protocol is IPProtocol.UDP
    assert records[1].ip_total_length == 33
    assert records[1].src_port == 45_875
    assert records[1].dst_port == 9_999

    assert records[2].protocol is IPProtocol.ICMP
    assert records[2].ip_total_length == 28
    assert records[2].src_port is None
    assert records[2].icmp_type == 8
    assert records[2].icmp_code == 0
    assert records[2].icmp_identifier == 0x1234
    assert records[2].icmp_sequence == 7


def test_empty_pcap_has_no_records() -> None:
    assert list(iter_pcap_packets("pcaps/normal/normal_001_idle.pcap")) == []


def test_rejects_truncated_supported_packet(tmp_path: Path) -> None:
    truncated_ip = _ipv4(_tcp(50_000, 22, 0x02), IPProtocol.TCP)[:-1]
    fixture = tmp_path / "truncated.pcap"
    _write_pcap(fixture, [(1, 0, _ethernet(truncated_ip))])

    with pytest.raises(MalformedPacketError, match="packet 0: captured IPv4"):
        list(iter_pcap_packets(fixture))


def test_rejects_fragmented_ipv4(tmp_path: Path) -> None:
    fragment = _ipv4(_tcp(50_000, 22, 0x02), IPProtocol.TCP, flags_fragment=0x2000)
    fixture = tmp_path / "fragment.pcap"
    _write_pcap(fixture, [(1, 0, _ethernet(fragment))])

    with pytest.raises(MalformedPacketError, match="fragmented IPv4"):
        list(iter_pcap_packets(fixture))


def test_rejects_non_ethernet_capture(tmp_path: Path) -> None:
    fixture = tmp_path / "raw_ip.pcap"
    _write_pcap(fixture, [], linktype=101)

    with pytest.raises(UnsupportedLinkTypeError, match="link type 101"):
        list(iter_pcap_packets(fixture))
