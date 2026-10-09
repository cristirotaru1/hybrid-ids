"""Deterministic, read-only parsing of supported packets from classic PCAP files."""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

from scapy.utils import RawPcapReader

ETHERNET_LINK_TYPE = 1
ETHERTYPE_IPV4 = 0x0800
VLAN_ETHERTYPES = frozenset({0x8100, 0x88A8})
MAX_VLAN_TAGS = 2


class IPProtocol(IntEnum):
    """IPv4 protocol numbers supported by feature schema version 1."""

    ICMP = 1
    TCP = 6
    UDP = 17

@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Protocol fields needed by the later bidirectional flow builder."""

    packet_index: int
    timestamp_ns: int
    src_ip: str
    dst_ip: str
    protocol: IPProtocol
    ip_total_length: int
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int = 0
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_identifier: int | None = None
    icmp_sequence: int | None = None


class PacketParserError(ValueError):
    """Base class for deterministic PCAP parsing failures."""


class UnsupportedLinkTypeError(PacketParserError):
    """Raised when a capture is not Ethernet, the version 1 link type."""


class MalformedPacketError(PacketParserError):
    """Raised when a supported packet cannot be represented without data loss."""


def iter_pcap_packets(path: str | Path) -> Iterator[PacketRecord]:
    """Yield supported packet records from *path* without modifying the capture."""
    capture_path = Path(path)
    with RawPcapReader(str(capture_path)) as reader:
        if reader.linktype != ETHERNET_LINK_TYPE:
            raise UnsupportedLinkTypeError(
                f"{capture_path}: link type {reader.linktype} is unsupported; "
                f"expected Ethernet ({ETHERNET_LINK_TYPE})"
            )

        timestamp_multiplier = 1 if reader.nano else 1_000
        for packet_index, (frame, metadata) in enumerate(reader):
            timestamp_ns = metadata.sec * 1_000_000_000 + (
                metadata.usec * timestamp_multiplier
            )
            record = _parse_ethernet_frame(frame, packet_index, timestamp_ns)
            if record is not None:
                yield record


def _parse_ethernet_frame(
    frame: bytes, packet_index: int, timestamp_ns: int
) -> PacketRecord | None:
    if len(frame) < 14:
        raise _malformed(packet_index, "truncated Ethernet header")

    ether_type = _unpack_u16(frame, 12)
    ip_offset = 14
    vlan_count = 0
    while ether_type in VLAN_ETHERTYPES:
        vlan_count += 1
        if vlan_count > MAX_VLAN_TAGS:
            raise _malformed(packet_index, "more than two VLAN tags are unsupported")
        if len(frame) < ip_offset + 4:
            raise _malformed(packet_index, "truncated VLAN header")
        ether_type = _unpack_u16(frame, ip_offset + 2)
        ip_offset += 4

    if ether_type != ETHERTYPE_IPV4:
        return None
    return _parse_ipv4(frame, ip_offset, packet_index, timestamp_ns)


def _parse_ipv4(
    frame: bytes, ip_offset: int, packet_index: int, timestamp_ns: int
) -> PacketRecord | None:
    if len(frame) < ip_offset + 20:
        raise _malformed(packet_index, "truncated IPv4 header")

    version_ihl = frame[ip_offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4:
        raise _malformed(packet_index, f"invalid IPv4 version {version}")
    if ihl < 20:
        raise _malformed(packet_index, f"invalid IPv4 header length {ihl}")
    if len(frame) < ip_offset + ihl:
        raise _malformed(packet_index, "truncated IPv4 options")

    total_length = _unpack_u16(frame, ip_offset + 2)
    if total_length < ihl:
        raise _malformed(
            packet_index,
            f"IPv4 total length {total_length} is smaller than header length {ihl}",
        )
    if len(frame) < ip_offset + total_length:
        raise _malformed(
            packet_index,
            f"captured IPv4 data is truncated: need {total_length} bytes, "
            f"have {len(frame) - ip_offset}",
        )

    flags_fragment = _unpack_u16(frame, ip_offset + 6)
    more_fragments = bool(flags_fragment & 0x2000)
    fragment_offset = flags_fragment & 0x1FFF
    if more_fragments or fragment_offset:
        raise _malformed(packet_index, "fragmented IPv4 packets are unsupported")

    protocol_number = frame[ip_offset + 9]
    try:
        protocol = IPProtocol(protocol_number)
    except ValueError:
        return None

    src_ip = socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16])
    dst_ip = socket.inet_ntoa(frame[ip_offset + 16 : ip_offset + 20])
    transport_offset = ip_offset + ihl
    transport_length = total_length - ihl

    common = {
        "packet_index": packet_index,
        "timestamp_ns": timestamp_ns,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "ip_total_length": total_length,
    }

    if protocol is IPProtocol.TCP:
        if transport_length < 20:
            raise _malformed(packet_index, "truncated TCP header")
        tcp_header_length = (frame[transport_offset + 12] >> 4) * 4
        if tcp_header_length < 20 or tcp_header_length > transport_length:
            raise _malformed(
                packet_index, f"invalid TCP header length {tcp_header_length}"
            )
        return PacketRecord(
            **common,
            src_port=_unpack_u16(frame, transport_offset),
            dst_port=_unpack_u16(frame, transport_offset + 2),
            tcp_flags=frame[transport_offset + 13],
        )

    if protocol is IPProtocol.UDP:
        if transport_length < 8:
            raise _malformed(packet_index, "truncated UDP header")
        udp_length = _unpack_u16(frame, transport_offset + 4)
        if udp_length < 8 or udp_length > transport_length:
            raise _malformed(packet_index, f"invalid UDP length {udp_length}")
        return PacketRecord(
            **common,
            src_port=_unpack_u16(frame, transport_offset),
            dst_port=_unpack_u16(frame, transport_offset + 2),
        )

    if transport_length < 8:
        raise _malformed(packet_index, "truncated ICMP header")
    icmp_type = frame[transport_offset]
    has_echo_fields = icmp_type in {0, 8}  # 0: echo reply; 8: echo request
    return PacketRecord(
        **common,
        icmp_type=icmp_type,
        icmp_code=frame[transport_offset + 1],
        icmp_identifier=(
            _unpack_u16(frame, transport_offset + 4) if has_echo_fields else None
        ),
        icmp_sequence=(
            _unpack_u16(frame, transport_offset + 6) if has_echo_fields else None
        ),
    )


def _unpack_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("!H", data, offset)[0]


def _malformed(packet_index: int, reason: str) -> MalformedPacketError:
    return MalformedPacketError(f"packet {packet_index}: {reason}")
