# Normal protocol-timing campaign V2

This campaign explores how separate TCP, UDP, and ICMP flows behave when they
are spaced apart or generated in short bursts.

- `normal_v2_001_tcp_spaced.pcap`: preliminary spaced TCP connections (warning).
- `normal_v2_002_tcp_spaced.pcap`: accepted spaced TCP connections.
- `normal_v2_003_tcp_burst.pcap`: accepted burst of TCP connections.
- `normal_v2_004_udp_spaced.pcap`: failed spaced UDP attempt with no replies.
- `normal_v2_005_udp_spaced_retry.pcap`: accepted retry with spaced UDP exchanges.
- `normal_v2_006_udp_burst.pcap`: accepted burst of UDP exchanges.
- `normal_v2_007_icmp_spaced.pcap`: accepted spaced ICMP echo exchanges.
- `normal_v2_008_icmp_burst.pcap`: accepted burst of ICMP echo exchanges.
- `normal_v2_009_mixed_burst.pcap`: accepted mixed TCP, UDP, and ICMP burst.
- `normal_v2_010_background.pcap`: empty background capture retained as evidence.
