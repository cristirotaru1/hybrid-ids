# Model-evaluation campaign V1

This campaign is reserved for evaluation. It contains one normal control and
four bounded behaviors designed to be unusual relative to the normal baseline.
An anomalous label does not prove that a capture contains an attack.

- `evaluation_v1_001_normal_control.pcap`: mixed normal TCP, UDP, and ICMP control.
- `evaluation_v1_002_tcp_refused_burst.pcap`: rapid TCP attempts to a closed port.
- `evaluation_v1_003_udp_burst.pcap`: rapid UDP request/reply flows.
- `evaluation_v1_004_icmp_rapid.pcap`: rapid ICMP echo processes.
- `evaluation_v1_005_tcp_port_fanout.pcap`: TCP attempts across ten destination ports.
