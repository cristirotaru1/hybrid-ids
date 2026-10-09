# Laboratory architecture

## Network topology

```mermaid
flowchart TB
    MGMT["Management network<br/>192.168.122.0/24"]
    FL["Floodlight controller<br/>192.168.122.10<br/>OpenFlow: 6653 / REST: 8080"]
    K["Kali traffic generator<br/>data: 10.10.0.2<br/>management: 192.168.122.11"]
    D["Debian target<br/>data: 10.10.0.3<br/>management: 192.168.122.12"]
    OVS["Open vSwitch<br/>OpenFlow 1.3<br/>DPID: 0000005000000401"]
    IDS["Debian 12 IDS host<br/>sensor ens3: 10.10.0.4<br/>management ens4: 192.168.122.13"]

    K ---|experiment traffic| OVS
    OVS ---|experiment traffic| D
    OVS -. mirrored traffic .-> IDS
    FL -->|OpenFlow control| OVS

    MGMT --- FL
    MGMT --- K
    MGMT --- D
    MGMT --- IDS
```

The IDS interface must receive an actual mirrored copy from the switch. Promiscuous mode alone does not make traffic between Kali and Debian visible.

## Application flow

```mermaid
flowchart LR
    TRAFFIC[Mirrored traffic] --> SNORT[Snort 3]
    SNORT --> ALERTS[JSON alerts]
    ALERTS --> REACTION[Reaction service]
    REACTION --> EMAIL[Operator email]
    EMAIL --> CONFIRM[Signed confirmation link]
    CONFIRM --> API[Flask rule API]
    API -->|dry run or verified REST call| FLOODLIGHT[Floodlight]
    FLOODLIGHT --> OVS[Open vSwitch]

    SNORT --> EXPORTER[Performance exporter]
    ALERTS --> ALLOY[Grafana Alloy]
    EXPORTER --> PROM[Prometheus]
    ALLOY --> LOKI[Loki]
    PROM --> GRAFANA[Grafana]
    LOKI --> GRAFANA
```

The Flask API also validates Snort rules through the local Snort agent before replacing the active ruleset and requesting a reload. Reaction state is stored in SQLite on the IDS host.

## Trust and safety boundaries

- The data network is an isolated experiment network. Do not bridge it directly to a production network.
- The management network carries the Floodlight REST calls, dashboards, confirmation links, and administrative traffic.
- `REACT_DRY_RUN=true` prevents the application from opening the Floodlight connection while still exercising rule construction.
- The controller-facing interface must not be added as an OVS data port.
- The repository contains no passwords, tokens, private keys, or full VM disks.
