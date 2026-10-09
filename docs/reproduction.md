# Reproducing the EVE-NG laboratory

This procedure rebuilds the laboratory without the original EVE-NG virtual disk. Perform all attack and blocking experiments only in an isolated environment you own or are authorized to test.

## 1. Prerequisites

Prepare a host capable of running EVE-NG with nested virtualization and enough capacity for five nodes:

- EVE-NG Community or Professional edition;
- one Kali Linux traffic-generator VM;
- one Debian target VM;
- one Debian 12 IDS VM with two interfaces and Docker Engine;
- one Linux VM for Open vSwitch;
- one VM for the Floodlight controller.

The tested image filenames, versions, resources, and checksums belong in [`../topology/images.csv`](../topology/images.csv). Obtain every image from its official project or vendor source and follow its license.

## 2. Import the EVE-NG topology

Import the `.unl` or EVE-NG lab archive stored beside [`../topology/README.md`](../topology/README.md). If the export has not yet been added, create the five nodes and links using the diagram in [`architecture.md`](architecture.md) and the interface map in [`../topology/nodes.csv`](../topology/nodes.csv).

Do not add any `.qcow2` disk to this Git repository. EVE-NG node image folders must use the names recorded in the image manifest so the imported lab can resolve its templates.

## 3. Configure addressing

Use the following plan, adapting interface names only when the imported guest uses different predictable names:

| Node | Data/experiment interface | Management interface |
| --- | --- | --- |
| Kali | `10.10.0.2/24` | `192.168.122.11/24` |
| Debian target | `10.10.0.3/24` | `192.168.122.12/24` |
| IDS | `10.10.0.4/24` on `ens3` | `192.168.122.13/24` on `ens4` |
| Floodlight | controller link `10.0.0.1` | `192.168.122.10/24` |

The IDS data interface is a passive monitoring endpoint. Its essential property is receiving mirrored traffic from the Kali/Debian switch ports.

## 4. Configure Floodlight and Open vSwitch

Start Floodlight with the Static Entry Pusher service and OpenFlow 1.3 support. On the switch VM, run:

```bash
sudo ./switch/configure_ovs_floodlight.sh
```

Supply the controller address, controller-facing interface, data interfaces, and requested OpenFlow port numbers. Verify:

```bash
sudo ovs-vsctl show
sudo ovs-ofctl -O OpenFlow13 show br0
```

Record the resulting DPID in `.env`. The thesis laboratory used `0000005000000401`, but a reconstructed bridge may receive a different value.

Configure port mirroring so traffic between the Kali and Debian ports is copied to the IDS-facing port. The exact OVS command depends on the interface names assigned by EVE-NG. Confirm mirroring with `tcpdump` on the IDS before starting application tests.

## 5. Prepare the IDS host

Install Docker Engine with Compose support on Debian 12, clone this repository, and create local configuration files:

```bash
cp .env.example .env
cp snort/agent/.env.example snort/agent/.env
```

Review every value in both files. Keep these settings initially:

```dotenv
REACT_DRY_RUN=true
SWITCH_CIDR=10.10.0.0/24
SNORT_IFACE=ens3
```

SMTP settings are optional for service startup only if the reaction-service workflow is not exercised. Never commit the populated files.

## 6. Start the stack

Validate and start the Compose application:

```bash
docker compose config
docker compose up --build -d
docker compose ps
```

Inspect unhealthy services before continuing:

```bash
docker compose logs --tail=200 snort flask reaction
```

## 7. Import dashboards

Open Grafana at `http://192.168.122.13:3000` and import:

- `grafana/dashboard.json` for Snort health and performance;
- `grafana/ml-dashboard.json` for ML replay output.

Configure the Prometheus and Loki data sources to point to the Compose service names `prometheus:9090` and `loki:3100` from inside the Docker network.

## 8. Verify the reconstruction

Complete these checks in order:

1. From the IDS host, reach Floodlight's REST endpoint on `192.168.122.10:8080`.
2. Confirm Floodlight reports the expected switch DPID.
3. Generate an ICMP exchange and an authorized TCP/UDP test between Kali and Debian.
4. Confirm `tcpdump -ni ens3` on the IDS observes both directions even though neither endpoint is the IDS.
5. Confirm the Snort agent health endpoint and Flask `/health` endpoint return success.
6. Confirm Prometheus targets are healthy and logs appear in Loki/Grafana.
7. Run the automated tests described in the root README.
8. Exercise a confirmation in dry-run mode and verify that no OpenFlow entry is installed.
9. Only after reviewing the generated source/destination matches, set `REACT_DRY_RUN=false` for an isolated live test.
10. Query Floodlight independently and verify both directional DROP entries. Then verify the test traffic is blocked and can be restored.

Record the date, repository commit, container image digests, EVE-NG version, guest-image checksums, DPID, and observed result. This distinguishes a repeatable reconstruction from a source-code-only test.

## 9. Reproduce the ML results

The repository includes the laboratory PCAPs, manifests, derived datasets, model artifacts, and evaluation scores. Install the package and run its tests:

```bash
python -m venv /tmp/ids-ml-venv
/tmp/ids-ml-venv/bin/pip install -e './ids-ml[dev]'
cd ids-ml
/tmp/ids-ml-venv/bin/pytest tests
```

The CLI entry points defined in `ids-ml/pyproject.toml` cover dataset export, quality checks, training, scoring, and replay. Use the versioned manifests rather than mixing captures or artifacts across campaigns.
