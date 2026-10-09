# Hybrid IDS Laboratory

This repository contains the reproducible part of a bachelor's thesis laboratory for hybrid intrusion detection and controlled SDN response. The laboratory combines Snort 3 signature detection, an offline Isolation Forest pipeline, observability services, operator notification, and optional traffic blocking through Floodlight.

The original EVE-NG virtual disk is intentionally excluded. It is roughly 50 GB, contains redistributable and non-redistributable machine images, and may contain machine-specific state. Evaluators can reconstruct the laboratory from the topology description, exported EVE-NG lab file, configuration, and source code stored here.

> Safety: the default configuration uses `REACT_DRY_RUN=true`. Keep it enabled until the controller address, switch DPID, managed CIDR, and effects of the generated OpenFlow rules have been verified in an isolated laboratory.

## Architecture

The laboratory has two networks:

- `10.10.0.0/24` carries experiment traffic between Kali (`10.10.0.2`) and Debian (`10.10.0.3`). The IDS sensor observes a mirrored copy on `ens3` (`10.10.0.4`).
- `192.168.122.0/24` is the management network. Floodlight is `192.168.122.10`; Kali, Debian, and the IDS host are `.11`, `.12`, and `.13` respectively.

See [the architecture document](docs/architecture.md) for the topology diagram, trust boundaries, and component flow.

## Repository contents

| Path | Purpose |
| --- | --- |
| `topology/` | EVE-NG export location, node/address manifest, and required-image manifest |
| `docs/reproduction.md` | End-to-end reconstruction and verification procedure |
| `compose.yml` | IDS host application and observability stack |
| `snort/` | Snort container integration, reload agent, custom configuration, and local rules |
| `flask/` | Rule-management API and Floodlight response endpoints |
| `reaction-service/` | Alert filtering, notification, and response state machine |
| `reaction_common/` | Shared persistent reaction-state implementation |
| `ids-ml/` | Deterministic packet-to-flow pipeline, datasets, models, and tests |
| `switch/` | Interactive Open vSwitch/Floodlight configuration helper |
| `grafana/` | Grafana dashboards and Loki/Alloy configuration |
| `prometheus/` | Prometheus scrape configuration |

## Quick start

The full network experiment requires EVE-NG and the nodes listed in [`topology/images.csv`](topology/images.csv). For a detailed setup, follow [`docs/reproduction.md`](docs/reproduction.md).

On the Debian 12 IDS node:

```bash
git clone <repository-url> hybrid-ids-lab
cd hybrid-ids-lab
cp .env.example .env
```

Edit `.env`, leaving `REACT_DRY_RUN=true`, then create the Snort-agent environment:

```bash
cp snort/agent/.env.example snort/agent/.env
docker compose config
docker compose up --build -d
```

If the Docker installation uses the legacy standalone client, replace `docker compose` with `docker-compose`.

The main local endpoints are:

| Service | URL |
| --- | --- |
| Rule API | `http://192.168.122.13:5000/health` |
| Grafana | `http://192.168.122.13:3000` |
| Prometheus | `http://192.168.122.13:9090` |
| Loki | `http://192.168.122.13:3100` |

## Tests

Run the application tests from the repository root:

```bash
python -m venv /tmp/ids-app-venv
/tmp/ids-app-venv/bin/pip install -r flask/requirements.txt pytest==9.1.1
PYTHONPATH=.:flask/src:reaction-service \
  /tmp/ids-app-venv/bin/pytest flask/tests reaction-service/tests
```

Run the ML pipeline tests in an isolated environment:

```bash
python -m venv /tmp/ids-ml-venv
/tmp/ids-ml-venv/bin/pip install -e './ids-ml[dev]'
cd ids-ml
/tmp/ids-ml-venv/bin/pytest tests
```

## Data and generated artifacts

The versioned PCAPs, derived datasets, trained models, and evaluation manifests are included because they support repeatable thesis results. They contain traffic generated inside the isolated `10.10.0.0/24` laboratory. Review them before using the repository in another disclosure context.

Runtime databases, replay output, virtual environments, compiled Snort files, VM images, and secret-bearing `.env` files are excluded by `.gitignore`.

## Known limitations

- The EVE-NG lab export and exact VM-image versions must be added to `topology/` before declaring the reconstruction package complete.
- Some container images currently use moving tags. Record the tested image digests in `topology/images.csv` after the first successful reconstruction.
- The programmatic Floodlight path has automated tests, but a successful test does not by itself prove that a real switch applied the rule. Use the verification steps in the reproduction guide.
- Email delivery requires evaluator-supplied SMTP credentials; no credentials are committed.

## Licensing

No license has been selected yet. Until a `LICENSE` file is added, copyright law reserves reuse rights to the author. Third-party software and VM images retain their own licenses and are not redistributed here.
