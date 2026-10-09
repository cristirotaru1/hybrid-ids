"""Tests for deterministic version 2 dataset export and column roles."""

import csv
import hashlib
import json
from pathlib import Path

from ids_ml.dataset_v2 import DATASET_COLUMNS_V2, export_dataset_v2

NORMAL_CAPTURE_MANIFEST = Path("pcaps/manifest.csv")
EVALUATION_CAPTURE_MANIFEST = Path("evaluation_manifests_v1/manifest.csv")
V1_DATASET = Path("data/derived/flows_v1.csv")
NORMAL_V3_FIT_MANIFEST = Path("pcaps/normal_v3/manifest_fit.csv")
NORMAL_V3_CALIBRATION_MANIFEST = Path("pcaps/normal_v3/manifest_calibration.csv")


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_exports_normal_schema_v2_with_explicit_column_roles(tmp_path: Path) -> None:
    result = export_dataset_v2(NORMAL_CAPTURE_MANIFEST, tmp_path)

    assert result.row_count == 114
    assert result.capture_count == 14
    assert result.empty_capture_ids == ("normal_001_idle", "normal_v2_010")
    with result.dataset_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        assert tuple(reader.fieldnames or ()) == DATASET_COLUMNS_V2
    assert {row["schema_version"] for row in rows} == {"2"}

    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["dataset_schema_version"] == 2
    assert manifest["flow_feature_schema_version"] == 2
    assert manifest["source_history_schema_version"] == 2
    assert manifest["dataset_sha256"] == _sha256(result.dataset_path)
    assert manifest["columns"]["context_only"] == ["src_port"]
    assert manifest["columns"]["protocol_routing"] == ["protocol"]
    assert manifest["columns"]["redundant_excluded"] == [
        "total_packet_count",
        "total_bytes",
    ]
    assert manifest["columns"]["behavioral_additions_by_protocol"]["tcp"] == [
        "syn_count",
        "ack_count",
        "fin_count",
    ]

    assigned = set(manifest["columns"]["context_only"])
    assigned.update(manifest["columns"]["protocol_routing"])
    assigned.update(manifest["columns"]["behavioral_common"])
    assigned.update(manifest["columns"]["novelty_policy_inputs"])
    assigned.update(manifest["columns"]["redundant_excluded"])
    for additions in manifest["columns"]["behavioral_additions_by_protocol"].values():
        assigned.update(additions)
    assert assigned == set(manifest["columns"]["exported_features"])


def test_preserves_every_shared_version_one_value(tmp_path: Path) -> None:
    result = export_dataset_v2(NORMAL_CAPTURE_MANIFEST, tmp_path)
    v1_rows = {row["flow_id"]: row for row in _rows(V1_DATASET)}
    v2_rows = {row["flow_id"]: row for row in _rows(result.dataset_path)}
    shared_columns = set(next(iter(v1_rows.values()))) & set(
        next(iter(v2_rows.values()))
    )
    shared_columns -= {"schema_version", "extractor_version"}

    assert v1_rows.keys() == v2_rows.keys()
    for flow_id in v1_rows:
        assert {column: v2_rows[flow_id][column] for column in shared_columns} == {
            column: v1_rows[flow_id][column] for column in shared_columns
        }


def test_exports_expected_evaluation_novelty_signals(tmp_path: Path) -> None:
    result = export_dataset_v2(EVALUATION_CAPTURE_MANIFEST, tmp_path)
    rows = _rows(result.dataset_path)

    assert result.row_count == 200
    refused = [row for row in rows if row["capture_id"] == "evaluation_v1_002"]
    assert len(refused) == 20
    assert {row["current_tcp_failed"] for row in refused} == {"1"}
    assert max(int(row["same_protocol_flows_last_10s"]) for row in refused) == 19
    assert max(int(row["tcp_attempts_last_10s"]) for row in refused) == 19
    assert max(int(row["failed_tcp_connections_last_10s"]) for row in refused) == 19

    rapid_icmp = [row for row in rows if row["capture_id"] == "evaluation_v1_004"]
    assert max(int(row["same_protocol_flows_last_10s"]) for row in rapid_icmp) == 59
    assert {
        (row["icmp_type_group"], row["icmp_code"], row["icmp_is_error"])
        for row in rapid_icmp
    } == {("8", "0", "0")}

    operational_icmp_errors = [
        row
        for row in rows
        if row["capture_id"] == "operational_v1_001_udp_closed"
        and row["protocol"] == "1"
    ]
    assert len(operational_icmp_errors) == 10
    assert {
        (row["icmp_type_group"], row["icmp_code"], row["icmp_is_error"])
        for row in operational_icmp_errors
    } == {("3", "3", "1")}


def test_schema_v2_export_is_byte_deterministic(tmp_path: Path) -> None:
    first = export_dataset_v2(NORMAL_CAPTURE_MANIFEST, tmp_path / "first")
    second = export_dataset_v2(NORMAL_CAPTURE_MANIFEST, tmp_path / "second")

    assert first.dataset_path.read_bytes() == second.dataset_path.read_bytes()
    assert first.manifest_path.read_bytes() == second.manifest_path.read_bytes()


def test_normal_v3_exports_match_independently_validated_flow_totals(
    tmp_path: Path,
) -> None:
    fit = export_dataset_v2(NORMAL_V3_FIT_MANIFEST, tmp_path / "fit")
    calibration = export_dataset_v2(
        NORMAL_V3_CALIBRATION_MANIFEST, tmp_path / "calibration"
    )
    fit_rows = _rows(fit.dataset_path)
    calibration_rows = _rows(calibration.dataset_path)

    assert fit.row_count == 377
    assert calibration.row_count == 300
    assert {
        protocol: sum(row["protocol"] == protocol for row in fit_rows)
        for protocol in ("1", "6", "17")
    } == {"1": 125, "6": 127, "17": 125}
    assert {
        protocol: sum(row["protocol"] == protocol for row in calibration_rows)
        for protocol in ("1", "6", "17")
    } == {"1": 100, "6": 100, "17": 100}
    assert sum(int(row["current_tcp_failed"]) for row in fit_rows) == 2
    assert sum(int(row["current_tcp_failed"]) for row in calibration_rows) == 2

    expected_services = {
        ("1", "0"),
        ("6", "22"),
        ("6", "8080"),
        ("6", "65000"),
        ("17", "9999"),
        ("17", "10000"),
    }
    assert {(row["protocol"], row["dst_port"]) for row in fit_rows} == (
        expected_services
    )
    assert {(row["protocol"], row["dst_port"]) for row in calibration_rows} == (
        expected_services
    )
