"""Tests for frozen behavioral and hybrid model-v2 scoring."""

import csv
import json
from pathlib import Path

from ids_ml.scoring_v2 import score_dataset_v2

MODEL = Path("artifacts/isolation_forest_v2_behavioral/models.joblib")
MODEL_MANIFEST = Path("artifacts/isolation_forest_v2_behavioral/model_manifest.json")
CALIBRATION_DATASET = Path("data/derived/v2/normal_v3_calibration/flows_v2.csv")
CALIBRATION_MANIFEST = Path("data/derived/v2/normal_v3_calibration/manifest_v2.json")
EVALUATION_DATASET = Path("data/evaluation/campaign_v1_v2/flows_v2.csv")
EVALUATION_MANIFEST = Path("data/evaluation/campaign_v1_v2/manifest_v2.json")


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_normal_calibration_has_no_semantic_novelty_beyond_behavioral_flags(
    tmp_path: Path,
) -> None:
    result = score_dataset_v2(
        CALIBRATION_DATASET,
        CALIBRATION_MANIFEST,
        MODEL,
        MODEL_MANIFEST,
        tmp_path,
    )
    rows = _rows(result.scores_path)

    assert result.row_count == 300
    assert result.behavioral_flagged_count == 15
    assert result.hybrid_flagged_count == 15
    assert {
        row["novelty_reason_codes"] for row in rows if row["novelty_reason_codes"]
    } == {"behavioral_score_high"}


def test_regression_campaign_gets_explainable_capture_level_flags(
    tmp_path: Path,
) -> None:
    result = score_dataset_v2(
        EVALUATION_DATASET,
        EVALUATION_MANIFEST,
        MODEL,
        MODEL_MANIFEST,
        tmp_path,
    )
    rows = _rows(result.scores_path)
    anomalous_rows = [row for row in rows if row["label"] != "normal"]

    assert result.row_count == 200
    assert result.behavioral_flagged_count == 165
    assert result.hybrid_flagged_count == 165
    anomalous_capture_ids = {row["capture_id"] for row in anomalous_rows}
    flagged_capture_ids = {
        row["capture_id"]
        for row in anomalous_rows
        if row["hybrid_anomaly_flag"] == "true"
    }
    assert flagged_capture_ids == anomalous_capture_ids

    refused = [row for row in rows if row["capture_id"] == "evaluation_v1_002"]
    assert (
        sum("tcp_failure_burst" in row["novelty_reason_codes"] for row in refused) == 19
    )
    assert all(
        "unseen_destination_service" not in row["novelty_reason_codes"]
        for row in refused
    )
    operational_icmp = [
        row
        for row in rows
        if row["capture_id"] == "operational_v1_001_udp_closed"
        and row["protocol"] == "1"
    ]
    assert all(
        "icmp_type_code_unseen" in row["novelty_reason_codes"]
        for row in operational_icmp
    )

    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["decision"]["meaning"].startswith(
        "flagged output denotes anomalous behavior"
    )


def test_scoring_is_byte_deterministic(tmp_path: Path) -> None:
    first = score_dataset_v2(
        EVALUATION_DATASET,
        EVALUATION_MANIFEST,
        MODEL,
        MODEL_MANIFEST,
        tmp_path / "first",
    )
    second = score_dataset_v2(
        EVALUATION_DATASET,
        EVALUATION_MANIFEST,
        MODEL,
        MODEL_MANIFEST,
        tmp_path / "second",
    )

    assert first.scores_path.read_bytes() == second.scores_path.read_bytes()
    assert first.manifest_path.read_bytes() == second.manifest_path.read_bytes()
