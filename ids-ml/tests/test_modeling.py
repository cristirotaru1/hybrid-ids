"""Tests for the frozen normal-only Isolation Forest workflow."""

import csv
import json
import warnings
from pathlib import Path

import joblib
import pytest

from ids_ml.modeling import ModelDevelopmentError, train_isolation_forest

DATASET = Path("data/derived/flows_v1.csv")
DATASET_MANIFEST = Path("data/derived/manifest_v1.json")


def test_trains_with_capture_split_and_records_contract(tmp_path: Path) -> None:
    result = train_isolation_forest(DATASET, DATASET_MANIFEST, tmp_path)

    assert result.train_row_count == 75
    assert result.validation_row_count == 30
    assert result.legacy_evaluation_row_count == 9
    assert result.provisional_anomaly_threshold == pytest.approx(0.6987829279266998)

    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["split"]["method"] == "capture-based; no random row split"
    assert manifest["split"]["train_capture_ids"] == [
        "normal_v2_002",
        "normal_v2_003",
        "normal_v2_005",
        "normal_v2_006",
        "normal_v2_007",
        "normal_v2_008",
    ]
    assert manifest["preprocessing"]["model_features_excluded"] == [
        "total_packet_count",
        "total_bytes",
        "src_port",
    ]
    assert manifest["preprocessing"][
        "constant_numeric_features_dropped_from_training"
    ] == ["rst_count", "failed_connection_rate_last_10s"]
    assert "src_ip" not in manifest["preprocessing"]["transformed_feature_names"]
    assert "src_port" not in manifest["preprocessing"]["transformed_feature_names"]
    assert "protocol_tcp" in manifest["preprocessing"]["transformed_feature_names"]
    assert "dst_port_other" in manifest["preprocessing"]["transformed_feature_names"]

    # Ignore a joblib 1.5.3 serialization warning triggered by NumPy 2.5.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Setting the shape on a NumPy array has been deprecated.*",
            category=DeprecationWarning,
        )
        bundle = joblib.load(result.model_path)
    assert bundle["estimator"].random_state == 42
    assert tuple(bundle["transformed_feature_names"]) == tuple(
        manifest["preprocessing"]["transformed_feature_names"]
    )


def test_scores_all_nonempty_normal_rows_and_marks_provisional_flags(
    tmp_path: Path,
) -> None:
    result = train_isolation_forest(DATASET, DATASET_MANIFEST, tmp_path)
    with result.scores_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 114
    split_counts = {
        split: sum(row["split"] == split for row in rows)
        for split in {row["split"] for row in rows}
    }
    assert split_counts == {
        "train": 75,
        "normal_validation": 30,
        "legacy_normal_evaluation": 9,
    }
    flagged = [row for row in rows if row["provisional_anomaly_flag"] == "true"]
    assert len(flagged) == 2
    assert {row["split"] for row in flagged} == {"normal_validation"}


def test_fixed_seed_produces_identical_scores_and_model(tmp_path: Path) -> None:
    first = train_isolation_forest(DATASET, DATASET_MANIFEST, tmp_path / "first")
    second = train_isolation_forest(DATASET, DATASET_MANIFEST, tmp_path / "second")

    assert first.scores_path.read_bytes() == second.scores_path.read_bytes()
    assert first.model_path.read_bytes() == second.model_path.read_bytes()
    assert first.manifest_path.read_bytes() == second.manifest_path.read_bytes()


def test_rejects_dataset_outside_frozen_version_one_contract(tmp_path: Path) -> None:
    changed_dataset = tmp_path / "flows_v1.csv"
    changed_dataset.write_bytes(DATASET.read_bytes() + b"\n")

    with pytest.raises(ModelDevelopmentError, match="frozen model version 1"):
        train_isolation_forest(changed_dataset, DATASET_MANIFEST, tmp_path / "model")
