"""Tests for scoring independent datasets with a frozen model."""

import json
from pathlib import Path

import pytest

from ids_ml.dataset import export_dataset
from ids_ml.scoring import DatasetScoringError, score_dataset

EVALUATION_CAPTURE_MANIFEST = Path("evaluation_manifests_v1/operational_manifest.csv")
MODEL = Path("artifacts/isolation_forest_v1/model.joblib")
MODEL_MANIFEST = Path("artifacts/isolation_forest_v1/model_manifest.json")
FULL_EVALUATION_CAPTURE_MANIFEST = Path("evaluation_manifests_v1/manifest.csv")


def _export_and_score(tmp_path: Path):
    exported = export_dataset(EVALUATION_CAPTURE_MANIFEST, tmp_path / "dataset")
    return score_dataset(
        exported.dataset_path,
        exported.manifest_path,
        MODEL,
        MODEL_MANIFEST,
        tmp_path / "scores",
    )


def test_scores_preserved_closed_udp_scenario_without_retraining(
    tmp_path: Path,
) -> None:
    result = _export_and_score(tmp_path)

    assert result.row_count == 20
    assert result.flagged_count == 0
    assert result.provisional_anomaly_threshold == pytest.approx(0.6987829279266998)
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    capture = report["captures"]["operational_v1_001_udp_closed"]
    assert capture["scenario_id"] == "udp_closed_service"
    assert capture["label"] == "operational_anomaly"
    assert capture["row_count"] == 20
    assert capture["provisional_flagged_count"] == 0
    assert capture["anomaly_score_maximum"] == pytest.approx(0.5546724510077553)


def test_independent_scoring_is_byte_deterministic(tmp_path: Path) -> None:
    first = _export_and_score(tmp_path / "first")
    second = _export_and_score(tmp_path / "second")

    assert first.scores_path.read_bytes() == second.scores_path.read_bytes()
    assert first.report_path.read_bytes() == second.report_path.read_bytes()


def test_rejects_model_that_does_not_match_manifest(tmp_path: Path) -> None:
    exported = export_dataset(EVALUATION_CAPTURE_MANIFEST, tmp_path / "dataset")
    changed_model = tmp_path / "model.joblib"
    changed_model.write_bytes(MODEL.read_bytes() + b"changed")

    with pytest.raises(DatasetScoringError, match="model SHA-256"):
        score_dataset(
            exported.dataset_path,
            exported.manifest_path,
            changed_model,
            MODEL_MANIFEST,
            tmp_path / "scores",
        )


def test_scores_complete_campaign_with_frozen_threshold(tmp_path: Path) -> None:
    exported = export_dataset(FULL_EVALUATION_CAPTURE_MANIFEST, tmp_path / "dataset")
    result = score_dataset(
        exported.dataset_path,
        exported.manifest_path,
        MODEL,
        MODEL_MANIFEST,
        tmp_path / "scores",
    )

    assert result.row_count == 200
    assert result.flagged_count == 2
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert report["label_counts"] == {
        "anomalous_evaluation": 150,
        "normal": 30,
        "operational_anomaly": 20,
    }
    assert report["captures"]["evaluation_v1_001"]["provisional_flagged_count"] == 2
    assert all(
        report["captures"][capture_id]["provisional_flagged_count"] == 0
        for capture_id in (
            "evaluation_v1_002",
            "evaluation_v1_003",
            "evaluation_v1_004",
            "evaluation_v1_005",
            "operational_v1_001_udp_closed",
        )
    )
