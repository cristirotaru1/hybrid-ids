"""Tests for deterministic exported-dataset quality inspection."""

import json
from pathlib import Path

import pytest

from ids_ml.quality import DataQualityError, analyze_dataset

DATASET = Path("data/derived/flows_v1.csv")
MANIFEST = Path("data/derived/manifest_v1.json")


def test_reports_current_dataset_quality_observations() -> None:
    report = analyze_dataset(DATASET, MANIFEST)

    assert report["row_count"] == 114
    assert report["model_feature_count"] == 25
    assert report["errors"] == []
    assert report["label_counts"] == {"normal": 114}
    assert report["protocol_counts"] == {"1": 40, "17": 37, "6": 37}
    assert report["duplicate_flow_ids"] == []
    assert report["duplicate_model_row_count"] == 0
    assert "rst_count" in report["constant_features"]
    assert "flows_last_10s" not in report["constant_features"]
    assert report["exact_relationships"] == {
        "total_bytes_equals_forward_plus_backward": True,
        "total_packet_count_equals_forward_plus_backward": True,
    }
    assert not report["ready_for_model_training"]
    warning_codes = {finding["code"] for finding in report["warnings"]}
    assert "single_label" in warning_codes
    assert "small_dataset" not in warning_codes
    assert "no_history_signal" not in warning_codes


def test_written_report_is_byte_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    analyze_dataset(DATASET, MANIFEST, first)
    analyze_dataset(DATASET, MANIFEST, second)

    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text(encoding="utf-8"))["row_count"] == 114


def test_rejects_dataset_that_no_longer_matches_manifest(tmp_path: Path) -> None:
    changed = tmp_path / "changed.csv"
    changed.write_bytes(DATASET.read_bytes() + b"\n")

    with pytest.raises(DataQualityError, match="SHA-256"):
        analyze_dataset(changed, MANIFEST)
