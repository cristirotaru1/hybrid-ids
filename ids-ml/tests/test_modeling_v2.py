"""Tests for protocol-specific model-v2 behavioral fitting."""

import csv
import json
import warnings
from pathlib import Path

import joblib
import pytest

from ids_ml.modeling_v2 import (
    ModelV2DevelopmentError,
    train_protocol_isolation_forests,
)

FIT_DATASET = Path("data/derived/v2/model_v2_fit/flows_v2.csv")
FIT_MANIFEST = Path("data/derived/v2/model_v2_fit/manifest_v2.json")
CALIBRATION_DATASET = Path("data/derived/v2/normal_v3_calibration/flows_v2.csv")
CALIBRATION_MANIFEST = Path("data/derived/v2/normal_v3_calibration/manifest_v2.json")


def _train(output: Path):
    return train_protocol_isolation_forests(
        FIT_DATASET,
        FIT_MANIFEST,
        CALIBRATION_DATASET,
        CALIBRATION_MANIFEST,
        output,
    )


def test_trains_three_protocol_models_with_capture_frozen_partitions(
    tmp_path: Path,
) -> None:
    result = _train(tmp_path)

    assert result.fit_row_counts == {"icmp": 150, "tcp": 152, "udp": 150}
    assert result.calibration_row_counts == {
        "icmp": 100,
        "tcp": 100,
        "udp": 100,
    }
    assert set(result.thresholds) == {"icmp", "tcp", "udp"}

    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["split"]["method"] == "capture-based; no random row split"
    assert not set(manifest["split"]["fit_capture_ids"]) & set(
        manifest["split"]["calibration_capture_ids"]
    )
    assert manifest["known_destination_services"]["services_by_protocol"] == {
        "tcp": [22, 8080, 65000],
        "udp": [9999, 10000],
    }
    assert manifest["known_destination_services"][
        "normal_failed_tcp_ports_included"
    ] == [65000]
    assert manifest["protocol_models"]["tcp"]["protocol_number"] == 6
    assert "syn_count" in manifest["protocol_models"]["tcp"]["learned_features"]
    assert (
        "syn_count"
        not in manifest["protocol_models"]["udp"]["behavioral_candidate_features"]
    )

    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Setting the shape on a NumPy array has been deprecated.*",
            category=DeprecationWarning,
        )
        bundle = joblib.load(result.model_path)
    assert set(bundle["protocol_models"]) == {"icmp", "tcp", "udp"}
    assert all(
        protocol_bundle["estimator"].random_state == 42
        for protocol_bundle in bundle["protocol_models"].values()
    )


def test_scores_every_fit_and_calibration_row_with_protocol_threshold(
    tmp_path: Path,
) -> None:
    result = _train(tmp_path)
    with result.scores_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 752
    assert sum(row["split"] == "fit" for row in rows) == 452
    assert sum(row["split"] == "calibration" for row in rows) == 300
    for protocol_name in ("icmp", "tcp", "udp"):
        calibration = [
            row
            for row in rows
            if row["split"] == "calibration" and row["protocol_name"] == protocol_name
        ]
        flagged = [
            row for row in calibration if row["behavioral_anomaly_flag"] == "true"
        ]
        assert len(calibration) == 100
        assert 0 <= len(flagged) <= 5
        calibration_thresholds = {
            float(row["protocol_threshold"]) for row in calibration
        }
        assert len(calibration_thresholds) == 1
        assert calibration_thresholds.pop() == pytest.approx(
            result.thresholds[protocol_name]
        )


def test_fixed_seed_produces_byte_identical_artifacts(tmp_path: Path) -> None:
    first = _train(tmp_path / "first")
    second = _train(tmp_path / "second")

    assert first.model_path.read_bytes() == second.model_path.read_bytes()
    assert first.scores_path.read_bytes() == second.scores_path.read_bytes()
    assert first.manifest_path.read_bytes() == second.manifest_path.read_bytes()


def test_rejects_overlapping_capture_partitions(tmp_path: Path) -> None:
    with pytest.raises(ModelV2DevelopmentError, match="capture IDs overlap"):
        train_protocol_isolation_forests(
            FIT_DATASET,
            FIT_MANIFEST,
            FIT_DATASET,
            FIT_MANIFEST,
            tmp_path,
        )


@pytest.mark.parametrize(
    ("profile", "excluded"),
    [
        ("current", set()),
        (
            "omit_udp_icmp_rates",
            {"packets_per_second", "bytes_per_second"},
        ),
        (
            "minimal_udp_icmp_timing",
            {"packets_per_second", "bytes_per_second", "inter_arrival_mean"},
        ),
    ],
)
def test_feature_profiles_apply_only_to_udp_and_icmp(
    tmp_path: Path, profile: str, excluded: set[str]
) -> None:
    result = train_protocol_isolation_forests(
        FIT_DATASET,
        FIT_MANIFEST,
        CALIBRATION_DATASET,
        CALIBRATION_MANIFEST,
        tmp_path,
        feature_profile=profile,
    )
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))

    assert manifest["feature_profile"]["name"] == profile
    for protocol in ("icmp", "udp"):
        contract = manifest["protocol_models"][protocol]
        assert set(contract["feature_profile_exclusions"]) == excluded
        assert excluded.isdisjoint(contract["behavioral_candidate_features"])
    assert manifest["protocol_models"]["tcp"]["feature_profile_exclusions"] == []
    assert {
        "packets_per_second",
        "bytes_per_second",
        "inter_arrival_mean",
    } <= set(manifest["protocol_models"]["tcp"]["behavioral_candidate_features"])


def test_rejects_unknown_feature_profile(tmp_path: Path) -> None:
    with pytest.raises(ModelV2DevelopmentError, match="unknown feature profile"):
        train_protocol_isolation_forests(
            FIT_DATASET,
            FIT_MANIFEST,
            CALIBRATION_DATASET,
            CALIBRATION_MANIFEST,
            tmp_path,
            feature_profile="not-a-profile",
        )
