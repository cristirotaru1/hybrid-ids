"""Tests for terminal-triggered PCAP replay."""

import csv
import json
from pathlib import Path

import pytest

from ids_ml.replay import ReplayError, replay_capture

MANIFEST = Path("pcaps/model_v2_v5/manifest_normal_validation.csv")
MODEL = Path("artifacts/isolation_forest_v2_v5_candidate_a/models.joblib")
MODEL_MANIFEST = Path(
    "artifacts/isolation_forest_v2_v5_candidate_a/model_manifest.json"
)
EXPECTED_SCORES = Path(
    "artifacts/normal_validation_v5_candidate_a/evaluation_scores.csv"
)


def _expected_rows(capture_id: str) -> list[dict[str, str]]:
    with EXPECTED_SCORES.open(newline="", encoding="utf-8") as handle:
        return [
            row for row in csv.DictReader(handle) if row["capture_id"] == capture_id
        ]


def test_replay_matches_frozen_candidate_a_scores(tmp_path: Path) -> None:
    output = tmp_path / "replay.jsonl"
    count = replay_capture(
        MANIFEST,
        "normal_v5_val_001",
        MODEL,
        MODEL_MANIFEST,
        output,
    )
    events = [json.loads(line) for line in output.read_text().splitlines()]
    flow_events = [event for event in events if event["event_type"] == "flow_scored"]
    expected = _expected_rows("normal_v5_val_001")

    assert count == 75
    assert events[0]["event_type"] == "replay_started"
    assert events[-1]["event_type"] == "replay_completed"
    assert [event["flow_id"] for event in flow_events] == [
        row["flow_id"] for row in expected
    ]
    assert [event["anomaly_score"] for event in flow_events] == pytest.approx(
        [float(row["anomaly_score"]) for row in expected], abs=1e-15
    )
    assert [event["hybrid_anomaly_flag"] for event in flow_events] == [
        row["hybrid_anomaly_flag"] == "true" for row in expected
    ]
    assert {event["scenario_id"] for event in flow_events} == {"normal_v5_val_001"}
    assert all(
        event["source_pcap"].endswith("normal_v5_val_001.pcap") for event in flow_events
    )


def test_replay_rejects_unknown_capture(tmp_path: Path) -> None:
    with pytest.raises(ReplayError, match="must occur exactly once"):
        replay_capture(
            MANIFEST,
            "not_present",
            MODEL,
            MODEL_MANIFEST,
            tmp_path / "replay.jsonl",
        )


def test_replay_rejects_invalid_speed(tmp_path: Path) -> None:
    with pytest.raises(ReplayError, match="speed must be greater than zero"):
        replay_capture(
            MANIFEST,
            "normal_v5_val_001",
            MODEL,
            MODEL_MANIFEST,
            tmp_path / "replay.jsonl",
            speed=0,
        )


def test_replay_rotates_log_and_limits_backups(tmp_path: Path) -> None:
    output = tmp_path / "replay.jsonl"
    replay_capture(
        MANIFEST,
        "normal_v5_val_001",
        MODEL,
        MODEL_MANIFEST,
        output,
        max_log_bytes=1_000,
        log_backups=2,
    )

    assert output.exists()
    assert output.with_name("replay.jsonl.1").exists()
    assert output.with_name("replay.jsonl.2").exists()
    assert not output.with_name("replay.jsonl.3").exists()
    for path in (
        output,
        output.with_name("replay.jsonl.1"),
        output.with_name("replay.jsonl.2"),
    ):
        for line in path.read_text(encoding="utf-8").splitlines():
            assert json.loads(line)["event_type"]


@pytest.mark.parametrize(
    ("max_log_bytes", "log_backups", "message"),
    [(0, 5, "maximum log size"), (1_000, 0, "log backup count")],
)
def test_replay_rejects_invalid_rotation_settings(
    tmp_path: Path,
    max_log_bytes: int,
    log_backups: int,
    message: str,
) -> None:
    with pytest.raises(ReplayError, match=message):
        replay_capture(
            MANIFEST,
            "normal_v5_val_001",
            MODEL,
            MODEL_MANIFEST,
            tmp_path / "replay.jsonl",
            max_log_bytes=max_log_bytes,
            log_backups=log_backups,
        )
