"""Replay one approved PCAP through the frozen model-v2 scoring pipeline."""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from ids_ml.dataset_v2 import export_dataset_v2
from ids_ml.scoring_v2 import score_dataset_v2

DEFAULT_MODEL = Path("artifacts/isolation_forest_v2_v5_candidate_a/models.joblib")
DEFAULT_MODEL_MANIFEST = Path(
    "artifacts/isolation_forest_v2_v5_candidate_a/model_manifest.json"
)
DEFAULT_OUTPUT = Path("output/replay_scores.jsonl")
DEFAULT_MAX_LOG_BYTES = 10 * 1024 * 1024
DEFAULT_LOG_BACKUPS = 5


class ReplayError(ValueError):
    """Raised when a replay request is invalid or already running."""


def replay_capture(
    capture_manifest: str | Path,
    capture_id: str,
    model: str | Path,
    model_manifest: str | Path,
    output: str | Path,
    *,
    speed: float | None = None,
    max_log_bytes: int = DEFAULT_MAX_LOG_BYTES,
    log_backups: int = DEFAULT_LOG_BACKUPS,
) -> int:
    """Extract, score, and emit one approved capture as JSONL events."""
    if speed is not None and speed <= 0:
        raise ReplayError("speed must be greater than zero")
    if max_log_bytes <= 0:
        raise ReplayError("maximum log size must be greater than zero")
    if log_backups <= 0:
        raise ReplayError("log backup count must be greater than zero")

    source_manifest = Path(capture_manifest).resolve()
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    selected, fieldnames = _select_capture(source_manifest, capture_id)
    source_pcap = (source_manifest.parent / selected["filename"]).resolve()
    selected["filename"] = source_pcap.as_posix()
    run_id = str(uuid.uuid4())

    with _exclusive_lock(output_path):

        def emit(event: dict[str, Any]) -> None:
            _append_event(output_path, event, max_log_bytes, log_backups)

        with TemporaryDirectory(prefix="ids-replay-") as temporary_directory:
            temporary = Path(temporary_directory)
            selected_manifest = temporary / "selected_capture.csv"
            _write_selected_manifest(selected_manifest, fieldnames, selected)
            dataset_result = export_dataset_v2(selected_manifest, temporary / "dataset")
            scoring_result = score_dataset_v2(
                dataset_result.dataset_path,
                dataset_result.manifest_path,
                model,
                model_manifest,
                temporary / "scores",
            )
            dataset_rows = _read_csv_by_flow_id(dataset_result.dataset_path)
            score_rows = _read_csv(scoring_result.scores_path)

            emit(
                {
                    "event_type": "replay_started",
                    "run_id": run_id,
                    "capture_id": capture_id,
                    "source_pcap": source_pcap.as_posix(),
                    "model": Path(model).parent.name,
                    "flow_count": len(score_rows),
                    "status": "experimental",
                },
            )
            previous_timestamp: datetime | None = None
            for score_row in score_rows:
                dataset_row = dataset_rows[score_row["flow_id"]]
                timestamp = _parse_timestamp(dataset_row["flow_end_utc"])
                if speed is not None and previous_timestamp is not None:
                    delay = (timestamp - previous_timestamp).total_seconds() / speed
                    if delay > 0:
                        time.sleep(delay)
                emit(_flow_event(run_id, score_row, dataset_row, Path(model)))
                previous_timestamp = timestamp

            emit(
                {
                    "event_type": "replay_completed",
                    "run_id": run_id,
                    "capture_id": capture_id,
                    "flow_count": len(score_rows),
                    "hybrid_flagged_count": scoring_result.hybrid_flagged_count,
                    "status": "experimental",
                },
            )
    return len(score_rows)


def _select_capture(
    manifest: Path, capture_id: str
) -> tuple[dict[str, str], tuple[str, ...]]:
    try:
        with manifest.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            rows = [row for row in reader if row.get("capture_id") == capture_id]
            fieldnames = tuple(reader.fieldnames or ())
    except OSError as error:
        raise ReplayError(
            f"cannot read capture manifest {manifest}: {error}"
        ) from error
    if len(rows) != 1:
        raise ReplayError(
            f"capture ID {capture_id!r} must occur exactly once in {manifest}"
        )
    return rows[0], fieldnames


def _write_selected_manifest(
    path: Path, fieldnames: tuple[str, ...], row: dict[str, str]
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerow(row)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _read_csv_by_flow_id(path: Path) -> dict[str, dict[str, str]]:
    return {row["flow_id"]: row for row in _read_csv(path)}


def _flow_event(
    run_id: str,
    score: dict[str, str],
    dataset: dict[str, str],
    model: Path,
) -> dict[str, Any]:
    reasons = [value for value in score["novelty_reason_codes"].split(";") if value]
    return {
        "event_type": "flow_scored",
        "run_id": run_id,
        "timestamp": dataset["flow_end_utc"],
        "flow_id": score["flow_id"],
        "capture_id": score["capture_id"],
        "scenario_id": dataset["scenario_id"],
        "source_pcap": dataset["source_pcap"],
        "source_ip": dataset["src_ip"],
        "destination_ip": dataset["dst_ip"],
        "protocol": score["protocol_name"],
        "destination_port": int(score["dst_port"]),
        "anomaly_score": float(score["anomaly_score"]),
        "protocol_threshold": float(score["protocol_threshold"]),
        "threshold_margin": float(score["threshold_margin"]),
        "behavioral_anomaly_flag": score["behavioral_anomaly_flag"] == "true",
        "hybrid_anomaly_flag": score["hybrid_anomaly_flag"] == "true",
        "reason_codes": reasons,
        "model": model.parent.name,
        "status": "experimental",
    }


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _append_event(
    path: Path,
    event: dict[str, Any],
    max_log_bytes: int,
    log_backups: int,
) -> None:
    event["emitted_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
    _rotate_log_if_needed(path, len(line.encode("utf-8")), max_log_bytes, log_backups)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()


def _rotate_log_if_needed(
    path: Path,
    incoming_bytes: int,
    max_log_bytes: int,
    log_backups: int,
) -> None:
    try:
        current_bytes = path.stat().st_size
    except FileNotFoundError:
        return
    if current_bytes == 0 or current_bytes + incoming_bytes <= max_log_bytes:
        return

    oldest = path.with_name(f"{path.name}.{log_backups}")
    oldest.unlink(missing_ok=True)
    for index in range(log_backups - 1, 0, -1):
        source = path.with_name(f"{path.name}.{index}")
        if source.exists():
            source.replace(path.with_name(f"{path.name}.{index + 1}"))
    path.replace(path.with_name(f"{path.name}.1"))


@contextmanager
def _exclusive_lock(output: Path) -> Iterator[None]:
    lock_path = output.with_suffix(output.suffix + ".lock")
    with lock_path.open("w", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReplayError(
                f"another replay is already writing to {output}"
            ) from error
        yield


def main() -> None:
    """Run one approved replay from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--model-manifest", type=Path, default=DEFAULT_MODEL_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--max-log-bytes", type=int, default=DEFAULT_MAX_LOG_BYTES)
    parser.add_argument("--log-backups", type=int, default=DEFAULT_LOG_BACKUPS)
    timing = parser.add_mutually_exclusive_group()
    timing.add_argument("--speed", type=float)
    timing.add_argument("--no-delay", action="store_true")
    args = parser.parse_args()
    speed = None if args.no_delay or args.speed is None else args.speed
    count = replay_capture(
        args.manifest,
        args.capture_id,
        args.model,
        args.model_manifest,
        args.output,
        speed=speed,
        max_log_bytes=args.max_log_bytes,
        log_backups=args.log_backups,
    )
    print(f"replayed {count} flows to {args.output}")


if __name__ == "__main__":
    main()
