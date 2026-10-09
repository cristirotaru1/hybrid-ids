"""Frozen behavioral and hybrid scoring for model version 2."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import warnings
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from ids_ml.dataset_v2 import DATASET_SCHEMA_VERSION_V2

REASON_ORDER = (
    "behavioral_score_high",
    "tcp_failure_burst",
    "unseen_destination_service",
    "icmp_type_code_unseen",
    "same_protocol_flow_rate_high",
    "destination_ip_fanout_high",
    "destination_port_fanout_high",
)

SCORE_COLUMNS = (
    "flow_id",
    "capture_id",
    "scenario_id",
    "label",
    "protocol",
    "protocol_name",
    "dst_port",
    "anomaly_score",
    "protocol_threshold",
    "threshold_margin",
    "behavioral_anomaly_flag",
    "novelty_reason_codes",
    "hybrid_anomaly_flag",
    "current_tcp_failed",
    "failed_tcp_connections_last_10s",
    "same_protocol_flows_last_10s",
    "unique_dst_ips_last_10s",
    "unique_dst_ports_last_10s",
    "icmp_type_group",
    "icmp_code",
)


class ModelV2ScoringError(ValueError):
    """Raised when frozen model-v2 scoring inputs violate their contracts."""


@dataclass(frozen=True, slots=True)
class ModelV2ScoringResult:
    """Paths and headline counts from one model-v2 scoring run."""

    scores_path: Path
    manifest_path: Path
    row_count: int
    behavioral_flagged_count: int
    hybrid_flagged_count: int


def score_dataset_v2(
    dataset_path: str | Path,
    dataset_manifest_path: str | Path,
    model_path: str | Path,
    model_manifest_path: str | Path,
    output_directory: str | Path,
) -> ModelV2ScoringResult:
    """Score schema-v2 rows without fitting or changing frozen boundaries."""
    dataset = Path(dataset_path)
    dataset_manifest_file = Path(dataset_manifest_path)
    model_file = Path(model_path)
    model_manifest_file = Path(model_manifest_path)
    output_dir = Path(output_directory)

    rows, columns = _read_dataset(dataset)
    dataset_manifest = _read_json(dataset_manifest_file)
    model_manifest = _read_json(model_manifest_file)
    _validate_dataset(dataset, rows, columns, dataset_manifest)
    _validate_model(model_file, model_manifest)
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message="Setting the shape on a NumPy array has been deprecated.*",
                category=DeprecationWarning,
            )
            bundle = joblib.load(model_file)
    except Exception as error:
        raise ModelV2ScoringError(f"cannot load model bundle: {error}") from error
    _validate_bundle(bundle, model_manifest)

    scored_rows = [_score_row(row, bundle) for row in rows]
    output_dir.mkdir(parents=True, exist_ok=True)
    scores_path = output_dir / "evaluation_scores.csv"
    manifest_path = output_dir / "scoring_manifest_v2.json"
    _write_scores(scores_path, scored_rows)

    behavioral_count = sum(row["behavioral_anomaly_flag"] for row in scored_rows)
    hybrid_count = sum(row["hybrid_anomaly_flag"] for row in scored_rows)
    reason_counts = Counter(
        reason
        for row in scored_rows
        for reason in row["novelty_reason_codes"].split(";")
        if reason
    )
    capture_metrics = _capture_metrics(scored_rows)
    manifest = {
        "scoring_version": 2,
        "model_version": 2,
        "candidates": ["v2_behavioral", "v2_hybrid"],
        "dataset": {
            "file": dataset.as_posix(),
            "sha256": _sha256(dataset),
            "manifest_file": dataset_manifest_file.as_posix(),
            "manifest_sha256": _sha256(dataset_manifest_file),
            "schema_version": dataset_manifest["dataset_schema_version"],
            "row_count": len(rows),
        },
        "model": {
            "file": model_file.as_posix(),
            "sha256": _sha256(model_file),
            "manifest_file": model_manifest_file.as_posix(),
            "manifest_sha256": _sha256(model_manifest_file),
        },
        "decision": {
            "behavioral": "anomaly_score > protocol_threshold",
            "hybrid": "behavioral flag OR any semantic novelty reason",
            "meaning": "flagged output denotes anomalous behavior, not proof of attack",
        },
        "metrics": {
            "row_count": len(scored_rows),
            "behavioral_flagged_count": behavioral_count,
            "behavioral_flagged_fraction": behavioral_count / len(scored_rows),
            "hybrid_flagged_count": hybrid_count,
            "hybrid_flagged_fraction": hybrid_count / len(scored_rows),
            "reason_counts": dict(sorted(reason_counts.items())),
            "by_capture": capture_metrics,
        },
        "artifacts": {
            "scores_file": scores_path.name,
            "scores_sha256": _sha256(scores_path),
        },
    }
    _write_json(manifest_path, manifest)
    return ModelV2ScoringResult(
        scores_path=scores_path,
        manifest_path=manifest_path,
        row_count=len(scored_rows),
        behavioral_flagged_count=behavioral_count,
        hybrid_flagged_count=hybrid_count,
    )


def _score_row(row: dict[str, str], bundle: dict[str, Any]) -> dict[str, Any]:
    protocol_number = _finite_int(row, "protocol")
    protocol_names = {1: "icmp", 6: "tcp", 17: "udp"}
    try:
        protocol_name = protocol_names[protocol_number]
        contract = bundle["protocol_models"][protocol_name]
    except KeyError as error:
        raise ModelV2ScoringError(
            f"{row['flow_id']}: unsupported protocol {protocol_number}"
        ) from error
    features = tuple(contract["learned_features"])
    matrix = np.asarray(
        [[_finite_float(row, feature) for feature in features]], dtype=np.float64
    )
    anomaly_score = float(-contract["estimator"].score_samples(matrix)[0])
    threshold = float(contract["anomaly_threshold"])
    behavioral_flag = anomaly_score > threshold
    reasons = _novelty_reasons(
        row,
        protocol_name,
        bundle["novelty_policy"],
        behavioral_flag,
    )
    return {
        "flow_id": row["flow_id"],
        "capture_id": row["capture_id"],
        "scenario_id": row["scenario_id"],
        "label": row["label"],
        "protocol": protocol_number,
        "protocol_name": protocol_name,
        "dst_port": _finite_int(row, "dst_port"),
        "anomaly_score": anomaly_score,
        "protocol_threshold": threshold,
        "threshold_margin": anomaly_score - threshold,
        "behavioral_anomaly_flag": behavioral_flag,
        "novelty_reason_codes": ";".join(reasons),
        "hybrid_anomaly_flag": bool(reasons),
        "current_tcp_failed": _finite_int(row, "current_tcp_failed"),
        "failed_tcp_connections_last_10s": _finite_int(
            row, "failed_tcp_connections_last_10s"
        ),
        "same_protocol_flows_last_10s": _finite_int(
            row, "same_protocol_flows_last_10s"
        ),
        "unique_dst_ips_last_10s": _finite_int(row, "unique_dst_ips_last_10s"),
        "unique_dst_ports_last_10s": _finite_int(row, "unique_dst_ports_last_10s"),
        "icmp_type_group": _finite_int(row, "icmp_type_group"),
        "icmp_code": _finite_int(row, "icmp_code"),
    }


def _novelty_reasons(
    row: dict[str, str],
    protocol_name: str,
    policy: dict[str, Any],
    behavioral_flag: bool,
) -> list[str]:
    selected: set[str] = set()
    if behavioral_flag:
        selected.add("behavioral_score_high")
    current_failed = _finite_int(row, "current_tcp_failed")
    recent_failures = _finite_int(row, "failed_tcp_connections_last_10s")
    minimum_failures = policy["tcp_failure_burst"]["minimum_failures_including_current"]
    if (
        protocol_name == "tcp"
        and current_failed == 1
        and current_failed + recent_failures >= minimum_failures
    ):
        selected.add("tcp_failure_burst")

    if protocol_name in {"tcp", "udp"}:
        known_services = set(policy["known_destination_services"][protocol_name])
        if _finite_int(row, "dst_port") not in known_services:
            selected.add("unseen_destination_service")
    if protocol_name == "icmp":
        seen = {tuple(values) for values in policy["seen_icmp_type_codes"]}
        current = (
            _finite_int(row, "icmp_type_group"),
            _finite_int(row, "icmp_code"),
        )
        if current not in seen:
            selected.add("icmp_type_code_unseen")

    boundaries = policy["numeric_upper_boundaries_by_protocol"][protocol_name]
    numeric_reasons = {
        "same_protocol_flows_last_10s": "same_protocol_flow_rate_high",
        "unique_dst_ips_last_10s": "destination_ip_fanout_high",
        "unique_dst_ports_last_10s": "destination_port_fanout_high",
    }
    for column, reason in numeric_reasons.items():
        if _finite_float(row, column) > float(boundaries[column]):
            selected.add(reason)
    return [reason for reason in REASON_ORDER if reason in selected]


def _validate_dataset(
    dataset: Path,
    rows: list[dict[str, str]],
    columns: tuple[str, ...],
    manifest: dict[str, Any],
) -> None:
    if manifest.get("dataset_sha256") != _sha256(dataset):
        raise ModelV2ScoringError("dataset SHA-256 does not match its manifest")
    if manifest.get("dataset_schema_version") != DATASET_SCHEMA_VERSION_V2:
        raise ModelV2ScoringError("scoring requires dataset schema version 2")
    if len(rows) != manifest.get("row_count"):
        raise ModelV2ScoringError("dataset row count does not match its manifest")
    required = set(SCORE_COLUMNS) - {
        "protocol_name",
        "anomaly_score",
        "protocol_threshold",
        "threshold_margin",
        "behavioral_anomaly_flag",
        "novelty_reason_codes",
        "hybrid_anomaly_flag",
    }
    missing = required - set(columns)
    if missing:
        raise ModelV2ScoringError(
            f"dataset is missing columns: {', '.join(sorted(missing))}"
        )
    if not rows:
        raise ModelV2ScoringError("dataset contains no rows")


def _validate_model(model_file: Path, manifest: dict[str, Any]) -> None:
    if manifest.get("model_version") != 2:
        raise ModelV2ScoringError("model manifest is not version 2")
    expected_hash = manifest.get("artifacts", {}).get("model_sha256")
    if expected_hash != _sha256(model_file):
        raise ModelV2ScoringError("model SHA-256 does not match its manifest")


def _validate_bundle(bundle: dict[str, Any], manifest: dict[str, Any]) -> None:
    if bundle.get("model_version") != 2:
        raise ModelV2ScoringError("model bundle is not version 2")
    if set(bundle.get("protocol_models", {})) != {"icmp", "tcp", "udp"}:
        raise ModelV2ScoringError("model bundle does not contain three protocols")
    if bundle.get("novelty_policy") != manifest.get("novelty_policy"):
        raise ModelV2ScoringError("bundle and manifest novelty policies disagree")


def _capture_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for capture_id in dict.fromkeys(row["capture_id"] for row in rows):
        capture_rows = [row for row in rows if row["capture_id"] == capture_id]
        output[capture_id] = {
            "scenario_id": capture_rows[0]["scenario_id"],
            "label": capture_rows[0]["label"],
            "row_count": len(capture_rows),
            "behavioral_flagged_count": sum(
                row["behavioral_anomaly_flag"] for row in capture_rows
            ),
            "hybrid_flagged_count": sum(
                row["hybrid_anomaly_flag"] for row in capture_rows
            ),
        }
    return output


def _read_dataset(path: Path) -> tuple[list[dict[str, str]], tuple[str, ...]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            return list(reader), tuple(reader.fieldnames or ())
    except OSError as error:
        raise ModelV2ScoringError(f"cannot read dataset {path}: {error}") from error


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ModelV2ScoringError(f"cannot read JSON {path}: {error}") from error


def _finite_float(row: dict[str, str], column: str) -> float:
    try:
        value = float(row[column])
    except (KeyError, ValueError) as error:
        raise ModelV2ScoringError(
            f"{row.get('flow_id', '<unknown>')}: invalid {column}"
        ) from error
    if not math.isfinite(value):
        raise ModelV2ScoringError(
            f"{row.get('flow_id', '<unknown>')}: non-finite {column}"
        )
    return value


def _finite_int(row: dict[str, str], column: str) -> int:
    value = _finite_float(row, column)
    if not value.is_integer():
        raise ModelV2ScoringError(
            f"{row.get('flow_id', '<unknown>')}: {column} is not an integer"
        )
    return int(value)


def _write_scores(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SCORE_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    **row,
                    "anomaly_score": repr(row["anomaly_score"]),
                    "protocol_threshold": repr(row["protocol_threshold"]),
                    "threshold_margin": repr(row["threshold_margin"]),
                    "behavioral_anomaly_flag": str(
                        row["behavioral_anomaly_flag"]
                    ).lower(),
                    "hybrid_anomaly_flag": str(row["hybrid_anomaly_flag"]).lower(),
                }
            )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> None:
    """Score an exported schema-v2 dataset with the frozen model-v2 artifact."""
    parser = argparse.ArgumentParser(description="Score dataset with model v2.")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--dataset-manifest", type=Path, required=True)
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("artifacts/isolation_forest_v2_behavioral/models.joblib"),
    )
    parser.add_argument(
        "--model-manifest",
        type=Path,
        default=Path("artifacts/isolation_forest_v2_behavioral/model_manifest.json"),
    )
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    result = score_dataset_v2(
        args.dataset,
        args.dataset_manifest,
        args.model,
        args.model_manifest,
        args.output_directory,
    )
    print(
        f"scored {result.row_count} flows; behavioral flags "
        f"{result.behavioral_flagged_count}, hybrid flags "
        f"{result.hybrid_flagged_count}"
    )


if __name__ == "__main__":
    main()
