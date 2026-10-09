"""Score an independently exported flow dataset with a frozen model."""

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
from statistics import fmean
from typing import Any

import joblib
import numpy as np

from ids_ml.dataset import DATASET_COLUMNS, DATASET_SCHEMA_VERSION
from ids_ml.modeling import (
    CATEGORICAL_FEATURE_NAMES,
    MODEL_VERSION,
    ModelDevelopmentError,
    _transform_rows,
)

EVALUATION_SCORES_FILENAME = "evaluation_scores.csv"
EVALUATION_REPORT_FILENAME = "evaluation_report_v1.json"
EVALUATION_SCORE_COLUMNS = (
    "flow_id",
    "capture_id",
    "scenario_id",
    "label",
    "protocol",
    "dst_port",
    "normality_score",
    "anomaly_score",
    "provisional_anomaly_flag",
)


class DatasetScoringError(ValueError):
    """Raised when an evaluation dataset or model contract is invalid."""


@dataclass(frozen=True, slots=True)
class DatasetScoringResult:
    """Paths and counts produced by deterministic offline scoring."""

    scores_path: Path
    report_path: Path
    row_count: int
    flagged_count: int
    provisional_anomaly_threshold: float


def score_dataset(
    dataset_path: str | Path,
    dataset_manifest_path: str | Path,
    model_path: str | Path,
    model_manifest_path: str | Path,
    output_directory: str | Path,
) -> DatasetScoringResult:
    """Apply a trusted frozen model to a separate schema-v1 flow dataset."""
    dataset = Path(dataset_path)
    dataset_manifest_file = Path(dataset_manifest_path)
    model_file = Path(model_path)
    model_manifest_file = Path(model_manifest_path)
    output_dir = Path(output_directory)

    rows, columns = _read_csv(dataset)
    dataset_manifest = _read_json(dataset_manifest_file)
    model_manifest = _read_json(model_manifest_file)
    _validate_dataset(dataset, rows, columns, dataset_manifest)
    _validate_model_file(model_file, model_manifest)
    bundle = _load_trusted_model(model_file)
    _validate_model_contract(bundle, model_manifest)

    try:
        matrix = _transform_rows(rows, tuple(bundle["numeric_features"]))
    except ModelDevelopmentError as error:
        raise DatasetScoringError(str(error)) from error
    anomaly_scores = -bundle["estimator"].score_samples(matrix)
    threshold = float(bundle["provisional_anomaly_threshold"])
    flagged = anomaly_scores > threshold

    output_dir.mkdir(parents=True, exist_ok=True)
    scores_path = output_dir / EVALUATION_SCORES_FILENAME
    report_path = output_dir / EVALUATION_REPORT_FILENAME
    _write_scores(scores_path, rows, anomaly_scores, threshold)
    report = _evaluation_report(
        dataset,
        dataset_manifest_file,
        dataset_manifest,
        model_file,
        model_manifest_file,
        rows,
        anomaly_scores,
        threshold,
        scores_path,
    )
    _write_json(report_path, report)
    return DatasetScoringResult(
        scores_path=scores_path,
        report_path=report_path,
        row_count=len(rows),
        flagged_count=int(flagged.sum()),
        provisional_anomaly_threshold=threshold,
    )


def _read_csv(path: Path) -> tuple[list[dict[str, str]], tuple[str, ...]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            return list(reader), tuple(reader.fieldnames or ())
    except OSError as error:
        raise DatasetScoringError(f"cannot read dataset {path}: {error}") from error


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DatasetScoringError(f"cannot read JSON {path}: {error}") from error


def _validate_dataset(
    path: Path,
    rows: list[dict[str, str]],
    columns: tuple[str, ...],
    manifest: dict[str, Any],
) -> None:
    if not rows:
        raise DatasetScoringError("evaluation dataset contains no flow rows")
    if columns != DATASET_COLUMNS:
        raise DatasetScoringError("evaluation dataset columns do not match schema v1")
    if manifest.get("dataset_schema_version") != DATASET_SCHEMA_VERSION:
        raise DatasetScoringError("evaluation dataset schema version is unsupported")
    if manifest.get("dataset_sha256") != _sha256(path):
        raise DatasetScoringError("evaluation dataset SHA-256 does not match manifest")
    if manifest.get("row_count") != len(rows):
        raise DatasetScoringError(
            "evaluation dataset row count does not match manifest"
        )
    for row in rows:
        if not row["capture_id"] or not row["flow_id"] or not row["label"]:
            raise DatasetScoringError("evaluation metadata cannot be empty")


def _validate_model_file(path: Path, manifest: dict[str, Any]) -> None:
    if manifest.get("model_version") != MODEL_VERSION:
        raise DatasetScoringError("model manifest version is unsupported")
    expected_hash = manifest.get("artifacts", {}).get("model_sha256")
    if expected_hash != _sha256(path):
        raise DatasetScoringError("model SHA-256 does not match model manifest")


def _load_trusted_model(path: Path) -> dict[str, Any]:
    # Only load the manifest-verified artifact; joblib/pickle can execute code.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Setting the shape on a NumPy array has been deprecated.*",
            category=DeprecationWarning,
        )
        try:
            bundle = joblib.load(path)
        except Exception as error:
            raise DatasetScoringError(f"cannot load model {path}: {error}") from error
    if not isinstance(bundle, dict):
        raise DatasetScoringError("model artifact is not a versioned bundle")
    return bundle


def _validate_model_contract(
    bundle: dict[str, Any], model_manifest: dict[str, Any]
) -> None:
    required = {
        "model_version",
        "estimator",
        "numeric_features",
        "categorical_feature_names",
        "transformed_feature_names",
        "provisional_anomaly_threshold",
        "dataset_sha256",
    }
    missing = required - set(bundle)
    if missing:
        raise DatasetScoringError(
            f"model bundle is missing keys: {', '.join(sorted(missing))}"
        )
    if bundle["model_version"] != MODEL_VERSION:
        raise DatasetScoringError("model bundle version is unsupported")
    expected_names = tuple(bundle["numeric_features"]) + CATEGORICAL_FEATURE_NAMES
    if tuple(bundle["categorical_feature_names"]) != CATEGORICAL_FEATURE_NAMES:
        raise DatasetScoringError("categorical preprocessing contract changed")
    if tuple(bundle["transformed_feature_names"]) != expected_names:
        raise DatasetScoringError("transformed model feature order is inconsistent")
    if bundle["dataset_sha256"] != model_manifest.get("dataset", {}).get("sha256"):
        raise DatasetScoringError("model training-dataset identity is inconsistent")
    threshold = float(bundle["provisional_anomaly_threshold"])
    manifest_threshold = model_manifest.get("threshold", {}).get(
        "anomaly_score_threshold"
    )
    if not math.isfinite(threshold) or threshold != manifest_threshold:
        raise DatasetScoringError("model threshold is inconsistent with its manifest")


def _write_scores(
    path: Path,
    rows: list[dict[str, str]],
    anomaly_scores: np.ndarray,
    threshold: float,
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=EVALUATION_SCORE_COLUMNS, lineterminator="\n"
        )
        writer.writeheader()
        for row, anomaly_score in zip(rows, anomaly_scores, strict=True):
            score = float(anomaly_score)
            writer.writerow(
                {
                    "flow_id": row["flow_id"],
                    "capture_id": row["capture_id"],
                    "scenario_id": row["scenario_id"],
                    "label": row["label"],
                    "protocol": row["protocol"],
                    "dst_port": row["dst_port"],
                    "normality_score": repr(-score),
                    "anomaly_score": repr(score),
                    "provisional_anomaly_flag": str(score > threshold).lower(),
                }
            )


def _evaluation_report(
    dataset: Path,
    dataset_manifest_file: Path,
    dataset_manifest: dict[str, Any],
    model_file: Path,
    model_manifest_file: Path,
    rows: list[dict[str, str]],
    anomaly_scores: np.ndarray,
    threshold: float,
    scores_path: Path,
) -> dict[str, Any]:
    groups: dict[str, list[int]] = {}
    for index, row in enumerate(rows):
        groups.setdefault(row["capture_id"], []).append(index)
    return {
        "evaluation_report_version": 1,
        "interpretation": (
            "A provisional flag means unusual relative to the normal baseline; "
            "it does not by itself prove an attack."
        ),
        "dataset": {
            "file": dataset.name,
            "sha256": _sha256(dataset),
            "manifest_file": dataset_manifest_file.name,
            "manifest_sha256": _sha256(dataset_manifest_file),
            "schema_version": dataset_manifest["dataset_schema_version"],
        },
        "model": {
            "file": model_file.name,
            "sha256": _sha256(model_file),
            "manifest_file": model_manifest_file.name,
            "manifest_sha256": _sha256(model_manifest_file),
            "version": MODEL_VERSION,
        },
        "threshold": {
            "status": "provisional",
            "anomaly_score_threshold": threshold,
            "flag_rule": "anomaly_score > threshold",
        },
        "label_counts": dict(sorted(Counter(row["label"] for row in rows).items())),
        "overall": _metrics(anomaly_scores, threshold),
        "captures": {
            capture_id: {
                "scenario_id": rows[indexes[0]]["scenario_id"],
                "label": rows[indexes[0]]["label"],
                **_metrics(anomaly_scores[indexes], threshold),
            }
            for capture_id, indexes in sorted(groups.items())
        },
        "artifacts": {
            "scores_file": scores_path.name,
            "scores_sha256": _sha256(scores_path),
        },
    }


def _metrics(scores: np.ndarray, threshold: float) -> dict[str, Any]:
    values = [float(value) for value in scores]
    flagged_count = sum(value > threshold for value in values)
    return {
        "row_count": len(values),
        "anomaly_score_minimum": min(values),
        "anomaly_score_mean": fmean(values),
        "anomaly_score_median": float(np.median(values)),
        "anomaly_score_maximum": max(values),
        "provisional_flagged_count": flagged_count,
        "provisional_flagged_fraction": flagged_count / len(values),
    }


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
    """Score an independently exported dataset using command-line paths."""
    parser = argparse.ArgumentParser(
        description="Score a separate flow dataset with the frozen model."
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--dataset-manifest", type=Path, required=True)
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("artifacts/isolation_forest_v1/model.joblib"),
    )
    parser.add_argument(
        "--model-manifest",
        type=Path,
        default=Path("artifacts/isolation_forest_v1/model_manifest.json"),
    )
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    result = score_dataset(
        args.dataset,
        args.dataset_manifest,
        args.model,
        args.model_manifest,
        args.output_directory,
    )
    print(
        f"scored={result.row_count} flagged={result.flagged_count} "
        f"threshold={result.provisional_anomaly_threshold:.12g}"
    )
    print(f"scores={result.scores_path}")
    print(f"report={result.report_path}")


if __name__ == "__main__":
    main()
