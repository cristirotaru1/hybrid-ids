"""Deterministic normal-only Isolation Forest development workflow."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

MODEL_VERSION = 1
RANDOM_SEED = 42
N_ESTIMATORS = 300
PROVISIONAL_NORMAL_FALSE_POSITIVE_TARGET = 0.05
EXPECTED_DATASET_SCHEMA_VERSION = 1
EXPECTED_DATASET_SHA256 = (
    "7f30808a0cc57becd79de8205c89334fc245f9cd3a724171fb4e0faa95dbbfe6"
)

TRAIN_CAPTURE_IDS = (
    "normal_v2_002",
    "normal_v2_003",
    "normal_v2_005",
    "normal_v2_006",
    "normal_v2_007",
    "normal_v2_008",
)
VALIDATION_CAPTURE_IDS = ("normal_v2_009",)
LEGACY_EVALUATION_CAPTURE_IDS = (
    "normal_002_ssh",
    "normal_003_ping",
    "normal_004_udp",
    "normal_005_mixed",
    "normal_test_001",
)

# Totals duplicate directional sums; source ports are typically ephemeral.
NUMERIC_CANDIDATE_FEATURES = (
    "flow_duration",
    "forward_packet_count",
    "backward_packet_count",
    "forward_bytes",
    "backward_bytes",
    "mean_packet_size",
    "std_packet_size",
    "packets_per_second",
    "bytes_per_second",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "inter_arrival_mean",
    "inter_arrival_std",
    "flows_last_10s",
    "unique_dst_ips_last_10s",
    "unique_dst_ports_last_10s",
    "connection_rate_last_10s",
    "failed_connection_rate_last_10s",
)
EXCLUDED_MODEL_FEATURES = (
    "total_packet_count",
    "total_bytes",
    "src_port",
)
PROTOCOL_CATEGORIES = ((1, "icmp"), (6, "tcp"), (17, "udp"))
DESTINATION_PORT_CATEGORIES = ((0, "none"), (22, "ssh"), (9999, "lab_udp"))
CATEGORICAL_FEATURE_NAMES = (
    tuple(f"protocol_{name}" for _, name in PROTOCOL_CATEGORIES)
    + tuple(f"dst_port_{name}" for _, name in DESTINATION_PORT_CATEGORIES)
    + ("dst_port_other",)
)

SCORE_COLUMNS = (
    "flow_id",
    "capture_id",
    "scenario_id",
    "label",
    "split",
    "protocol",
    "dst_port",
    "normality_score",
    "anomaly_score",
    "provisional_anomaly_flag",
)


class ModelDevelopmentError(ValueError):
    """Raised when the frozen model-development contract is violated."""


@dataclass(frozen=True, slots=True)
class ModelDevelopmentResult:
    """Paths and headline results from one model-development run."""

    model_path: Path
    scores_path: Path
    manifest_path: Path
    train_row_count: int
    validation_row_count: int
    legacy_evaluation_row_count: int
    provisional_anomaly_threshold: float


def train_isolation_forest(
    dataset_path: str | Path,
    dataset_manifest_path: str | Path,
    output_directory: str | Path,
) -> ModelDevelopmentResult:
    """Fit and score the frozen version 1 normal-only development split."""
    dataset = Path(dataset_path)
    dataset_manifest = Path(dataset_manifest_path)
    output_dir = Path(output_directory)
    rows, columns = _read_dataset(dataset)
    source_manifest = _read_json(dataset_manifest)
    _validate_dataset(dataset, rows, columns, source_manifest)

    partitions = _partition_rows(rows)
    train_rows = partitions["train"]
    constant_numeric = _constant_numeric_features(train_rows)
    numeric_features = tuple(
        name for name in NUMERIC_CANDIDATE_FEATURES if name not in constant_numeric
    )
    transformed_feature_names = numeric_features + CATEGORICAL_FEATURE_NAMES

    train_matrix = _transform_rows(train_rows, numeric_features)
    estimator = IsolationForest(
        n_estimators=N_ESTIMATORS,
        max_samples="auto",
        contamination="auto",
        bootstrap=False,
        random_state=RANDOM_SEED,
        n_jobs=1,
    )
    estimator.fit(train_matrix)

    scored_partitions: dict[str, tuple[list[dict[str, str]], np.ndarray]] = {}
    for split, split_rows in partitions.items():
        matrix = _transform_rows(split_rows, numeric_features)
        normality_scores = estimator.score_samples(matrix)
        scored_partitions[split] = (split_rows, -normality_scores)

    validation_anomaly_scores = scored_partitions["normal_validation"][1]
    threshold = float(
        np.quantile(
            validation_anomaly_scores,
            1.0 - PROVISIONAL_NORMAL_FALSE_POSITIVE_TARGET,
            method="linear",
        )
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "model.joblib"
    scores_path = output_dir / "model_development_scores.csv"
    manifest_path = output_dir / "model_manifest.json"

    bundle = {
        "model_version": MODEL_VERSION,
        "estimator": estimator,
        "numeric_features": numeric_features,
        "categorical_feature_names": CATEGORICAL_FEATURE_NAMES,
        "transformed_feature_names": transformed_feature_names,
        "protocol_categories": PROTOCOL_CATEGORIES,
        "destination_port_categories": DESTINATION_PORT_CATEGORIES,
        "provisional_anomaly_threshold": threshold,
        "score_direction": "higher anomaly_score means more anomalous behavior",
        "dataset_sha256": EXPECTED_DATASET_SHA256,
    }
    joblib.dump(bundle, model_path, compress=3)
    _write_scores(scores_path, scored_partitions, threshold)

    split_metrics = {
        split: _score_metrics(anomaly_scores, threshold)
        for split, (_, anomaly_scores) in scored_partitions.items()
    }
    manifest = {
        "model_version": MODEL_VERSION,
        "intended_use": "development-only normal-behavior baseline",
        "limitation": (
            "No anomalous or attack captures were used; these results do not "
            "measure attack-detection performance."
        ),
        "dataset": {
            "file": dataset.name,
            "sha256": _sha256(dataset),
            "manifest_file": dataset_manifest.name,
            "manifest_sha256": _sha256(dataset_manifest),
            "schema_version": source_manifest["dataset_schema_version"],
        },
        "split": {
            "method": "capture-based; no random row split",
            "train_capture_ids": list(TRAIN_CAPTURE_IDS),
            "normal_validation_capture_ids": list(VALIDATION_CAPTURE_IDS),
            "legacy_normal_evaluation_capture_ids": list(LEGACY_EVALUATION_CAPTURE_IDS),
            "row_counts": {
                split: len(split_rows) for split, split_rows in partitions.items()
            },
        },
        "preprocessing": {
            "metadata_excluded": list(source_manifest["columns"]["metadata"]),
            "model_features_excluded": list(EXCLUDED_MODEL_FEATURES),
            "numeric_candidates": list(NUMERIC_CANDIDATE_FEATURES),
            "constant_numeric_features_dropped_from_training": list(constant_numeric),
            "categorical_encoding": {
                "protocol": {str(value): name for value, name in PROTOCOL_CATEGORIES},
                "dst_port": {
                    **{str(value): name for value, name in DESTINATION_PORT_CATEGORIES},
                    "other": "other",
                },
            },
            "transformed_feature_names": list(transformed_feature_names),
            "scaling": "none; Isolation Forest uses feature split ordering",
        },
        "estimator": {
            "class": "sklearn.ensemble.IsolationForest",
            "n_estimators": N_ESTIMATORS,
            "max_samples": "auto",
            "contamination": "auto",
            "bootstrap": False,
            "random_state": RANDOM_SEED,
            "n_jobs": 1,
        },
        "threshold": {
            "status": "provisional",
            "definition": (
                "95th percentile of anomaly scores on the normal-validation capture"
            ),
            "target_normal_false_positive_fraction": (
                PROVISIONAL_NORMAL_FALSE_POSITIVE_TARGET
            ),
            "anomaly_score_threshold": threshold,
            "flag_rule": "anomaly_score > threshold",
        },
        "metrics": split_metrics,
        "artifacts": {
            "model_file": model_path.name,
            "model_sha256": _sha256(model_path),
            "scores_file": scores_path.name,
            "scores_sha256": _sha256(scores_path),
        },
        "software": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
    }
    _write_json(manifest_path, manifest)

    return ModelDevelopmentResult(
        model_path=model_path,
        scores_path=scores_path,
        manifest_path=manifest_path,
        train_row_count=len(train_rows),
        validation_row_count=len(partitions["normal_validation"]),
        legacy_evaluation_row_count=len(partitions["legacy_normal_evaluation"]),
        provisional_anomaly_threshold=threshold,
    )


def _read_dataset(path: Path) -> tuple[list[dict[str, str]], tuple[str, ...]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            return list(reader), tuple(reader.fieldnames or ())
    except OSError as error:
        raise ModelDevelopmentError(f"cannot read dataset {path}: {error}") from error


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ModelDevelopmentError(f"cannot read JSON {path}: {error}") from error


def _validate_dataset(
    dataset: Path,
    rows: list[dict[str, str]],
    columns: tuple[str, ...],
    manifest: dict[str, Any],
) -> None:
    actual_hash = _sha256(dataset)
    if actual_hash != EXPECTED_DATASET_SHA256:
        raise ModelDevelopmentError(
            "dataset does not match the frozen model version 1 SHA-256"
        )
    if manifest.get("dataset_sha256") != actual_hash:
        raise ModelDevelopmentError("dataset SHA-256 does not match its manifest")
    if manifest.get("dataset_schema_version") != EXPECTED_DATASET_SCHEMA_VERSION:
        raise ModelDevelopmentError("unsupported dataset schema version")
    if len(rows) != manifest.get("row_count"):
        raise ModelDevelopmentError("dataset row count does not match its manifest")
    required = {
        "capture_id",
        "flow_id",
        "scenario_id",
        "label",
        "protocol",
        "dst_port",
        *NUMERIC_CANDIDATE_FEATURES,
    }
    missing = required - set(columns)
    if missing:
        raise ModelDevelopmentError(
            f"dataset is missing columns: {', '.join(sorted(missing))}"
        )
    if any(row["label"] != "normal" for row in rows):
        raise ModelDevelopmentError("version 1 development input must be normal-only")


def _partition_rows(
    rows: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    capture_to_split = {
        **dict.fromkeys(TRAIN_CAPTURE_IDS, "train"),
        **dict.fromkeys(VALIDATION_CAPTURE_IDS, "normal_validation"),
        **dict.fromkeys(LEGACY_EVALUATION_CAPTURE_IDS, "legacy_normal_evaluation"),
    }
    partitions = {
        "train": [],
        "normal_validation": [],
        "legacy_normal_evaluation": [],
    }
    unknown_capture_ids: set[str] = set()
    for row in rows:
        split = capture_to_split.get(row["capture_id"])
        if split is None:
            unknown_capture_ids.add(row["capture_id"])
        else:
            partitions[split].append(row)
    if unknown_capture_ids:
        raise ModelDevelopmentError(
            "dataset contains unassigned nonempty captures: "
            + ", ".join(sorted(unknown_capture_ids))
        )
    if any(not split_rows for split_rows in partitions.values()):
        raise ModelDevelopmentError("every model-development split must contain rows")
    return partitions


def _constant_numeric_features(rows: list[dict[str, str]]) -> tuple[str, ...]:
    constants: list[str] = []
    for feature in NUMERIC_CANDIDATE_FEATURES:
        values = {_finite_float(row, feature) for row in rows}
        if len(values) == 1:
            constants.append(feature)
    return tuple(constants)


def _transform_rows(
    rows: list[dict[str, str]], numeric_features: tuple[str, ...]
) -> np.ndarray:
    transformed: list[list[float]] = []
    known_ports = {value for value, _ in DESTINATION_PORT_CATEGORIES}
    for row in rows:
        protocol = _finite_int(row, "protocol")
        if protocol not in {value for value, _ in PROTOCOL_CATEGORIES}:
            raise ModelDevelopmentError(f"unsupported protocol number {protocol}")
        destination_port = _finite_int(row, "dst_port")
        vector = [_finite_float(row, feature) for feature in numeric_features]
        vector.extend(float(protocol == value) for value, _ in PROTOCOL_CATEGORIES)
        vector.extend(
            float(destination_port == value) for value, _ in DESTINATION_PORT_CATEGORIES
        )
        vector.append(float(destination_port not in known_ports))
        transformed.append(vector)
    matrix = np.asarray(transformed, dtype=np.float64)
    if matrix.ndim != 2 or not np.isfinite(matrix).all():
        raise ModelDevelopmentError("transformed features must form a finite matrix")
    return matrix


def _finite_float(row: dict[str, str], column: str) -> float:
    try:
        value = float(row[column])
    except (KeyError, ValueError) as error:
        raise ModelDevelopmentError(
            f"{row.get('flow_id', '<unknown>')}: invalid {column}"
        ) from error
    if not math.isfinite(value):
        raise ModelDevelopmentError(
            f"{row.get('flow_id', '<unknown>')}: non-finite {column}"
        )
    return value


def _finite_int(row: dict[str, str], column: str) -> int:
    value = _finite_float(row, column)
    if not value.is_integer():
        raise ModelDevelopmentError(
            f"{row.get('flow_id', '<unknown>')}: {column} is not an integer"
        )
    return int(value)


def _write_scores(
    path: Path,
    scored_partitions: dict[str, tuple[list[dict[str, str]], np.ndarray]],
    threshold: float,
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SCORE_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for split, (rows, anomaly_scores) in scored_partitions.items():
            for row, anomaly_score in zip(rows, anomaly_scores, strict=True):
                score = float(anomaly_score)
                writer.writerow(
                    {
                        "flow_id": row["flow_id"],
                        "capture_id": row["capture_id"],
                        "scenario_id": row["scenario_id"],
                        "label": row["label"],
                        "split": split,
                        "protocol": row["protocol"],
                        "dst_port": row["dst_port"],
                        "normality_score": repr(-score),
                        "anomaly_score": repr(score),
                        "provisional_anomaly_flag": str(score > threshold).lower(),
                    }
                )


def _score_metrics(scores: np.ndarray, threshold: float) -> dict[str, Any]:
    values = [float(value) for value in scores]
    flagged = sum(value > threshold for value in values)
    return {
        "row_count": len(values),
        "anomaly_score_minimum": min(values),
        "anomaly_score_mean": fmean(values),
        "anomaly_score_median": float(np.median(values)),
        "anomaly_score_maximum": max(values),
        "provisional_flagged_count": flagged,
        "provisional_flagged_fraction": flagged / len(values),
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
    """Train the frozen version 1 development model from command-line paths."""
    parser = argparse.ArgumentParser(
        description="Train the normal-only Isolation Forest development model."
    )
    parser.add_argument(
        "--dataset", type=Path, default=Path("data/derived/flows_v1.csv")
    )
    parser.add_argument(
        "--dataset-manifest",
        type=Path,
        default=Path("data/derived/manifest_v1.json"),
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("artifacts/isolation_forest_v1"),
    )
    args = parser.parse_args()
    result = train_isolation_forest(
        args.dataset, args.dataset_manifest, args.output_directory
    )
    print(
        f"trained={result.train_row_count} "
        f"normal_validation={result.validation_row_count} "
        f"legacy_normal_evaluation={result.legacy_evaluation_row_count}"
    )
    print(f"provisional_anomaly_threshold={result.provisional_anomaly_threshold:.12g}")
    print(f"model={result.model_path}")
    print(f"scores={result.scores_path}")
    print(f"manifest={result.manifest_path}")


if __name__ == "__main__":
    main()
