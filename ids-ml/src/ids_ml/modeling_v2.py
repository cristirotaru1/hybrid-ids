"""Deterministic protocol-specific Isolation Forest workflow for model v2."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from ids_ml.dataset_v2 import (
    BEHAVIORAL_ADDITIONS_BY_PROTOCOL_V2,
    COMMON_BEHAVIORAL_COLUMNS_V2,
    DATASET_SCHEMA_VERSION_V2,
)

MODEL_VERSION_V2 = 2
RANDOM_SEED = 42
N_ESTIMATORS = 300
NORMAL_FALSE_POSITIVE_TARGET = 0.05
PROTOCOLS = ((1, "icmp"), (6, "tcp"), (17, "udp"))
FEATURE_PROFILES_V2 = {
    "current": {
        "description": "Current schema-v2 behavioral contract.",
        "excluded_by_protocol": {"icmp": (), "tcp": (), "udp": ()},
    },
    "omit_udp_icmp_rates": {
        "description": (
            "Exclude packets_per_second and bytes_per_second from UDP and ICMP."
        ),
        "excluded_by_protocol": {
            "icmp": ("packets_per_second", "bytes_per_second"),
            "tcp": (),
            "udp": ("packets_per_second", "bytes_per_second"),
        },
    },
    "minimal_udp_icmp_timing": {
        "description": (
            "Also exclude inter_arrival_mean from two-packet UDP and ICMP models."
        ),
        "excluded_by_protocol": {
            "icmp": (
                "packets_per_second",
                "bytes_per_second",
                "inter_arrival_mean",
            ),
            "tcp": (),
            "udp": (
                "packets_per_second",
                "bytes_per_second",
                "inter_arrival_mean",
            ),
        },
    },
}

SCORE_COLUMNS_V2 = (
    "flow_id",
    "capture_id",
    "scenario_id",
    "label",
    "split",
    "protocol",
    "protocol_name",
    "dst_port",
    "normality_score",
    "anomaly_score",
    "protocol_threshold",
    "threshold_margin",
    "behavioral_anomaly_flag",
)


class ModelV2DevelopmentError(ValueError):
    """Raised when the model-v2 behavioral contract is violated."""


@dataclass(frozen=True, slots=True)
class ModelV2DevelopmentResult:
    """Paths and row counts produced by a model-v2 behavioral fit."""

    model_path: Path
    scores_path: Path
    manifest_path: Path
    fit_row_counts: dict[str, int]
    calibration_row_counts: dict[str, int]
    thresholds: dict[str, float]


def train_protocol_isolation_forests(
    fit_dataset_path: str | Path,
    fit_manifest_path: str | Path,
    calibration_dataset_path: str | Path,
    calibration_manifest_path: str | Path,
    output_directory: str | Path,
    *,
    feature_profile: str = "current",
) -> ModelV2DevelopmentResult:
    """Fit one forest per protocol and calibrate independent normal cutoffs."""
    fit_dataset = Path(fit_dataset_path)
    fit_manifest_file = Path(fit_manifest_path)
    calibration_dataset = Path(calibration_dataset_path)
    calibration_manifest_file = Path(calibration_manifest_path)
    output_dir = Path(output_directory)
    try:
        profile = FEATURE_PROFILES_V2[feature_profile]
    except KeyError as error:
        choices = ", ".join(sorted(FEATURE_PROFILES_V2))
        raise ModelV2DevelopmentError(
            f"unknown feature profile {feature_profile!r}; choose one of: {choices}"
        ) from error

    fit_rows, fit_columns = _read_dataset(fit_dataset)
    calibration_rows, calibration_columns = _read_dataset(calibration_dataset)
    fit_manifest = _read_json(fit_manifest_file)
    calibration_manifest = _read_json(calibration_manifest_file)
    _validate_dataset(fit_dataset, fit_rows, fit_columns, fit_manifest, "fit")
    _validate_dataset(
        calibration_dataset,
        calibration_rows,
        calibration_columns,
        calibration_manifest,
        "calibration",
    )
    _validate_partition_separation(fit_rows, calibration_rows)
    _validate_feature_contracts(fit_manifest, calibration_manifest)

    rows_by_split = {
        "fit": _rows_by_protocol(fit_rows),
        "calibration": _rows_by_protocol(calibration_rows),
    }
    protocol_bundles: dict[str, dict[str, Any]] = {}
    scored: list[dict[str, Any]] = []
    thresholds: dict[str, float] = {}

    for protocol_number, protocol_name in PROTOCOLS:
        protocol_fit_rows = rows_by_split["fit"][protocol_name]
        protocol_calibration_rows = rows_by_split["calibration"][protocol_name]
        excluded_features = tuple(profile["excluded_by_protocol"][protocol_name])
        candidate_features = tuple(
            feature
            for feature in (
                COMMON_BEHAVIORAL_COLUMNS_V2
                + tuple(BEHAVIORAL_ADDITIONS_BY_PROTOCOL_V2[protocol_name])
            )
            if feature not in excluded_features
        )
        constant_features = _constant_features(protocol_fit_rows, candidate_features)
        learned_features = tuple(
            feature
            for feature in candidate_features
            if feature not in constant_features
        )
        if not learned_features:
            raise ModelV2DevelopmentError(
                f"{protocol_name}: every behavioral candidate is constant"
            )

        estimator = IsolationForest(
            n_estimators=N_ESTIMATORS,
            max_samples="auto",
            contamination="auto",
            bootstrap=False,
            random_state=RANDOM_SEED,
            n_jobs=1,
        )
        estimator.fit(_matrix(protocol_fit_rows, learned_features))
        calibration_scores = -estimator.score_samples(
            _matrix(protocol_calibration_rows, learned_features)
        )
        threshold = float(
            np.quantile(
                calibration_scores,
                1.0 - NORMAL_FALSE_POSITIVE_TARGET,
                method="linear",
            )
        )
        thresholds[protocol_name] = threshold

        for split in ("fit", "calibration"):
            protocol_rows = rows_by_split[split][protocol_name]
            anomaly_scores = -estimator.score_samples(
                _matrix(protocol_rows, learned_features)
            )
            scored.extend(
                _score_rows(
                    protocol_rows,
                    anomaly_scores,
                    split,
                    protocol_name,
                    threshold,
                )
            )

        protocol_bundles[protocol_name] = {
            "protocol_number": protocol_number,
            "estimator": estimator,
            "feature_profile_exclusions": excluded_features,
            "behavioral_candidate_features": candidate_features,
            "constant_features_dropped": constant_features,
            "learned_features": learned_features,
            "anomaly_threshold": threshold,
        }

    known_services = _known_services(fit_rows + calibration_rows)
    novelty_policy = _novelty_policy(fit_rows + calibration_rows, known_services)
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "models.joblib"
    scores_path = output_dir / "model_development_scores.csv"
    manifest_path = output_dir / "model_manifest.json"
    bundle = {
        "model_version": MODEL_VERSION_V2,
        "candidate": "v2_behavioral",
        "feature_profile": feature_profile,
        "protocol_models": protocol_bundles,
        "known_destination_services": known_services,
        "novelty_policy": novelty_policy,
        "score_direction": "higher anomaly_score means more anomalous behavior",
        "flag_rule": "anomaly_score > protocol_threshold",
        "fit_dataset_sha256": _sha256(fit_dataset),
        "calibration_dataset_sha256": _sha256(calibration_dataset),
    }
    joblib.dump(bundle, model_path, compress=3)
    _write_scores(scores_path, scored)

    metrics = {
        protocol_name: {
            split: _score_metrics(
                [
                    row
                    for row in scored
                    if row["protocol_name"] == protocol_name and row["split"] == split
                ]
            )
            for split in ("fit", "calibration")
        }
        for _, protocol_name in PROTOCOLS
    }
    manifest = {
        "model_version": MODEL_VERSION_V2,
        "candidate": "v2_behavioral",
        "feature_profile": {
            "name": feature_profile,
            "description": profile["description"],
            "excluded_by_protocol": {
                name: list(excluded)
                for name, excluded in profile["excluded_by_protocol"].items()
            },
        },
        "status": "development-only",
        "limitation": (
            "Normal-only fitting and calibration do not measure anomalous-scenario "
            "detection. Semantic novelty rules are not part of this candidate."
        ),
        "datasets": {
            "fit": _dataset_provenance(fit_dataset, fit_manifest_file, fit_manifest),
            "calibration": _dataset_provenance(
                calibration_dataset,
                calibration_manifest_file,
                calibration_manifest,
            ),
        },
        "split": {
            "method": "capture-based; no random row split",
            "fit_capture_ids": _capture_ids(fit_rows),
            "calibration_capture_ids": _capture_ids(calibration_rows),
            "row_counts_by_protocol": {
                split: {
                    protocol_name: len(rows_by_split[split][protocol_name])
                    for _, protocol_name in PROTOCOLS
                }
                for split in ("fit", "calibration")
            },
        },
        "protocol_models": {
            name: {
                key: list(value) if isinstance(value, tuple) else value
                for key, value in protocol_bundle.items()
                if key != "estimator"
            }
            for name, protocol_bundle in protocol_bundles.items()
        },
        "known_destination_services": {
            "definition": (
                "positive TCP/UDP destination ports intentionally observed in "
                "accepted normal fit or calibration, including isolated normal "
                "operational failures"
            ),
            "services_by_protocol": known_services,
            "normal_failed_tcp_ports_included": sorted(
                {
                    _finite_int(row, "dst_port")
                    for row in fit_rows + calibration_rows
                    if _finite_int(row, "protocol") == 6
                    and _finite_int(row, "current_tcp_failed") == 1
                }
            ),
        },
        "novelty_policy": novelty_policy,
        "estimator": {
            "class": "sklearn.ensemble.IsolationForest",
            "n_estimators": N_ESTIMATORS,
            "max_samples": "auto",
            "contamination": "auto",
            "bootstrap": False,
            "random_state": RANDOM_SEED,
            "n_jobs": 1,
            "scaling": "none",
        },
        "threshold": {
            "definition": "95th percentile of independent normal calibration scores",
            "target_normal_false_positive_fraction": NORMAL_FALSE_POSITIVE_TARGET,
            "quantile_method": "linear",
            "flag_rule": "anomaly_score > protocol_threshold",
        },
        "metrics": metrics,
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

    return ModelV2DevelopmentResult(
        model_path=model_path,
        scores_path=scores_path,
        manifest_path=manifest_path,
        fit_row_counts={name: len(rows_by_split["fit"][name]) for _, name in PROTOCOLS},
        calibration_row_counts={
            name: len(rows_by_split["calibration"][name]) for _, name in PROTOCOLS
        },
        thresholds=thresholds,
    )


def _validate_dataset(
    dataset: Path,
    rows: list[dict[str, str]],
    columns: tuple[str, ...],
    manifest: dict[str, Any],
    split: str,
) -> None:
    actual_hash = _sha256(dataset)
    if manifest.get("dataset_sha256") != actual_hash:
        raise ModelV2DevelopmentError(
            f"{split} dataset SHA-256 does not match its manifest"
        )
    if manifest.get("dataset_schema_version") != DATASET_SCHEMA_VERSION_V2:
        raise ModelV2DevelopmentError(f"{split} dataset is not schema version 2")
    if len(rows) != manifest.get("row_count"):
        raise ModelV2DevelopmentError(
            f"{split} dataset row count does not match its manifest"
        )
    required = {
        "flow_id",
        "capture_id",
        "scenario_id",
        "label",
        "protocol",
        "dst_port",
        "current_tcp_failed",
        *COMMON_BEHAVIORAL_COLUMNS_V2,
        *BEHAVIORAL_ADDITIONS_BY_PROTOCOL_V2["tcp"],
    }
    missing = required - set(columns)
    if missing:
        raise ModelV2DevelopmentError(
            f"{split} dataset is missing columns: {', '.join(sorted(missing))}"
        )
    if not rows:
        raise ModelV2DevelopmentError(f"{split} dataset contains no rows")
    if any(row["label"] != "normal" for row in rows):
        raise ModelV2DevelopmentError(f"{split} dataset must be normal-only")


def _validate_feature_contracts(
    fit_manifest: dict[str, Any], calibration_manifest: dict[str, Any]
) -> None:
    keys = ("behavioral_common", "behavioral_additions_by_protocol")
    for key in keys:
        if fit_manifest["columns"].get(key) != calibration_manifest["columns"].get(key):
            raise ModelV2DevelopmentError(
                f"fit and calibration disagree on the {key} contract"
            )


def _validate_partition_separation(
    fit_rows: list[dict[str, str]], calibration_rows: list[dict[str, str]]
) -> None:
    overlap = set(_capture_ids(fit_rows)) & set(_capture_ids(calibration_rows))
    if overlap:
        raise ModelV2DevelopmentError(
            "fit and calibration capture IDs overlap: " + ", ".join(sorted(overlap))
        )


def _rows_by_protocol(
    rows: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    protocol_names = dict(PROTOCOLS)
    grouped = {name: [] for _, name in PROTOCOLS}
    for row in rows:
        number = _finite_int(row, "protocol")
        try:
            grouped[protocol_names[number]].append(row)
        except KeyError as error:
            raise ModelV2DevelopmentError(
                f"{row['flow_id']}: unsupported protocol {number}"
            ) from error
    for name, protocol_rows in grouped.items():
        if not protocol_rows:
            raise ModelV2DevelopmentError(f"dataset has no {name} rows")
    return grouped


def _constant_features(
    rows: list[dict[str, str]], candidates: tuple[str, ...]
) -> tuple[str, ...]:
    return tuple(
        feature
        for feature in candidates
        if len({_finite_float(row, feature) for row in rows}) == 1
    )


def _matrix(rows: list[dict[str, str]], features: tuple[str, ...]) -> np.ndarray:
    matrix = np.asarray(
        [[_finite_float(row, feature) for feature in features] for row in rows],
        dtype=np.float64,
    )
    if matrix.ndim != 2 or not np.isfinite(matrix).all():
        raise ModelV2DevelopmentError("behavioral features must form a finite matrix")
    return matrix


def _score_rows(
    rows: list[dict[str, str]],
    anomaly_scores: np.ndarray,
    split: str,
    protocol_name: str,
    threshold: float,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row, anomaly_score in zip(rows, anomaly_scores, strict=True):
        score = float(anomaly_score)
        output.append(
            {
                "flow_id": row["flow_id"],
                "capture_id": row["capture_id"],
                "scenario_id": row["scenario_id"],
                "label": row["label"],
                "split": split,
                "protocol": row["protocol"],
                "protocol_name": protocol_name,
                "dst_port": row["dst_port"],
                "normality_score": -score,
                "anomaly_score": score,
                "protocol_threshold": threshold,
                "threshold_margin": score - threshold,
                "behavioral_anomaly_flag": score > threshold,
            }
        )
    return output


def _known_services(rows: list[dict[str, str]]) -> dict[str, list[int]]:
    services = {"tcp": set(), "udp": set()}
    protocol_names = {6: "tcp", 17: "udp"}
    for row in rows:
        protocol = _finite_int(row, "protocol")
        if protocol not in protocol_names:
            continue
        destination_port = _finite_int(row, "dst_port")
        if destination_port > 0:
            services[protocol_names[protocol]].add(destination_port)
    return {name: sorted(ports) for name, ports in services.items()}


def _novelty_policy(
    rows: list[dict[str, str]], known_services: dict[str, list[int]]
) -> dict[str, Any]:
    grouped = _rows_by_protocol(rows)
    envelope_columns = (
        "same_protocol_flows_last_10s",
        "unique_dst_ips_last_10s",
        "unique_dst_ports_last_10s",
    )
    envelopes = {
        protocol_name: {
            column: max(_finite_float(row, column) for row in protocol_rows)
            for column in envelope_columns
        }
        for protocol_name, protocol_rows in grouped.items()
    }
    icmp_type_codes = sorted(
        {
            (_finite_int(row, "icmp_type_group"), _finite_int(row, "icmp_code"))
            for row in grouped["icmp"]
        }
    )
    return {
        "policy_version": 1,
        "boundary_provenance": (
            "strict maximum observed across accepted normal fit and calibration rows"
        ),
        "known_destination_services": known_services,
        "seen_icmp_type_codes": [list(values) for values in icmp_type_codes],
        "numeric_upper_boundaries_by_protocol": envelopes,
        "tcp_failure_burst": {
            "definition": (
                "current_tcp_failed + failed_tcp_connections_last_10s >= 2 "
                "and current_tcp_failed == 1"
            ),
            "minimum_failures_including_current": 2,
        },
        "comparison": "numeric novelty is flagged only when value > boundary",
    }


def _score_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [float(row["anomaly_score"]) for row in rows]
    flagged = sum(bool(row["behavioral_anomaly_flag"]) for row in rows)
    capture_counts = Counter(
        row["capture_id"] for row in rows if row["behavioral_anomaly_flag"]
    )
    return {
        "row_count": len(rows),
        "anomaly_score_minimum": min(scores),
        "anomaly_score_mean": fmean(scores),
        "anomaly_score_median": float(np.median(scores)),
        "anomaly_score_maximum": max(scores),
        "flagged_count": flagged,
        "flagged_fraction": flagged / len(rows),
        "flagged_counts_by_capture": dict(sorted(capture_counts.items())),
    }


def _dataset_provenance(
    dataset: Path, manifest_file: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    return {
        "file": dataset.as_posix(),
        "sha256": _sha256(dataset),
        "manifest_file": manifest_file.as_posix(),
        "manifest_sha256": _sha256(manifest_file),
        "schema_version": manifest["dataset_schema_version"],
        "extractor_version": manifest["extractor_version"],
        "source_manifest_sha256": manifest["source_manifest_sha256"],
    }


def _capture_ids(rows: list[dict[str, str]]) -> list[str]:
    return list(dict.fromkeys(row["capture_id"] for row in rows))


def _read_dataset(path: Path) -> tuple[list[dict[str, str]], tuple[str, ...]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            return list(reader), tuple(reader.fieldnames or ())
    except OSError as error:
        raise ModelV2DevelopmentError(f"cannot read dataset {path}: {error}") from error


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ModelV2DevelopmentError(f"cannot read JSON {path}: {error}") from error


def _finite_float(row: dict[str, str], column: str) -> float:
    try:
        value = float(row[column])
    except (KeyError, ValueError) as error:
        raise ModelV2DevelopmentError(
            f"{row.get('flow_id', '<unknown>')}: invalid {column}"
        ) from error
    if not math.isfinite(value):
        raise ModelV2DevelopmentError(
            f"{row.get('flow_id', '<unknown>')}: non-finite {column}"
        )
    return value


def _finite_int(row: dict[str, str], column: str) -> int:
    value = _finite_float(row, column)
    if not value.is_integer():
        raise ModelV2DevelopmentError(
            f"{row.get('flow_id', '<unknown>')}: {column} is not an integer"
        )
    return int(value)


def _write_scores(path: Path, rows: list[dict[str, Any]]) -> None:
    ordered = sorted(rows, key=lambda row: (row["split"], row["flow_id"]))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=SCORE_COLUMNS_V2, lineterminator="\n"
        )
        writer.writeheader()
        for row in ordered:
            writer.writerow(
                {
                    **row,
                    "normality_score": repr(row["normality_score"]),
                    "anomaly_score": repr(row["anomaly_score"]),
                    "protocol_threshold": repr(row["protocol_threshold"]),
                    "threshold_margin": repr(row["threshold_margin"]),
                    "behavioral_anomaly_flag": str(
                        row["behavioral_anomaly_flag"]
                    ).lower(),
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
    """Train model-v2 behavioral forests from frozen fit/calibration data."""
    parser = argparse.ArgumentParser(
        description="Train protocol-specific Isolation Forest model v2."
    )
    parser.add_argument(
        "--fit-dataset",
        type=Path,
        default=Path("data/derived/v2/model_v2_fit/flows_v2.csv"),
    )
    parser.add_argument(
        "--fit-manifest",
        type=Path,
        default=Path("data/derived/v2/model_v2_fit/manifest_v2.json"),
    )
    parser.add_argument(
        "--calibration-dataset",
        type=Path,
        default=Path("data/derived/v2/normal_v3_calibration/flows_v2.csv"),
    )
    parser.add_argument(
        "--calibration-manifest",
        type=Path,
        default=Path("data/derived/v2/normal_v3_calibration/manifest_v2.json"),
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("artifacts/isolation_forest_v2_behavioral"),
    )
    parser.add_argument(
        "--feature-profile",
        choices=tuple(FEATURE_PROFILES_V2),
        default="current",
        help="Frozen protocol behavioral feature profile.",
    )
    args = parser.parse_args()
    result = train_protocol_isolation_forests(
        args.fit_dataset,
        args.fit_manifest,
        args.calibration_dataset,
        args.calibration_manifest,
        args.output_directory,
        feature_profile=args.feature_profile,
    )
    print(
        "trained protocol models with fit rows "
        f"{result.fit_row_counts} and calibration rows "
        f"{result.calibration_row_counts}"
    )


if __name__ == "__main__":
    main()
