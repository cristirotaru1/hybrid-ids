"""Deterministic data-quality inspection for an exported flow dataset."""

from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from statistics import fmean
from typing import Any

MINIMUM_SCREENING_ROWS = 100
ZERO_DOMINATED_FRACTION = 0.90
QUALITY_REPORT_FILENAME = "quality_report_v1.json"


class DataQualityError(ValueError):
    """Raised when dataset artifacts cannot be inspected safely."""


def analyze_dataset(
    dataset_path: str | Path,
    manifest_path: str | Path,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Inspect an exported dataset and optionally write a deterministic report."""
    dataset = Path(dataset_path)
    manifest_file = Path(manifest_path)
    manifest = _read_json(manifest_file)
    rows, columns = _read_csv(dataset)
    _validate_manifest(dataset, rows, manifest)

    model_columns = tuple(manifest["columns"]["model_features"])
    missing_columns = set(model_columns) - set(columns)
    if missing_columns:
        raise DataQualityError(
            f"dataset is missing model columns: {', '.join(sorted(missing_columns))}"
        )

    numeric_values, missing_counts, nonfinite_counts = _numeric_columns(
        rows, model_columns
    )
    summaries = {
        column: _numeric_summary(numeric_values[column]) for column in model_columns
    }
    constant_features = [
        column for column in model_columns if summaries[column]["unique_count"] == 1
    ]
    zero_dominated_features = [
        column
        for column in model_columns
        if summaries[column]["zero_fraction"] >= ZERO_DOMINATED_FRACTION
    ]
    duplicate_flow_ids = _duplicates(row.get("flow_id", "") for row in rows)
    duplicate_model_rows = _duplicate_model_row_count(rows, model_columns)

    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    if any(missing_counts.values()):
        errors.append(
            _finding("missing_values", "Model features contain empty values.")
        )
    if any(nonfinite_counts.values()):
        errors.append(
            _finding("nonfinite_values", "Model features contain NaN or infinity.")
        )
    if duplicate_flow_ids:
        errors.append(_finding("duplicate_flow_ids", "Flow IDs are not unique."))
    if len(rows) < MINIMUM_SCREENING_ROWS:
        warnings.append(
            _finding(
                "small_dataset",
                f"Only {len(rows)} flow rows are available; the screening heuristic "
                f"is at least {MINIMUM_SCREENING_ROWS}.",
            )
        )
    label_counts = _counts(rows, "label")
    if len(label_counts) < 2:
        warnings.append(
            _finding(
                "single_label",
                "Only one label is present; no anomalous/attack evaluation rows exist.",
            )
        )
    if constant_features:
        warnings.append(
            _finding(
                "constant_features",
                f"{len(constant_features)} model features are constant and add no "
                "separation in this dataset.",
            )
        )
    history_columns = set(model_columns) & {
        "flows_last_10s",
        "unique_dst_ips_last_10s",
        "unique_dst_ports_last_10s",
        "connection_rate_last_10s",
        "failed_connection_rate_last_10s",
    }
    if history_columns and history_columns <= set(constant_features):
        warnings.append(
            _finding(
                "no_history_signal",
                "All source-history features are constant in the available captures.",
            )
        )
    empty_capture_ids = manifest.get("empty_capture_ids", [])
    if empty_capture_ids:
        warnings.append(
            _finding(
                "empty_captures",
                f"{len(empty_capture_ids)} source capture produced no flow rows.",
            )
        )
    unverified_interfaces = sum(row.get("interface") == "unverified" for row in rows)
    if unverified_interfaces:
        warnings.append(
            _finding(
                "unverified_interface",
                f"{unverified_interfaces} rows come from a capture with an "
                "unverified interface.",
            )
        )

    report: dict[str, Any] = {
        "quality_report_version": 1,
        "dataset_file": dataset.name,
        "dataset_sha256": _sha256(dataset),
        "dataset_schema_version": manifest["dataset_schema_version"],
        "row_count": len(rows),
        "model_feature_count": len(model_columns),
        "capture_counts": _counts(rows, "capture_id"),
        "label_counts": label_counts,
        "protocol_counts": _counts(rows, "protocol"),
        "termination_counts": _counts(rows, "termination_reason"),
        "interface_counts": _counts(rows, "interface"),
        "empty_capture_ids": empty_capture_ids,
        "missing_value_counts": missing_counts,
        "nonfinite_value_counts": nonfinite_counts,
        "duplicate_flow_ids": duplicate_flow_ids,
        "duplicate_model_row_count": duplicate_model_rows,
        "constant_features": constant_features,
        "zero_dominated_features": zero_dominated_features,
        "feature_summaries": summaries,
        "exact_relationships": _exact_relationships(rows),
        "extreme_rows": _extreme_rows(rows),
        "screening": {
            "minimum_row_heuristic": MINIMUM_SCREENING_ROWS,
            "zero_dominated_fraction": ZERO_DOMINATED_FRACTION,
        },
        "errors": errors,
        "warnings": warnings,
        "ready_for_model_training": not errors and not warnings,
    }
    if output_path is not None:
        _write_json(Path(output_path), report)
    return report


def _numeric_columns(
    rows: list[dict[str, str]], columns: tuple[str, ...]
) -> tuple[dict[str, list[float]], dict[str, int], dict[str, int]]:
    values = {column: [] for column in columns}
    missing = {column: 0 for column in columns}
    nonfinite = {column: 0 for column in columns}
    for row_number, row in enumerate(rows, start=2):
        for column in columns:
            raw = row.get(column, "")
            if raw == "":
                missing[column] += 1
                continue
            try:
                value = float(raw)
            except ValueError as error:
                raise DataQualityError(
                    f"row {row_number}, column {column}: not numeric"
                ) from error
            if not math.isfinite(value):
                nonfinite[column] += 1
                continue
            values[column].append(value)
    return values, missing, nonfinite


def _numeric_summary(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {
            "count": 0,
            "unique_count": 0,
            "minimum": None,
            "q1": None,
            "median": None,
            "q3": None,
            "maximum": None,
            "mean": None,
            "zero_fraction": 0.0,
        }
    ordered = sorted(values)
    return {
        "count": len(values),
        "unique_count": len(set(values)),
        "minimum": ordered[0],
        "q1": _quantile(ordered, 0.25),
        "median": _quantile(ordered, 0.5),
        "q3": _quantile(ordered, 0.75),
        "maximum": ordered[-1],
        "mean": fmean(ordered),
        "zero_fraction": sum(value == 0 for value in ordered) / len(ordered),
    }


def _quantile(ordered: list[float], fraction: float) -> float:
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[upper] * weight + ordered[lower] * (1 - weight)


def _exact_relationships(rows: list[dict[str, str]]) -> dict[str, bool]:
    return {
        "total_packet_count_equals_forward_plus_backward": all(
            int(row["total_packet_count"])
            == int(row["forward_packet_count"]) + int(row["backward_packet_count"])
            for row in rows
        ),
        "total_bytes_equals_forward_plus_backward": all(
            int(row["total_bytes"])
            == int(row["forward_bytes"]) + int(row["backward_bytes"])
            for row in rows
        ),
    }


def _extreme_rows(rows: list[dict[str, str]]) -> dict[str, dict[str, Any] | None]:
    return {
        column: _maximum_row(rows, column)
        for column in (
            "flow_duration",
            "total_packet_count",
            "total_bytes",
            "packets_per_second",
            "bytes_per_second",
            "inter_arrival_std",
        )
    }


def _maximum_row(rows: list[dict[str, str]], column: str) -> dict[str, Any] | None:
    candidates = [row for row in rows if row.get(column, "") != ""]
    if not candidates:
        return None
    row = max(candidates, key=lambda item: float(item[column]))
    return {
        "flow_id": row["flow_id"],
        "capture_id": row["capture_id"],
        "protocol": int(row["protocol"]),
        "value": float(row[column]),
    }


def _duplicates(values: Any) -> list[str]:
    counts = Counter(values)
    return sorted(value for value, count in counts.items() if count > 1)


def _duplicate_model_row_count(
    rows: list[dict[str, str]], columns: tuple[str, ...]
) -> int:
    signatures = Counter(tuple(row[column] for column in columns) for row in rows)
    return sum(count - 1 for count in signatures.values() if count > 1)


def _counts(rows: list[dict[str, str]], column: str) -> dict[str, int]:
    return dict(sorted(Counter(row.get(column, "") for row in rows).items()))


def _finding(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _read_csv(path: Path) -> tuple[list[dict[str, str]], tuple[str, ...]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
            columns = tuple(reader.fieldnames or ())
    except OSError as error:
        raise DataQualityError(f"cannot read dataset {path}: {error}") from error
    if not columns:
        raise DataQualityError("dataset has no header")
    return rows, columns


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DataQualityError(
            f"cannot read dataset manifest {path}: {error}"
        ) from error


def _validate_manifest(
    dataset: Path, rows: list[dict[str, str]], manifest: dict[str, Any]
) -> None:
    if _sha256(dataset) != manifest.get("dataset_sha256"):
        raise DataQualityError("dataset SHA-256 does not match its manifest")
    if len(rows) != manifest.get("row_count"):
        raise DataQualityError("dataset row count does not match its manifest")
    try:
        manifest["columns"]["model_features"]
        manifest["dataset_schema_version"]
    except KeyError as error:
        raise DataQualityError(
            f"dataset manifest is missing {error.args[0]}"
        ) from error


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> None:
    """Inspect the default version 1 dataset and write its quality report."""
    output = Path("data/derived") / QUALITY_REPORT_FILENAME
    report = analyze_dataset(
        "data/derived/flows_v1.csv",
        "data/derived/manifest_v1.json",
        output,
    )
    print(
        f"inspected {report['row_count']} rows: {len(report['errors'])} errors, "
        f"{len(report['warnings'])} warnings; wrote {output}"
    )
