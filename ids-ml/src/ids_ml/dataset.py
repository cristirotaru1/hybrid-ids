"""Deterministic version 1 CSV dataset export and provenance manifest."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ids_ml import __version__
from ids_ml.features import FlowFeatures, calculate_flow_features
from ids_ml.flows import Flow, FlowTimeouts, build_flows
from ids_ml.history import (
    DEFAULT_WINDOW_SECONDS,
    SourceHistoryFeatures,
    calculate_source_history,
)
from ids_ml.packets import iter_pcap_packets

DATASET_SCHEMA_VERSION = 1
DATASET_FILENAME = "flows_v1.csv"
DATASET_MANIFEST_FILENAME = "manifest_v1.json"

METADATA_COLUMNS = (
    "schema_version",
    "extractor_version",
    "capture_id",
    "scenario_id",
    "label",
    "validation_status",
    "interface",
    "source_pcap",
    "source_pcap_sha256",
    "flow_id",
    "flow_start_utc",
    "flow_end_utc",
    "src_ip",
    "dst_ip",
    "termination_reason",
)
FLOW_FEATURE_COLUMNS = tuple(FlowFeatures.__dataclass_fields__)
HISTORY_FEATURE_COLUMNS = tuple(SourceHistoryFeatures.__dataclass_fields__)
DATASET_COLUMNS = METADATA_COLUMNS + FLOW_FEATURE_COLUMNS + HISTORY_FEATURE_COLUMNS


@dataclass(frozen=True, slots=True)
class CaptureMetadata:
    """Manifest fields required to trace an exported flow to its source."""

    capture_id: str
    scenario_id: str
    label: str
    validation_status: str
    interface: str
    filename: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class DatasetExportResult:
    """Paths and counts produced by a completed dataset export."""

    dataset_path: Path
    manifest_path: Path
    row_count: int
    capture_count: int
    empty_capture_ids: tuple[str, ...]


class DatasetExportError(ValueError):
    """Raised when source metadata or captures fail export validation."""


def export_dataset(
    capture_manifest_path: str | Path,
    output_directory: str | Path,
    *,
    timeouts: FlowTimeouts | None = None,
    history_window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> DatasetExportResult:
    """Export all manifest captures to deterministic CSV and JSON artifacts."""
    source_manifest = Path(capture_manifest_path)
    output_dir = Path(output_directory)
    timeout_config = timeouts or FlowTimeouts()
    captures = _read_capture_manifest(source_manifest)
    source_manifest_hash = _sha256(source_manifest)
    rows: list[dict[str, Any]] = []
    input_records: list[dict[str, Any]] = []
    empty_capture_ids: list[str] = []

    for capture in captures:
        pcap_path = source_manifest.parent / capture.filename
        _validate_source_capture(pcap_path, capture)
        flows = build_flows(iter_pcap_packets(pcap_path), timeout_config)
        enriched_flows = calculate_source_history(flows, history_window_seconds)
        if not flows:
            empty_capture_ids.append(capture.capture_id)

        for flow_index, item in enumerate(enriched_flows, start=1):
            rows.append(
                _dataset_row(
                    capture,
                    item.flow,
                    item.history,
                    flow_index,
                )
            )

        input_records.append(
            {
                "capture_id": capture.capture_id,
                "filename": capture.filename,
                "sha256": capture.sha256,
                "size_bytes": capture.size_bytes,
                "flow_count": len(flows),
            }
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_path = output_dir / DATASET_FILENAME
    manifest_path = output_dir / DATASET_MANIFEST_FILENAME
    _write_csv(dataset_path, rows)
    dataset_hash = _sha256(dataset_path)
    manifest = _dataset_manifest(
        source_manifest,
        source_manifest_hash,
        dataset_hash,
        rows,
        input_records,
        empty_capture_ids,
        timeout_config,
        history_window_seconds,
    )
    _write_json(manifest_path, manifest)

    return DatasetExportResult(
        dataset_path=dataset_path,
        manifest_path=manifest_path,
        row_count=len(rows),
        capture_count=len(captures),
        empty_capture_ids=tuple(empty_capture_ids),
    )


def _read_capture_manifest(path: Path) -> list[CaptureMetadata]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    except OSError as error:
        raise DatasetExportError(
            f"cannot read capture manifest {path}: {error}"
        ) from error

    required = {
        "capture_id",
        "scenario_id",
        "label",
        "validation_status",
        "interface",
        "filename",
        "sha256",
        "size_bytes",
    }
    if not rows:
        raise DatasetExportError("capture manifest contains no captures")
    missing = required - set(rows[0])
    if missing:
        raise DatasetExportError(
            f"capture manifest is missing columns: {', '.join(sorted(missing))}"
        )

    captures: list[CaptureMetadata] = []
    seen_ids: set[str] = set()
    for row_number, row in enumerate(rows, start=2):
        capture_id = row["capture_id"]
        if not capture_id or capture_id in seen_ids:
            raise DatasetExportError(
                f"capture manifest row {row_number}: capture_id is empty or duplicated"
            )
        seen_ids.add(capture_id)
        try:
            size_bytes = int(row["size_bytes"])
        except ValueError as error:
            raise DatasetExportError(
                f"capture manifest row {row_number}: invalid size_bytes"
            ) from error
        captures.append(
            CaptureMetadata(
                capture_id=capture_id,
                scenario_id=row["scenario_id"],
                label=row["label"],
                validation_status=row["validation_status"],
                interface=row["interface"],
                filename=row["filename"],
                sha256=row["sha256"],
                size_bytes=size_bytes,
            )
        )
    return captures


def _validate_source_capture(path: Path, capture: CaptureMetadata) -> None:
    try:
        size_bytes = path.stat().st_size
    except OSError as error:
        raise DatasetExportError(
            f"cannot read source capture {path}: {error}"
        ) from error
    if size_bytes != capture.size_bytes:
        raise DatasetExportError(
            f"{capture.capture_id}: size is {size_bytes}, "
            f"manifest says {capture.size_bytes}"
        )
    actual_hash = _sha256(path)
    if actual_hash != capture.sha256:
        raise DatasetExportError(
            f"{capture.capture_id}: SHA-256 {actual_hash} does not match manifest"
        )


def _dataset_row(
    capture: CaptureMetadata,
    flow: Flow,
    history: SourceHistoryFeatures,
    flow_index: int,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "schema_version": DATASET_SCHEMA_VERSION,
        "extractor_version": __version__,
        "capture_id": capture.capture_id,
        "scenario_id": capture.scenario_id,
        "label": capture.label,
        "validation_status": capture.validation_status,
        "interface": capture.interface,
        "source_pcap": capture.filename,
        "source_pcap_sha256": capture.sha256,
        "flow_id": f"{capture.capture_id}:{flow_index:06d}",
        "flow_start_utc": _timestamp_utc(flow.start_timestamp_ns),
        "flow_end_utc": _timestamp_utc(flow.end_timestamp_ns),
        "src_ip": flow.forward_endpoint.ip,
        "dst_ip": flow.backward_endpoint.ip,
        "termination_reason": flow.termination_reason.value,
    }
    row.update(asdict(calculate_flow_features(flow)))
    row.update(asdict(history))
    if tuple(row) != DATASET_COLUMNS:
        raise DatasetExportError("dataset row does not match the version 1 schema")
    return row


def _timestamp_utc(timestamp_ns: int) -> str:
    seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
    base = datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{nanoseconds:09d}Z"


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=DATASET_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _dataset_manifest(
    source_manifest: Path,
    source_manifest_hash: str,
    dataset_hash: str,
    rows: list[dict[str, Any]],
    inputs: list[dict[str, Any]],
    empty_capture_ids: list[str],
    timeouts: FlowTimeouts,
    history_window_seconds: int,
) -> dict[str, Any]:
    return {
        "dataset_schema_version": DATASET_SCHEMA_VERSION,
        "extractor_version": __version__,
        "format": "csv",
        "dataset_file": DATASET_FILENAME,
        "dataset_sha256": dataset_hash,
        "row_count": len(rows),
        "capture_count": len(inputs),
        "empty_capture_ids": empty_capture_ids,
        "source_manifest": source_manifest.name,
        "source_manifest_sha256": source_manifest_hash,
        "columns": {
            "metadata": list(METADATA_COLUMNS),
            "model_features": list(FLOW_FEATURE_COLUMNS + HISTORY_FEATURE_COLUMNS),
        },
        "configuration": {
            "byte_count_basis": "ipv4_total_length",
            "tcp_idle_timeout_seconds": timeouts.tcp_ns / 1_000_000_000,
            "udp_idle_timeout_seconds": timeouts.udp_ns / 1_000_000_000,
            "icmp_idle_timeout_seconds": timeouts.icmp_ns / 1_000_000_000,
            "source_history_window_seconds": history_window_seconds,
        },
        "inputs": inputs,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    """Export the repository's validated captures using default version 1 paths."""
    result = export_dataset("pcaps/manifest.csv", "data/derived")
    print(
        f"exported {result.row_count} flows from {result.capture_count} captures "
        f"to {result.dataset_path}"
    )
