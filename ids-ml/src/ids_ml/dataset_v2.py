"""Deterministic dataset export for feature and history schema version 2."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ids_ml.dataset import CaptureMetadata, DatasetExportError
from ids_ml.features_v2 import FlowFeaturesV2, calculate_flow_features_v2
from ids_ml.flows import Flow, FlowTimeouts, build_flows
from ids_ml.history import DEFAULT_WINDOW_SECONDS
from ids_ml.history_v2 import (
    SourceHistoryFeaturesV2,
    calculate_source_history_v2,
)
from ids_ml.packets import iter_pcap_packets

DATASET_SCHEMA_VERSION_V2 = 2
FEATURE_SCHEMA_VERSION_V2 = 2
HISTORY_SCHEMA_VERSION_V2 = 2
EXTRACTOR_VERSION_V2 = "0.3.0"
DATASET_FILENAME_V2 = "flows_v2.csv"
DATASET_MANIFEST_FILENAME_V2 = "manifest_v2.json"

METADATA_COLUMNS_V2 = (
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
FLOW_FEATURE_COLUMNS_V2 = tuple(FlowFeaturesV2.__dataclass_fields__)
HISTORY_FEATURE_COLUMNS_V2 = tuple(SourceHistoryFeaturesV2.__dataclass_fields__)
EXPORTED_FEATURE_COLUMNS_V2 = FLOW_FEATURE_COLUMNS_V2 + HISTORY_FEATURE_COLUMNS_V2
DATASET_COLUMNS_V2 = METADATA_COLUMNS_V2 + EXPORTED_FEATURE_COLUMNS_V2

CONTEXT_ONLY_COLUMNS_V2 = ("src_port",)
PROTOCOL_ROUTING_COLUMNS_V2 = ("protocol",)
REDUNDANT_EXCLUDED_COLUMNS_V2 = ("total_packet_count", "total_bytes")

COMMON_BEHAVIORAL_COLUMNS_V2 = (
    "flow_duration",
    "forward_packet_count",
    "backward_packet_count",
    "forward_bytes",
    "backward_bytes",
    "mean_packet_size",
    "std_packet_size",
    "packets_per_second",
    "bytes_per_second",
    "inter_arrival_mean",
    "inter_arrival_std",
    "flows_last_10s",
    "unique_dst_ips_last_10s",
    "unique_dst_ports_last_10s",
    "connection_rate_last_10s",
    "same_protocol_flows_last_10s",
)
BEHAVIORAL_ADDITIONS_BY_PROTOCOL_V2 = {
    "icmp": (),
    "tcp": ("syn_count", "ack_count", "fin_count"),
    "udp": (),
}
NOVELTY_POLICY_COLUMNS_V2 = (
    "dst_port",
    "rst_count",
    "current_tcp_failed",
    "icmp_type_group",
    "icmp_code",
    "icmp_is_error",
    "same_protocol_flows_last_10s",
    "unique_dst_ips_last_10s",
    "unique_dst_ports_last_10s",
    "tcp_attempts_last_10s",
    "failed_tcp_connections_last_10s",
    "failed_connection_rate_last_10s",
)


@dataclass(frozen=True, slots=True)
class DatasetV2ExportResult:
    """Paths and counts produced by a completed schema-v2 export."""

    dataset_path: Path
    manifest_path: Path
    row_count: int
    capture_count: int
    empty_capture_ids: tuple[str, ...]


def export_dataset_v2(
    capture_manifest_path: str | Path,
    output_directory: str | Path,
    *,
    timeouts: FlowTimeouts | None = None,
    history_window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> DatasetV2ExportResult:
    """Export validated captures without modifying source PCAPs or v1 data."""
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
        flows = build_flows(
            iter_pcap_packets(pcap_path),
            timeout_config,
            linger_terminated_tcp=True,
        )
        enriched_flows = calculate_source_history_v2(flows, history_window_seconds)
        if not flows:
            empty_capture_ids.append(capture.capture_id)

        for flow_index, item in enumerate(enriched_flows, start=1):
            rows.append(_dataset_row_v2(capture, item.flow, item.history, flow_index))

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
    dataset_path = output_dir / DATASET_FILENAME_V2
    manifest_path = output_dir / DATASET_MANIFEST_FILENAME_V2
    _write_csv(dataset_path, rows)
    dataset_hash = _sha256(dataset_path)
    manifest = _dataset_manifest_v2(
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

    return DatasetV2ExportResult(
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


def _dataset_row_v2(
    capture: CaptureMetadata,
    flow: Flow,
    history: SourceHistoryFeaturesV2,
    flow_index: int,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "schema_version": DATASET_SCHEMA_VERSION_V2,
        "extractor_version": EXTRACTOR_VERSION_V2,
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
    row.update(asdict(calculate_flow_features_v2(flow)))
    row.update(asdict(history))
    if tuple(row) != DATASET_COLUMNS_V2:
        raise DatasetExportError("dataset row does not match schema version 2")
    return row


def _timestamp_utc(timestamp_ns: int) -> str:
    seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
    base = datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{nanoseconds:09d}Z"


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=DATASET_COLUMNS_V2, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


def _dataset_manifest_v2(
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
        "dataset_schema_version": DATASET_SCHEMA_VERSION_V2,
        "flow_feature_schema_version": FEATURE_SCHEMA_VERSION_V2,
        "source_history_schema_version": HISTORY_SCHEMA_VERSION_V2,
        "extractor_version": EXTRACTOR_VERSION_V2,
        "format": "csv",
        "dataset_file": DATASET_FILENAME_V2,
        "dataset_sha256": dataset_hash,
        "row_count": len(rows),
        "capture_count": len(inputs),
        "empty_capture_ids": empty_capture_ids,
        "source_manifest": source_manifest.name,
        "source_manifest_sha256": source_manifest_hash,
        "columns": {
            "all": list(DATASET_COLUMNS_V2),
            "metadata": list(METADATA_COLUMNS_V2),
            "exported_features": list(EXPORTED_FEATURE_COLUMNS_V2),
            "context_only": list(CONTEXT_ONLY_COLUMNS_V2),
            "protocol_routing": list(PROTOCOL_ROUTING_COLUMNS_V2),
            "behavioral_common": list(COMMON_BEHAVIORAL_COLUMNS_V2),
            "behavioral_additions_by_protocol": {
                protocol: list(columns)
                for protocol, columns in BEHAVIORAL_ADDITIONS_BY_PROTOCOL_V2.items()
            },
            "novelty_policy_inputs": list(NOVELTY_POLICY_COLUMNS_V2),
            "redundant_excluded": list(REDUNDANT_EXCLUDED_COLUMNS_V2),
        },
        "role_notes": {
            "roles_may_overlap": True,
            "context_only": "Exported for debugging; never a learned input.",
            "protocol_routing": "Selects the protocol-specific model.",
            "novelty_policy_inputs": (
                "Saved inputs for explicit reason-coded checks; some also provide "
                "useful behavioral context."
            ),
            "redundant_excluded": (
                "Exported for auditability but excluded from learned matrices."
            ),
        },
        "configuration": {
            "byte_count_basis": "ipv4_total_length",
            "tcp_idle_timeout_seconds": timeouts.tcp_ns / 1_000_000_000,
            "udp_idle_timeout_seconds": timeouts.udp_ns / 1_000_000_000,
            "icmp_idle_timeout_seconds": timeouts.icmp_ns / 1_000_000_000,
            "source_history_window_seconds": history_window_seconds,
            "not_applicable_integer": -1,
            "tcp_terminal_packet_policy": (
                "retain terminal TCP tuples through trailing packets until a new "
                "bare SYN, idle timeout, or capture end"
            ),
        },
        "inputs": inputs,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    """Export the canonical normal captures using schema version 2."""
    parser = argparse.ArgumentParser(
        description="Export validated captures with feature schema version 2."
    )
    parser.add_argument(
        "--capture-manifest", type=Path, default=Path("pcaps/manifest.csv")
    )
    parser.add_argument(
        "--output-directory", type=Path, default=Path("data/derived/v2")
    )
    args = parser.parse_args()
    result = export_dataset_v2(args.capture_manifest, args.output_directory)
    print(
        f"exported {result.row_count} flows from {result.capture_count} captures "
        f"to {result.dataset_path}"
    )


if __name__ == "__main__":
    main()
