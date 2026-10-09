"""Tests for deterministic versioned dataset export."""

import csv
import hashlib
import json
from pathlib import Path

import pytest

from ids_ml.dataset import (
    DATASET_COLUMNS,
    DatasetExportError,
    export_dataset,
)

CAPTURE_MANIFEST = Path("pcaps/manifest.csv")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_exports_expected_rows_columns_and_provenance(tmp_path: Path) -> None:
    result = export_dataset(CAPTURE_MANIFEST, tmp_path)

    assert result.row_count == 114
    assert result.capture_count == 14
    assert result.empty_capture_ids == ("normal_001_idle", "normal_v2_010")
    with result.dataset_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        assert tuple(reader.fieldnames or ()) == DATASET_COLUMNS
    assert len(rows) == 114
    assert rows[0]["flow_id"] == "normal_002_ssh:000001"
    assert rows[0]["flow_start_utc"] == "2026-08-12T13:21:57.743551000Z"
    assert rows[0]["src_ip"] == "10.10.0.2"
    assert rows[0]["dst_ip"] == "10.10.0.3"
    assert rows[0]["protocol"] == "6"
    assert rows[0]["label"] == "normal"

    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["row_count"] == 114
    assert manifest["empty_capture_ids"] == ["normal_001_idle", "normal_v2_010"]
    assert manifest["dataset_sha256"] == _sha256(result.dataset_path)
    assert manifest["inputs"][0]["flow_count"] == 0
    assert manifest["inputs"][1]["flow_count"] == 1
    assert manifest["inputs"][-1]["capture_id"] == "normal_v2_010"
    assert manifest["inputs"][-1]["flow_count"] == 0
    assert "src_ip" in manifest["columns"]["metadata"]
    assert "src_ip" not in manifest["columns"]["model_features"]
    assert "flows_last_10s" in manifest["columns"]["model_features"]


def test_export_is_byte_deterministic(tmp_path: Path) -> None:
    first = export_dataset(CAPTURE_MANIFEST, tmp_path / "first")
    second = export_dataset(CAPTURE_MANIFEST, tmp_path / "second")

    assert first.dataset_path.read_bytes() == second.dataset_path.read_bytes()
    assert first.manifest_path.read_bytes() == second.manifest_path.read_bytes()


def test_rejects_capture_when_manifest_hash_does_not_match(tmp_path: Path) -> None:
    source_rows = list(csv.DictReader(CAPTURE_MANIFEST.open(newline="")))
    source_rows[0]["sha256"] = "0" * 64
    manifest_copy = tmp_path / "manifest.csv"
    with manifest_copy.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=source_rows[0])
        writer.writeheader()
        writer.writerows(source_rows)

    # Copied manifest needs the same capture layout as the real manifest.
    (tmp_path / "normal").symlink_to(
        Path.cwd() / "pcaps/normal", target_is_directory=True
    )
    with pytest.raises(DatasetExportError, match="does not match manifest"):
        export_dataset(manifest_copy, tmp_path / "output")
