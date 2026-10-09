"""Smoke tests for the initial project scaffold."""

import ids_ml


def test_package_version() -> None:
    """The package exposes the version declared in project metadata."""
    assert ids_ml.__version__ == "0.1.0"
