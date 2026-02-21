from __future__ import annotations

import json
from pathlib import Path

import pytest
from foxclaw.release.sbom import validate_cyclonedx_sbom


def _write_sbom(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def test_validate_cyclonedx_sbom_accepts_valid_payload(tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom.cyclonedx.json"
    _write_sbom(
        sbom_path,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "application",
                    "name": "foxclaw",
                    "version": "0.1.0",
                },
                {
                    "type": "library",
                    "name": "typer",
                    "version": "0.24.0",
                },
            ],
        },
    )

    summary = validate_cyclonedx_sbom(sbom_path)
    assert summary.spec_version == "1.6"
    assert summary.component_count == 2
    assert summary.foxclaw_component_version == "0.1.0"


def test_validate_cyclonedx_sbom_rejects_missing_foxclaw_component(tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom.cyclonedx.json"
    _write_sbom(
        sbom_path,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "typer",
                    "version": "0.24.0",
                }
            ],
        },
    )

    with pytest.raises(ValueError, match="missing foxclaw component metadata"):
        validate_cyclonedx_sbom(sbom_path)
