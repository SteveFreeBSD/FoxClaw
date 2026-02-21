"""CycloneDX SBOM validation helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SbomValidationSummary:
    """Validated CycloneDX SBOM summary."""

    path: Path
    spec_version: str
    component_count: int
    foxclaw_component_version: str | None


def validate_cyclonedx_sbom(path: Path) -> SbomValidationSummary:
    """Validate a CycloneDX SBOM and return a compact summary."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read SBOM: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"SBOM is not valid JSON: {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"SBOM top-level JSON must be an object: {path}")

    bom_format = payload.get("bomFormat")
    if bom_format != "CycloneDX":
        raise ValueError(f"SBOM bomFormat must be CycloneDX: {path}")

    spec_version = payload.get("specVersion")
    if not isinstance(spec_version, str) or not spec_version.strip():
        raise ValueError(f"SBOM specVersion must be a non-empty string: {path}")

    components_obj = payload.get("components")
    if not isinstance(components_obj, list) or not components_obj:
        raise ValueError(f"SBOM components must be a non-empty array: {path}")

    component_count = len(components_obj)
    foxclaw_component_version = _resolve_foxclaw_component_version(payload)
    if foxclaw_component_version is None:
        raise ValueError(f"SBOM missing foxclaw component metadata: {path}")

    return SbomValidationSummary(
        path=path,
        spec_version=spec_version.strip(),
        component_count=component_count,
        foxclaw_component_version=foxclaw_component_version,
    )


def _resolve_foxclaw_component_version(payload: dict[str, object]) -> str | None:
    components_obj = payload.get("components")
    if isinstance(components_obj, list):
        for item in components_obj:
            if not isinstance(item, dict):
                continue
            if item.get("name") != "foxclaw":
                continue
            version = item.get("version")
            if isinstance(version, str) and version.strip():
                return version.strip()
            return ""

    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return None
    component = metadata.get("component")
    if not isinstance(component, dict):
        return None
    if component.get("name") != "foxclaw":
        return None
    version = component.get("version")
    if isinstance(version, str):
        return version.strip()
    return ""
