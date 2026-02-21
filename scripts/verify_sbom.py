#!/usr/bin/env python3
"""Validate CycloneDX SBOM files for release gates."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path


def _load_validator() -> Callable[[Path], object]:
    try:
        from foxclaw.release.sbom import validate_cyclonedx_sbom
    except ModuleNotFoundError:
        # Allow direct script execution from repository root without editable install.
        repo_root = Path(__file__).resolve().parents[1]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        from foxclaw.release.sbom import validate_cyclonedx_sbom
    return validate_cyclonedx_sbom


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate CycloneDX SBOM structure and foxclaw component presence."
    )
    parser.add_argument("sbom", type=Path, help="Path to CycloneDX JSON SBOM file.")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    validate_cyclonedx_sbom = _load_validator()
    summary = validate_cyclonedx_sbom(args.sbom)
    print(
        "[sbom] ok:"
        f" path={summary.path}"
        f" spec={summary.spec_version}"
        f" components={summary.component_count}"
        f" foxclaw_version={summary.foxclaw_component_version or 'unknown'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
