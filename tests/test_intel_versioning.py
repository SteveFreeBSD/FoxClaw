from __future__ import annotations

import pytest
from foxclaw.intel.versioning import normalize_version, validate_version_spec, version_matches_spec


def test_normalize_version_extracts_numeric_prefix() -> None:
    assert normalize_version("135.0_20260201000000/20260201000000") == "135.0"
    assert normalize_version("128.9.0esr") == "128.9.0"
    assert normalize_version("Firefox 136.0") == "136.0"


def test_version_matches_spec_with_multiple_comparators() -> None:
    assert version_matches_spec(version="135.0", spec=">=130.0,<136.0")
    assert not version_matches_spec(version="136.0", spec=">=130.0,<136.0")
    assert version_matches_spec(version="135.0", spec="<=135.0")


def test_validate_version_spec_rejects_invalid_tokens() -> None:
    with pytest.raises(ValueError, match="invalid affected_versions token"):
        validate_version_spec("135.0")
