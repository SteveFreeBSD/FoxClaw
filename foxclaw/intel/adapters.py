"""Source adapter parsing for intelligence sync indexing."""

from __future__ import annotations

import json

from pydantic import ValidationError

from foxclaw.intel.models import IntelSourceIndex, MozillaFirefoxAdvisoryBundle
from foxclaw.intel.versioning import validate_version_spec

MOZILLA_FIREFOX_ADVISORY_SCHEMA = "foxclaw.mozilla.firefox_advisories.v1"
MOZILLA_FIREFOX_ADVISORY_ADAPTER = "mozilla_firefox_advisories_v1"


def build_source_index(*, source_name: str, payload: bytes) -> IntelSourceIndex:
    """Build normalized index metadata from one source payload."""
    decoded = _decode_json_payload(payload)
    if decoded is None:
        return IntelSourceIndex(source_name=source_name)

    raw_schema_version = decoded.get("schema_version")
    schema_version = raw_schema_version if isinstance(raw_schema_version, str) else None
    if schema_version != MOZILLA_FIREFOX_ADVISORY_SCHEMA:
        return IntelSourceIndex(
            source_name=source_name,
            schema_version=schema_version,
        )

    try:
        bundle = MozillaFirefoxAdvisoryBundle.model_validate(decoded)
    except ValidationError as exc:
        raise ValueError(
            f"source '{source_name}' failed schema validation for {schema_version}: {exc}"
        ) from exc

    advisories = sorted(
        bundle.advisories,
        key=lambda item: (
            item.cve_id,
            item.advisory_id,
            item.affected_versions,
            item.fixed_version or "",
        ),
    )
    for advisory in advisories:
        validate_version_spec(advisory.affected_versions)

    return IntelSourceIndex(
        source_name=source_name,
        adapter=MOZILLA_FIREFOX_ADVISORY_ADAPTER,
        schema_version=schema_version,
        record_count=len(advisories),
        mozilla_advisories=advisories,
    )


def _decode_json_payload(payload: bytes) -> dict[str, object] | None:
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded
