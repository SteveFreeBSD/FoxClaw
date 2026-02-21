"""Source adapter parsing for intelligence sync indexing."""

from __future__ import annotations

import json

from pydantic import ValidationError

from foxclaw.intel.models import (
    AmoExtensionIntelBundle,
    CisaKevBundle,
    CveListRecordBundle,
    EpssScoreBundle,
    IntelSourceIndex,
    MozillaExtensionBlocklistBundle,
    MozillaFirefoxAdvisoryBundle,
    NvdCveRecordBundle,
)
from foxclaw.intel.versioning import validate_version_spec

MOZILLA_FIREFOX_ADVISORY_SCHEMA = "foxclaw.mozilla.firefox_advisories.v1"
MOZILLA_FIREFOX_ADVISORY_ADAPTER = "mozilla_firefox_advisories_v1"
MOZILLA_EXTENSION_BLOCKLIST_SCHEMA = "foxclaw.mozilla.extension_blocklist.v1"
MOZILLA_EXTENSION_BLOCKLIST_ADAPTER = "mozilla_extension_blocklist_v1"
AMO_EXTENSION_INTEL_SCHEMA = "foxclaw.amo.extension_intel.v1"
AMO_EXTENSION_INTEL_ADAPTER = "amo_extension_intel_v1"
NVD_CVE_RECORD_SCHEMA = "foxclaw.nvd.cve_records.v1"
NVD_CVE_RECORD_ADAPTER = "nvd_cve_records_v1"
CVE_LIST_RECORD_SCHEMA = "foxclaw.cve.list_records.v1"
CVE_LIST_RECORD_ADAPTER = "cve_list_records_v1"
CISA_KEV_SCHEMA = "foxclaw.cisa.known_exploited_vulnerabilities.v1"
CISA_KEV_ADAPTER = "cisa_kev_v1"
EPSS_SCORE_SCHEMA = "foxclaw.epss.scores.v1"
EPSS_SCORE_ADAPTER = "epss_scores_v1"


def build_source_index(*, source_name: str, payload: bytes) -> IntelSourceIndex:
    """Build normalized index metadata from one source payload."""
    decoded = _decode_json_payload(payload)
    if decoded is None:
        return IntelSourceIndex(source_name=source_name)

    raw_schema_version = decoded.get("schema_version")
    schema_version = raw_schema_version if isinstance(raw_schema_version, str) else None
    if schema_version == MOZILLA_FIREFOX_ADVISORY_SCHEMA:
        try:
            advisories_bundle = MozillaFirefoxAdvisoryBundle.model_validate(decoded)
        except ValidationError as exc:
            raise ValueError(
                f"source '{source_name}' failed schema validation for {schema_version}: {exc}"
            ) from exc

        advisories = sorted(
            advisories_bundle.advisories,
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

    if schema_version == MOZILLA_EXTENSION_BLOCKLIST_SCHEMA:
        try:
            blocklist_bundle = MozillaExtensionBlocklistBundle.model_validate(decoded)
        except ValidationError as exc:
            raise ValueError(
                f"source '{source_name}' failed schema validation for {schema_version}: {exc}"
            ) from exc

        entries = sorted(
            blocklist_bundle.entries,
            key=lambda item: (
                item.addon_id.lower(),
                item.version or "",
                item.block_state,
                item.reason or "",
                item.reference_url or "",
            ),
        )
        return IntelSourceIndex(
            source_name=source_name,
            schema_version=schema_version,
            adapter=MOZILLA_EXTENSION_BLOCKLIST_ADAPTER,
            record_count=len(entries),
            extension_blocklist=entries,
        )

    if schema_version == AMO_EXTENSION_INTEL_SCHEMA:
        try:
            amo_bundle = AmoExtensionIntelBundle.model_validate(decoded)
        except ValidationError as exc:
            raise ValueError(
                f"source '{source_name}' failed schema validation for {schema_version}: {exc}"
            ) from exc

        records = sorted(
            amo_bundle.records,
            key=lambda item: (
                item.addon_id.lower(),
                item.version or "",
                item.reputation,
                int(item.listed),
                item.reference_url or "",
                item.reason or "",
            ),
        )
        return IntelSourceIndex(
            source_name=source_name,
            schema_version=schema_version,
            adapter=AMO_EXTENSION_INTEL_ADAPTER,
            record_count=len(records),
            amo_extension_intel=records,
        )

    if schema_version == NVD_CVE_RECORD_SCHEMA:
        try:
            nvd_bundle = NvdCveRecordBundle.model_validate(decoded)
        except ValidationError as exc:
            raise ValueError(
                f"source '{source_name}' failed schema validation for {schema_version}: {exc}"
            ) from exc

        nvd_records = sorted(
            nvd_bundle.records,
            key=lambda item: (
                item.cve_id.upper(),
                item.severity or "",
                item.reference_url or "",
                item.summary or "",
            ),
        )
        return IntelSourceIndex(
            source_name=source_name,
            schema_version=schema_version,
            adapter=NVD_CVE_RECORD_ADAPTER,
            record_count=len(nvd_records),
            nvd_cves=nvd_records,
        )

    if schema_version == CVE_LIST_RECORD_SCHEMA:
        try:
            cve_list_bundle = CveListRecordBundle.model_validate(decoded)
        except ValidationError as exc:
            raise ValueError(
                f"source '{source_name}' failed schema validation for {schema_version}: {exc}"
            ) from exc

        cve_records = sorted(
            cve_list_bundle.records,
            key=lambda item: (
                item.cve_id.upper(),
                item.severity or "",
                item.reference_url or "",
                item.summary or "",
            ),
        )
        return IntelSourceIndex(
            source_name=source_name,
            schema_version=schema_version,
            adapter=CVE_LIST_RECORD_ADAPTER,
            record_count=len(cve_records),
            cve_list_records=cve_records,
        )

    if schema_version == CISA_KEV_SCHEMA:
        try:
            kev_bundle = CisaKevBundle.model_validate(decoded)
        except ValidationError as exc:
            raise ValueError(
                f"source '{source_name}' failed schema validation for {schema_version}: {exc}"
            ) from exc

        kev_records = sorted(
            kev_bundle.entries,
            key=lambda item: (
                item.cve_id.upper(),
                item.vendor_project or "",
                item.product or "",
                item.date_added or "",
                item.due_date or "",
                item.known_ransomware_campaign_use or "",
                item.reference_url or "",
                item.short_description or "",
            ),
        )
        return IntelSourceIndex(
            source_name=source_name,
            schema_version=schema_version,
            adapter=CISA_KEV_ADAPTER,
            record_count=len(kev_records),
            kev_records=kev_records,
        )

    if schema_version == EPSS_SCORE_SCHEMA:
        try:
            epss_bundle = EpssScoreBundle.model_validate(decoded)
        except ValidationError as exc:
            raise ValueError(
                f"source '{source_name}' failed schema validation for {schema_version}: {exc}"
            ) from exc

        epss_records = sorted(
            epss_bundle.records,
            key=lambda item: (
                item.cve_id.upper(),
                item.score,
                item.percentile if item.percentile is not None else -1.0,
                item.reference_url or "",
            ),
        )
        return IntelSourceIndex(
            source_name=source_name,
            schema_version=schema_version,
            adapter=EPSS_SCORE_ADAPTER,
            record_count=len(epss_records),
            epss_records=epss_records,
        )

    return IntelSourceIndex(
        source_name=source_name,
        schema_version=schema_version,
    )


def _decode_json_payload(payload: bytes) -> dict[str, object] | None:
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded
