"""Read-only extension inventory and posture collection."""

from __future__ import annotations

import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Literal

from foxclaw.collect.safe_paths import (
    ProfilePathEscapeError,
    resolve_safe_profile_path,
)
from foxclaw.models import ExtensionEntry, ExtensionEvidence, ExtensionPermissionRisk

_EXTENSIONS_JSON_NAME = "extensions.json"
_EXTENSIONS_DIR_NAME = "extensions"
_SYSTEM_LOCATION_TOKENS = (
    "app-system-defaults",
    "app-system-addons",
    "app-builtin",
    "app-global",
)
_BUILTIN_PATH_TOKENS = ("/browser/features/", "/features/")

SourceKind = Literal["profile", "system", "builtin", "external", "unknown"]
SignedStatus = Literal["valid", "invalid", "unavailable"]
ManifestStatus = Literal["parsed", "unavailable", "error"]

_HIGH_RISK_API_PERMISSIONS: dict[str, str] = {
    "debugger": "Can inspect/modify page runtime state.",
    "management": "Can manage other installed extensions.",
    "nativeMessaging": "Can bridge browser extension logic to native host processes.",
    "privacy": "Can alter browser privacy settings globally.",
    "proxy": "Can redirect and alter browser traffic flow.",
    "webRequestBlocking": "Can intercept and block/modify network requests.",
}

_MEDIUM_RISK_API_PERMISSIONS: dict[str, str] = {
    "browsingData": "Can read or clear local browsing data stores.",
    "clipboardRead": "Can read clipboard contents.",
    "cookies": "Can access and mutate browser cookies.",
    "downloads": "Can inspect downloads metadata and behavior.",
    "history": "Can read browsing history.",
    "tabs": "Can inspect and manage browser tabs.",
    "webRequest": "Can observe network request metadata.",
}


def collect_extensions(profile_dir: Path) -> ExtensionEvidence:
    """Collect extension inventory and manifest-derived posture signals."""
    extensions_json_path = resolve_safe_profile_path(profile_dir, _EXTENSIONS_JSON_NAME)
    evidence = ExtensionEvidence(extensions_json_path=str(extensions_json_path))

    if not extensions_json_path.is_file():
        return evidence

    try:
        payload = json.loads(extensions_json_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        evidence.parse_error = str(exc)
        return evidence

    if not isinstance(payload, dict):
        evidence.parse_error = "extensions.json top-level JSON is not an object"
        return evidence

    addons = payload.get("addons")
    if not isinstance(addons, list):
        evidence.parse_error = "extensions.json missing addons list"
        return evidence

    entries: list[ExtensionEntry] = []
    for index, raw_addon in enumerate(addons):
        if not isinstance(raw_addon, dict):
            entries.append(
                ExtensionEntry(
                    addon_id=f"invalid-addon-{index}",
                    parse_error="addon entry is not an object",
                )
            )
            continue

        entry = _build_entry(profile_dir=profile_dir, addon=raw_addon, index=index)
        if entry is None:
            continue
        entries.append(entry)

    entries.sort(key=lambda item: item.addon_id)
    evidence.entries = entries
    evidence.addons_seen = len(entries)
    evidence.active_addons = sum(1 for item in entries if item.active is True)
    return evidence


def _build_entry(profile_dir: Path, *, addon: dict[str, object], index: int) -> ExtensionEntry | None:
    addon_type = _optional_str(addon.get("type"))
    if addon_type is not None and addon_type != "extension":
        return None

    addon_id = _optional_str(addon.get("id")) or f"unknown-addon-{index}"
    name = _extract_name(addon)
    version = _optional_str(addon.get("version"))
    active = _coerce_bool(addon.get("active"))
    location = _optional_str(addon.get("location"))
    source = _optional_str(addon.get("path"))
    source_kind = _classify_source_kind(profile_dir=profile_dir, location=location, source=source)
    debug_install, debug_reason = _extract_debug_install(
        addon=addon,
        location=location,
        source=source,
        profile_dir=profile_dir,
    )

    signed_state_value = addon.get("signedState")
    signed_state = str(signed_state_value) if signed_state_value is not None else None
    signed_valid = _signed_state_valid(signed_state_value)
    if source_kind in {"builtin", "system"}:
        signed_valid = None
    signed_status = _signed_status(signed_valid)

    manifest = _load_manifest(
        profile_dir=profile_dir,
        addon=addon,
        addon_id=addon_id,
        source_kind=source_kind,
    )

    blocklisted = False
    risky_permissions = _classify_risky_permissions(
        permissions=manifest.permissions,
        host_permissions=manifest.host_permissions,
    )

    return ExtensionEntry(
        addon_id=addon_id,
        name=name,
        version=version,
        active=active,
        addon_type=addon_type or "extension",
        location=location,
        source_kind=source_kind,
        source=source,
        debug_install=debug_install,
        debug_reason=debug_reason,
        signed_state=signed_state,
        signed_valid=signed_valid,
        signed_status=signed_status,
        manifest_path=manifest.path,
        manifest_status=manifest.manifest_status,
        manifest_version=manifest.manifest_version,
        permissions=manifest.permissions,
        host_permissions=manifest.host_permissions,
        risky_permissions=risky_permissions,
        blocklisted=blocklisted,
        parse_error=manifest.parse_error,
    )


class _ManifestData:
    def __init__(
        self,
        *,
        path: str | None = None,
        manifest_status: ManifestStatus = "unavailable",
        manifest_version: int | None = None,
        permissions: list[str] | None = None,
        host_permissions: list[str] | None = None,
        parse_error: str | None = None,
    ) -> None:
        self.path = path
        self.manifest_status = manifest_status
        self.manifest_version = manifest_version
        self.permissions = permissions or []
        self.host_permissions = host_permissions or []
        self.parse_error = parse_error


def _load_manifest(
    profile_dir: Path,
    *,
    addon: dict[str, object],
    addon_id: str,
    source_kind: str,
) -> _ManifestData:
    for candidate in _manifest_candidates(profile_dir=profile_dir, addon=addon, addon_id=addon_id):
        if candidate.is_dir():
            manifest_path = resolve_safe_profile_path(profile_dir, candidate / "manifest.json")
            if not manifest_path.is_file():
                continue
            return _parse_manifest_file(manifest_path)

        if candidate.is_file() and candidate.name == "manifest.json":
            return _parse_manifest_file(candidate)

        if candidate.is_file() and candidate.suffix.lower() == ".xpi":
            return _parse_manifest_zip(candidate)

    if source_kind in {"builtin", "system"}:
        return _ManifestData(manifest_status="unavailable")
    return _ManifestData(parse_error="manifest not found")


def _manifest_candidates(profile_dir: Path, *, addon: dict[str, object], addon_id: str) -> list[Path]:
    candidates: list[Path] = []

    addon_path = _optional_str(addon.get("path"))
    if addon_path:
        candidates.append(Path(addon_path).expanduser())

    extensions_dir = Path(_EXTENSIONS_DIR_NAME)
    candidates.append(extensions_dir / f"{addon_id}.xpi")
    candidates.append(extensions_dir / addon_id)

    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = resolve_safe_profile_path(profile_dir, path)
        except ProfilePathEscapeError:
            # Extension metadata may include absolute external/system paths. Never open those.
            if path.is_absolute():
                continue
            raise
        if resolved in seen:
            continue
        deduped.append(resolved)
        seen.add(resolved)
    return deduped


def _parse_manifest_file(path: Path) -> _ManifestData:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return _ManifestData(path=str(path), manifest_status="error", parse_error=str(exc))

    return _manifest_data_from_payload(path=str(path), payload=payload)


def _parse_manifest_zip(path: Path) -> _ManifestData:
    try:
        with zipfile.ZipFile(path) as archive:
            raw = archive.read("manifest.json")
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        return _ManifestData(path=str(path), manifest_status="error", parse_error=str(exc))

    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return _ManifestData(path=str(path), manifest_status="error", parse_error=str(exc))

    return _manifest_data_from_payload(path=str(path), payload=payload)


def _manifest_data_from_payload(*, path: str, payload: object) -> _ManifestData:
    if not isinstance(payload, dict):
        return _ManifestData(
            path=path,
            manifest_status="error",
            parse_error="manifest top-level JSON is not an object",
        )

    manifest_version = payload.get("manifest_version")
    if not isinstance(manifest_version, int):
        manifest_version = None

    permissions, host_permissions = _extract_permissions(payload)
    return _ManifestData(
        path=path,
        manifest_status="parsed",
        manifest_version=manifest_version,
        permissions=permissions,
        host_permissions=host_permissions,
    )


def _extract_permissions(payload: dict[str, object]) -> tuple[list[str], list[str]]:
    api_permissions: set[str] = set()
    host_permissions: set[str] = set()

    for key in (
        "permissions",
        "optional_permissions",
        "host_permissions",
        "optional_host_permissions",
    ):
        value = payload.get(key)
        if not isinstance(value, list):
            continue

        for item in value:
            if not isinstance(item, str):
                continue
            token = item.strip()
            if not token:
                continue
            if _is_host_permission(token):
                host_permissions.add(token)
            else:
                api_permissions.add(token)

    return sorted(api_permissions), sorted(host_permissions)


def _classify_risky_permissions(
    *, permissions: list[str], host_permissions: list[str]
) -> list[ExtensionPermissionRisk]:
    risks: dict[str, ExtensionPermissionRisk] = {}

    for permission in permissions:
        if permission in _HIGH_RISK_API_PERMISSIONS:
            risks[permission] = ExtensionPermissionRisk(
                permission=permission,
                level="high",
                reason=_HIGH_RISK_API_PERMISSIONS[permission],
            )
            continue

        if permission in _MEDIUM_RISK_API_PERMISSIONS:
            risks[permission] = ExtensionPermissionRisk(
                permission=permission,
                level="medium",
                reason=_MEDIUM_RISK_API_PERMISSIONS[permission],
            )

    for host_permission in host_permissions:
        if _is_high_risk_host_permission(host_permission):
            risks[host_permission] = ExtensionPermissionRisk(
                permission=host_permission,
                level="high",
                reason="Host permission includes broad wildcard origin access.",
            )
            continue

        risks.setdefault(
            host_permission,
            ExtensionPermissionRisk(
                permission=host_permission,
                level="medium",
                reason="Host permission grants origin-specific page access.",
            ),
        )

    return sorted(risks.values(), key=lambda item: (item.level != "high", item.permission))


def _is_host_permission(permission: str) -> bool:
    return permission == "<all_urls>" or "://" in permission


def _is_high_risk_host_permission(permission: str) -> bool:
    normalized = permission.strip().lower()
    return normalized in {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def _extract_name(addon: dict[str, object]) -> str | None:
    locale = addon.get("defaultLocale")
    if isinstance(locale, dict):
        name = locale.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return _optional_str(addon.get("name"))


def _optional_str(value: object) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def _coerce_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _extract_debug_install(
    *, addon: dict[str, object], location: str | None, source: str | None, profile_dir: Path
) -> tuple[bool, str | None]:
    signals: list[str] = []

    temporarily_installed = addon.get("temporarilyInstalled")
    if temporarily_installed is True:
        signals.append("temporarilyInstalled=1")

    if location and "temporary" in location.lower():
        signals.append(f"location={location}")

    source_path = _resolve_source_path(profile_dir=profile_dir, source=source)
    if (
        source_path is not None
        and _is_volatile_source_path(source_path)
        and not _is_under_profile(source_path, profile_dir)
    ):
        signals.append(f"source_path={source_path}")

    if not signals:
        return False, None
    return True, ", ".join(signals)


def _signed_state_valid(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value >= 2
    return None


def _signed_status(signed_valid: bool | None) -> SignedStatus:
    if signed_valid is True:
        return "valid"
    if signed_valid is False:
        return "invalid"
    return "unavailable"


def _classify_source_kind(
    *, profile_dir: Path, location: str | None, source: str | None
) -> SourceKind:
    source_path = _resolve_source_path(profile_dir=profile_dir, source=source)

    if location:
        normalized_location = location.lower()
        if any(token in normalized_location for token in _SYSTEM_LOCATION_TOKENS):
            if "builtin" in normalized_location:
                return "builtin"
            return "system"
        if "profile" in normalized_location:
            if source_path is not None and not _is_under_profile(source_path, profile_dir):
                return "external"
            return "profile"

    if source_path is not None:
        normalized_source = str(source_path).lower()
        if any(token in normalized_source for token in _BUILTIN_PATH_TOKENS):
            return "builtin"

        if _is_under_profile(source_path, profile_dir):
            return "profile"
        if source_path.is_absolute():
            return "external"

    return "unknown"


def _resolve_source_path(*, profile_dir: Path, source: str | None) -> Path | None:
    if not source:
        return None

    candidate = Path(source).expanduser()
    if not candidate.is_absolute():
        candidate = profile_dir.joinpath(candidate)
    return candidate.resolve(strict=False)


def _is_under_profile(candidate: Path, profile_dir: Path) -> bool:
    profile_root = profile_dir.resolve(strict=False)
    return _is_within_root(candidate, profile_root)


def _is_volatile_source_path(path: Path) -> bool:
    root = Path(os.sep)
    volatile_roots = (
        Path(tempfile.gettempdir()).resolve(strict=False),
        (root / "var" / "tmp").resolve(strict=False),
        (root / "dev" / "shm").resolve(strict=False),
        (root / "run" / "user").resolve(strict=False),
    )
    return any(_is_within_root(path, volatile_root) for volatile_root in volatile_roots)


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
