"""Read-only collector for additional Firefox profile artifacts."""

from __future__ import annotations

import configparser
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from foxclaw.collect.certificates import audit_cert9_root_store
from foxclaw.collect.handlers import collect_protocol_handler_hijacks
from foxclaw.collect.pkcs11 import audit_pkcs11_modules
from foxclaw.collect.safe_paths import iter_safe_profile_files
from foxclaw.models import ProfileArtifactEntry, ProfileArtifactEvidence

_PROFILE_ARTIFACTS: tuple[str, ...] = (
    # Canonical Firefox HSTS state artifact; keep legacy .bin for compatibility
    # with historical captures.
    "SiteSecurityServiceState.txt",
    "SiteSecurityServiceState.bin",
    "cert9.db",
    "compatibility.ini",
    "containers.json",
    "content-prefs.sqlite",
    "handlers.json",
    "permissions.sqlite",
    "pkcs11.txt",
    "protections.sqlite",
    "search.json.mozlz4",
    "sessionstore.jsonlz4",
)
_HASH_BYTES_CAP = 50 * 1024 * 1024  # 50 MiB

ParseStatus = Literal["metadata_only", "parsed", "error"]
_ArtifactParser = Callable[[Path], tuple[ParseStatus, list[str], dict[str, str], str | None]]


def collect_profile_artifacts(profile_dir: Path) -> ProfileArtifactEvidence:
    """Collect metadata and lightweight summaries for selected ESR profile artifacts."""
    entries: list[ProfileArtifactEntry] = []

    for rel_path, artifact_path in iter_safe_profile_files(profile_dir, _PROFILE_ARTIFACTS):
        if not artifact_path.is_file():
            continue

        try:
            artifact_stat = artifact_path.stat()
        except OSError as exc:
            entries.append(
                ProfileArtifactEntry(
                    rel_path=rel_path,
                    parse_status="error",
                    parse_error=str(exc),
                )
            )
            continue

        hash_skipped: str | None = None
        if artifact_stat.st_size <= _HASH_BYTES_CAP:
            try:
                sha256 = _sha256_file(artifact_path)
            except OSError as exc:
                entries.append(
                    ProfileArtifactEntry(
                        rel_path=rel_path,
                        parse_status="error",
                        parse_error=str(exc),
                    )
                )
                continue
        else:
            sha256 = None
            hash_skipped = "size_cap"

        parser = _parser_for(rel_path)
        parse_status: ParseStatus
        if parser is None:
            parse_status = "metadata_only"
            top_level_keys: list[str] = []
            key_values: dict[str, str] = {}
            parse_error: str | None = None
        else:
            parse_status, top_level_keys, key_values, parse_error = parser(artifact_path)

        merged_key_values = dict(key_values)
        if hash_skipped is not None:
            merged_key_values["hash_skipped"] = hash_skipped

        entries.append(
            ProfileArtifactEntry(
                rel_path=rel_path,
                size=artifact_stat.st_size,
                mtime_utc=_iso_utc(artifact_stat.st_mtime),
                sha256=sha256,
                parse_status=parse_status,
                top_level_keys=top_level_keys,
                key_values=merged_key_values,
                parse_error=parse_error,
            )
        )

    entries.sort(key=lambda item: item.rel_path)
    return ProfileArtifactEvidence(entries=entries)


def _parser_for(rel_path: str) -> _ArtifactParser | None:
    if rel_path == "containers.json":
        return _parse_containers_json
    if rel_path == "handlers.json":
        return _parse_handlers_json
    if rel_path == "cert9.db":
        return _parse_cert9_db
    if rel_path == "pkcs11.txt":
        return _parse_pkcs11_txt
    if rel_path == "compatibility.ini":
        return _parse_compatibility_ini
    return None


def _parse_containers_json(path: Path) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    return _parse_json_artifact(path, collector=_collect_container_keys)


def _parse_handlers_json(path: Path) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    return _parse_json_artifact(path, collector=_collect_handler_keys)


def _parse_cert9_db(path: Path) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    result = audit_cert9_root_store(path)
    if result.parse_error is not None:
        return "error", [], {}, result.parse_error

    key_values: dict[str, str] = {
        "root_ca_entries_count": str(result.root_entries_total),
        "suspicious_root_ca_count": str(len(result.suspicious_roots)),
    }
    if result.suspicious_roots:
        key_values["suspicious_root_ca_entries"] = json.dumps(
            [
                {
                    "issuer": item.issuer,
                    "not_before_utc": item.not_before_utc,
                    "reasons": list(item.reasons),
                    "subject": item.subject,
                    "trust_flags": item.trust_flags,
                }
                for item in result.suspicious_roots
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
    return "parsed", [], dict(sorted(key_values.items())), None


def _parse_pkcs11_txt(path: Path) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    result = audit_pkcs11_modules(path)
    if result.parse_error is not None:
        return "error", [], {}, result.parse_error

    key_values: dict[str, str] = {
        "pkcs11_modules_count": str(len(result.modules)),
        "suspicious_pkcs11_module_count": str(len(result.suspicious_modules)),
    }
    if result.suspicious_modules:
        key_values["suspicious_pkcs11_modules"] = json.dumps(
            [
                {
                    "library_path": item.library_path,
                    "name": item.name,
                    "reasons": list(item.reasons),
                }
                for item in result.suspicious_modules
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
    return "parsed", [], dict(sorted(key_values.items())), None


def _parse_json_artifact(
    path: Path, *, collector: Callable[[dict[str, object]], dict[str, str]]
) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return "error", [], {}, str(exc)

    if not isinstance(payload, dict):
        return "error", [], {}, "top-level JSON is not an object"

    top_level_keys = sorted(str(key) for key in payload.keys())
    key_values = collector(payload)
    return "parsed", top_level_keys, dict(sorted(key_values.items())), None


def _collect_container_keys(payload: dict[str, object]) -> dict[str, str]:
    key_values: dict[str, str] = {}

    identities = payload.get("identities")
    if isinstance(identities, list):
        key_values["identities_count"] = str(len(identities))

    version = payload.get("version")
    if isinstance(version, (int, float, str, bool)):
        key_values["version"] = str(version)

    return key_values


def _collect_handler_keys(payload: dict[str, object]) -> dict[str, str]:
    key_values: dict[str, str] = {}

    default_handlers_version = payload.get("defaultHandlersVersion")
    if isinstance(default_handlers_version, (int, float, str, bool)):
        key_values["default_handlers_version"] = str(default_handlers_version)

    mime_types = payload.get("mimeTypes")
    if isinstance(mime_types, dict):
        key_values["mime_types_count"] = str(len(mime_types))

    schemes = payload.get("schemes")
    if isinstance(schemes, dict):
        key_values["schemes_count"] = str(len(schemes))

    suspicious_handlers = collect_protocol_handler_hijacks(payload)
    key_values["suspicious_local_exec_count"] = str(len(suspicious_handlers))
    if suspicious_handlers:
        key_values["suspicious_local_exec_handlers"] = json.dumps(
            [
                {"scheme": item.scheme, "path": item.handler_path}
                for item in suspicious_handlers
            ],
            sort_keys=True,
            separators=(",", ":"),
        )

    return key_values


def _parse_compatibility_ini(
    path: Path,
) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, configparser.Error) as exc:
        return "error", [], {}, str(exc)

    top_level_keys = sorted(parser.sections())
    key_values: dict[str, str] = {}
    if parser.has_section("Compatibility"):
        compatibility = parser["Compatibility"]
        for source_key, output_key in (
            ("LastVersion", "last_version"),
            ("LastOSABI", "last_osabi"),
            ("LastPlatformDir", "last_platform_dir"),
            ("LastAppDir", "last_app_dir"),
        ):
            value = compatibility.get(source_key, fallback="").strip()
            if value:
                key_values[output_key] = value

    return "parsed", top_level_keys, dict(sorted(key_values.items())), None


def _iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
