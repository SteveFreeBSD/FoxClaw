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
from foxclaw.collect.cookies import audit_cookies_sqlite
from foxclaw.collect.handlers import collect_protocol_handler_hijacks
from foxclaw.collect.hsts import audit_hsts_state
from foxclaw.collect.pkcs11 import audit_pkcs11_modules
from foxclaw.collect.safe_paths import iter_safe_profile_files
from foxclaw.collect.search import audit_search_json
from foxclaw.collect.session import audit_sessionstore
from foxclaw.models import ProfileArtifactEntry, ProfileArtifactEvidence

_PROFILE_ARTIFACTS: tuple[str, ...] = (
    # Canonical Firefox HSTS state artifact; keep legacy .bin for compatibility
    # with historical captures.
    "SiteSecurityServiceState.txt",
    "SiteSecurityServiceState.bin",
    "cert9.db",
    "cookies.sqlite",
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
        # Large artifacts skip deep parsing to keep collection bounded and stable.
        if hash_skipped is not None or parser is None:
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
    if rel_path == "SiteSecurityServiceState.txt":
        return _parse_hsts_state_txt
    if rel_path == "containers.json":
        return _parse_containers_json
    if rel_path == "handlers.json":
        return _parse_handlers_json
    if rel_path == "cert9.db":
        return _parse_cert9_db
    if rel_path == "cookies.sqlite":
        return _parse_cookies_sqlite
    if rel_path == "pkcs11.txt":
        return _parse_pkcs11_txt
    if rel_path == "search.json.mozlz4":
        return _parse_search_json_mozlz4
    if rel_path == "sessionstore.jsonlz4":
        return _parse_sessionstore_jsonlz4
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


def _parse_cookies_sqlite(path: Path) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    result = audit_cookies_sqlite(path)
    if result.parse_error is not None:
        return "error", [], {}, result.parse_error

    key_values: dict[str, str] = {
        "cookies_total_count": str(result.cookies_total),
        "long_lived_cookie_count": str(result.long_lived_cookie_count),
        "samesite_none_sensitive_count": str(result.samesite_none_sensitive_count),
        "auth_cookie_missing_httponly_count": str(result.auth_cookie_missing_httponly_count),
        "third_party_tracking_cookie_count": str(result.third_party_tracking_cookie_count),
        "suspicious_cookie_security_count": str(len(result.suspicious_signals)),
    }
    if result.suspicious_signals:
        key_values["suspicious_cookie_security_signals"] = json.dumps(
            [
                {
                    "host": item.host,
                    "name": item.name,
                    "reasons": list(item.reasons),
                }
                for item in result.suspicious_signals
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
    return "parsed", [], dict(sorted(key_values.items())), None


def _parse_hsts_state_txt(path: Path) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    result = audit_hsts_state(path)
    if result.parse_error is not None:
        return "error", [], {}, result.parse_error

    key_values: dict[str, str] = {
        "hsts_entries_count": str(len(result.entries)),
        "hsts_critical_hosts_expected_count": str(len(result.critical_hosts_expected)),
        "hsts_critical_hosts_missing_count": str(len(result.missing_critical_hosts)),
        "hsts_malformed_line_count": str(result.malformed_line_count),
        "suspicious_hsts_state_count": str(len(result.suspicious_signals)),
    }
    if result.missing_critical_hosts:
        key_values["hsts_critical_hosts_missing"] = json.dumps(
            list(result.missing_critical_hosts),
            sort_keys=True,
            separators=(",", ":"),
        )
    if result.suspicious_signals:
        key_values["suspicious_hsts_state_entries"] = json.dumps(
            [
                {
                    "host": item.host,
                    "reasons": list(item.reasons),
                }
                for item in result.suspicious_signals
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


def _parse_search_json_mozlz4(
    path: Path,
) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    result = audit_search_json(path)
    if result.parse_error is not None:
        return "error", [], {}, result.parse_error

    key_values: dict[str, str] = {
        "search_engines_count": str(len(result.engines)),
        "suspicious_search_engine_count": str(len(result.suspicious_defaults)),
    }
    if result.default_engine_name is not None:
        key_values["default_search_engine_name"] = result.default_engine_name
    if result.default_engine_url is not None:
        key_values["default_search_engine_url"] = result.default_engine_url
    if result.suspicious_defaults:
        key_values["suspicious_search_engines"] = json.dumps(
            [
                {
                    "name": item.name,
                    "reasons": list(item.reasons),
                    "search_url": item.search_url,
                }
                for item in result.suspicious_defaults
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
    return "parsed", [], dict(sorted(key_values.items())), None


def _parse_sessionstore_jsonlz4(
    path: Path,
) -> tuple[ParseStatus, list[str], dict[str, str], str | None]:
    result = audit_sessionstore(path)
    if result.parse_error is not None:
        return "error", [], {}, result.parse_error

    key_values: dict[str, str] = {
        "session_restore_enabled": "1" if result.session_restore_enabled else "0",
        "session_windows_count": str(result.windows_count),
        "session_sensitive_entry_count": str(len(result.sensitive_entries)),
    }
    if result.sensitive_entries:
        key_values["session_sensitive_entries"] = json.dumps(
            [{"kind": item.kind, "path": item.path} for item in result.sensitive_entries],
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
