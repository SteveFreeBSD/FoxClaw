"""Explicit intelligence synchronization workflow."""

from __future__ import annotations

import hashlib
import http.client
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

from foxclaw.intel.models import IntelSnapshotManifest, IntelSourceMaterial
from foxclaw.intel.store import default_store_dir, write_snapshot


@dataclass(frozen=True, slots=True)
class IntelSyncResult:
    """Result of one synchronization run."""

    manifest: IntelSnapshotManifest
    manifest_path: Path
    store_dir: Path


@dataclass(frozen=True, slots=True)
class _SourceSpec:
    name: str
    origin: str


def sync_sources(
    *,
    source_specs: list[str],
    store_dir: Path | None,
    normalize_json: bool,
    cwd: Path,
) -> IntelSyncResult:
    """Synchronize configured source materials into local storage."""
    parsed_specs = _parse_source_specs(source_specs)
    target_store_dir = (store_dir or default_store_dir()).expanduser().resolve(strict=False)

    source_payloads: list[tuple[IntelSourceMaterial, bytes]] = []
    for spec in parsed_specs:
        payload = _read_source_payload(origin=spec.origin, cwd=cwd)
        payload = _normalize_payload_if_json(payload, normalize_json=normalize_json)
        source_payloads.append(
            (
                IntelSourceMaterial(
                    name=spec.name,
                    origin=spec.origin,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size_bytes=len(payload),
                    fetched_at=datetime.now(UTC),
                    artifact_path="",
                ),
                payload,
            )
        )

    manifest, manifest_path = write_snapshot(
        store_dir=target_store_dir,
        source_payloads=source_payloads,
    )
    return IntelSyncResult(
        manifest=manifest,
        manifest_path=manifest_path,
        store_dir=target_store_dir,
    )


def _parse_source_specs(specs: list[str]) -> list[_SourceSpec]:
    if not specs:
        raise ValueError("at least one --source value is required")

    parsed: list[_SourceSpec] = []
    seen_names: set[str] = set()
    for raw_spec in specs:
        if "=" not in raw_spec:
            raise ValueError(f"invalid --source value '{raw_spec}'; expected name=origin")
        raw_name, raw_origin = raw_spec.split("=", 1)
        name = raw_name.strip()
        origin = raw_origin.strip()
        if not name:
            raise ValueError("source name cannot be empty")
        if not origin:
            raise ValueError(f"source origin cannot be empty for '{name}'")
        if name in seen_names:
            raise ValueError(f"duplicate source name '{name}'")
        seen_names.add(name)
        parsed.append(_SourceSpec(name=name, origin=origin))

    parsed.sort(key=lambda item: item.name)
    return parsed


def _read_source_payload(*, origin: str, cwd: Path) -> bytes:
    if origin.startswith("https://") or origin.startswith("http://"):
        return _read_http_payload(origin)

    source_path = Path(origin).expanduser()
    if not source_path.is_absolute():
        source_path = cwd / source_path
    source_path = source_path.resolve(strict=False)
    try:
        return source_path.read_bytes()
    except OSError as exc:
        raise OSError(f"unable to read source '{source_path}': {exc}") from exc


def _normalize_payload_if_json(payload: bytes, *, normalize_json: bool) -> bytes:
    if not normalize_json:
        return payload

    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return payload
    return (json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _read_http_payload(origin: str) -> bytes:
    parsed = urlparse(origin)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise OSError(f"unsupported URL scheme for source '{origin}'")
    if not parsed.hostname:
        raise OSError(f"missing host in source URL '{origin}'")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    connection_cls: type[http.client.HTTPConnection]
    connection_cls = (
        http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_cls(parsed.hostname, parsed.port, timeout=30)
    try:
        connection.request("GET", path, headers={"User-Agent": "foxclaw-intel-sync/1.0"})
        response = connection.getresponse()
        body = cast(bytes, response.read())
        if response.status < 200 or response.status >= 300:
            raise OSError(
                f"source '{origin}' returned HTTP {response.status} {response.reason}"
            )
        return body
    except OSError as exc:
        raise OSError(f"unable to fetch source '{origin}': {exc}") from exc
    finally:
        connection.close()
