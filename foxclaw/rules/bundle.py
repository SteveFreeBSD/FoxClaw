"""External ruleset bundle distribution management."""

from __future__ import annotations

import json
import tarfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from pydantic import ValidationError

from foxclaw.rules.keyring import load_keyring, verify_bundle_manifest
from foxclaw.rules.trust import RulesetBundleManifest


def fetch_bundle(url: str, dest_path: Path, *, allow_insecure_http: bool = False) -> None:
    """Download a ruleset bundle tarball from a remote URL."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {url}")
    if parsed.scheme == "http" and not allow_insecure_http:
        raise ValueError(
            "Insecure HTTP transport is forbidden. Use --allow-insecure-http to override."
        )
    if not parsed.netloc:
        raise ValueError(f"Invalid bundle URL (missing host): {url}")

    req = urllib.request.Request(url, headers={"User-Agent": "foxclaw-bundle-fetcher/1.0"})
    try:
        # URL scheme and host are validated above; only HTTP(S) is permitted.
        with urllib.request.urlopen(req, timeout=15) as response:  # nosec B310
            payload = response.read()
    except Exception as exc:
        raise OSError(f"Failed to fetch bundle from {url}: {exc}") from exc

    dest_path.write_bytes(payload)


def verify_and_unpack_bundle(
    archive_path: Path,
    install_dir: Path,
    key_id: str,
    keyring_path: Path,
) -> RulesetBundleManifest:
    """Verify an external bundle's signatures and extract it if valid."""
    install_dir = install_dir.expanduser().resolve()
    keyring = load_keyring(keyring_path)

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            # We strictly require __manifest__.json in the root of the archive
            try:
                manifest_member = tar.getmember("__manifest__.json")
            except KeyError as exc:
                raise ValueError("Bundle is missing __manifest__.json") from exc

            manifest_file = tar.extractfile(manifest_member)
            if manifest_file is None:
                raise ValueError("Failed to extract __manifest__.json from bundle")

            manifest_bytes = manifest_file.read()
            try:
                payload = json.loads(manifest_bytes.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"__manifest__.json is not valid JSON: {exc}") from exc

            try:
                bundle_manifest = RulesetBundleManifest.model_validate(payload)
            except ValidationError as exc:
                raise ValueError(f"Bundle manifest validation failed: {exc}") from exc

            # Verify the bundle's signature using the keyring
            verify_bundle_manifest(
                bundle_manifest=bundle_manifest,
                keyring=keyring,
                expected_key_id=key_id,
            )

            # If execution reaches here, the bundle is fully authentic. Extract it.
            _safe_extract_tar(tar, install_dir)
            return bundle_manifest

    except tarfile.TarError as exc:
        raise ValueError(f"Failed to extract bundle archive: {exc}") from exc


def _safe_extract_tar(tar: tarfile.TarFile, install_dir: Path) -> None:
    install_dir.mkdir(parents=True, exist_ok=True)
    install_root = install_dir.resolve(strict=False)

    for member in tar.getmembers():
        member_path = install_dir / member.name
        resolved = member_path.resolve(strict=False)
        if not str(resolved).startswith(f"{install_root}/") and resolved != install_root:
            raise ValueError(f"Unsafe file path in bundle: {member.name}")
        if member.islnk() or member.issym():
            raise ValueError(f"Bundle links are not allowed: {member.name}")

        if member.isdir():
            resolved.mkdir(parents=True, exist_ok=True)
            continue
        if not member.isfile():
            raise ValueError(f"Unsupported tar member type in bundle: {member.name}")

        resolved.parent.mkdir(parents=True, exist_ok=True)
        extracted = tar.extractfile(member)
        if extracted is None:
            raise ValueError(f"Failed to extract bundle member: {member.name}")
        with extracted, resolved.open("wb") as handle:
            handle.write(extracted.read())
