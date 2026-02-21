"""External ruleset bundle distribution management."""

from __future__ import annotations

import json
import tarfile
import urllib.request
from pathlib import Path

from pydantic import ValidationError

from foxclaw.rules.keyring import load_keyring, verify_bundle_manifest
from foxclaw.rules.trust import RulesetBundleManifest


def fetch_bundle(url: str, dest_path: Path, *, allow_insecure_http: bool = False) -> None:
    """Download a ruleset bundle tarball from a remote URL."""
    if url.startswith("http://") and not allow_insecure_http:
        raise ValueError("Insecure HTTP transport is forbidden. Use --allow-insecure-http to override.")

    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError(f"Unsupported URL scheme: {url}")

    req = urllib.request.Request(url, headers={"User-Agent": "foxclaw-bundle-fetcher/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
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
            )

            # If execution reaches here, the bundle is fully authentic. Extract it.
            install_dir.mkdir(parents=True, exist_ok=True)
            
            # Safe extraction: prevent path traversal (Zip Slip)
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise ValueError(f"Unsafe file path in bundle: {member.name}")
            
            tar.extractall(path=install_dir)
            
            return bundle_manifest

    except tarfile.TarError as exc:
        raise ValueError(f"Failed to extract bundle archive: {exc}") from exc
