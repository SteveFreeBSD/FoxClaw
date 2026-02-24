"""Managed keyring for bundle verification."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

from foxclaw.rules.trust import (
    RulesetBundleManifest,
    RulesetTrustKey,
    _validate_key_availability,
    _verify_ed25519_signature,
)

_SUPPORTED_SCHEMA_VERSIONS = {"1.0.0", "1.1.0"}


class KeyringManifest(BaseModel):
    """A collection of trusted root keys for external bundle verification."""

    schema_version: str = "1.1.0"
    keys: list[RulesetTrustKey] = Field(default_factory=list)


def load_keyring(path: Path) -> KeyringManifest:
    """Load and parse a keyring manifest from YAML or JSON."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OSError(f"Unable to read keyring file: {path}: {exc}") from exc

    try:
        payload = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Unable to parse keyring YAML: {path}: {exc}") from exc

    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError(f"Keyring must be a YAML object: {path}")

    try:
        manifest = KeyringManifest.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"Keyring validation failed: {path}: {exc}") from exc

    if manifest.schema_version not in _SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(sorted(_SUPPORTED_SCHEMA_VERSIONS))
        raise ValueError(
            f"Unsupported keyring schema version: {manifest.schema_version} (supported: {supported})"
        )
    return manifest


def verify_bundle_manifest(
    *,
    bundle_manifest: RulesetBundleManifest,
    keyring: KeyringManifest,
    expected_key_id: str,
    verification_time: datetime | None = None,
) -> None:
    """Verify a downloaded bundle manifest envelope against the trusted keyring."""
    reference_time = (
        verification_time.astimezone(UTC)
        if verification_time is not None
        else datetime.now(UTC)
    )

    signature_entry = bundle_manifest.manifest_signature
    if signature_entry.key_id != expected_key_id:
        raise ValueError(
            f"bundle verification failed: manifest signed by '{signature_entry.key_id}', "
            f"but expected '{expected_key_id}'"
        )

    # We verify the signature over the strict JSON representation of the rulesets_manifest
    # This ensures deterministic byte comparison.
    payload_bytes = json.dumps(
        bundle_manifest.rulesets_manifest.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    key_id = signature_entry.key_id
    key = next((k for k in keyring.keys if k.key_id == key_id), None)
    if key is None:
        raise ValueError(f"bundle verification failed: key_id '{key_id}' not found in keyring")

    availability_error = _validate_key_availability(key=key, reference_time=reference_time)
    if availability_error is not None:
        raise ValueError(f"bundle verification failed: key_id '{key_id}' is unavailable: {availability_error}")

    try:
        _verify_ed25519_signature(
            public_key_b64=key.public_key,
            signature_b64=signature_entry.signature,
            payload=payload_bytes,
        )
    except ValueError as exc:
        raise ValueError(f"bundle verification failed for key_id '{key_id}': {exc}") from exc
