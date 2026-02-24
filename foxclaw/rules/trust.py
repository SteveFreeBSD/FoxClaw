"""Ruleset trust manifest loading and verification."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, Field, ValidationError, field_validator

_SUPPORTED_SCHEMA_VERSIONS = {"1.0.0", "1.1.0"}


class RulesetTrustKey(BaseModel):
    """One trusted public key entry for ruleset signature verification."""

    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"
    public_key: str
    status: Literal["active", "deprecated", "revoked"] = "active"
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class RulesetTrustSignature(BaseModel):
    """Detached signature reference for one ruleset entry."""

    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"
    signature: str


class RulesetTrustEntry(BaseModel):
    """One trusted ruleset path with pinned digest and optional signatures."""

    path: str
    sha256: str
    min_valid_signatures: int = 0
    signatures: list[RulesetTrustSignature] = Field(default_factory=list)

    @field_validator("sha256")
    @classmethod
    def _validate_sha256(_cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
            raise ValueError("sha256 must be a 64-character lowercase hex digest")
        return normalized

    @field_validator("min_valid_signatures")
    @classmethod
    def _validate_min_valid_signatures(_cls, value: int) -> int:
        if value < 0:
            raise ValueError("min_valid_signatures must be >= 0")
        return value


class RulesetTrustManifest(BaseModel):
    """Ruleset trust policy contract."""

    schema_version: str = "1.0.0"
    keys: list[RulesetTrustKey] = Field(default_factory=list)
    rulesets: list[RulesetTrustEntry] = Field(default_factory=list)


class RulesetBundleManifest(BaseModel):
    """Manifest describing a distributed ruleset bundle envelope."""

    schema_version: str = "1.0.0"
    bundle_name: str
    bundle_version: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    manifest_signature: RulesetTrustSignature
    rulesets_manifest: RulesetTrustManifest


def verify_ruleset_with_manifest(
    *,
    ruleset_path: Path,
    manifest_path: Path,
    require_signatures: bool,
    verification_time: datetime | None = None,
) -> None:
    """Verify ruleset digest/signature trust policy from a manifest file."""
    manifest = _load_manifest(manifest_path)
    entry = _resolve_ruleset_entry(manifest=manifest, ruleset_path=ruleset_path, manifest_path=manifest_path)

    ruleset_bytes = _read_ruleset_bytes(ruleset_path)
    digest = hashlib.sha256(ruleset_bytes).hexdigest()
    if digest != entry.sha256:
        raise ValueError(
            "ruleset trust verification failed: sha256 mismatch for "
            f"{ruleset_path} (expected={entry.sha256}, observed={digest})"
        )

    signatures = entry.signatures
    if not signatures:
        if require_signatures:
            raise ValueError(
                "ruleset trust verification failed: signatures are required but "
                f"manifest entry has none for {ruleset_path}"
            )
        if entry.min_valid_signatures > 0:
            raise ValueError(
                "ruleset trust verification failed: min_valid_signatures is configured "
                f"as {entry.min_valid_signatures} but manifest entry has no signatures "
                f"for {ruleset_path}"
            )
        return

    required_valid_signatures = max(1, entry.min_valid_signatures)
    key_map = _build_key_map(manifest=manifest)
    if not key_map:
        raise ValueError(
            "ruleset trust verification failed: manifest contains signatures but no keys"
        )

    reference_time = (
        verification_time.astimezone(UTC)
        if verification_time is not None
        else datetime.now(UTC)
    )

    verified_key_ids: set[str] = set()
    errors: list[str] = []
    for signature in signatures:
        key = key_map.get(signature.key_id)
        if key is None:
            errors.append(f"signature references unknown key_id='{signature.key_id}'")
            continue

        availability_error = validate_key_availability(
            key=key,
            reference_time=reference_time,
        )
        if availability_error is not None:
            errors.append(f"key_id='{signature.key_id}': {availability_error}")
            continue

        try:
            verify_ed25519_signature(
                public_key_b64=key.public_key,
                signature_b64=signature.signature,
                payload=ruleset_bytes,
            )
        except ValueError as exc:
            errors.append(f"key_id='{signature.key_id}': {exc}")
            continue

        verified_key_ids.add(signature.key_id)

    if len(verified_key_ids) < required_valid_signatures:
        details = "; ".join(errors) if errors else "no valid signature found"
        raise ValueError(
            "ruleset trust verification failed: signature threshold not met "
            f"for {ruleset_path}: required_valid_signatures={required_valid_signatures}, "
            f"verified_unique_keys={len(verified_key_ids)}: {details}"
        )


def validate_key_availability(*, key: RulesetTrustKey, reference_time: datetime) -> str | None:
    if key.status == "revoked":
        return "key is revoked"

    valid_from = key.valid_from.astimezone(UTC) if key.valid_from is not None else None
    valid_to = key.valid_to.astimezone(UTC) if key.valid_to is not None else None

    if valid_from is not None and reference_time < valid_from:
        return f"key is not yet valid (valid_from={valid_from.isoformat()})"
    if valid_to is not None and reference_time > valid_to:
        return f"key validity window expired (valid_to={valid_to.isoformat()})"
    return None


def _load_manifest(path: Path) -> RulesetTrustManifest:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OSError(f"Unable to read ruleset trust manifest: {path}: {exc}") from exc

    try:
        payload = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Unable to parse ruleset trust manifest YAML: {path}: {exc}") from exc

    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError(f"Ruleset trust manifest must be a YAML object: {path}")

    try:
        manifest = RulesetTrustManifest.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"Ruleset trust manifest validation failed: {path}: {exc}") from exc

    if manifest.schema_version not in _SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(sorted(_SUPPORTED_SCHEMA_VERSIONS))
        raise ValueError(
            "Unsupported ruleset trust manifest schema version: "
            f"{manifest.schema_version} (supported: {supported})"
        )
    return manifest


def _resolve_ruleset_entry(
    *,
    manifest: RulesetTrustManifest,
    ruleset_path: Path,
    manifest_path: Path,
) -> RulesetTrustEntry:
    resolved_ruleset_path = ruleset_path.expanduser().resolve(strict=False)
    manifest_dir = manifest_path.expanduser().resolve(strict=False).parent

    matches = [
        entry
        for entry in manifest.rulesets
        if _resolve_manifest_ruleset_path(manifest_dir=manifest_dir, raw_path=entry.path)
        == resolved_ruleset_path
    ]

    if not matches:
        raise ValueError(
            "ruleset trust verification failed: no matching ruleset entry in manifest "
            f"for {resolved_ruleset_path}"
        )
    if len(matches) > 1:
        raise ValueError(
            "ruleset trust verification failed: multiple manifest entries match "
            f"{resolved_ruleset_path}"
        )
    return matches[0]


def _resolve_manifest_ruleset_path(*, manifest_dir: Path, raw_path: str) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = manifest_dir / path
    return path.resolve(strict=False)


def _read_ruleset_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise OSError(f"Unable to read ruleset file for trust verification: {path}: {exc}") from exc


def _build_key_map(*, manifest: RulesetTrustManifest) -> dict[str, RulesetTrustKey]:
    key_map: dict[str, RulesetTrustKey] = {}
    duplicates: set[str] = set()
    for key in manifest.keys:
        if key.key_id in key_map:
            duplicates.add(key.key_id)
        key_map[key.key_id] = key

    if duplicates:
        duplicate_text = ", ".join(sorted(duplicates))
        raise ValueError(
            "ruleset trust verification failed: duplicate key_id values in manifest: "
            f"{duplicate_text}"
        )
    return key_map


def verify_ed25519_signature(
    *,
    public_key_b64: str,
    signature_b64: str,
    payload: bytes,
) -> None:
    try:
        public_key = base64.b64decode(public_key_b64, validate=True)
    except ValueError as exc:
        raise ValueError(f"invalid base64 public key: {exc}") from exc
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except ValueError as exc:
        raise ValueError(f"invalid base64 signature: {exc}") from exc

    try:
        verifier = Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError as exc:
        raise ValueError(f"invalid ed25519 public key bytes: {exc}") from exc

    try:
        verifier.verify(signature, payload)
    except InvalidSignature as exc:
        raise ValueError("ed25519 signature verification failed") from exc
