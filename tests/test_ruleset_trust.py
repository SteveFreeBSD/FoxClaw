from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from foxclaw.rules.trust import verify_ruleset_with_manifest


def _write_ruleset(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "name: trust-test",
                "version: 1.0.0",
                "rules:",
                "  - id: TRUST-001",
                "    title: trust test",
                "    severity: INFO",
                "    category: preferences",
                "    check:",
                "      pref_exists:",
                "        key: missing.pref",
                "    rationale: test",
                "    recommendation: test",
                "    confidence: low",
            ]
        ),
        encoding="utf-8",
    )


def _write_manifest(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_verify_ruleset_manifest_sha256_match(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    sha256 = hashlib.sha256(ruleset.read_bytes()).hexdigest()

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.0.0",
            "rulesets": [{"path": str(ruleset), "sha256": sha256}],
            "keys": [],
        },
    )

    verify_ruleset_with_manifest(
        ruleset_path=ruleset,
        manifest_path=manifest,
        require_signatures=False,
    )


def test_verify_ruleset_manifest_sha256_mismatch_fails(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.0.0",
            "rulesets": [
                {
                    "path": str(ruleset),
                    "sha256": "0" * 64,
                }
            ],
            "keys": [],
        },
    )

    with pytest.raises(ValueError, match="sha256 mismatch"):
        verify_ruleset_with_manifest(
            ruleset_path=ruleset,
            manifest_path=manifest,
            require_signatures=False,
        )


def test_verify_ruleset_manifest_relative_ruleset_path_match(tmp_path: Path) -> None:
    ruleset_dir = tmp_path / "rules"
    ruleset_dir.mkdir(parents=True, exist_ok=True)
    ruleset = ruleset_dir / "rules.yml"
    _write_ruleset(ruleset)
    sha256 = hashlib.sha256(ruleset.read_bytes()).hexdigest()

    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = manifest_dir / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.0.0",
            "rulesets": [{"path": "../rules/rules.yml", "sha256": sha256}],
            "keys": [],
        },
    )

    verify_ruleset_with_manifest(
        ruleset_path=ruleset,
        manifest_path=manifest,
        require_signatures=False,
    )


def test_verify_ruleset_manifest_ed25519_signature_passes(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    ruleset_bytes = ruleset.read_bytes()
    sha256 = hashlib.sha256(ruleset_bytes).hexdigest()

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(ruleset_bytes)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.0.0",
            "keys": [
                {
                    "key_id": "test-key",
                    "algorithm": "ed25519",
                    "public_key": base64.b64encode(public_key).decode("ascii"),
                }
            ],
            "rulesets": [
                {
                    "path": str(ruleset),
                    "sha256": sha256,
                    "signatures": [
                        {
                            "key_id": "test-key",
                            "algorithm": "ed25519",
                            "signature": base64.b64encode(signature).decode("ascii"),
                        }
                    ],
                }
            ],
        },
    )

    verify_ruleset_with_manifest(
        ruleset_path=ruleset,
        manifest_path=manifest,
        require_signatures=True,
    )


def test_verify_ruleset_manifest_signature_required_without_signatures_fails(
    tmp_path: Path,
) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    sha256 = hashlib.sha256(ruleset.read_bytes()).hexdigest()

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.0.0",
            "rulesets": [{"path": str(ruleset), "sha256": sha256}],
            "keys": [],
        },
    )

    with pytest.raises(ValueError, match="signatures are required"):
        verify_ruleset_with_manifest(
            ruleset_path=ruleset,
            manifest_path=manifest,
            require_signatures=True,
        )


def test_verify_ruleset_manifest_multiple_matching_entries_fail(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    sha256 = hashlib.sha256(ruleset.read_bytes()).hexdigest()

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.0.0",
            "rulesets": [
                {"path": str(ruleset), "sha256": sha256},
                {"path": str(ruleset), "sha256": sha256},
            ],
            "keys": [],
        },
    )

    with pytest.raises(ValueError, match="multiple manifest entries match"):
        verify_ruleset_with_manifest(
            ruleset_path=ruleset,
            manifest_path=manifest,
            require_signatures=False,
        )


def test_verify_ruleset_manifest_duplicate_key_ids_fail(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    sha256 = hashlib.sha256(ruleset.read_bytes()).hexdigest()
    public_key_b64 = base64.b64encode(b"k" * 32).decode("ascii")

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.0.0",
            "rulesets": [
                {
                    "path": str(ruleset),
                    "sha256": sha256,
                    "signatures": [{"key_id": "dup-key", "signature": "AAAA"}],
                }
            ],
            "keys": [
                {
                    "key_id": "dup-key",
                    "algorithm": "ed25519",
                    "public_key": public_key_b64,
                },
                {
                    "key_id": "dup-key",
                    "algorithm": "ed25519",
                    "public_key": public_key_b64,
                },
            ],
        },
    )

    with pytest.raises(ValueError, match="duplicate key_id"):
        verify_ruleset_with_manifest(
            ruleset_path=ruleset,
            manifest_path=manifest,
            require_signatures=False,
        )


def test_verify_ruleset_manifest_unknown_signature_key_fails(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    sha256 = hashlib.sha256(ruleset.read_bytes()).hexdigest()
    public_key_b64 = base64.b64encode(b"k" * 32).decode("ascii")

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.0.0",
            "rulesets": [
                {
                    "path": str(ruleset),
                    "sha256": sha256,
                    "signatures": [{"key_id": "missing-key", "signature": "AAAA"}],
                }
            ],
            "keys": [
                {
                    "key_id": "known-key",
                    "algorithm": "ed25519",
                    "public_key": public_key_b64,
                }
            ],
        },
    )

    with pytest.raises(ValueError, match="unknown key_id"):
        verify_ruleset_with_manifest(
            ruleset_path=ruleset,
            manifest_path=manifest,
            require_signatures=True,
        )


def test_verify_ruleset_manifest_unsupported_schema_version_fails(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    sha256 = hashlib.sha256(ruleset.read_bytes()).hexdigest()

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "2.0.0",
            "rulesets": [{"path": str(ruleset), "sha256": sha256}],
            "keys": [],
        },
    )

    with pytest.raises(ValueError, match="Unsupported ruleset trust manifest schema version"):
        verify_ruleset_with_manifest(
            ruleset_path=ruleset,
            manifest_path=manifest,
            require_signatures=False,
        )


def test_verify_ruleset_manifest_signature_threshold_with_rotated_keys_passes(
    tmp_path: Path,
) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    ruleset_bytes = ruleset.read_bytes()
    sha256 = hashlib.sha256(ruleset_bytes).hexdigest()

    private_a = Ed25519PrivateKey.generate()
    public_a = private_a.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature_a = private_a.sign(ruleset_bytes)

    private_b = Ed25519PrivateKey.generate()
    public_b = private_b.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature_b = private_b.sign(ruleset_bytes)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.1.0",
            "keys": [
                {
                    "key_id": "release-key-1",
                    "algorithm": "ed25519",
                    "public_key": base64.b64encode(public_a).decode("ascii"),
                    "status": "deprecated",
                    "valid_to": "2030-01-01T00:00:00+00:00",
                },
                {
                    "key_id": "release-key-2",
                    "algorithm": "ed25519",
                    "public_key": base64.b64encode(public_b).decode("ascii"),
                    "status": "active",
                    "valid_from": "2025-01-01T00:00:00+00:00",
                },
            ],
            "rulesets": [
                {
                    "path": str(ruleset),
                    "sha256": sha256,
                    "min_valid_signatures": 2,
                    "signatures": [
                        {
                            "key_id": "release-key-1",
                            "algorithm": "ed25519",
                            "signature": base64.b64encode(signature_a).decode("ascii"),
                        },
                        {
                            "key_id": "release-key-2",
                            "algorithm": "ed25519",
                            "signature": base64.b64encode(signature_b).decode("ascii"),
                        },
                    ],
                }
            ],
        },
    )

    verify_ruleset_with_manifest(
        ruleset_path=ruleset,
        manifest_path=manifest,
        require_signatures=True,
        verification_time=datetime(2026, 2, 21, tzinfo=UTC),
    )


def test_verify_ruleset_manifest_signature_threshold_fails_when_not_met(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    ruleset_bytes = ruleset.read_bytes()
    sha256 = hashlib.sha256(ruleset_bytes).hexdigest()

    private_a = Ed25519PrivateKey.generate()
    public_a = private_a.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature_a = private_a.sign(ruleset_bytes)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.1.0",
            "keys": [
                {
                    "key_id": "release-key-1",
                    "algorithm": "ed25519",
                    "public_key": base64.b64encode(public_a).decode("ascii"),
                }
            ],
            "rulesets": [
                {
                    "path": str(ruleset),
                    "sha256": sha256,
                    "min_valid_signatures": 2,
                    "signatures": [
                        {
                            "key_id": "release-key-1",
                            "algorithm": "ed25519",
                            "signature": base64.b64encode(signature_a).decode("ascii"),
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(ValueError, match="signature threshold not met"):
        verify_ruleset_with_manifest(
            ruleset_path=ruleset,
            manifest_path=manifest,
            require_signatures=True,
        )


def test_verify_ruleset_manifest_revoked_key_rejected(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    ruleset_bytes = ruleset.read_bytes()
    sha256 = hashlib.sha256(ruleset_bytes).hexdigest()

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(ruleset_bytes)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.1.0",
            "keys": [
                {
                    "key_id": "revoked-key",
                    "algorithm": "ed25519",
                    "public_key": base64.b64encode(public_key).decode("ascii"),
                    "status": "revoked",
                }
            ],
            "rulesets": [
                {
                    "path": str(ruleset),
                    "sha256": sha256,
                    "signatures": [
                        {
                            "key_id": "revoked-key",
                            "algorithm": "ed25519",
                            "signature": base64.b64encode(signature).decode("ascii"),
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(ValueError, match="key is revoked"):
        verify_ruleset_with_manifest(
            ruleset_path=ruleset,
            manifest_path=manifest,
            require_signatures=True,
        )


def test_verify_ruleset_manifest_expired_key_rejected(tmp_path: Path) -> None:
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    ruleset_bytes = ruleset.read_bytes()
    sha256 = hashlib.sha256(ruleset_bytes).hexdigest()

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(ruleset_bytes)
    past = datetime.now(UTC) - timedelta(days=1)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        manifest,
        {
            "schema_version": "1.1.0",
            "keys": [
                {
                    "key_id": "expired-key",
                    "algorithm": "ed25519",
                    "public_key": base64.b64encode(public_key).decode("ascii"),
                    "status": "active",
                    "valid_to": past.isoformat(),
                }
            ],
            "rulesets": [
                {
                    "path": str(ruleset),
                    "sha256": sha256,
                    "signatures": [
                        {
                            "key_id": "expired-key",
                            "algorithm": "ed25519",
                            "signature": base64.b64encode(signature).decode("ascii"),
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(ValueError, match="key validity window expired"):
        verify_ruleset_with_manifest(
            ruleset_path=ruleset,
            manifest_path=manifest,
            require_signatures=True,
            verification_time=datetime.now(UTC),
        )
