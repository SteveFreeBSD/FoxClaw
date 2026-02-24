"""Unit tests for ruleset bundle fetching and verification."""

from __future__ import annotations

import base64
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from foxclaw.rules.bundle import verify_and_unpack_bundle
from foxclaw.rules.trust import RulesetTrustManifest


@pytest.fixture
def test_keypair() -> tuple[str, str]:
    """Return a generated Ed25519 public and private key in base64."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_b64 = base64.b64encode(public_key.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
    )).decode("ascii")
    priv_b64 = base64.b64encode(private_key.private_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PrivateFormat"]).PrivateFormat.Raw,
        encryption_algorithm=__import__("cryptography.hazmat.primitives.serialization", fromlist=["NoEncryption"]).NoEncryption(),
    )).decode("ascii")
    return pub_b64, priv_b64


@pytest.fixture
def valid_keyring(test_keypair: tuple[str, str], tmp_path: Path) -> Path:
    pub_key, _ = test_keypair
    payload = {
        "schema_version": "1.1.0",
        "keys": [
            {
                "key_id": "test-root",
                "algorithm": "ed25519",
                "public_key": pub_key,
                "status": "active"
            }
        ]
    }
    path = tmp_path / "keyring.json"
    path.write_text(json.dumps(payload))
    return path


def _create_bundle_tarball(
    archive_path: Path,
    bundle_manifest: dict[str, object],
    extra_files: dict[str, str] | None = None,
) -> None:
    manifest_bytes = json.dumps(bundle_manifest).encode("utf-8")
    with tarfile.open(archive_path, "w:gz") as tar:
        ti = tarfile.TarInfo("__manifest__.json")
        ti.size = len(manifest_bytes)
        import io
        tar.addfile(ti, io.BytesIO(manifest_bytes))

        if extra_files:
            for name, content in extra_files.items():
                content_bytes = content.encode("utf-8")
                ti = tarfile.TarInfo(name)
                ti.size = len(content_bytes)
                tar.addfile(ti, io.BytesIO(content_bytes))


def test_verify_and_unpack_bundle_success(test_keypair: tuple[str, str], valid_keyring: Path, tmp_path: Path) -> None:
    _pub_key, priv_key = test_keypair
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_key))

    rulesets_manifest = RulesetTrustManifest(
        schema_version="1.0.0",
        keys=[],
        rulesets=[],
    )

    payload_bytes = json.dumps(
        rulesets_manifest.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    signature = private_key.sign(payload_bytes)
    sig_b64 = base64.b64encode(signature).decode("ascii")

    bundle_manifest = {
        "schema_version": "1.0.0",
        "bundle_name": "foxclaw-test",
        "bundle_version": "1.0.0",
        "manifest_signature": {
            "key_id": "test-root",
            "algorithm": "ed25519",
            "signature": sig_b64,
        },
        "rulesets_manifest": rulesets_manifest.model_dump(mode="json"),
    }

    archive_path = tmp_path / "bundle.tar.gz"
    _create_bundle_tarball(archive_path, bundle_manifest, extra_files={"strict.yml": "name: strict\nversion: 1.0.0\nrules: []\n"})

    install_dir = tmp_path / "installed"
    manifest = verify_and_unpack_bundle(
        archive_path=archive_path,
        install_dir=install_dir,
        key_id="test-root",
        keyring_path=valid_keyring,
    )

    assert manifest.bundle_name == "foxclaw-test"
    assert (install_dir / "strict.yml").exists()


def test_verify_and_unpack_bundle_revoked_key(test_keypair: tuple[str, str], tmp_path: Path) -> None:
    pub_key, priv_key = test_keypair
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_key))

    # Key is revoked in keyring
    payload = {
        "schema_version": "1.1.0",
        "keys": [
            {
                "key_id": "test-root",
                "algorithm": "ed25519",
                "public_key": pub_key,
                "status": "revoked"
            }
        ]
    }
    keyring_path = tmp_path / "keyring.json"
    keyring_path.write_text(json.dumps(payload))

    rulesets_manifest = RulesetTrustManifest(schema_version="1.0.0", keys=[], rulesets=[])
    payload_bytes = json.dumps(rulesets_manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_b64 = base64.b64encode(private_key.sign(payload_bytes)).decode("ascii")

    bundle_manifest = {
        "schema_version": "1.0.0",
        "bundle_name": "foxclaw-test",
        "bundle_version": "1.0.0",
        "manifest_signature": {
            "key_id": "test-root",
            "algorithm": "ed25519",
            "signature": sig_b64,
        },
        "rulesets_manifest": rulesets_manifest.model_dump(mode="json"),
    }

    archive_path = tmp_path / "bundle.tar.gz"
    _create_bundle_tarball(archive_path, bundle_manifest)

    install_dir = tmp_path / "installed"
    with pytest.raises(ValueError, match="is revoked"):
        verify_and_unpack_bundle(
            archive_path=archive_path, install_dir=install_dir, key_id="test-root", keyring_path=keyring_path,
        )


def test_verify_and_unpack_bundle_invalid_signature(test_keypair: tuple[str, str], valid_keyring: Path, tmp_path: Path) -> None:
    _pub_key, _ = test_keypair
    # Forge a bad signature
    bad_sig = base64.b64encode(b"a" * 64).decode("ascii")

    rulesets_manifest = RulesetTrustManifest(schema_version="1.0.0", keys=[], rulesets=[])

    bundle_manifest = {
        "schema_version": "1.0.0",
        "bundle_name": "foxclaw-test",
        "bundle_version": "1.0.0",
        "manifest_signature": {
            "key_id": "test-root",
            "algorithm": "ed25519",
            "signature": bad_sig,
        },
        "rulesets_manifest": rulesets_manifest.model_dump(mode="json"),
    }

    archive_path = tmp_path / "bundle.tar.gz"
    _create_bundle_tarball(archive_path, bundle_manifest)

    install_dir = tmp_path / "installed"
    with pytest.raises(ValueError, match="ed25519 signature verification failed"):
        verify_and_unpack_bundle(
            archive_path=archive_path, install_dir=install_dir, key_id="test-root", keyring_path=valid_keyring,
        )


def test_verify_and_unpack_bundle_wrong_expected_key(test_keypair: tuple[str, str], valid_keyring: Path, tmp_path: Path) -> None:
    _pub_key, priv_key = test_keypair
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_key))

    rulesets_manifest = RulesetTrustManifest(schema_version="1.0.0", keys=[], rulesets=[])
    payload_bytes = json.dumps(rulesets_manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_b64 = base64.b64encode(private_key.sign(payload_bytes)).decode("ascii")

    bundle_manifest = {
        "schema_version": "1.0.0",
        "bundle_name": "foxclaw-test",
        "bundle_version": "1.0.0",
        "manifest_signature": {
            "key_id": "test-root",
            "algorithm": "ed25519",
            "signature": sig_b64,
        },
        "rulesets_manifest": rulesets_manifest.model_dump(mode="json"),
    }

    archive_path = tmp_path / "bundle.tar.gz"
    _create_bundle_tarball(archive_path, bundle_manifest)

    install_dir = tmp_path / "installed"
    with pytest.raises(ValueError, match="manifest signed by 'test-root', but expected 'wrong-key'"):
        verify_and_unpack_bundle(
            archive_path=archive_path, install_dir=install_dir, key_id="wrong-key", keyring_path=valid_keyring,
        )
