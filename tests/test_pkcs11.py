from __future__ import annotations

from pathlib import Path

from foxclaw.collect.pkcs11 import audit_pkcs11_modules


def test_audit_pkcs11_modules_missing_file_returns_empty(tmp_path: Path) -> None:
    result = audit_pkcs11_modules(tmp_path / "missing-pkcs11.txt")

    assert result.parse_error is None
    assert result.modules == ()
    assert result.suspicious_modules == ()


def test_audit_pkcs11_modules_benign_store(tmp_path: Path) -> None:
    pkcs11_path = tmp_path / "pkcs11.txt"
    pkcs11_path.write_text(
        "\n".join(
            [
                "name=NSS Internal PKCS #11 Module",
                "library=",
                "",
                "name=Mozilla Shared Security Module",
                "library=/usr/lib/x86_64-linux-gnu/libsoftokn3.so",
                "",
                "name=Windows Builtin Module",
                "library=C:\\Windows\\System32\\nssckbi.dll",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = audit_pkcs11_modules(pkcs11_path)

    assert result.parse_error is None
    assert len(result.modules) == 3
    assert result.suspicious_modules == ()


def test_audit_pkcs11_modules_flags_non_standard_paths(tmp_path: Path) -> None:
    pkcs11_path = tmp_path / "pkcs11.txt"
    pkcs11_path.write_text(
        "\n".join(
            [
                "name=Injected Relative Module",
                "library=evilpkcs11.so",
                "",
                "name=Injected Tmp Module",
                "library=/tmp/evilpkcs11.so",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = audit_pkcs11_modules(pkcs11_path)

    assert result.parse_error is None
    assert len(result.modules) == 2
    assert [item.name for item in result.suspicious_modules] == [
        "Injected Relative Module",
        "Injected Tmp Module",
    ]
    assert result.suspicious_modules[0].reasons == ("relative_or_unqualified_library_path",)
    assert result.suspicious_modules[1].reasons == ("non_standard_library_path",)

