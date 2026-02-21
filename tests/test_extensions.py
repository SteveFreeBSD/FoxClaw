from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from foxclaw.cli import app
from foxclaw.collect.extensions import collect_extensions
from foxclaw.models import (
    EvidenceBundle,
    ExtensionEntry,
    ExtensionEvidence,
    ExtensionPermissionRisk,
    PolicyEvidence,
    PrefEvidence,
    ProfileEvidence,
    ScanSummary,
    SqliteEvidence,
)
from foxclaw.rules.dsl import evaluate_check
from typer.testing import CliRunner


def _create_sqlite_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def _write_xpi_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True))


def _empty_bundle() -> EvidenceBundle:
    return EvidenceBundle(
        profile=ProfileEvidence(
            profile_id="Profile0",
            name="default",
            path="/tmp/profile",
            selected=True,
            lock_detected=False,
            lock_files=[],
        ),
        prefs=PrefEvidence(root={}),
        filesystem=[],
        policies=PolicyEvidence(),
        sqlite=SqliteEvidence(checks=[]),
        summary=ScanSummary(
            prefs_parsed=0,
            sensitive_files_checked=0,
            high_risk_perms_count=0,
            policies_found=0,
            sqlite_checks_total=0,
            sqlite_non_ok_count=0,
        ),
    )


def test_collect_extensions_parses_manifest_permissions_and_risk_levels(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    extensions_dir = profile_dir / "extensions"
    extension_id = "risky@example.com"
    xpi_path = extensions_dir / f"{extension_id}.xpi"

    _write_xpi_manifest(
        xpi_path,
        {
            "manifest_version": 2,
            "name": "Risky Extension",
            "version": "1.0.0",
            "permissions": ["tabs", "nativeMessaging", "<all_urls>"],
        },
    )

    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": extension_id,
                        "type": "extension",
                        "active": True,
                        "version": "1.0.0",
                        "signedState": 2,
                        "path": str(xpi_path),
                        "defaultLocale": {"name": "Risky Extension"},
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    evidence = collect_extensions(profile_dir)

    assert evidence.parse_error is None
    assert evidence.addons_seen == 1
    assert evidence.active_addons == 1
    assert len(evidence.entries) == 1

    entry = evidence.entries[0]
    assert entry.addon_id == extension_id
    assert entry.name == "Risky Extension"
    assert entry.source_kind == "profile"
    assert entry.signed_valid is True
    assert entry.signed_status == "valid"
    assert entry.manifest_status == "parsed"
    assert entry.manifest_version == 2
    assert "nativeMessaging" in entry.permissions
    assert "<all_urls>" in entry.host_permissions

    risky_by_permission = {risk.permission: risk.level for risk in entry.risky_permissions}
    assert risky_by_permission["nativeMessaging"] == "high"
    assert risky_by_permission["tabs"] == "medium"
    assert risky_by_permission["<all_urls>"] == "high"


def test_collect_extensions_reports_missing_manifest(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "missing@example.com",
                        "type": "extension",
                        "active": True,
                        "signedState": 2,
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    evidence = collect_extensions(profile_dir)
    assert evidence.addons_seen == 1
    assert evidence.entries[0].parse_error == "manifest not found"
    assert evidence.entries[0].manifest_status == "unavailable"


def test_collect_extensions_marks_temporarily_installed_debug_extensions(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "debug@example.com",
                        "type": "extension",
                        "active": True,
                        "signedState": 2,
                        "temporarilyInstalled": True,
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    evidence = collect_extensions(profile_dir)
    assert evidence.addons_seen == 1
    entry = evidence.entries[0]
    assert entry.debug_install is True
    assert entry.debug_reason == "temporarilyInstalled=1"


def test_collect_extensions_marks_external_temp_source_path_as_debug_install(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "external-temp@example.com",
                        "type": "extension",
                        "active": True,
                        "location": "app-profile",
                        "path": "/tmp/external-temp@example.com.xpi",
                        "signedState": 2,
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    evidence = collect_extensions(profile_dir)
    assert evidence.addons_seen == 1
    entry = evidence.entries[0]
    assert entry.source_kind == "external"
    assert entry.debug_install is True
    assert entry.debug_reason == "source_path=/tmp/external-temp@example.com.xpi"


def test_collect_extensions_profile_path_is_not_marked_debug_install(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    extension_id = "profile-installed@example.com"
    relative_path = f"extensions/{extension_id}.xpi"
    _write_xpi_manifest(
        profile_dir / relative_path,
        {
            "manifest_version": 2,
            "name": "Profile Installed",
            "version": "1.0.0",
        },
    )

    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": extension_id,
                        "type": "extension",
                        "active": True,
                        "location": "app-profile",
                        "path": relative_path,
                        "signedState": 2,
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    evidence = collect_extensions(profile_dir)
    assert evidence.addons_seen == 1
    entry = evidence.entries[0]
    assert entry.source_kind == "profile"
    assert entry.debug_install is False
    assert entry.debug_reason is None


def test_collect_extensions_builtin_without_manifest_is_reported_as_unavailable(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "screenshots@mozilla.org",
                        "type": "extension",
                        "active": True,
                        "location": "app-system-defaults",
                        "signedState": 0,
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    evidence = collect_extensions(profile_dir)
    assert evidence.addons_seen == 1
    entry = evidence.entries[0]
    assert entry.source_kind == "system"
    assert entry.manifest_status == "unavailable"
    assert entry.manifest_version is None
    assert entry.parse_error is None
    assert entry.signed_valid is None
    assert entry.signed_status == "unavailable"


def test_dsl_extension_unsigned_debug_and_permission_risk_absent() -> None:
    bundle = _empty_bundle()
    bundle.extensions = ExtensionEvidence(
        entries=[
            ExtensionEntry(
                addon_id="builtin-unsigned@example.com",
                active=True,
                source_kind="builtin",
                signed_valid=False,
                signed_state="0",
                risky_permissions=[
                    ExtensionPermissionRisk(
                        permission="nativeMessaging",
                        level="high",
                        reason="test",
                    )
                ],
            ),
            ExtensionEntry(
                addon_id="unsigned@example.com",
                active=True,
                source_kind="profile",
                signed_valid=False,
                signed_state="0",
                debug_install=True,
                debug_reason="temporarilyInstalled=1",
                intel_reputation_level="high",
                intel_listed=False,
                intel_source="amo",
                risky_permissions=[
                    ExtensionPermissionRisk(
                        permission="nativeMessaging",
                        level="high",
                        reason="test",
                    ),
                    ExtensionPermissionRisk(
                        permission="tabs",
                        level="medium",
                        reason="test",
                    ),
                ],
            )
        ],
        addons_seen=1,
        active_addons=1,
    )

    unsigned_result = evaluate_check(bundle, {"extension_unsigned_absent": {}})
    assert unsigned_result.passed is False
    assert unsigned_result.evidence == [
        "unsigned@example.com: signed_valid=0, signed_state=0, active=1"
    ]

    unsigned_with_system = evaluate_check(
        bundle,
        {"extension_unsigned_absent": {"include_system": True}},
    )
    assert unsigned_with_system.passed is False
    assert len(unsigned_with_system.evidence) == 2

    debug_result = evaluate_check(bundle, {"extension_debug_absent": {}})
    assert debug_result.passed is False
    assert debug_result.evidence == [
        "unsigned@example.com: debug_install=1, reason=temporarilyInstalled=1, active=1"
    ]

    high_only = evaluate_check(
        bundle,
        {"extension_permission_risk_absent": {"min_level": "high"}},
    )
    assert high_only.passed is False
    assert high_only.evidence == [
        "unsigned@example.com: permission=nativeMessaging, level=high, active=1"
    ]
    assert all("tabs" not in line for line in high_only.evidence)

    high_only_with_system = evaluate_check(
        bundle,
        {"extension_permission_risk_absent": {"min_level": "high", "include_system": True}},
    )
    assert high_only_with_system.passed is False
    assert len(high_only_with_system.evidence) == 2

    medium = evaluate_check(
        bundle,
        {"extension_permission_risk_absent": {"min_level": "medium"}},
    )
    assert medium.passed is False
    assert any("tabs" in line for line in medium.evidence)

    intel_high = evaluate_check(
        bundle,
        {
            "extension_intel_reputation_absent": {
                "min_level": "high",
                "include_unlisted": True,
            }
        },
    )
    assert intel_high.passed is False
    assert intel_high.evidence == [
        "unsigned@example.com: intel_reputation=high, intel_listed=0, active=1, intel_source=amo"
    ]


def test_scan_emits_extension_posture_summary_and_findings(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")
    (profile_dir / "prefs.js").write_text(
        'user_pref("scan.pref", true);\n',
        encoding="utf-8",
    )

    extension_id = "unsigned-risky@example.com"
    xpi_path = profile_dir / "extensions" / f"{extension_id}.xpi"
    _write_xpi_manifest(
        xpi_path,
        {
            "manifest_version": 2,
            "name": "Unsigned Risky",
            "version": "1.0.0",
            "permissions": ["nativeMessaging", "tabs", "<all_urls>"],
        },
    )

    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": extension_id,
                        "type": "extension",
                        "active": True,
                        "version": "1.0.0",
                        "signedState": 0,
                        "temporarilyInstalled": True,
                        "path": str(xpi_path),
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: extension-posture-test",
                "version: 1.0.0",
                "rules:",
                "  - id: EXT-HIGH-001",
                "    title: unsigned extensions are disallowed",
                "    severity: HIGH",
                "    category: extensions",
                "    check:",
                "      extension_unsigned_absent: {}",
                "    rationale: extension signature trust",
                "    recommendation: remove unsigned extension",
                "    confidence: high",
                "  - id: EXT-MED-001",
                "    title: high-risk permissions are disallowed",
                "    severity: MEDIUM",
                "    category: extensions",
                "    check:",
                "      extension_permission_risk_absent:",
                "        min_level: high",
                "    rationale: least privilege",
                "    recommendation: remove risky extension",
                "    confidence: medium",
                "  - id: EXT-MED-DBG",
                "    title: debug installs are disallowed",
                "    severity: MEDIUM",
                "    category: extensions",
                "    check:",
                "      extension_debug_absent: {}",
                "    rationale: debug installs are volatile",
                "    recommendation: remove temporary extension installs",
                "    confidence: medium",
            ]
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)

    findings = {item["id"] for item in payload["findings"]}
    assert findings == {"EXT-HIGH-001", "EXT-MED-001", "EXT-MED-DBG"}

    summary = payload["summary"]
    assert summary["extensions_found"] == 1
    assert summary["extensions_active"] == 1
    assert summary["extensions_high_risk_count"] == 1
    assert summary["extensions_unsigned_count"] == 1
    assert summary["extensions_debug_count"] == 1

    extensions_payload = payload["extensions"]
    assert extensions_payload["addons_seen"] == 1
    assert len(extensions_payload["entries"]) == 1
    assert extensions_payload["entries"][0]["addon_id"] == extension_id
