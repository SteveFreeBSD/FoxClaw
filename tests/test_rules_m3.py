from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from foxclaw.cli import app
from foxclaw.models import (
    EvidenceBundle,
    FilePermEvidence,
    PolicyEvidence,
    PolicyFileSummary,
    PrefEvidence,
    PrefValue,
    ProfileEvidence,
    RuleDefinition,
    Ruleset,
    ScanSummary,
    SqliteCheck,
    SqliteEvidence,
)
from foxclaw.rules.dsl import evaluate_check
from foxclaw.rules.engine import evaluate_rules
from typer.testing import CliRunner


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
        high_findings=[],
    )


def _write_profiles_ini(base_dir: Path, content: str) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "profiles.ini").write_text(content, encoding="utf-8")


def _create_sqlite_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def test_dsl_pref_equals_and_pref_unset_semantics() -> None:
    bundle = _empty_bundle()
    bundle.prefs = PrefEvidence(
        root={
            "test.pref": PrefValue(value=False, source="prefs.js", raw_type="bool"),
        }
    )

    mismatch = evaluate_check(bundle, {"pref_equals": {"key": "test.pref", "value": True}})
    assert mismatch.passed is False
    assert mismatch.evidence

    unset = evaluate_check(bundle, {"pref_equals": {"key": "missing.pref", "value": True}})
    assert unset.passed is True


def test_dsl_pref_equals_requires_type_stable_matches() -> None:
    bundle = _empty_bundle()
    bundle.prefs = PrefEvidence(
        root={
            "bool.pref": PrefValue(value=True, source="prefs.js", raw_type="bool"),
            "int.pref": PrefValue(value=1, source="prefs.js", raw_type="int"),
        }
    )

    bool_vs_int = evaluate_check(bundle, {"pref_equals": {"key": "bool.pref", "value": 1}})
    assert bool_vs_int.passed is False
    assert "expected=1 (int), observed=True (bool)" in bool_vs_int.evidence[0]

    int_vs_bool = evaluate_check(bundle, {"pref_equals": {"key": "int.pref", "value": True}})
    assert int_vs_bool.passed is False
    assert "expected=True (bool), observed=1 (int)" in int_vs_bool.evidence[0]


def test_dsl_pref_exists() -> None:
    bundle = _empty_bundle()

    missing = evaluate_check(bundle, {"pref_exists": {"key": "missing.pref"}})
    assert missing.passed is False

    bundle.prefs = PrefEvidence(
        root={
            "present.pref": PrefValue(value=1, source="user.js", raw_type="int"),
        }
    )
    present = evaluate_check(bundle, {"pref_exists": {"key": "present.pref"}})
    assert present.passed is True


def test_dsl_file_perm_strict_flags_relaxed_permissions() -> None:
    bundle = _empty_bundle()
    bundle.filesystem = [
        FilePermEvidence(
            path="/tmp/profile/key4.db",
            mode="0644",
            owner_uid=1000,
            owner_gid=1000,
            group_readable=True,
            group_writable=False,
            world_readable=True,
            world_writable=False,
            recommended_chmod="chmod 600 /tmp/profile/key4.db",
        )
    ]

    result = evaluate_check(bundle, {"file_perm_strict": {"key": "key4"}})
    assert result.passed is False
    assert any("0644" in line for line in result.evidence)


def test_dsl_policy_key_exists() -> None:
    bundle = _empty_bundle()
    bundle.policies = PolicyEvidence(
        discovered_paths=["/etc/firefox/policies/policies.json"],
        summaries=[
            PolicyFileSummary(
                path="/etc/firefox/policies/policies.json",
                top_level_keys=["policies"],
                key_paths=["policies.DisableTelemetry"],
                policies_count=1,
            )
        ],
    )

    result = evaluate_check(bundle, {"policy_key_exists": {"path": "policies.DisableTelemetry"}})
    assert result.passed is True


def test_dsl_sqlite_quickcheck_ok() -> None:
    bundle = _empty_bundle()
    bundle.sqlite = SqliteEvidence(
        checks=[
            SqliteCheck(
                db_path="/tmp/profile/places.sqlite",
                opened_ro=True,
                quick_check_result="ok",
            )
        ]
    )

    ok_result = evaluate_check(bundle, {"sqlite_quickcheck_ok": {"db": "places"}})
    assert ok_result.passed is True

    bundle.sqlite.checks[0].quick_check_result = "error: database is locked"
    bad_result = evaluate_check(bundle, {"sqlite_quickcheck_ok": {"db": "places"}})
    assert bad_result.passed is False


def test_findings_are_sorted_by_severity_then_id() -> None:
    bundle = _empty_bundle()
    ruleset = Ruleset(
        name="sort-test",
        version="1.0.0",
        rules=[
            RuleDefinition(
                id="Z-HIGH",
                title="z high",
                severity="HIGH",
                category="test",
                check={"pref_exists": {"key": "missing.z"}},
                rationale="r",
                recommendation="rec",
                confidence="high",
            ),
            RuleDefinition(
                id="A-HIGH",
                title="a high",
                severity="HIGH",
                category="test",
                check={"pref_exists": {"key": "missing.a"}},
                rationale="r",
                recommendation="rec",
                confidence="high",
            ),
            RuleDefinition(
                id="M-INFO",
                title="m info",
                severity="INFO",
                category="test",
                check={"pref_exists": {"key": "missing.m"}},
                rationale="r",
                recommendation="rec",
                confidence="low",
            ),
        ],
    )

    findings = evaluate_rules(bundle, ruleset)
    assert [item.id for item in findings] == ["A-HIGH", "Z-HIGH", "M-INFO"]


def test_scan_e2e_emits_high_and_info_findings(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    base_dir = home / ".mozilla" / "firefox"
    profile_dir = base_dir / "Profiles" / "main.default-release"

    _write_profiles_ini(
        base_dir,
        """[Profile0]
Name=main
IsRelative=1
Path=Profiles/main.default-release
Default=1
""",
    )

    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    (profile_dir / "prefs.js").chmod(0o600)

    # Intentionally relaxed mode to trigger HIGH file_perm_strict failure.
    (profile_dir / "key4.db").write_text("k", encoding="utf-8")
    (profile_dir / "key4.db").chmod(0o644)

    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")
    (profile_dir / "places.sqlite").chmod(0o600)
    (profile_dir / "cookies.sqlite").chmod(0o600)

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: m3-test",
                "version: 1.0.0",
                "rules:",
                "  - id: T-HIGH-001",
                "    title: key4 strict perms",
                "    severity: HIGH",
                "    category: filesystem",
                "    check:",
                "      file_perm_strict:",
                "        key: key4",
                "    rationale: key file must be strict",
                "    recommendation: chmod 600 key4.db",
                "    confidence: high",
                "  - id: T-INFO-001",
                "    title: missing pref check",
                "    severity: INFO",
                "    category: preferences",
                "    check:",
                "      pref_exists:",
                "        key: expected.pref",
                "    rationale: pref should be explicit",
                "    recommendation: set expected.pref in user.js",
                "    confidence: medium",
                "  - id: T-SQL-001",
                "    title: places quick check",
                "    severity: HIGH",
                "    category: sqlite",
                "    check:",
                "      sqlite_quickcheck_ok:",
                "        db: places",
                "    rationale: db integrity required",
                "    recommendation: repair places.sqlite if needed",
                "    confidence: high",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr("foxclaw.scan.DEFAULT_RULESET_PATH", ruleset)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)

    assert "findings" in payload
    assert len(payload["findings"]) >= 2
    assert payload["findings"][0]["severity"] == "HIGH"
    assert payload["findings"][0]["id"] == "T-HIGH-001"
    severities = {finding["severity"] for finding in payload["findings"]}
    assert "HIGH" in severities
    assert "INFO" in severities
    assert payload["summary"]["findings_high_count"] >= 1
    assert payload["summary"]["findings_info_count"] >= 1


def test_scan_profile_override_skips_discovery(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home-without-firefox-config"
    profile_dir = tmp_path / "manual-profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: override-test",
                "version: 1.0.0",
                "rules:",
                "  - id: OVR-INFO-001",
                "    title: profile override rule",
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

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

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

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["profile"]["profile_id"] == "manual"
    assert payload["profile"]["path"] == str(profile_dir.resolve())


def test_require_quiet_profile_exits_before_sqlite_checks(tmp_path: Path, monkeypatch) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "parent.lock").write_text("", encoding="utf-8")
    (profile_dir / "prefs.js").write_text("", encoding="utf-8")

    def _sqlite_must_not_run(_profile_dir: Path) -> SqliteEvidence:
        raise AssertionError("sqlite collector should not run when quiet profile is required")

    monkeypatch.setattr("foxclaw.scan.collect_sqlite_quick_checks", _sqlite_must_not_run)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--require-quiet-profile",
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "quiet profile required" in result.stdout


def test_high_findings_ids_and_summary_counts_align(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text("", encoding="utf-8")
    (profile_dir / "key4.db").write_text("k", encoding="utf-8")
    (profile_dir / "key4.db").chmod(0o644)

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: consistency-test",
                "version: 1.0.0",
                "rules:",
                "  - id: CONS-HIGH-001",
                "    title: key4 strict perms",
                "    severity: HIGH",
                "    category: filesystem",
                "    check:",
                "      file_perm_strict:",
                "        key: key4",
                "    rationale: test",
                "    recommendation: test",
                "    confidence: high",
                "  - id: CONS-INFO-001",
                "    title: explicit pref required",
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
    findings = payload["findings"]
    high_ids_from_findings = [item["id"] for item in findings if item["severity"] == "HIGH"]

    assert all(isinstance(item, str) for item in payload["high_findings"])
    assert payload["high_findings"] == high_ids_from_findings

    summary = payload["summary"]
    assert len(findings) == summary["findings_total"]
    assert len(high_ids_from_findings) == summary["findings_high_count"]
    assert (
        sum(1 for item in findings if item["severity"] == "MEDIUM")
        == summary["findings_medium_count"]
    )
    assert (
        sum(1 for item in findings if item["severity"] == "INFO") == summary["findings_info_count"]
    )
