from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from foxclaw.cli import app
from foxclaw.models import (
    EvidenceBundle,
    Finding,
    PolicyEvidence,
    PrefEvidence,
    ProfileEvidence,
    ScanSummary,
    SqliteEvidence,
)
from foxclaw.report.sarif import render_scan_sarif


def _bundle_with_findings(findings: list[Finding]) -> EvidenceBundle:
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
            high_findings_count=0,
            findings_total=len(findings),
            findings_high_count=sum(1 for item in findings if item.severity == "HIGH"),
            findings_medium_count=sum(
                1 for item in findings if item.severity == "MEDIUM"
            ),
            findings_info_count=sum(1 for item in findings if item.severity == "INFO"),
        ),
        high_findings=[],
        findings=findings,
    )


def _write_profiles_ini(base_dir: Path, content: str) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "profiles.ini").write_text(content, encoding="utf-8")


def test_render_sarif_has_required_fields_and_result_mappings() -> None:
    findings = [
        Finding(
            id="R-HIGH-001",
            title="High issue",
            severity="HIGH",
            category="filesystem",
            rationale="High rationale",
            recommendation="Fix high",
            confidence="high",
            evidence=["/tmp/profile/key4.db: mode=0644"],
        ),
        Finding(
            id="R-MED-001",
            title="Medium issue",
            severity="MEDIUM",
            category="preferences",
            rationale="Medium rationale",
            recommendation="Fix medium",
            confidence="medium",
            evidence=["some.pref: expected=true observed=false"],
        ),
        Finding(
            id="R-HIGH-001",
            title="High issue duplicate",
            severity="HIGH",
            category="filesystem",
            rationale="High rationale",
            recommendation="Fix high",
            confidence="high",
            evidence=["no path in this evidence"],
        ),
        Finding(
            id="R-INFO-001",
            title="Info issue",
            severity="INFO",
            category="policy",
            rationale="Info rationale",
            recommendation="Fix info",
            confidence="low",
            evidence=["file:///etc/firefox/policies/policies.json: found key"],
        ),
    ]
    bundle = _bundle_with_findings(findings)

    payload = json.loads(render_scan_sarif(bundle))
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "FoxClaw"

    results = payload["runs"][0]["results"]
    assert len(results) == len(findings)
    assert [item["ruleId"] for item in results] == [item.id for item in findings]

    levels = [item["level"] for item in results]
    assert levels == ["error", "warning", "error", "note"]

    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "/tmp/profile/key4.db"
    )
    assert results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "foxclaw://profile"
    )
    assert results[3]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "file:///etc/firefox/policies/policies.json"
    )

    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [item["id"] for item in rules]
    assert rule_ids == sorted(set(rule_ids))
    assert set(rule_ids) == set(result["ruleId"] for result in results)


def test_scan_cli_rejects_json_and_sarif_together() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--json", "--sarif"])
    assert result.exit_code == 1
    assert "mutually exclusive" in result.stdout


def test_scan_cli_sarif_stdout_and_file_output(tmp_path: Path, monkeypatch) -> None:
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
    (profile_dir / "prefs.js").write_text(
        'user_pref("scan.pref", true);\n', encoding="utf-8"
    )
    (profile_dir / "prefs.js").chmod(0o600)

    # Ruleset intentionally emits INFO only so exit code remains 0.
    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: sarif-test",
                "version: 1.0.0",
                "rules:",
                "  - id: T-INFO-001",
                "    title: pref should exist",
                "    severity: INFO",
                "    category: preferences",
                "    check:",
                "      pref_exists:",
                "        key: expected.pref",
                "    rationale: pref should be explicit",
                "    recommendation: set expected.pref",
                "    confidence: medium",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr("foxclaw.scan.DEFAULT_RULESET_PATH", ruleset)

    runner = CliRunner()
    stdout_result = runner.invoke(app, ["scan", "--sarif"])
    assert stdout_result.exit_code == 0
    stdout_payload = json.loads(stdout_result.stdout)
    assert stdout_payload["version"] == "2.1.0"

    sarif_path = tmp_path / "out" / "scan.sarif"
    file_result = runner.invoke(app, ["scan", "--sarif-out", str(sarif_path)])
    assert file_result.exit_code == 0
    written = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert written["runs"][0]["tool"]["driver"]["name"] == "FoxClaw"
