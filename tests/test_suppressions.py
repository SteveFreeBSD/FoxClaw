from __future__ import annotations

import json
from pathlib import Path

from foxclaw.cli import app
from typer.testing import CliRunner


def _write_ruleset(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "name: suppression-test",
                "version: 1.0.0",
                "rules:",
                "  - id: SUP-HIGH-001",
                "    title: missing pref is high",
                "    severity: HIGH",
                "    category: preferences",
                "    check:",
                "      pref_exists:",
                "        key: missing.pref",
                "    rationale: deterministic high for suppression tests",
                "    recommendation: set missing.pref",
                "    confidence: high",
            ]
        ),
        encoding="utf-8",
    )


def _write_profile(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "prefs.js").write_text("", encoding="utf-8")


def test_scan_applies_suppression_and_drops_high_exit_code(tmp_path: Path) -> None:
    runner = CliRunner()
    profile = tmp_path / "profile"
    _write_profile(profile)
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    suppressions = tmp_path / "suppressions.yml"
    suppressions.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "suppressions": [
                    {
                        "id": "sup-001",
                        "rule_id": "SUP-HIGH-001",
                        "owner": "security-team",
                        "reason": "Accepted risk for local lab profile.",
                        "expires_at": "2099-01-01T00:00:00+00:00",
                        "scope": {
                            "profile_glob": profile.resolve().as_posix(),
                        },
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--suppression-path",
            str(suppressions),
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings_total"] == 0
    assert payload["summary"]["findings_high_count"] == 0
    assert payload["summary"]["findings_suppressed_count"] == 1
    assert payload["findings"] == []
    assert len(payload["suppressions"]["applied"]) == 1
    applied = payload["suppressions"]["applied"][0]
    assert applied["id"] == "sup-001"
    assert applied["rule_id"] == "SUP-HIGH-001"
    assert applied["owner"] == "security-team"
    assert payload["suppressions"]["expired"] == []


def test_scan_ignores_expired_suppression(tmp_path: Path) -> None:
    runner = CliRunner()
    profile = tmp_path / "profile"
    _write_profile(profile)
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    suppressions = tmp_path / "suppressions.yml"
    suppressions.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "suppressions": [
                    {
                        "id": "sup-expired",
                        "rule_id": "SUP-HIGH-001",
                        "owner": "security-team",
                        "reason": "Previously accepted risk.",
                        "expires_at": "2000-01-01T00:00:00+00:00",
                        "scope": {
                            "profile_glob": profile.resolve().as_posix(),
                        },
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--suppression-path",
            str(suppressions),
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings_total"] == 1
    assert payload["summary"]["findings_high_count"] == 1
    assert payload["summary"]["findings_suppressed_count"] == 0
    assert payload["findings"][0]["id"] == "SUP-HIGH-001"
    assert len(payload["suppressions"]["expired"]) == 1
    assert payload["suppressions"]["expired"][0]["id"] == "sup-expired"
    assert payload["suppressions"]["applied"] == []


def test_scan_rejects_invalid_suppression_policy(tmp_path: Path) -> None:
    runner = CliRunner()
    profile = tmp_path / "profile"
    _write_profile(profile)
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    suppressions = tmp_path / "suppressions.yml"
    suppressions.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "suppressions": [
                    {
                        "rule_id": "SUP-HIGH-001",
                        "reason": "Missing owner should fail validation.",
                        "expires_at": "2099-01-01T00:00:00+00:00",
                        "scope": {"profile_glob": "*"},
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--suppression-path",
            str(suppressions),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "Suppression policy validation failed" in result.stdout


def test_scan_applies_evidence_contains_scope(tmp_path: Path) -> None:
    runner = CliRunner()
    profile = tmp_path / "profile"
    _write_profile(profile)
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    suppressions = tmp_path / "suppressions.yml"
    suppressions.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "suppressions": [
                    {
                        "rule_id": "SUP-HIGH-001",
                        "owner": "security-team",
                        "reason": "Only suppress this evidence fragment.",
                        "expires_at": "2099-01-01T00:00:00+00:00",
                        "scope": {
                            "profile_glob": "*",
                            "evidence_contains": "missing.pref",
                        },
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--suppression-path",
            str(suppressions),
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings_suppressed_count"] == 1
    assert payload["suppressions"]["applied"][0]["evidence_match"] == "missing.pref"


def test_scan_governance_v1_1_0_success(tmp_path: Path) -> None:
    runner = CliRunner()
    profile = tmp_path / "profile"
    _write_profile(profile)
    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    suppressions = tmp_path / "suppressions.yml"
    suppressions.write_text(
        json.dumps(
            {
                "schema_version": "1.1.0",
                "suppressions": [
                    {
                        "rule_id": "SUP-HIGH-001",
                        "owner": "security-team",
                        "reason": "Governance test.",
                        "expires_at": "2099-01-01T00:00:00+00:00",
                        "scope": {"profile_glob": "*"},
                        "approval": {
                            "requested_by": "analyst@example.com",
                            "requested_at": "2026-01-01T00:00:00+00:00",
                            "approved_by": "lead@example.com",
                            "approved_at": "2026-01-02T00:00:00+00:00",
                            "ticket": "SEC-1234",
                            "justification_type": "accepted_risk",
                        },
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--suppression-path",
            str(suppressions),
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings_suppressed_count"] == 1
    assert payload["suppressions"]["legacy_schema_count"] == 0
    assert payload["suppressions"]["applied_by_approver"]["lead@example.com"] == 1


def test_scan_governance_v1_1_0_fails_without_approval(tmp_path: Path) -> None:
    runner = CliRunner()
    suppressions = tmp_path / "suppressions.yml"
    suppressions.write_text(
        json.dumps(
            {
                "schema_version": "1.1.0",
                "suppressions": [
                    {
                        "rule_id": "SUP-HIGH-001",
                        "owner": "security-team",
                        "reason": "Missing approval block triggers error in 1.1.0.",
                        "expires_at": "2099-01-01T00:00:00+00:00",
                        "scope": {"profile_glob": "*"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["suppression", "audit", "--suppression-path", str(suppressions)])
    assert result.exit_code == 1
    assert "approval is required for schema_version 1.1.0" in result.stdout


def test_scan_governance_v1_1_0_fails_time_ordering(tmp_path: Path) -> None:
    runner = CliRunner()
    suppressions = tmp_path / "suppressions.yml"
    suppressions.write_text(
        json.dumps(
            {
                "schema_version": "1.1.0",
                "suppressions": [
                    {
                        "rule_id": "SUP-HIGH-001",
                        "owner": "security-team",
                        "reason": "Approval time > Expires time.",
                        "expires_at": "2026-01-01T00:00:00+00:00",
                        "scope": {"profile_glob": "*"},
                        "approval": {
                            "requested_by": "analyst@example.com",
                            "requested_at": "2026-01-01T00:00:00+00:00",
                            "approved_by": "lead@example.com",
                            "approved_at": "2026-01-05T00:00:00+00:00",  # later than expires!
                            "ticket": "SEC-1234",
                            "justification_type": "accepted_risk",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["suppression", "audit", "--suppression-path", str(suppressions)])
    assert result.exit_code == 1
    assert "approved_at" in result.stdout
    assert "must be < expires_at" in result.stdout
