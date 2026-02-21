from __future__ import annotations

import json
from pathlib import Path

from foxclaw.cli import app
from foxclaw.collect.policies import collect_policies
from typer.testing import CliRunner


def test_collect_policies_parses_top_level_and_nested_key_paths(tmp_path: Path) -> None:
    policy_path = tmp_path / "enterprise" / "policies.json"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(
        json.dumps(
            {
                "policies": {
                    "DisableTelemetry": True,
                    "DisableFirefoxStudies": True,
                    "ExtensionSettings": {"*": {"installation_mode": "blocked"}},
                    "HTTPSOnlyMode": "enabled",
                    "Homepage": {"URL": "https://example.invalid"},
                }
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    evidence = collect_policies(policy_paths=[policy_path])
    assert evidence.searched_paths == [str(policy_path)]
    assert evidence.discovered_paths == [str(policy_path)]
    assert len(evidence.summaries) == 1
    summary = evidence.summaries[0]
    assert summary.parse_error is None
    assert "policies" in summary.top_level_keys
    assert "policies.DisableTelemetry" in summary.key_paths
    assert "policies.DisableFirefoxStudies" in summary.key_paths
    assert "policies.ExtensionSettings" in summary.key_paths
    assert "policies.HTTPSOnlyMode" in summary.key_paths
    assert "policies.Homepage.URL" in summary.key_paths


def test_scan_policy_path_override_uses_only_explicit_paths(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text(
        'user_pref("testbed.pref.enabled", true);\n',
        encoding="utf-8",
    )

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: policy-override-test",
                "version: 1.0.0",
                "rules:",
                "  - id: POLICY-INFO-001",
                "    title: telemetry disable policy should exist",
                "    severity: INFO",
                "    category: policy",
                "    check:",
                "      policy_key_exists:",
                "        path: policies.DisableTelemetry",
                "    rationale: deterministic policy coverage",
                "    recommendation: set policies.DisableTelemetry",
                "    confidence: low",
                "  - id: POLICY-INFO-002",
                "    title: firefox studies disable policy should exist",
                "    severity: INFO",
                "    category: policy",
                "    check:",
                "      policy_key_exists:",
                "        path: policies.DisableFirefoxStudies",
                "    rationale: deterministic policy coverage",
                "    recommendation: set policies.DisableFirefoxStudies",
                "    confidence: low",
                "  - id: POLICY-INFO-003",
                "    title: extension settings policy should exist",
                "    severity: INFO",
                "    category: policy",
                "    check:",
                "      policy_key_exists:",
                "        path: policies.ExtensionSettings",
                "    rationale: deterministic policy coverage",
                "    recommendation: set policies.ExtensionSettings",
                "    confidence: low",
            ]
        ),
        encoding="utf-8",
    )

    missing_policy = tmp_path / "missing" / "policies.json"
    present_policy = tmp_path / "enterprise" / "policies.json"
    present_policy.parent.mkdir(parents=True, exist_ok=True)
    present_policy.write_text(
        json.dumps(
            {
                "policies": {
                    "DisableTelemetry": True,
                    "DisableFirefoxStudies": True,
                    "ExtensionSettings": {"*": {"installation_mode": "blocked"}},
                }
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    runner = CliRunner()

    missing_result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--policy-path",
            str(missing_policy),
            "--json",
        ],
    )
    assert missing_result.exit_code == 0
    missing_payload = json.loads(missing_result.stdout)
    assert missing_payload["policies"]["searched_paths"] == [str(missing_policy.resolve())]
    assert missing_payload["summary"]["policies_found"] == 0
    assert {item["id"] for item in missing_payload["findings"]} == {
        "POLICY-INFO-001",
        "POLICY-INFO-002",
        "POLICY-INFO-003",
    }

    present_result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--policy-path",
            str(present_policy),
            "--json",
        ],
    )
    assert present_result.exit_code == 0
    present_payload = json.loads(present_result.stdout)
    assert present_payload["policies"]["searched_paths"] == [str(present_policy.resolve())]
    assert present_payload["policies"]["discovered_paths"] == [str(present_policy.resolve())]
    assert present_payload["summary"]["policies_found"] == 1
    assert present_payload["findings"] == []
