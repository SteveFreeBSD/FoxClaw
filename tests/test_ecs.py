from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

from foxclaw import cli as cli_module
from foxclaw.acquire.windows_share import stage_windows_share_profile
from foxclaw.cli import _build_stage_scan_manifest_command, app
from foxclaw.models import (
    EvidenceBundle,
    ExtensionEvidence,
    Finding,
    FleetHostMetadata,
    PolicyEvidence,
    PrefEvidence,
    ProfileArtifactEvidence,
    ProfileEvidence,
    ScanSummary,
    SqliteEvidence,
)
from foxclaw.report.ecs import iter_ecs_events, write_ecs_ndjson
from typer.testing import CliRunner


def _make_bundle(*, findings: list[Finding]) -> EvidenceBundle:
    return EvidenceBundle(
        generated_at=datetime(2026, 2, 28, 18, 0, 0, tzinfo=UTC),
        profile=ProfileEvidence(
            profile_id="profile-abc123",
            name="default-release",
            path="/tmp/profile",
            selected=True,
            lock_detected=False,
            lock_files=[],
        ),
        prefs=PrefEvidence(root={}),
        filesystem=[],
        policies=PolicyEvidence(),
        extensions=ExtensionEvidence(),
        sqlite=SqliteEvidence(),
        artifacts=ProfileArtifactEvidence(),
        summary=ScanSummary(
            prefs_parsed=0,
            sensitive_files_checked=0,
            high_risk_perms_count=0,
            policies_found=0,
            extensions_found=0,
            sqlite_checks_total=0,
            sqlite_non_ok_count=0,
            findings_total=len(findings),
            findings_high_count=sum(1 for item in findings if item.severity == "HIGH"),
            findings_medium_count=sum(1 for item in findings if item.severity == "MEDIUM"),
            findings_info_count=sum(1 for item in findings if item.severity == "INFO"),
            findings_suppressed_count=0,
        ),
        high_findings=[item.id for item in findings if item.severity == "HIGH"],
        findings=findings,
    )


def _make_finding(*, rule_id: str = "FC-HSTS-001", severity: str = "HIGH") -> Finding:
    return Finding(
        id=rule_id,
        title="HSTS downgrade state detected",
        severity=severity,
        category="transport",
        rationale="Profile contains HSTS state inconsistent with expected downgrade-safe posture.",
        recommendation="Reset the profile HSTS state from a trusted baseline.",
        confidence="high",
        risk_priority="high",
        risk_factors=["kev-listed", "suspicious-artifact"],
        evidence=["SiteSecurityServiceState.txt: downgrade marker present"],
    )


def _fixed_host_metadata() -> FleetHostMetadata:
    return FleetHostMetadata(
        host_id="host-01",
        hostname="workstation-01",
        fqdn="workstation-01.example.test",
        os_name="Linux",
        os_release="6.0",
        os_version="6.0.0-test",
        architecture="x86_64",
        machine_id_sha256="machine-id-sha",
    )


def _write_minimal_profile(path: Path) -> Path:
    profile_dir = path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text(
        'user_pref("browser.startup.homepage", "about:blank");\n',
        encoding="utf-8",
    )
    return profile_dir


def test_iter_ecs_events_emits_one_finding_and_one_summary(monkeypatch) -> None:
    bundle = _make_bundle(findings=[_make_finding()])
    monkeypatch.setattr("foxclaw.report.ecs._build_host_metadata", _fixed_host_metadata)

    events = list(iter_ecs_events(bundle))

    assert [item["event"]["action"] for item in events] == [
        "foxclaw.finding",
        "foxclaw.scan.summary",
    ]
    finding_event, summary_event = events
    assert finding_event["@timestamp"] == "2026-02-28T18:00:00Z"
    assert finding_event["ecs"]["version"] == "9.2.0"
    assert finding_event["event"]["kind"] == "alert"
    assert finding_event["event"]["category"] == ["configuration", "host"]
    assert finding_event["rule"]["id"] == "FC-HSTS-001"
    assert finding_event["observer"]["vendor"] == "FoxClaw"
    assert finding_event["foxclaw"]["scan"]["id"]
    assert finding_event["foxclaw"]["finding"]["risk_priority"] == "high"
    assert summary_event["event"]["kind"] == "event"
    assert summary_event["event"]["outcome"] == "success"
    assert "rule" not in summary_event
    assert summary_event["foxclaw"]["summary"]["findings_total"] == 1


def test_write_ecs_ndjson_writes_one_json_object_per_line(monkeypatch) -> None:
    bundle = _make_bundle(findings=[_make_finding()])
    monkeypatch.setattr("foxclaw.report.ecs._build_host_metadata", _fixed_host_metadata)

    output = io.StringIO()
    write_ecs_ndjson(iter_ecs_events(bundle), output)

    lines = output.getvalue().splitlines()
    assert len(lines) == 2
    assert all("\n" not in line and "\r" not in line for line in lines)
    assert [json.loads(line)["event"]["action"] for line in lines] == [
        "foxclaw.finding",
        "foxclaw.scan.summary",
    ]


def test_scan_cli_ecs_stdout_and_file_output(tmp_path: Path, monkeypatch) -> None:
    bundle = _make_bundle(findings=[_make_finding(severity="INFO")])
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    ecs_path = tmp_path / "out" / "scan.ecs.ndjson"

    monkeypatch.setattr(cli_module, "run_scan", lambda *args, **kwargs: bundle)
    monkeypatch.setattr("foxclaw.report.ecs._build_host_metadata", _fixed_host_metadata)

    runner = CliRunner()
    stdout_result = runner.invoke(app, ["scan", "--profile", str(profile_dir), "--ecs"])
    assert stdout_result.exit_code == 0
    stdout_lines = stdout_result.stdout.splitlines()
    assert len(stdout_lines) == 2
    assert [json.loads(line)["event"]["action"] for line in stdout_lines] == [
        "foxclaw.finding",
        "foxclaw.scan.summary",
    ]

    file_result = runner.invoke(
        app,
        ["scan", "--profile", str(profile_dir), "--ecs-out", str(ecs_path)],
    )
    assert file_result.exit_code == 0
    written_lines = ecs_path.read_text(encoding="utf-8").splitlines()
    assert len(written_lines) == 2
    assert "ECS report written to" in file_result.stdout


def test_scan_cli_rejects_ndjson_and_ecs_together() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--ndjson", "--ecs"])
    assert result.exit_code == 1
    assert "--json, --sarif, --ndjson, and --ecs are mutually exclusive" in result.stdout


def test_scan_cli_ecs_write_error_returns_operational_error(tmp_path: Path, monkeypatch) -> None:
    bundle = _make_bundle(findings=[_make_finding(severity="INFO")])
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    occupied_parent = tmp_path / "occupied"
    occupied_parent.write_text("not a directory", encoding="utf-8")

    monkeypatch.setattr(cli_module, "run_scan", lambda *args, **kwargs: bundle)
    monkeypatch.setattr("foxclaw.report.ecs._build_host_metadata", _fixed_host_metadata)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ecs-out",
            str(occupied_parent / "scan.ecs.ndjson"),
        ],
    )
    assert result.exit_code == 1
    assert "Operational error writing ECS output" in result.stdout


def test_build_stage_scan_manifest_command_includes_ecs_flags(tmp_path: Path) -> None:
    command = _build_stage_scan_manifest_command(
        profile_path=tmp_path / "profile",
        resolved_ruleset_path=tmp_path / "balanced.yml",
        json_output=False,
        ndjson_output=False,
        ecs_output=True,
        sarif_output=False,
        output=tmp_path / "scan.json",
        ndjson_out=None,
        ecs_out=tmp_path / "scan.ecs.ndjson",
        sarif_out=tmp_path / "scan.sarif",
        snapshot_out=tmp_path / "scan.snapshot.json",
        deterministic=True,
        policy_path=None,
        suppression_path=None,
        intel_store_dir=None,
        intel_snapshot_id=None,
        require_quiet_profile=False,
        ruleset_trust_manifest=None,
        require_ruleset_signatures=False,
        history_db=None,
        learning_artifact_out=None,
    )

    assert "--ecs" in command
    assert "--ecs-out" in command
    assert str(tmp_path / "scan.ecs.ndjson") in command


def test_acquire_windows_share_scan_passes_ecs_out(tmp_path: Path, monkeypatch) -> None:
    source_profile = _write_minimal_profile(tmp_path)
    captured: list[str] = []

    def _fake_run(argv: list[str]) -> int:
        captured.extend(argv)
        return 0

    monkeypatch.setattr(cli_module, "run_windows_share_scan_from_argv", _fake_run)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(source_profile),
            "--ecs-out",
            str(tmp_path / "out" / "scan.ecs.ndjson"),
        ],
    )

    assert result.exit_code == 0
    assert "--ecs-out" in captured
    assert str(tmp_path / "out" / "scan.ecs.ndjson") in captured


def test_stage_windows_share_profile_records_ecs_artifact(tmp_path: Path) -> None:
    source_profile = _write_minimal_profile(tmp_path)
    output_dir = tmp_path / "artifacts"
    ecs_out = output_dir / "scan.ecs.ndjson"

    stage_result = stage_windows_share_profile(
        source_profile=source_profile,
        output_dir=output_dir,
        ecs_out=ecs_out,
    )

    assert stage_result.paths.ecs_out == ecs_out
    assert stage_result.manifest_payload["artifacts"]["ecs"] == str(ecs_out)
