from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

from foxclaw import cli as cli_module
from foxclaw.cli import app
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
from foxclaw.report.siem import iter_siem_events, write_ndjson
from typer.testing import CliRunner


def _make_bundle(*, findings: list[Finding]) -> EvidenceBundle:
    return EvidenceBundle(
        generated_at=datetime(2026, 2, 27, 15, 0, 0, tzinfo=UTC),
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


def test_iter_siem_events_emits_one_finding_and_one_summary(monkeypatch) -> None:
    bundle = _make_bundle(findings=[_make_finding()])
    monkeypatch.setattr("foxclaw.report.siem._build_host_metadata", _fixed_host_metadata)

    events = list(iter_siem_events(bundle))

    assert [item["event_type"] for item in events] == [
        "foxclaw.finding",
        "foxclaw.scan.summary",
    ]
    finding_event, summary_event = events

    assert finding_event["rule_id"] == "FC-HSTS-001"
    assert "rule_id" not in summary_event
    assert finding_event["profile"]["profile_id"] == "profile-abc123"
    assert finding_event["host"]["id"] == "host-01"
    assert summary_event["findings_total"] == 1

    for event in events:
        assert event["schema_version"] == "1.0.0"
        assert event["timestamp"] == "2026-02-27T15:00:00Z"
        assert event["event_id"]
        assert event["title"]
        assert event["message"]


def test_write_ndjson_writes_one_json_object_per_line(monkeypatch) -> None:
    bundle = _make_bundle(findings=[_make_finding()])
    monkeypatch.setattr("foxclaw.report.siem._build_host_metadata", _fixed_host_metadata)

    output = io.StringIO()
    write_ndjson(iter_siem_events(bundle), output)

    lines = output.getvalue().splitlines()
    assert len(lines) == 2
    assert all("\n" not in line and "\r" not in line for line in lines)
    assert [json.loads(line)["event_type"] for line in lines] == [
        "foxclaw.finding",
        "foxclaw.scan.summary",
    ]


def test_event_id_is_stable_for_identical_inputs(monkeypatch) -> None:
    bundle = _make_bundle(findings=[_make_finding()])
    monkeypatch.setattr("foxclaw.report.siem._build_host_metadata", _fixed_host_metadata)

    events_a = list(iter_siem_events(bundle))
    events_b = list(iter_siem_events(bundle))

    assert [item["event_id"] for item in events_a] == [item["event_id"] for item in events_b]


def test_scan_cli_ndjson_stdout_and_file_output(tmp_path: Path, monkeypatch) -> None:
    bundle = _make_bundle(findings=[_make_finding(severity="INFO")])
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    ndjson_path = tmp_path / "out" / "scan.ndjson"

    monkeypatch.setattr(cli_module, "run_scan", lambda *args, **kwargs: bundle)
    monkeypatch.setattr("foxclaw.report.siem._build_host_metadata", _fixed_host_metadata)

    runner = CliRunner()
    stdout_result = runner.invoke(app, ["scan", "--profile", str(profile_dir), "--ndjson"])
    assert stdout_result.exit_code == 0
    stdout_lines = stdout_result.stdout.splitlines()
    assert len(stdout_lines) == 2
    assert [json.loads(line)["event_type"] for line in stdout_lines] == [
        "foxclaw.finding",
        "foxclaw.scan.summary",
    ]

    file_result = runner.invoke(
        app,
        ["scan", "--profile", str(profile_dir), "--ndjson-out", str(ndjson_path)],
    )
    assert file_result.exit_code == 0
    written_lines = ndjson_path.read_text(encoding="utf-8").splitlines()
    assert len(written_lines) == 2


def test_scan_cli_rejects_json_and_ndjson_together() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--json", "--ndjson"])
    assert result.exit_code == 1
    assert "--json, --sarif, and --ndjson are mutually exclusive" in result.stdout


def test_scan_cli_ndjson_write_error_returns_operational_error(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = _make_bundle(findings=[_make_finding(severity="INFO")])
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    occupied_parent = tmp_path / "occupied"
    occupied_parent.write_text("not a directory", encoding="utf-8")

    monkeypatch.setattr(cli_module, "run_scan", lambda *args, **kwargs: bundle)
    monkeypatch.setattr("foxclaw.report.siem._build_host_metadata", _fixed_host_metadata)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ndjson-out",
            str(occupied_parent / "scan.ndjson"),
        ],
    )
    assert result.exit_code == 1
    assert "Operational error writing NDJSON output" in result.stdout
