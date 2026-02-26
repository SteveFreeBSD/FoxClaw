"""Tests for foxclaw.learning.history (WS-55A scan history ingestion)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from foxclaw.learning.history import ScanHistoryStore, _compute_scan_id
from foxclaw.models import (
    CredentialEvidence,
    EvidenceBundle,
    ExtensionEvidence,
    Finding,
    PolicyEvidence,
    PrefEvidence,
    ProfileArtifactEntry,
    ProfileArtifactEvidence,
    ProfileEvidence,
    ScanSummary,
    SqliteEvidence,
)


def _make_finding(rule_id: str, severity: str = "HIGH") -> Finding:
    return Finding(
        id=rule_id,
        title=f"{rule_id} finding",
        severity=severity,
        category="test",
        rationale="Testing",
        recommendation="Fix it",
        confidence="high",
        evidence=[f"{rule_id} evidence"],
    )


def _make_evidence(
    profile_path: str = "/home/user/.mozilla/firefox/test.default",
    profile_name: str = "test.default",
    findings: list[Finding] | None = None,
    generated_at: datetime | None = None,
) -> EvidenceBundle:
    """Build a minimal EvidenceBundle for testing."""
    if findings is None:
        findings = [
            Finding(
                id="FC-TEST-001",
                title="Test finding",
                severity="HIGH",
                category="test",
                rationale="Testing",
                recommendation="Fix it",
                confidence="high",
                evidence=["test evidence line 1", "test evidence line 2"],
            ),
            Finding(
                id="FC-TEST-002",
                title="Another finding",
                severity="MEDIUM",
                category="test",
                rationale="Also testing",
                recommendation="Also fix it",
                confidence="medium",
                evidence=["medium evidence"],
            ),
        ]
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
    info_count = sum(1 for f in findings if f.severity == "INFO")

    return EvidenceBundle(
        generated_at=generated_at or datetime(2026, 2, 24, 12, 0, 0, tzinfo=UTC),
        profile=ProfileEvidence(
            profile_id="test",
            name=profile_name,
            path=profile_path,
            selected=True,
            lock_detected=False,
        ),
        prefs=PrefEvidence(root={}),
        filesystem=[],
        policies=PolicyEvidence(),
        extensions=ExtensionEvidence(),
        sqlite=SqliteEvidence(),
        credentials=CredentialEvidence(),
        artifacts=ProfileArtifactEvidence(),
        summary=ScanSummary(
            prefs_parsed=10,
            sensitive_files_checked=5,
            high_risk_perms_count=0,
            policies_found=1,
            extensions_found=3,
            sqlite_checks_total=4,
            sqlite_non_ok_count=0,
            findings_total=len(findings),
            findings_high_count=high_count,
            findings_medium_count=medium_count,
            findings_info_count=info_count,
            findings_suppressed_count=0,
        ),
        high_findings=[f.id for f in findings if f.severity == "HIGH"],
        findings=findings,
    )


class TestScanHistoryStore:
    """Tests for the append-only scan history store."""

    def test_create_empty_store(self, tmp_path: Path) -> None:
        """New store creates schema and is empty."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)
        assert store.scan_count() == 0
        assert store.finding_count() == 0
        store.close()

    def test_ingest_single_scan(self, tmp_path: Path) -> None:
        """Ingesting one scan creates rows for scan and findings."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)
        evidence = _make_evidence()

        scan_id = store.ingest(evidence)
        assert isinstance(scan_id, str)
        assert len(scan_id) == 16
        assert store.scan_count() == 1
        assert store.finding_count() == 2
        store.close()

    def test_ingest_is_idempotent(self, tmp_path: Path) -> None:
        """Ingesting the same evidence twice does not create duplicates."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)
        evidence = _make_evidence()

        scan_id_1 = store.ingest(evidence)
        scan_id_2 = store.ingest(evidence)

        assert scan_id_1 == scan_id_2
        assert store.scan_count() == 1
        assert store.finding_count() == 2
        store.close()

    def test_ingest_multiple_scans(self, tmp_path: Path) -> None:
        """Distinct scans produce distinct history entries."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)

        e1 = _make_evidence(generated_at=datetime(2026, 2, 24, 12, 0, 0, tzinfo=UTC))
        e2 = _make_evidence(generated_at=datetime(2026, 2, 24, 13, 0, 0, tzinfo=UTC))

        store.ingest(e1)
        store.ingest(e2)

        assert store.scan_count() == 2
        assert store.finding_count() == 4
        store.close()

    def test_scans_for_profile(self, tmp_path: Path) -> None:
        """Querying history by profile path returns ordered results."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)

        prof_a = "/profiles/a.default"
        prof_b = "/profiles/b.default"
        e1 = _make_evidence(profile_path=prof_a, generated_at=datetime(2026, 1, 1, tzinfo=UTC))
        e2 = _make_evidence(profile_path=prof_a, generated_at=datetime(2026, 2, 1, tzinfo=UTC))
        e3 = _make_evidence(profile_path=prof_b, generated_at=datetime(2026, 1, 15, tzinfo=UTC))

        store.ingest(e1)
        store.ingest(e2)
        store.ingest(e3)

        a_scans = store.scans_for_profile(prof_a)
        assert len(a_scans) == 2
        assert a_scans[0]["scanned_at_utc"] < a_scans[1]["scanned_at_utc"]

        b_scans = store.scans_for_profile(prof_b)
        assert len(b_scans) == 1

        assert store.scans_for_profile("/nonexistent") == []
        store.close()

    def test_rule_history(self, tmp_path: Path) -> None:
        """Querying by rule_id returns all occurrences across scans."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)

        e1 = _make_evidence(generated_at=datetime(2026, 1, 1, tzinfo=UTC))
        e2 = _make_evidence(generated_at=datetime(2026, 2, 1, tzinfo=UTC))
        store.ingest(e1)
        store.ingest(e2)

        history = store.rule_history("FC-TEST-001")
        assert len(history) == 2
        assert all(h["severity"] == "HIGH" for h in history)

        assert store.rule_history("FC-NONEXISTENT") == []
        store.close()

    def test_learning_artifact_structure(self, tmp_path: Path) -> None:
        """Learning artifact contains expected keys and deterministic data."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)

        e1 = _make_evidence(generated_at=datetime(2026, 1, 1, tzinfo=UTC))
        e2 = _make_evidence(
            profile_path="/other/profile",
            profile_name="other.default",
            generated_at=datetime(2026, 2, 1, tzinfo=UTC),
        )
        store.ingest(e1)
        store.ingest(e2)

        artifact = store.generate_learning_artifact()

        assert artifact["schema_version"] == "1.0.0"
        assert "generated_at_utc" in artifact
        assert artifact["history_summary"]["total_scans"] == 2
        assert artifact["history_summary"]["total_findings"] == 4
        assert artifact["history_summary"]["unique_rules_triggered"] == 2
        assert artifact["history_summary"]["unique_profiles_scanned"] == 2
        assert len(artifact["rule_frequencies"]) == 2
        assert artifact["rule_frequencies"][0]["trigger_rate"] == 1.0
        assert "HIGH" in artifact["severity_distribution"]
        assert len(artifact["profile_coverage"]) == 2
        store.close()

    def test_learning_artifact_serializable(self, tmp_path: Path) -> None:
        """Learning artifact is JSON-serializable."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)
        store.ingest(_make_evidence())

        artifact = store.generate_learning_artifact()
        json_str = json.dumps(artifact, indent=2, sort_keys=True)
        parsed = json.loads(json_str)
        assert parsed["history_summary"]["total_scans"] == 1
        store.close()

    def test_empty_store_artifact(self, tmp_path: Path) -> None:
        """Learning artifact from empty store has zero counts."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)

        artifact = store.generate_learning_artifact()
        assert artifact["history_summary"]["total_scans"] == 0
        assert artifact["history_summary"]["total_findings"] == 0
        assert artifact["rule_frequencies"] == []
        assert artifact["rule_trend_novelty"] == []
        store.close()

    def test_rule_trend_novelty_first_seen(self, tmp_path: Path) -> None:
        """First-seen finding in latest snapshot reports novelty 1.0."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)
        generated_at = datetime(2026, 2, 24, 12, 0, 0, tzinfo=UTC)
        evidence = _make_evidence(
            findings=[_make_finding("FC-TREND-001")],
            generated_at=generated_at,
        )
        store.ingest(evidence)

        trend = {item["rule_id"]: item for item in store.rule_trend_novelty()}["FC-TREND-001"]
        assert trend["trend_direction"] == "new_profile"
        assert trend["first_seen_at"] == generated_at.isoformat()
        assert trend["novelty_score"] == 1.0
        assert trend["latest_present"] is True
        store.close()

    def test_rule_trend_novelty_repeated(self, tmp_path: Path) -> None:
        """Repeated finding in consecutive snapshots reduces novelty to 0.0."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)

        store.ingest(
            _make_evidence(
                findings=[_make_finding("FC-TREND-REP")],
                generated_at=datetime(2026, 2, 24, 12, 0, 0, tzinfo=UTC),
            )
        )
        store.ingest(
            _make_evidence(
                findings=[_make_finding("FC-TREND-REP")],
                generated_at=datetime(2026, 2, 24, 13, 0, 0, tzinfo=UTC),
            )
        )

        trend = {item["rule_id"]: item for item in store.rule_trend_novelty()}["FC-TREND-REP"]
        assert trend["trend_direction"] == "stable"
        assert trend["novelty_score"] == 0.0
        assert trend["scans_triggered"] == 2
        store.close()

    def test_rule_trend_direction_transition(self, tmp_path: Path) -> None:
        """Trend direction transitions improving -> degrading when rule reappears."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)

        store.ingest(
            _make_evidence(
                findings=[_make_finding("FC-TREND-SWITCH")],
                generated_at=datetime(2026, 2, 24, 12, 0, 0, tzinfo=UTC),
            )
        )
        store.ingest(
            _make_evidence(
                findings=[],
                generated_at=datetime(2026, 2, 24, 13, 0, 0, tzinfo=UTC),
            )
        )

        trend_after_drop = {
            item["rule_id"]: item for item in store.rule_trend_novelty()
        }["FC-TREND-SWITCH"]
        assert trend_after_drop["trend_direction"] == "improving"
        assert trend_after_drop["latest_present"] is False

        store.ingest(
            _make_evidence(
                findings=[_make_finding("FC-TREND-SWITCH")],
                generated_at=datetime(2026, 2, 24, 14, 0, 0, tzinfo=UTC),
            )
        )
        trend_after_return = {
            item["rule_id"]: item for item in store.rule_trend_novelty()
        }["FC-TREND-SWITCH"]
        assert trend_after_return["trend_direction"] == "degrading"
        assert trend_after_return["latest_present"] is True
        store.close()

    def test_schema_version_mismatch_raises(self, tmp_path: Path) -> None:
        """Opening a DB with wrong schema version fails closed."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)

        # Tamper with schema version
        import sqlite3

        conn = sqlite3.connect(str(db))
        conn.execute("UPDATE schema_meta SET value = '99.0.0' WHERE key = 'schema_version'")
        conn.commit()
        conn.close()
        store.close()

        with pytest.raises(ValueError, match="schema version mismatch"):
            ScanHistoryStore(db)

    def test_scan_id_deterministic(self) -> None:
        """Same evidence always produces the same scan_id."""
        e1 = _make_evidence()
        e2 = _make_evidence()
        assert _compute_scan_id(e1) == _compute_scan_id(e2)

    def test_scan_id_varies_by_time(self) -> None:
        """Different timestamps produce different scan_ids."""
        e1 = _make_evidence(generated_at=datetime(2026, 1, 1, tzinfo=UTC))
        e2 = _make_evidence(generated_at=datetime(2026, 1, 2, tzinfo=UTC))
        assert _compute_scan_id(e1) != _compute_scan_id(e2)

    def test_persistence_across_reopen(self, tmp_path: Path) -> None:
        """Data persists when store is closed and reopened."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)
        store.ingest(_make_evidence())
        assert store.scan_count() == 1
        store.close()

        store2 = ScanHistoryStore(db)
        assert store2.scan_count() == 1
        assert store2.finding_count() == 2
        store2.close()

    def test_no_findings_scan(self, tmp_path: Path) -> None:
        """Clean scan with no findings is stored correctly."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)

        evidence = _make_evidence(findings=[])
        store.ingest(evidence)

        assert store.scan_count() == 1
        assert store.finding_count() == 0

        artifact = store.generate_learning_artifact()
        assert artifact["history_summary"]["total_findings"] == 0
        assert artifact["rule_frequencies"] == []
        store.close()

    def test_ingest_persists_ruleset_metadata(self, tmp_path: Path) -> None:
        """Ruleset metadata is persisted and normalized."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)
        evidence = _make_evidence()

        store.ingest(
            evidence,
            ruleset_name="  ESR Baseline  ",
            ruleset_version=" 2026.02.24 ",
        )

        row = store._conn.execute(
            "SELECT ruleset_name, ruleset_version FROM scan_history"
        ).fetchone()
        assert row == ("ESR Baseline", "2026.02.24")
        store.close()

    def test_ingest_empty_ruleset_metadata_persists_null(self, tmp_path: Path) -> None:
        """Whitespace-only metadata is normalized to NULL."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)
        evidence = _make_evidence()

        store.ingest(
            evidence,
            ruleset_name="   ",
            ruleset_version="",
        )

        row = store._conn.execute(
            "SELECT ruleset_name, ruleset_version FROM scan_history"
        ).fetchone()
        assert row == (None, None)
        store.close()

    def test_ingest_extracts_firefox_version_from_normalized_artifact_key(
        self, tmp_path: Path
    ) -> None:
        """Firefox version uses normalized `last_version` key from compatibility.ini."""
        db = tmp_path / "history.sqlite"
        store = ScanHistoryStore(db)
        evidence = _make_evidence()
        evidence.artifacts = ProfileArtifactEvidence(
            entries=[
                ProfileArtifactEntry(
                    rel_path="compatibility.ini",
                    parse_status="parsed",
                    key_values={"last_version": "140.0.2_20260220000000/20260220000000"},
                )
            ]
        )

        store.ingest(evidence)

        row = store._conn.execute("SELECT firefox_version FROM scan_history").fetchone()
        assert row == ("140.0.2_20260220000000/20260220000000",)
        store.close()
