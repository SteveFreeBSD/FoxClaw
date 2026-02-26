"""Append-only scan history storage (WS-55A).

This module provides deterministic, offline, append-only storage for scan
results.  It never modifies existing records and is never consulted during
rule evaluation — it only enriches output after findings are produced.

Schema version: 1.0.0
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from foxclaw.learning.novel import compute_novelty_score
from foxclaw.learning.trends import compute_trend_direction

if TYPE_CHECKING:
    from foxclaw.models import EvidenceBundle

SCHEMA_VERSION = "1.0.0"

_DDL = """\
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT    NOT NULL UNIQUE,
    profile_path    TEXT    NOT NULL,
    profile_name    TEXT    NOT NULL,
    scanned_at_utc  TEXT    NOT NULL,
    firefox_version TEXT,
    ruleset_name    TEXT,
    ruleset_version TEXT,
    finding_count   INTEGER NOT NULL,
    high_count      INTEGER NOT NULL,
    medium_count    INTEGER NOT NULL,
    info_count      INTEGER NOT NULL,
    suppressed_count INTEGER NOT NULL,
    rule_ids_json   TEXT    NOT NULL,
    profile_hash    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT    NOT NULL REFERENCES scan_history(scan_id),
    rule_id         TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    evidence_hash   TEXT    NOT NULL,
    UNIQUE(scan_id, rule_id, evidence_hash)
);

CREATE INDEX IF NOT EXISTS idx_scan_history_profile
    ON scan_history(profile_path);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned
    ON scan_history(scanned_at_utc);
CREATE INDEX IF NOT EXISTS idx_finding_history_rule
    ON finding_history(rule_id);
"""


def _compute_scan_id(evidence: EvidenceBundle) -> str:
    """Deterministic scan ID from profile path + generated_at timestamp."""
    raw = f"{evidence.profile.path}|{evidence.generated_at.isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _compute_profile_hash(evidence: EvidenceBundle) -> str:
    """Hash of profile shape for similarity grouping."""
    shape = {
        "prefs_count": evidence.summary.prefs_parsed,
        "extensions_count": evidence.summary.extensions_found,
        "policies_count": evidence.summary.policies_found,
        "sqlite_checks": evidence.summary.sqlite_checks_total,
        "firefox_version": _extract_firefox_version(evidence),
    }
    raw = json.dumps(shape, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _compute_evidence_hash(rule_id: str, evidence_list: list[str]) -> str:
    """Deterministic hash of a finding's evidence for deduplication."""
    raw = f"{rule_id}|{'|'.join(sorted(evidence_list))}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _extract_firefox_version(evidence: EvidenceBundle) -> str | None:
    """Extract Firefox version from profile artifact evidence if available."""
    if evidence.artifacts is None:
        return None
    for entry in evidence.artifacts.entries:
        if entry.rel_path == "compatibility.ini":
            return entry.key_values.get("last_version") or entry.key_values.get("LastVersion")
    return None


def _normalize_metadata_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized if normalized else None


class ScanHistoryStore:
    """Append-only SQLite store for scan history.

    This store:
    - Never modifies or deletes existing records.
    - Is deterministic: same evidence produces same scan_id.
    - Is local and offline.
    - Is never consulted during rule evaluation.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def __enter__(self) -> ScanHistoryStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _init_schema(self) -> None:
        """Create tables if they don't exist; verify schema version."""
        self._conn.executescript(_DDL)

        row = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                (SCHEMA_VERSION,),
            )
            self._conn.commit()
        elif row[0] != SCHEMA_VERSION:
            raise ValueError(
                f"Scan history DB schema version mismatch: "
                f"expected {SCHEMA_VERSION}, found {row[0]}"
            )

    def ingest(
        self,
        evidence: EvidenceBundle,
        *,
        ruleset_name: str | None = None,
        ruleset_version: str | None = None,
    ) -> str:
        """Ingest scan results into the history store.

        Returns the scan_id.  If the same scan_id already exists (deterministic
        duplicate), the call is a no-op and returns the existing scan_id.
        """
        scan_id = _compute_scan_id(evidence)

        existing = self._conn.execute(
            "SELECT 1 FROM scan_history WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if existing is not None:
            return scan_id

        profile_hash = _compute_profile_hash(evidence)
        firefox_version = _extract_firefox_version(evidence)
        normalized_ruleset_name = _normalize_metadata_text(ruleset_name)
        normalized_ruleset_version = _normalize_metadata_text(ruleset_version)
        rule_ids = sorted({f.id for f in evidence.findings})

        self._conn.execute(
            """INSERT INTO scan_history
               (scan_id, profile_path, profile_name, scanned_at_utc,
                firefox_version, ruleset_name, ruleset_version,
                finding_count, high_count, medium_count, info_count,
                suppressed_count, rule_ids_json, profile_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                evidence.profile.path,
                evidence.profile.name,
                evidence.generated_at.isoformat(),
                firefox_version,
                normalized_ruleset_name,
                normalized_ruleset_version,
                evidence.summary.findings_total,
                evidence.summary.findings_high_count,
                evidence.summary.findings_medium_count,
                evidence.summary.findings_info_count,
                evidence.summary.findings_suppressed_count,
                json.dumps(rule_ids),
                profile_hash,
            ),
        )

        for finding in evidence.findings:
            evidence_hash = _compute_evidence_hash(finding.id, finding.evidence)
            self._conn.execute(
                """INSERT OR IGNORE INTO finding_history
                   (scan_id, rule_id, severity, evidence_hash)
                   VALUES (?, ?, ?, ?)""",
                (scan_id, finding.id, finding.severity, evidence_hash),
            )

        self._conn.commit()
        return scan_id

    def scan_count(self) -> int:
        """Total number of ingested scans."""
        row = self._conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()
        return row[0] if row else 0

    def finding_count(self) -> int:
        """Total number of ingested finding records."""
        row = self._conn.execute("SELECT COUNT(*) FROM finding_history").fetchone()
        return row[0] if row else 0

    def scans_for_profile(self, profile_path: str) -> list[dict]:
        """Return scan history rows for a given profile path, ordered by time."""
        rows = self._conn.execute(
            """SELECT scan_id, scanned_at_utc, finding_count, high_count,
                      medium_count, info_count, suppressed_count, rule_ids_json
               FROM scan_history
               WHERE profile_path = ?
               ORDER BY scanned_at_utc ASC""",
            (profile_path,),
        ).fetchall()
        return [
            {
                "scan_id": r[0],
                "scanned_at_utc": r[1],
                "finding_count": r[2],
                "high_count": r[3],
                "medium_count": r[4],
                "info_count": r[5],
                "suppressed_count": r[6],
                "rule_ids": json.loads(r[7]),
            }
            for r in rows
        ]

    def rule_history(self, rule_id: str) -> list[dict]:
        """Return all finding records for a rule, ordered by scan time."""
        rows = self._conn.execute(
            """SELECT fh.scan_id, fh.severity, fh.evidence_hash,
                      sh.scanned_at_utc, sh.profile_path
               FROM finding_history fh
               JOIN scan_history sh ON fh.scan_id = sh.scan_id
               WHERE fh.rule_id = ?
               ORDER BY sh.scanned_at_utc ASC""",
            (rule_id,),
        ).fetchall()
        return [
            {
                "scan_id": r[0],
                "severity": r[1],
                "evidence_hash": r[2],
                "scanned_at_utc": r[3],
                "profile_path": r[4],
            }
            for r in rows
        ]

    def generate_learning_artifact(self, evidence_generated_at_utc: str | None = None) -> dict:
        """Generate a deterministic learning artifact summarizing all history.

        This artifact is designed to be consumed by profile generators to
        inform mutation weighting decisions.
        """
        scan_count = self.scan_count()
        finding_count = self.finding_count()

        # Rule frequency: how often each rule fires across all scans
        rule_freq_rows = self._conn.execute(
            """SELECT rule_id, COUNT(DISTINCT scan_id) as scan_hits,
                      COUNT(*) as total_hits
               FROM finding_history
               GROUP BY rule_id
               ORDER BY scan_hits DESC"""
        ).fetchall()

        rule_frequencies = [
            {
                "rule_id": r[0],
                "scans_triggered": r[1],
                "total_occurrences": r[2],
                "trigger_rate": round(r[1] / scan_count, 4) if scan_count > 0 else 0,
            }
            for r in rule_freq_rows
        ]

        # Severity distribution
        severity_rows = self._conn.execute(
            """SELECT severity, COUNT(*) FROM finding_history GROUP BY severity"""
        ).fetchall()
        severity_distribution = {r[0]: r[1] for r in severity_rows}

        # Profile scan counts
        profile_rows = self._conn.execute(
            """SELECT profile_path, COUNT(*) as scans,
                      MAX(scanned_at_utc) as last_scan
               FROM scan_history
               GROUP BY profile_path
               ORDER BY scans DESC"""
        ).fetchall()
        profile_coverage = [
            {
                "profile_path": r[0],
                "scan_count": r[1],
                "last_scanned_utc": r[2],
            }
            for r in profile_rows
        ]
        rule_trend_novelty = self.rule_trend_novelty()

        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at_utc": evidence_generated_at_utc or datetime.now(UTC).isoformat(),
            "history_summary": {
                "total_scans": scan_count,
                "total_findings": finding_count,
                "unique_rules_triggered": len(rule_frequencies),
                "unique_profiles_scanned": len(profile_coverage),
            },
            "rule_frequencies": rule_frequencies,
            "severity_distribution": severity_distribution,
            "profile_coverage": profile_coverage,
            "rule_trend_novelty": rule_trend_novelty,
        }

    def rule_trend_novelty(self) -> list[dict]:
        """Compute deterministic per-rule trend/novelty from history snapshots.

        Results are ordered by `rule_id` so identical history state produces
        identical output ordering.
        """
        rows = self._conn.execute(
            """SELECT scan_id, scanned_at_utc, rule_ids_json
               FROM scan_history
               ORDER BY scanned_at_utc ASC, scan_id ASC"""
        ).fetchall()
        if not rows:
            return []

        snapshots: list[tuple[str, str, set[str]]] = []
        all_rules: set[str] = set()
        for scan_id, scanned_at_utc, rule_ids_json in rows:
            rule_ids = set(json.loads(rule_ids_json))
            snapshots.append((scan_id, scanned_at_utc, rule_ids))
            all_rules.update(rule_ids)

        if not all_rules:
            return []

        latest_rules = snapshots[-1][2]
        previous_rules = snapshots[-2][2] if len(snapshots) > 1 else None
        prior_scan_count = max(len(snapshots) - 1, 0)
        output: list[dict] = []

        for rule_id in sorted(all_rules):
            first_seen_at: str | None = None
            scans_triggered = 0
            for _scan_id, scanned_at_utc, rule_ids in snapshots:
                if rule_id in rule_ids:
                    scans_triggered += 1
                    if first_seen_at is None:
                        first_seen_at = scanned_at_utc

            latest_present = rule_id in latest_rules
            previous_present = (
                None
                if previous_rules is None
                else rule_id in previous_rules
            )
            prior_hits = scans_triggered - (1 if latest_present else 0)
            novelty_score = (
                compute_novelty_score(prior_hits=prior_hits, prior_scans=prior_scan_count)
                if latest_present
                else 0.0
            )

            output.append(
                {
                    "rule_id": rule_id,
                    "trend_direction": compute_trend_direction(
                        latest_present=latest_present,
                        previous_present=previous_present,
                    ),
                    "first_seen_at": first_seen_at,
                    "novelty_score": novelty_score,
                    "latest_present": latest_present,
                    "scans_triggered": scans_triggered,
                }
            )

        return output

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
