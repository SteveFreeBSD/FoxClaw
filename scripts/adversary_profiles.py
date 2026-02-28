#!/usr/bin/env python3
"""Generate adversarial Firefox profiles and run FoxClaw scans against them."""

from __future__ import annotations

import argparse
import json
import random
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from profile_generation_common import (
    SCENARIOS,
    AMOFetcher,
    Scenario,
    apply_mutations,
    generate_realistic_profile,
    load_catalog,
    write_metadata,
)

DEFAULT_SCENARIOS = ("compromised", "enterprise_managed", "developer_heavy", "privacy_hardened")
CVE_EXPECTED_STRICT_RULES: dict[str, str] = {
    "cve_handler_hijack": "FC-STRICT-HANDLER-001",
    "cve_cert_injection": "FC-STRICT-CERT-001",
    "cve_extension_abuse": "FC-STRICT-PKCS11-001",
    "cve_session_hijack": "FC-STRICT-SESSION-001",
    "cve_search_hijack": "FC-STRICT-SEARCH-001",
    "cve_sandbox_escape": "FC-STRICT-COOKIE-001",
    "cve_hsts_downgrade": "FC-STRICT-HSTS-001",
}
_CVE_SCENARIO_EXTENSION_IDS = ("support@lastpass.com", "malicious@sideload.net")
CVE_SCENARIOS: dict[str, Scenario] = {
    scenario_name: Scenario(
        name=scenario_name,
        weight=1,
        pref_posture="weak",
        policy_posture="tampered",
        extension_ids=_CVE_SCENARIO_EXTENSION_IDS,
    )
    for scenario_name in CVE_EXPECTED_STRICT_RULES
}
ADVERSARY_SCENARIOS: dict[str, Scenario] = {**SCENARIOS, **CVE_SCENARIOS}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default="/tmp/foxclaw-adversary-profiles",
        help="Directory for generated profiles and summary outputs.",
    )
    parser.add_argument(
        "--count-per-scenario",
        type=int,
        default=2,
        help="Profiles generated per scenario (default: 2).",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        dest="scenarios",
        default=[],
        choices=tuple(ADVERSARY_SCENARIOS.keys()),
        help="Repeatable scenario override. Defaults to curated adversary matrix.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=606060,
        help="Deterministic base seed (default: 606060).",
    )
    parser.add_argument(
        "--mutation-budget",
        type=int,
        default=3,
        help="Mutations per generated profile (default: 3).",
    )
    parser.add_argument(
        "--max-mutation-severity",
        choices=("low", "medium", "high"),
        default="high",
        help="Highest mutation severity allowed (default: high).",
    )
    parser.add_argument(
        "--ruleset",
        default="foxclaw/rulesets/strict.yml",
        help="Ruleset used for each scan (default: foxclaw/rulesets/strict.yml).",
    )
    parser.add_argument(
        "--foxclaw-cmd",
        default=f"{sys.executable} -m foxclaw",
        help="FoxClaw invocation command prefix (default: current python -m foxclaw).",
    )
    parser.add_argument(
        "--catalog-path",
        default="",
        help="Optional extension catalog snapshot JSON path.",
    )
    parser.add_argument(
        "--allow-network-fetch",
        action="store_true",
        help="Allow live AMO fetches for uncached extension IDs.",
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Keep existing output dir content; default removes it for deterministic runs.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress per-profile progress output.")
    return parser.parse_args()


def _extract_error_line(stdout_payload: str, stderr_payload: str) -> str | None:
    lines = [line.strip() for line in (stderr_payload + "\n" + stdout_payload).splitlines() if line.strip()]
    if not lines:
        return None

    for line in reversed(lines):
        if "Operational error:" in line or line.lower().startswith("error:"):
            return line
    return lines[-1]


def _scan_profile(
    *,
    foxclaw_cmd: str,
    ruleset: Path,
    profile_dir: Path,
) -> tuple[int, dict[str, Any] | None, str | None]:
    cmd = [
        *shlex.split(foxclaw_cmd),
        "scan",
        "--profile",
        str(profile_dir),
        "--ruleset",
        str(ruleset),
        "--json",
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)

    payload: dict[str, Any] | None = None
    if result.returncode in (0, 2):
        try:
            decoded = json.loads(result.stdout)
            if isinstance(decoded, dict):
                payload = decoded
        except json.JSONDecodeError:
            payload = None

    error_line = _extract_error_line(result.stdout, result.stderr)
    return (result.returncode, payload, error_line)


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    if isinstance(payload, dict):
        return payload
    return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_cve_handler_hijack(profile_dir: Path) -> None:
    handlers_path = profile_dir / "handlers.json"
    payload = _load_json_object(handlers_path)
    schemes = payload.get("schemes")
    if not isinstance(schemes, dict):
        schemes = {}
    schemes["ms-cve-handler"] = {
        "action": 4,
        "ask": False,
        "handlers": [
            {
                "name": "CVE Handler Bridge",
                "path": r"C:\Users\Public\cve-handler.exe",
            }
        ],
    }
    payload["schemes"] = schemes
    if not isinstance(payload.get("mimeTypes"), dict):
        payload["mimeTypes"] = {}
    if "defaultHandlersVersion" not in payload:
        payload["defaultHandlersVersion"] = {"en-US": 4}
    _write_json(handlers_path, payload)


def _seed_cve_cert_injection(profile_dir: Path) -> None:
    cert9_path = profile_dir / "cert9.db"
    conn = sqlite3.connect(cert9_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nssPublic (
                id INTEGER PRIMARY KEY,
                a11 BLOB,
                a102 BLOB,
                a81 BLOB,
                a90 INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nssTrust (
                id INTEGER PRIMARY KEY,
                a11 BLOB
            )
            """
        )
        next_id = int(conn.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM nssPublic").fetchone()[0])
        subject = "CN=Contoso Inspection Root,O=Contoso Security Lab,C=US"
        conn.execute(
            "INSERT OR REPLACE INTO nssPublic (id, a11, a102, a81, a90) VALUES (?, ?, ?, ?, ?)",
            (next_id, subject, subject, "2025-12-01T00:00:00+00:00", 1),
        )
        conn.execute(
            "INSERT OR REPLACE INTO nssTrust (id, a11) VALUES (?, ?)",
            (next_id, "CT,C,C"),
        )
        conn.commit()
    finally:
        conn.close()
    cert9_path.chmod(0o600)


def _seed_cve_pkcs11_extension_abuse(profile_dir: Path) -> None:
    pkcs11_path = profile_dir / "pkcs11.txt"
    injected_library = r"C:\Users\Public\AppData\Roaming\tokenbridge.dll"
    content = pkcs11_path.read_text(encoding="utf-8", errors="replace") if pkcs11_path.exists() else ""
    if injected_library in content:
        return
    extra_lines = [
        "",
        "name=Extension Token Bridge",
        f"library={injected_library}",
        "",
    ]
    pkcs11_path.write_text(content.rstrip("\n") + "\n" + "\n".join(extra_lines), encoding="utf-8")
    pkcs11_path.chmod(0o600)


def _seed_cve_session_hijack(profile_dir: Path) -> None:
    payload = {
        "windows": [
            {
                "extData": {
                    "session_token": "tok-cve-session-hijack",
                    "auth_bearer": "Bearer cve-proof",
                },
                "tabs": [
                    {
                        "entries": [{"url": "https://mail.example.test/inbox"}],
                        "formdata": {
                            "id": {
                                "password": "Password1",  # pragma: allowlist secret
                                "card_number": "4111111111111111",
                            }
                        },
                    }
                ],
            }
        ],
        "selectedWindow": 1,
    }
    _write_json(profile_dir / "sessionstore.jsonlz4", payload)


def _seed_cve_search_hijack(profile_dir: Path) -> None:
    payload = {
        "engines": [
            {
                "name": "CVE Search Relay",
                "searchUrl": "https://search.attacker.example/query?q={searchTerms}",
                "isDefault": True,
            },
            {
                "name": "Google",
                "searchUrl": "https://www.google.com/search?q={searchTerms}",
            },
        ],
        "metaData": {"current": "CVE Search Relay"},
    }
    _write_json(profile_dir / "search.json.mozlz4", payload)


def _seed_cve_sandbox_escape(profile_dir: Path) -> None:
    cookies_path = profile_dir / "cookies.sqlite"
    conn = sqlite3.connect(cookies_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS moz_cookies (
                id INTEGER PRIMARY KEY,
                originAttributes TEXT NOT NULL DEFAULT '',
                name TEXT,
                value TEXT,
                host TEXT,
                path TEXT,
                expiry INTEGER,
                lastAccessed INTEGER,
                creationTime INTEGER,
                isSecure INTEGER,
                isHttpOnly INTEGER,
                inBrowserElement INTEGER DEFAULT 0,
                sameSite INTEGER DEFAULT 0,
                schemeMap INTEGER DEFAULT 0,
                isPartitionedAttributeSet INTEGER DEFAULT 0,
                updateTime INTEGER
            )
            """
        )
        created_us = 1_735_689_600_000_000
        conn.execute(
            """
            INSERT OR REPLACE INTO moz_cookies (
                originAttributes,
                name,
                value,
                host,
                path,
                expiry,
                lastAccessed,
                creationTime,
                isSecure,
                isHttpOnly,
                inBrowserElement,
                sameSite,
                schemeMap,
                updateTime
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "",
                "session_token",
                "tok-cve-sandbox-escape",
                ".login.microsoftonline.com",
                "/",
                1_893_456_000,
                created_us + 1_000_000,
                created_us,
                0,
                0,
                0,
                0,
                0,
                created_us + 2_000_000,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    cookies_path.chmod(0o600)


def _seed_cve_hsts_downgrade(profile_dir: Path) -> None:
    places_path = profile_dir / "places.sqlite"
    conn = sqlite3.connect(places_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS moz_places (
                id INTEGER PRIMARY KEY,
                url LONGVARCHAR,
                title LONGVARCHAR,
                rev_host LONGVARCHAR,
                visit_count INTEGER DEFAULT 0,
                hidden INTEGER DEFAULT 0 NOT NULL,
                typed INTEGER DEFAULT 0 NOT NULL,
                frecency INTEGER DEFAULT -1 NOT NULL,
                last_visit_date INTEGER,
                guid TEXT,
                foreign_count INTEGER DEFAULT 0 NOT NULL,
                url_hash INTEGER DEFAULT 0 NOT NULL
            )
            """
        )
        hosts = ("login.microsoftonline.com", "account.microsoftonline.com")
        for idx, host in enumerate(hosts, start=1):
            url = f"https://{host}/"
            exists = conn.execute("SELECT 1 FROM moz_places WHERE url = ? LIMIT 1", (url,)).fetchone()
            if exists is not None:
                continue
            next_id = int(conn.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM moz_places").fetchone()[0])
            conn.execute(
                """
                INSERT INTO moz_places (
                    id, url, title, rev_host, visit_count, hidden, typed, frecency,
                    last_visit_date, guid, foreign_count, url_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_id,
                    url,
                    f"CVE HSTS {idx}",
                    host[::-1] + ".",
                    4,
                    0,
                    1,
                    900,
                    1_735_689_600_000_000 + idx,
                    f"cvehsts{idx:04d}",
                    0,
                    0,
                ),
            )
        conn.commit()
    finally:
        conn.close()

    hsts_lines = [
        "# HSTS state (CVE simulation)",
        "login.microsoftonline.com:443\tHSTS\t0\t1893456000000\t1735689600000\t1\t1\t0",
    ]
    (profile_dir / "SiteSecurityServiceState.txt").write_text("\n".join(hsts_lines) + "\n", encoding="utf-8")


def _apply_cve_scenario(profile_dir: Path, scenario_name: str) -> None:
    if scenario_name == "cve_handler_hijack":
        _seed_cve_handler_hijack(profile_dir)
    elif scenario_name == "cve_cert_injection":
        _seed_cve_cert_injection(profile_dir)
    elif scenario_name == "cve_extension_abuse":
        _seed_cve_pkcs11_extension_abuse(profile_dir)
    elif scenario_name == "cve_session_hijack":
        _seed_cve_session_hijack(profile_dir)
    elif scenario_name == "cve_search_hijack":
        _seed_cve_search_hijack(profile_dir)
    elif scenario_name == "cve_sandbox_escape":
        _seed_cve_sandbox_escape(profile_dir)
    elif scenario_name == "cve_hsts_downgrade":
        _seed_cve_hsts_downgrade(profile_dir)


def main() -> int:
    args = parse_args()
    if args.count_per_scenario < 1:
        raise SystemExit("--count-per-scenario must be greater than zero")
    if args.mutation_budget < 0:
        raise SystemExit("--mutation-budget must be non-negative")

    selected_scenarios = tuple(args.scenarios) if args.scenarios else DEFAULT_SCENARIOS
    for scenario_name in selected_scenarios:
        if scenario_name not in ADVERSARY_SCENARIOS:
            raise SystemExit(f"unknown scenario: {scenario_name}")

    output_dir = Path(args.output_dir).expanduser().resolve(strict=False)
    if output_dir.exists() and not args.keep_existing:
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    catalog_path = Path(args.catalog_path).expanduser().resolve(strict=False) if args.catalog_path else None
    catalog_version, catalog = load_catalog(catalog_path)
    fetcher = AMOFetcher(
        Path("/tmp/foxclaw-amo-cache"),
        catalog,
        allow_network=args.allow_network_fetch,
    )

    ruleset_path = Path(args.ruleset).expanduser().resolve(strict=False)
    if not ruleset_path.is_file():
        raise SystemExit(f"ruleset path does not exist: {ruleset_path}")

    clean_count = 0
    findings_count = 0
    operational_failure_count = 0
    failures_by_error: dict[str, list[str]] = {}
    per_profile: list[dict[str, Any]] = []
    started = time.perf_counter()

    profile_index = 0
    for scenario_offset, scenario_name in enumerate(selected_scenarios):
        scenario = ADVERSARY_SCENARIOS[scenario_name]
        expected_rule_id = CVE_EXPECTED_STRICT_RULES.get(scenario_name)
        for ordinal in range(args.count_per_scenario):
            profile_seed = args.seed + (scenario_offset * 10_000) + ordinal
            rng = random.Random(profile_seed)
            profile_name = f"{profile_index:04d}-{scenario_name}.adv-{profile_seed}"
            profile_dir = output_dir / profile_name
            profile_index += 1

            metadata = generate_realistic_profile(
                profile_dir=profile_dir,
                scenario=scenario,
                rng=rng,
                fetcher=fetcher,
                mode="adversary",
            )
            mutations = apply_mutations(
                profile_dir=profile_dir,
                rng=rng,
                mutation_budget=args.mutation_budget,
                max_severity=args.max_mutation_severity,
            )
            if expected_rule_id is not None:
                _apply_cve_scenario(profile_dir=profile_dir, scenario_name=scenario_name)
            metadata.update(
                {
                    "seed": profile_seed,
                    "catalog_version": catalog_version,
                    "generator_mode": "adversary",
                    "mutation_budget": args.mutation_budget,
                    "max_mutation_severity": args.max_mutation_severity,
                    "mutations": mutations,
                    "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            )
            if expected_rule_id is not None:
                metadata["expected_rule_id"] = expected_rule_id
                metadata["scenario_family"] = "cve_advisory_simulation"
            write_metadata(profile_dir, metadata)

            scan_started = time.perf_counter()
            exit_code, payload, error_line = _scan_profile(
                foxclaw_cmd=args.foxclaw_cmd,
                ruleset=ruleset_path,
                profile_dir=profile_dir,
            )
            runtime_seconds = round(time.perf_counter() - scan_started, 3)
            findings_high_count: int | None = None
            findings_total: int | None = None
            finding_rule_ids: list[str] = []
            if payload is not None:
                summary = payload.get("summary", {})
                if isinstance(summary, dict):
                    raw_high = summary.get("findings_high_count")
                    raw_total = summary.get("findings_total")
                    findings_high_count = int(raw_high) if isinstance(raw_high, int) else None
                    findings_total = int(raw_total) if isinstance(raw_total, int) else None
                findings_obj = payload.get("findings")
                if isinstance(findings_obj, list):
                    collected_rule_ids: set[str] = set()
                    for item in findings_obj:
                        if not isinstance(item, dict):
                            continue
                        raw_rule_id = item.get("id")
                        if not isinstance(raw_rule_id, str):
                            raw_rule_id = item.get("rule_id")
                        if isinstance(raw_rule_id, str) and raw_rule_id.strip():
                            collected_rule_ids.add(raw_rule_id.strip())
                    finding_rule_ids = sorted(collected_rule_ids)

            profile_record: dict[str, Any] = {
                "profile": profile_name,
                "scenario": scenario_name,
                "seed": profile_seed,
                "exit_code": exit_code,
                "runtime_seconds": runtime_seconds,
                "findings_high_count": findings_high_count,
                "findings_total": findings_total,
                "finding_rule_ids": finding_rule_ids,
            }
            if expected_rule_id is not None:
                profile_record["expected_rule_id"] = expected_rule_id
                profile_record["expected_rule_matched"] = expected_rule_id in finding_rule_ids
            if error_line is not None and exit_code not in (0, 2):
                profile_record["error"] = error_line
            per_profile.append(profile_record)

            if exit_code == 0:
                clean_count += 1
            elif exit_code == 2:
                findings_count += 1
            else:
                operational_failure_count += 1
                normalized_error = error_line or "error: foxclaw scan operational failure"
                failures_by_error.setdefault(normalized_error, []).append(profile_name)

            if not args.quiet:
                print(
                    "[adversary] profile="
                    f"{profile_name} scenario={scenario_name} exit_code={exit_code} "
                    f"runtime_seconds={runtime_seconds:.3f}"
                )

    runtime_seconds_total = round(time.perf_counter() - started, 3)
    summary_payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "catalog_version": catalog_version,
        "ruleset": str(ruleset_path),
        "scenarios": list(selected_scenarios),
        "count_per_scenario": args.count_per_scenario,
        "profiles_total": len(per_profile),
        "clean_count": clean_count,
        "findings_count": findings_count,
        "operational_failure_count": operational_failure_count,
        "failures_by_error": failures_by_error,
        "runtime_seconds_total": runtime_seconds_total,
        "per_profile": per_profile,
    }

    summary_path = output_dir / "adversary-summary.json"
    summary_path.write_text(
        json.dumps(summary_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not args.quiet:
        print(f"[adversary] summary: {summary_path}")

    return 1 if operational_failure_count > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
