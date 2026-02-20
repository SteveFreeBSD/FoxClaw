#!/usr/bin/env python3
"""Generate and validate deterministic testbed fixtures for FoxClaw integration tests."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = "1.0.0"
GENERATOR_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "testbed"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"
SQLITE_TEMPLATE_PATH = REPO_ROOT / "tests" / "fixtures" / "firefox_profile" / "places.sqlite"


@dataclass(frozen=True, slots=True)
class FixtureFile:
    """One generated testbed fixture file."""

    relpath: str
    content: bytes
    mode: int


@dataclass(frozen=True, slots=True)
class FixtureRecord:
    """Manifest record for one fixture file."""

    relpath: str
    mode: str
    size: int
    sha256: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--write",
        action="store_true",
        help="Write fixtures and manifest to disk (default mode).",
    )
    mode_group.add_argument(
        "--check",
        action="store_true",
        help="Validate fixtures and manifest against deterministic expectations.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    fixture_files = build_fixture_files()
    records = build_manifest_records(fixture_files)
    expected_manifest = build_manifest_payload(records)

    if args.check:
        return run_check(fixture_files, expected_manifest)

    write_fixtures(fixture_files, expected_manifest)
    print(f"[testbed] wrote {len(fixture_files)} fixture files.")
    print(f"[testbed] manifest: {MANIFEST_PATH.relative_to(REPO_ROOT)}")
    return 0


def build_fixture_files() -> list[FixtureFile]:
    policy_present = json.dumps(
        {"policies": {"DisableTelemetry": True}},
        indent=2,
        sort_keys=True,
    ) + "\n"

    ruleset = "\n".join(
        [
            "name: testbed-integration",
            "version: 1.0.0",
            "rules:",
            "  - id: TB-PREF-001",
            "    title: testbed preference must be set",
            "    severity: INFO",
            "    category: preferences",
            "    check:",
            "      pref_exists:",
            "        key: testbed.pref.enabled",
            "    rationale: deterministic pref parsing coverage",
            "    recommendation: set testbed.pref.enabled explicitly",
            "    confidence: medium",
            "  - id: TB-PREF-OVERRIDE-001",
            "    title: user.js must override testbed.pref.override",
            "    severity: INFO",
            "    category: preferences",
            "    check:",
            "      pref_equals:",
            "        key: testbed.pref.override",
            "        value: from-user",
            "    rationale: user.js precedence should override prefs.js when both define a key",
            "    recommendation: define override value in user.js for deterministic preference control",
            "    confidence: medium",
            "  - id: TB-FILE-001",
            "    title: key4.db must remain owner-only",
            "    severity: HIGH",
            "    category: filesystem",
            "    check:",
            "      file_perm_strict:",
            "        key: key4",
            "    rationale: key material metadata should not be broadly readable",
            "    recommendation: chmod 600 key4.db",
            "    confidence: high",
            "  - id: TB-SQL-001",
            "    title: places.sqlite quick_check must be ok",
            "    severity: HIGH",
            "    category: sqlite",
            "    check:",
            "      sqlite_quickcheck_ok:",
            "        db: places",
            "    rationale: deterministic sqlite health validation",
            "    recommendation: repair or replace places.sqlite if corrupt",
            "    confidence: high",
            "  - id: TB-POL-001",
            "    title: enterprise telemetry disable policy should exist",
            "    severity: INFO",
            "    category: policy",
            "    check:",
            "      policy_key_exists:",
            "        path: policies.DisableTelemetry",
            "    rationale: integration tests need deterministic policy evidence",
            "    recommendation: define policies.DisableTelemetry in policies.json",
            "    confidence: low",
        ]
    ) + "\n"

    files: list[FixtureFile] = [
        FixtureFile(
            relpath="rulesets/integration.yml",
            content=ruleset.encode("utf-8"),
            mode=0o644,
        ),
        FixtureFile(
            relpath="policies/disable_telemetry.json",
            content=policy_present.encode("utf-8"),
            mode=0o644,
        ),
    ]

    for scenario in (
        "profile_baseline",
        "profile_weak_perms",
        "profile_sqlite_error",
        "profile_policy_present",
        "profile_active_lock",
        "profile_userjs_override",
        "profile_third_party_xpi",
    ):
        files.extend(build_profile_fixture_files(scenario))

    return sorted(files, key=lambda item: item.relpath)


def build_profile_fixture_files(scenario: str) -> list[FixtureFile]:
    pref_lines = [
        "// Deterministic profile fixture generated by scripts/generate_testbed_fixtures.py",
        'user_pref("testbed.pref.enabled", true);',
        'user_pref("browser.contentblocking.category", "strict");',
    ]
    if scenario == "profile_userjs_override":
        pref_lines.append('user_pref("testbed.pref.override", "from-prefs");')
    prefs = "\n".join(pref_lines) + "\n"

    key4_mode = 0o644 if scenario == "profile_weak_perms" else 0o600
    places_bytes = (
        b"this is not a sqlite database\n"
        if scenario == "profile_sqlite_error"
        else build_sqlite_bytes(db_name="places", scenario=scenario)
    )

    profile_files: list[FixtureFile] = [
        FixtureFile(
            relpath=f"{scenario}/prefs.js",
            content=prefs.encode("utf-8"),
            mode=0o600,
        ),
        FixtureFile(
            relpath=f"{scenario}/key4.db",
            content=f"key material fixture for {scenario}\n".encode(),
            mode=key4_mode,
        ),
        FixtureFile(
            relpath=f"{scenario}/places.sqlite",
            content=places_bytes,
            mode=0o600,
        ),
        FixtureFile(
            relpath=f"{scenario}/cookies.sqlite",
            content=build_sqlite_bytes(db_name="cookies", scenario=scenario),
            mode=0o600,
        ),
    ]

    if scenario == "profile_active_lock":
        profile_files.append(
            FixtureFile(
                relpath=f"{scenario}/parent.lock",
                content=b"",
                mode=0o600,
            )
        )
    if scenario == "profile_userjs_override":
        profile_files.append(
            FixtureFile(
                relpath=f"{scenario}/user.js",
                content=(
                    b"// Deterministic user.js override fixture\n"
                    b'user_pref("testbed.pref.override", "from-user");\n'
                ),
                mode=0o600,
            )
        )
    if scenario == "profile_third_party_xpi":
        ext_id = "third-party@example.com"
        xpi_path = f"extensions/{ext_id}.xpi"
        xpi_bytes = _build_xpi_bytes(
            {
                "manifest_version": 2,
                "name": "Third Party Test",
                "version": "1.0.0",
                "permissions": ["<all_urls>", "webRequest"],
            }
        )
        extensions_json = {
            "schemaVersion": 35,
            "addons": [
                {
                    "id": ext_id,
                    "type": "extension",
                    "name": "Third Party Test",
                    "version": "1.0.0",
                    "active": True,
                    "location": "app-profile",
                    "path": xpi_path,
                    "signedState": 2,
                }
            ],
        }
        profile_files.extend(
            [
                FixtureFile(
                    relpath=f"{scenario}/{xpi_path}",
                    content=xpi_bytes,
                    mode=0o644,
                ),
                FixtureFile(
                    relpath=f"{scenario}/extensions.json",
                    content=(
                        json.dumps(extensions_json, indent=2, sort_keys=True) + "\n"
                    ).encode("utf-8"),
                    mode=0o600,
                ),
            ]
        )

    return profile_files


def _build_xpi_bytes(manifest: dict[str, object]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as archive:
        _write_deterministic_zip_entry(
            archive,
            name="manifest.json",
            content=(json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        _write_deterministic_zip_entry(
            archive,
            name="background.js",
            content=b"// deterministic fixture entrypoint\n",
        )
    return buf.getvalue()


def _write_deterministic_zip_entry(
    archive: zipfile.ZipFile, *, name: str, content: bytes
) -> None:
    zip_info = zipfile.ZipInfo(filename=name)
    zip_info.date_time = (1980, 1, 1, 0, 0, 0)
    zip_info.compress_type = zipfile.ZIP_STORED
    zip_info.external_attr = 0o100644 << 16
    archive.writestr(zip_info, content)


def build_sqlite_bytes(*, db_name: str, scenario: str) -> bytes:
    _ = (db_name, scenario)
    return SQLITE_TEMPLATE_PATH.read_bytes()


def build_manifest_records(fixture_files: list[FixtureFile]) -> list[FixtureRecord]:
    records: list[FixtureRecord] = []
    for fixture in fixture_files:
        records.append(
            FixtureRecord(
                relpath=fixture.relpath,
                mode=f"{fixture.mode:04o}",
                size=len(fixture.content),
                sha256=hashlib.sha256(fixture.content).hexdigest(),
            )
        )
    return records


def build_manifest_payload(records: list[FixtureRecord]) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "fixtures": [
            {
                "path": record.relpath,
                "mode": record.mode,
                "size": record.size,
                "sha256": record.sha256,
            }
            for record in records
        ],
    }


def write_fixtures(
    fixture_files: list[FixtureFile], expected_manifest: dict[str, object]
) -> None:
    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    expected_paths = {fixture.relpath for fixture in fixture_files}
    expected_paths.add(MANIFEST_PATH.relative_to(FIXTURE_ROOT).as_posix())

    # Remove stale files from previous generations.
    for current_path in sorted(FIXTURE_ROOT.rglob("*"), key=lambda item: item.as_posix(), reverse=True):
        if current_path.is_dir():
            if current_path == FIXTURE_ROOT:
                continue
            if not any(current_path.iterdir()):
                current_path.rmdir()
            continue

        relpath = current_path.relative_to(FIXTURE_ROOT).as_posix()
        if relpath in expected_paths:
            continue
        current_path.unlink()

    for fixture in fixture_files:
        path = FIXTURE_ROOT / fixture.relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixture.content)
        path.chmod(fixture.mode)

    MANIFEST_PATH.write_text(
        json.dumps(expected_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    MANIFEST_PATH.chmod(0o644)


def run_check(
    fixture_files: list[FixtureFile], expected_manifest: dict[str, object]
) -> int:
    if not FIXTURE_ROOT.is_dir():
        print("[testbed] missing fixture root: tests/fixtures/testbed", file=sys.stderr)
        return 1

    for fixture in fixture_files:
        path = FIXTURE_ROOT / fixture.relpath
        if not path.is_file():
            print(f"[testbed] missing fixture file: {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            return 1

        actual = path.read_bytes()
        if actual != fixture.content:
            print(f"[testbed] content drift: {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            return 1

        if _is_posix_mode_check_supported():
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode != fixture.mode:
                print(
                    f"[testbed] mode drift: {path.relative_to(REPO_ROOT)} expected={fixture.mode:04o} got={mode:04o}",
                    file=sys.stderr,
                )
                return 1

    expected_relpaths = {fixture.relpath for fixture in fixture_files}
    expected_relpaths.add(MANIFEST_PATH.relative_to(FIXTURE_ROOT).as_posix())
    actual_relpaths = {
        path.relative_to(FIXTURE_ROOT).as_posix()
        for path in FIXTURE_ROOT.rglob("*")
        if path.is_file()
    }
    unexpected = sorted(actual_relpaths - expected_relpaths)
    if unexpected:
        print("[testbed] unexpected fixture file(s):", file=sys.stderr)
        for relpath in unexpected:
            print(f"  - tests/fixtures/testbed/{relpath}", file=sys.stderr)
        return 1

    if not MANIFEST_PATH.is_file():
        print("[testbed] missing manifest: tests/fixtures/testbed/manifest.json", file=sys.stderr)
        return 1

    actual_manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if actual_manifest != expected_manifest:
        print("[testbed] manifest drift: tests/fixtures/testbed/manifest.json", file=sys.stderr)
        tmp_manifest = MANIFEST_PATH.with_suffix(".expected.json")
        tmp_manifest.write_text(
            json.dumps(expected_manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"[testbed] expected manifest emitted to: {tmp_manifest.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1

    print(f"[testbed] fixture check ok ({len(fixture_files)} files).")
    return 0


def _is_posix_mode_check_supported() -> bool:
    return os.name == "posix"


if __name__ == "__main__":
    raise SystemExit(main())
