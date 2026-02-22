#!/usr/bin/env python3
"""Stage a Firefox profile from a Windows share and run a deterministic FoxClaw scan.

This workflow is designed for enterprise collection patterns where the source profile
may live on an SMB share. The script copies the profile to a local staging snapshot
before scanning so FoxClaw reads local files only.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

LOCK_MARKERS = ("parent.lock", ".parentlock", "lock")


@dataclass
class CopyStats:
    files_copied: int
    dirs_copied: int
    bytes_copied: int


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_snapshot_id() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _default_staging_root() -> Path:
    return Path(tempfile.gettempdir()) / "foxclaw-windows-share"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Copy a Firefox profile from SMB/UNC storage into a local staging snapshot "
            "and run FoxClaw scan artifacts against the local copy."
        )
    )
    parser.add_argument(
        "--source-profile",
        required=True,
        help="Source Firefox profile path (UNC path or mounted share path).",
    )
    parser.add_argument(
        "--staging-root",
        default=str(_default_staging_root()),
        help="Root directory for staged snapshots (default: system temp dir).",
    )
    parser.add_argument(
        "--snapshot-id",
        default="",
        help="Optional snapshot identifier (default: UTC timestamp).",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Optional artifact directory (default: <staging-root>/<snapshot-id>/artifacts).",
    )
    parser.add_argument(
        "--foxclaw-cmd",
        default=f"{sys.executable} -m foxclaw",
        help="Command used to invoke FoxClaw CLI (default: current python -m foxclaw).",
    )
    parser.add_argument(
        "--ruleset",
        default="foxclaw/rulesets/balanced.yml",
        help="Ruleset path passed to foxclaw scan.",
    )
    parser.add_argument(
        "--policy-path",
        action="append",
        default=[],
        help="Optional repeatable policy override path.",
    )
    parser.add_argument(
        "--suppression-path",
        action="append",
        default=[],
        help="Optional repeatable suppression policy path.",
    )
    parser.add_argument(
        "--intel-store-dir",
        default="",
        help="Optional intel snapshot store directory.",
    )
    parser.add_argument(
        "--intel-snapshot-id",
        default="",
        help="Optional intel snapshot id (requires --intel-store-dir).",
    )
    parser.add_argument(
        "--allow-active-profile",
        action="store_true",
        help=(
            "Allow staging when lock markers are present. Use only when source is a "
            "crash-consistent snapshot (for example VSS)."
        ),
    )
    parser.add_argument(
        "--keep-stage-writeable",
        action="store_true",
        help="Do not remove write bits from staged files.",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional scan JSON output path (default: <output-dir>/foxclaw.json).",
    )
    parser.add_argument(
        "--sarif-out",
        default="",
        help="Optional scan SARIF output path (default: <output-dir>/foxclaw.sarif).",
    )
    parser.add_argument(
        "--scan-snapshot-out",
        default="",
        help="Optional scan snapshot output path (default: <output-dir>/foxclaw.snapshot.json).",
    )
    parser.add_argument(
        "--manifest-out",
        default="",
        help="Optional staging manifest output path (default: <output-dir>/stage-manifest.json).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate paths and write manifest without launching foxclaw scan.",
    )
    return parser.parse_args(argv)


def _resolve_paths(args: argparse.Namespace) -> tuple[Path, Path, Path, Path, Path, Path, Path]:
    snapshot_id = args.snapshot_id or _default_snapshot_id()
    source_profile = Path(args.source_profile).expanduser().resolve()
    staging_root = Path(args.staging_root).expanduser().resolve()
    stage_root = staging_root / snapshot_id
    staged_profile = stage_root / "profile"

    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else stage_root / "artifacts"
    json_out = Path(args.json_out).expanduser().resolve() if args.json_out else output_dir / "foxclaw.json"
    sarif_out = Path(args.sarif_out).expanduser().resolve() if args.sarif_out else output_dir / "foxclaw.sarif"
    scan_snapshot_out = (
        Path(args.scan_snapshot_out).expanduser().resolve()
        if args.scan_snapshot_out
        else output_dir / "foxclaw.snapshot.json"
    )
    manifest_out = (
        Path(args.manifest_out).expanduser().resolve()
        if args.manifest_out
        else output_dir / "stage-manifest.json"
    )
    return source_profile, staged_profile, output_dir, json_out, sarif_out, scan_snapshot_out, manifest_out


def _find_lock_markers(profile_root: Path) -> list[str]:
    present: list[str] = []
    for marker in LOCK_MARKERS:
        if (profile_root / marker).exists():
            present.append(marker)
    return present


def _copy_tree(source_root: Path, target_root: Path) -> CopyStats:
    if target_root.exists():
        shutil.rmtree(target_root)
    target_root.mkdir(parents=True, exist_ok=True)

    files_copied = 0
    dirs_copied = 0
    bytes_copied = 0

    for root, dirs, files in os.walk(source_root):
        src_dir = Path(root)
        rel = src_dir.relative_to(source_root)
        dst_dir = target_root / rel

        dst_dir.mkdir(parents=True, exist_ok=True)
        dirs_copied += 1

        for directory in dirs:
            src_child = src_dir / directory
            if src_child.is_symlink():
                raise RuntimeError(f"symlinked directory not allowed in source profile: {src_child}")

        for file_name in files:
            src_file = src_dir / file_name
            if src_file.is_symlink():
                raise RuntimeError(f"symlinked file not allowed in source profile: {src_file}")

            dst_file = dst_dir / file_name
            shutil.copy2(src_file, dst_file)
            try:
                bytes_copied += dst_file.stat().st_size
            except OSError:
                pass
            files_copied += 1

    return CopyStats(files_copied=files_copied, dirs_copied=dirs_copied, bytes_copied=bytes_copied)


def _make_tree_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        read_only_mode = mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
        try:
            path.chmod(read_only_mode)
        except OSError:
            continue


def _build_scan_command(
    args: argparse.Namespace,
    staged_profile: Path,
    json_out: Path,
    sarif_out: Path,
    scan_snapshot_out: Path,
) -> list[str]:
    foxclaw_cmd = shlex.split(args.foxclaw_cmd)
    if not foxclaw_cmd:
        raise RuntimeError("--foxclaw-cmd produced an empty command")

    cmd = foxclaw_cmd + [
        "scan",
        "--profile",
        str(staged_profile),
        "--ruleset",
        str(args.ruleset),
        "--output",
        str(json_out),
        "--sarif-out",
        str(sarif_out),
        "--snapshot-out",
        str(scan_snapshot_out),
        "--deterministic",
    ]

    for policy_path in args.policy_path:
        cmd.extend(["--policy-path", str(policy_path)])
    for suppression_path in args.suppression_path:
        cmd.extend(["--suppression-path", str(suppression_path)])

    if args.intel_store_dir:
        cmd.extend(["--intel-store-dir", str(args.intel_store_dir)])
    if args.intel_snapshot_id:
        cmd.extend(["--intel-snapshot-id", str(args.intel_snapshot_id)])

    return cmd


def _write_manifest(manifest_out: Path, payload: dict[str, object]) -> None:
    manifest_out.parent.mkdir(parents=True, exist_ok=True)
    manifest_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _main(argv: list[str]) -> int:
    args = _parse_args(argv)
    (
        source_profile,
        staged_profile,
        output_dir,
        json_out,
        sarif_out,
        scan_snapshot_out,
        manifest_out,
    ) = _resolve_paths(args)

    if not source_profile.exists() or not source_profile.is_dir():
        print(f"error: source profile does not exist or is not a directory: {source_profile}", file=sys.stderr)
        return 1

    if args.intel_snapshot_id and not args.intel_store_dir:
        print("error: --intel-snapshot-id requires --intel-store-dir", file=sys.stderr)
        return 2

    lock_markers = _find_lock_markers(source_profile)
    if lock_markers and not args.allow_active_profile:
        marker_list = ", ".join(lock_markers)
        print(
            "error: active-profile lock markers detected in source profile "
            f"({marker_list}). Close Firefox on the source host or collect from a crash-consistent "
            "snapshot, then rerun. Use --allow-active-profile only for validated snapshots.",
            file=sys.stderr,
        )
        return 1

    copy_stats = _copy_tree(source_profile, staged_profile)
    if not args.keep_stage_writeable:
        _make_tree_read_only(staged_profile)

    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "captured_at_utc": _utc_now_iso(),
        "source_profile": str(source_profile),
        "source_is_unc_path": str(source_profile).startswith("\\\\"),
        "source_lock_markers": lock_markers,
        "staged_profile": str(staged_profile),
        "stage_writeable": bool(args.keep_stage_writeable),
        "copy": {
            "directories": copy_stats.dirs_copied,
            "files": copy_stats.files_copied,
            "bytes": copy_stats.bytes_copied,
        },
        "artifacts": {
            "json": str(json_out),
            "sarif": str(sarif_out),
            "snapshot": str(scan_snapshot_out),
        },
        "scan": {
            "command": [],
            "exit_code": 0,
            "status": "SKIPPED" if args.dry_run else "PENDING",
        },
    }

    if args.dry_run:
        _write_manifest(manifest_out, manifest_payload)
        print(f"[share-scan] staged profile at: {staged_profile}")
        print(f"[share-scan] dry-run: manifest written to {manifest_out}")
        return 0

    cmd = _build_scan_command(args, staged_profile, json_out, sarif_out, scan_snapshot_out)
    manifest_payload["scan"] = {
        "command": cmd,
        "exit_code": 0,
        "status": "PENDING",
    }

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)

    scan_status = "PASS"
    if result.returncode not in (0, 2):
        scan_status = "FAIL"

    manifest_payload["scan"] = {
        "command": cmd,
        "exit_code": result.returncode,
        "status": scan_status,
    }
    _write_manifest(manifest_out, manifest_payload)

    print(f"[share-scan] staged profile: {staged_profile}")
    print(f"[share-scan] artifacts: {output_dir}")
    print(f"[share-scan] manifest: {manifest_out}")

    if result.returncode not in (0, 2):
        print(f"error: foxclaw scan failed with exit code {result.returncode}", file=sys.stderr)
        return result.returncode

    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
