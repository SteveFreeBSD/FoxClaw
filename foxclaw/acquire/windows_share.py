"""Windows-share Firefox profile staging and scan orchestration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

LOCK_MARKERS = ("parent.lock", ".parentlock", "lock")


@dataclass
class CopyStats:
    files_copied: int
    dirs_copied: int
    bytes_copied: int
    file_entries: list["StagedFileEntry"]


@dataclass
class StagedFileEntry:
    rel_path: str
    size: int
    mtime_utc: str
    sha256: str


def _utc_now_iso() -> str:
    return datetime.now(tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_snapshot_id() -> str:
    return datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")


def _default_staging_root() -> Path:
    return Path(tempfile.gettempdir()) / "foxclaw-windows-share"


def parse_windows_share_scan_args(argv: list[str]) -> argparse.Namespace:
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
    parser.add_argument(
        "--treat-high-findings-as-success",
        action="store_true",
        help="Return exit code 0 when foxclaw scan returns 2 (HIGH findings present).",
    )
    return parser.parse_args(argv)


def _resolve_paths(
    args: argparse.Namespace,
) -> tuple[Path, Path, Path, Path, Path, Path, Path, Path]:
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
    return (
        source_profile,
        staging_root,
        staged_profile,
        output_dir,
        json_out,
        sarif_out,
        scan_snapshot_out,
        manifest_out,
    )


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
    file_entries: list[StagedFileEntry] = []

    for root, dirs, files in os.walk(source_root):
        src_dir = Path(root)
        rel = src_dir.relative_to(source_root)
        dst_dir = target_root / rel

        dst_dir.mkdir(parents=True, exist_ok=True)
        dirs_copied += 1
        dirs.sort()

        for directory in dirs:
            src_child = src_dir / directory
            if src_child.is_symlink():
                raise RuntimeError(f"symlinked directory not allowed in source profile: {src_child}")

        for file_name in sorted(files):
            src_file = src_dir / file_name
            if src_file.is_symlink():
                raise RuntimeError(f"symlinked file not allowed in source profile: {src_file}")

            dst_file = dst_dir / file_name
            shutil.copy2(src_file, dst_file)
            file_stat = dst_file.stat()
            bytes_copied += file_stat.st_size
            files_copied += 1
            file_entries.append(
                StagedFileEntry(
                    rel_path=src_file.relative_to(source_root).as_posix(),
                    size=file_stat.st_size,
                    mtime_utc=_timestamp_to_utc_iso(file_stat.st_mtime),
                    sha256=_sha256_file(dst_file),
                )
            )

    file_entries.sort(key=lambda item: item.rel_path)
    return CopyStats(
        files_copied=files_copied,
        dirs_copied=dirs_copied,
        bytes_copied=bytes_copied,
        file_entries=file_entries,
    )


def _timestamp_to_utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_staging_root(*, source_profile: Path, staging_root: Path) -> str | None:
    filesystem_root = Path(staging_root.anchor or os.sep).resolve(strict=False)
    if staging_root == filesystem_root:
        return f"staging root cannot be filesystem root: {staging_root}"

    home_root = Path.home().expanduser().resolve(strict=False)
    if staging_root == home_root:
        return f"staging root cannot be home directory root: {staging_root}"

    if _is_within_root(staging_root, source_profile):
        return (
            "staging root cannot be inside source profile: "
            f"{staging_root} is under {source_profile}"
        )

    if _is_within_root(source_profile, staging_root):
        return (
            "source profile cannot be inside staging root: "
            f"{source_profile} is under {staging_root}"
        )

    return None


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

    cmd = [
        *foxclaw_cmd,
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


def run_windows_share_scan(
    args: argparse.Namespace,
    *,
    out_stream: TextIO | None = None,
    err_stream: TextIO | None = None,
) -> int:
    out_stream = out_stream or sys.stdout
    err_stream = err_stream or sys.stderr

    (
        source_profile,
        staging_root,
        staged_profile,
        output_dir,
        json_out,
        sarif_out,
        scan_snapshot_out,
        manifest_out,
    ) = _resolve_paths(args)

    if not source_profile.exists() or not source_profile.is_dir():
        print(f"error: source profile does not exist or is not a directory: {source_profile}", file=err_stream)
        return 1

    if args.intel_snapshot_id and not args.intel_store_dir:
        print("error: --intel-snapshot-id requires --intel-store-dir", file=err_stream)
        return 2

    staging_root_error = _validate_staging_root(
        source_profile=source_profile,
        staging_root=staging_root,
    )
    if staging_root_error is not None:
        print(f"error: {staging_root_error}", file=err_stream)
        return 1

    lock_markers = _find_lock_markers(source_profile)
    if lock_markers and not args.allow_active_profile:
        marker_list = ", ".join(lock_markers)
        print(
            "error: active-profile lock markers detected in source profile "
            f"({marker_list}). Close Firefox on the source host or collect from a crash-consistent "
            "snapshot, then rerun. Use --allow-active-profile only for validated snapshots.",
            file=err_stream,
        )
        return 1

    try:
        copy_stats = _copy_tree(source_profile, staged_profile)
        if not args.keep_stage_writeable:
            _make_tree_read_only(staged_profile)
        output_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, RuntimeError) as exc:
        print(f"error: failed to stage source profile: {exc}", file=err_stream)
        return 1

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
        "files": [
            {
                "rel_path": entry.rel_path,
                "size": entry.size,
                "mtime_utc": entry.mtime_utc,
                "sha256": entry.sha256,
            }
            for entry in copy_stats.file_entries
        ],
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
        print(f"[share-scan] staged profile at: {staged_profile}", file=out_stream)
        print(f"[share-scan] dry-run: manifest written to {manifest_out}", file=out_stream)
        return 0

    try:
        cmd = _build_scan_command(args, staged_profile, json_out, sarif_out, scan_snapshot_out)
    except RuntimeError as exc:
        print(f"error: failed to build scan command: {exc}", file=err_stream)
        return 1

    manifest_payload["scan"] = {
        "command": cmd,
        "exit_code": 0,
        "status": "PENDING",
    }

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout, end="", file=out_stream)
    if result.stderr:
        print(result.stderr, end="", file=err_stream)

    scan_status = "PASS"
    if result.returncode not in (0, 2):
        scan_status = "FAIL"

    manifest_payload["scan"] = {
        "command": cmd,
        "exit_code": result.returncode,
        "status": scan_status,
    }
    _write_manifest(manifest_out, manifest_payload)

    print(f"[share-scan] staged profile: {staged_profile}", file=out_stream)
    print(f"[share-scan] artifacts: {output_dir}", file=out_stream)
    print(f"[share-scan] manifest: {manifest_out}", file=out_stream)

    if result.returncode == 2 and args.treat_high_findings_as_success:
        return 0

    if result.returncode not in (0, 2):
        print(f"error: foxclaw scan failed with exit code {result.returncode}", file=err_stream)

    return result.returncode


def run_windows_share_scan_from_argv(argv: list[str]) -> int:
    args = parse_windows_share_scan_args(argv)
    return run_windows_share_scan(args)
