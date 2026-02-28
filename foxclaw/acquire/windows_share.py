"""Windows-share Firefox profile staging and scan orchestration."""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess  # nosec B404
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from foxclaw.profiles import PROFILE_LOCK_FILES

_SMB_FILESYSTEM_TYPES = frozenset(
    {
        "cifs",
        "smb3",
        "smbfs",
        "fuse.smbnetfs",
    }
)
_MOUNT_ESCAPE_RE = re.compile(r"\\([0-7]{3})")


@dataclass
class CopyStats:
    files_copied: int
    dirs_copied: int
    bytes_copied: int
    file_entries: list[StagedFileEntry]


@dataclass
class StagedFileEntry:
    rel_path: str
    size: int
    mtime_utc: str
    sha256: str


@dataclass
class WindowsShareStagePaths:
    source_profile: Path
    source_is_unc_path: bool
    staging_root: Path
    staged_profile: Path
    output_dir: Path
    json_out: Path
    ndjson_out: Path | None
    sarif_out: Path
    scan_snapshot_out: Path
    manifest_out: Path


@dataclass
class WindowsShareStageResult:
    paths: WindowsShareStagePaths
    lock_markers: list[str]
    copy_stats: CopyStats
    manifest_payload: dict[str, object]


def _utc_now_iso() -> str:
    return datetime.now(tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_snapshot_id() -> str:
    return datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")


def _default_staging_root() -> Path:
    return Path(tempfile.gettempdir()) / "foxclaw-windows-share"


def _decode_mount_token(token: str) -> str:
    return _MOUNT_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 8)), token)


@functools.lru_cache(maxsize=1)
def _load_proc_mounts() -> tuple[tuple[Path, str], ...]:
    mounts: list[tuple[Path, str]] = []
    try:
        lines = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()

    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        mount_point = Path(_decode_mount_token(parts[1]))
        fs_type = parts[2].lower()
        mounts.append((mount_point, fs_type))

    mounts.sort(key=lambda item: len(item[0].as_posix()), reverse=True)
    return tuple(mounts)


def _mount_fs_type_for_path(path: Path) -> str | None:
    candidate = path.expanduser().resolve(strict=False).as_posix()
    for mount_point, fs_type in _load_proc_mounts():
        mount_prefix = mount_point.as_posix().rstrip("/") or "/"
        if candidate == mount_prefix or candidate.startswith(f"{mount_prefix}/"):
            return fs_type
    return None


def is_windows_share_profile_source(profile_path: Path) -> bool:
    raw = str(profile_path)
    if raw.startswith("\\\\") or raw.startswith("//"):
        return True
    if os.name == "nt":
        return False
    fs_type = _mount_fs_type_for_path(profile_path)
    return fs_type in _SMB_FILESYSTEM_TYPES


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
        "--keep-stage-writable",
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


def resolve_windows_share_stage_paths(
    *,
    source_profile: Path | str,
    staging_root: Path | None = None,
    snapshot_id: str | None = None,
    output_dir: Path | None = None,
    json_out: Path | None = None,
    ndjson_out: Path | None = None,
    sarif_out: Path | None = None,
    scan_snapshot_out: Path | None = None,
    manifest_out: Path | None = None,
) -> WindowsShareStagePaths:
    resolved_snapshot_id = snapshot_id or _default_snapshot_id()
    source_profile_input = str(source_profile)
    source_is_unc_path = source_profile_input.startswith("\\\\")
    source_profile_candidate = Path(source_profile).expanduser()
    if source_is_unc_path and os.name != "nt":
        resolved_source_profile = source_profile_candidate
    else:
        resolved_source_profile = source_profile_candidate.resolve()

    resolved_staging_root = (staging_root or _default_staging_root()).expanduser().resolve()
    stage_root = resolved_staging_root / resolved_snapshot_id
    staged_profile = stage_root / "profile"

    resolved_output_dir = (
        output_dir.expanduser().resolve() if output_dir else stage_root / "artifacts"
    )
    resolved_json_out = (
        json_out.expanduser().resolve() if json_out else resolved_output_dir / "foxclaw.json"
    )
    resolved_ndjson_out = ndjson_out.expanduser().resolve() if ndjson_out else None
    resolved_sarif_out = (
        sarif_out.expanduser().resolve() if sarif_out else resolved_output_dir / "foxclaw.sarif"
    )
    resolved_scan_snapshot_out = (
        scan_snapshot_out.expanduser().resolve()
        if scan_snapshot_out
        else resolved_output_dir / "foxclaw.snapshot.json"
    )
    resolved_manifest_out = (
        manifest_out.expanduser().resolve()
        if manifest_out
        else resolved_output_dir / "stage-manifest.json"
    )

    return WindowsShareStagePaths(
        source_profile=resolved_source_profile,
        source_is_unc_path=source_is_unc_path,
        staging_root=resolved_staging_root,
        staged_profile=staged_profile,
        output_dir=resolved_output_dir,
        json_out=resolved_json_out,
        ndjson_out=resolved_ndjson_out,
        sarif_out=resolved_sarif_out,
        scan_snapshot_out=resolved_scan_snapshot_out,
        manifest_out=resolved_manifest_out,
    )


def _find_lock_markers(profile_root: Path) -> list[str]:
    present: list[str] = []
    for marker in PROFILE_LOCK_FILES:
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
                raise RuntimeError(
                    f"symlinked directory not allowed in source profile: {src_child}"
                )

        for file_name in sorted(files):
            src_file = src_dir / file_name
            if src_file.is_symlink():
                raise RuntimeError(f"symlinked file not allowed in source profile: {src_file}")

            dst_file = dst_dir / file_name
            
            max_attempts = 4
            for attempt in range(1, max_attempts + 1):
                try:
                    shutil.copy2(src_file, dst_file)
                    break
                except OSError as e:
                    if file_name in PROFILE_LOCK_FILES:
                        # Ignore locked lock-markers on SMB shares when copying
                        break
                    
                    if attempt == max_attempts:
                        raise e
                    
                    # Exponential backoff (1s, 2s, 4s...)
                    time.sleep(2 ** (attempt - 1))
                    
            if not dst_file.exists() and file_name in PROFILE_LOCK_FILES:
                continue

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


def write_windows_share_manifest(manifest_out: Path, payload: dict[str, object]) -> None:
    _write_manifest(manifest_out, payload)


def stage_windows_share_profile(
    *,
    source_profile: Path | str,
    staging_root: Path | None = None,
    snapshot_id: str | None = None,
    output_dir: Path | None = None,
    json_out: Path | None = None,
    ndjson_out: Path | None = None,
    sarif_out: Path | None = None,
    scan_snapshot_out: Path | None = None,
    manifest_out: Path | None = None,
    allow_active_profile: bool = False,
    keep_stage_writable: bool = False,
) -> WindowsShareStageResult:
    paths = resolve_windows_share_stage_paths(
        source_profile=source_profile,
        staging_root=staging_root,
        snapshot_id=snapshot_id,
        output_dir=output_dir,
        json_out=json_out,
        ndjson_out=ndjson_out,
        sarif_out=sarif_out,
        scan_snapshot_out=scan_snapshot_out,
        manifest_out=manifest_out,
    )

    if paths.source_is_unc_path and os.name != "nt":
        raise ValueError(
            "UNC source profile paths are not directly accessible on this platform; "
            "mount the share and pass the mounted path."
        )
    if not paths.source_profile.exists() or not paths.source_profile.is_dir():
        raise ValueError(
            f"source profile does not exist or is not a directory: {paths.source_profile}"
        )

    staging_root_error = _validate_staging_root(
        source_profile=paths.source_profile,
        staging_root=paths.staging_root,
    )
    if staging_root_error is not None:
        raise ValueError(staging_root_error)

    lock_markers = _find_lock_markers(paths.source_profile)
    if lock_markers and not allow_active_profile:
        marker_list = ", ".join(lock_markers)
        raise ValueError(
            "active-profile lock markers detected in source profile "
            f"({marker_list}). Close Firefox on the source host or collect from a "
            "crash-consistent snapshot, then rerun. Use --allow-active-profile only "
            "for validated snapshots."
        )

    try:
        copy_stats = _copy_tree(paths.source_profile, paths.staged_profile)
        if not keep_stage_writable:
            _make_tree_read_only(paths.staged_profile)
        paths.output_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"failed to stage source profile: {exc}") from exc

    artifacts: dict[str, str] = {
        "json": str(paths.json_out),
        "sarif": str(paths.sarif_out),
        "snapshot": str(paths.scan_snapshot_out),
    }
    if paths.ndjson_out is not None:
        artifacts["ndjson"] = str(paths.ndjson_out)

    manifest_payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "captured_at_utc": _utc_now_iso(),
        "source_profile": str(paths.source_profile),
        "source_is_unc_path": paths.source_is_unc_path,
        "source_lock_markers": lock_markers,
        "staged_profile": str(paths.staged_profile),
        "stage_writable": bool(keep_stage_writable),
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
        "artifacts": artifacts,
        "scan": {
            "command": [],
            "exit_code": 0,
            "status": "PENDING",
        },
    }
    return WindowsShareStageResult(
        paths=paths,
        lock_markers=lock_markers,
        copy_stats=copy_stats,
        manifest_payload=manifest_payload,
    )


def run_windows_share_scan(
    args: argparse.Namespace,
    *,
    out_stream: TextIO | None = None,
    err_stream: TextIO | None = None,
) -> int:
    out_stream = out_stream or sys.stdout
    err_stream = err_stream or sys.stderr

    if args.intel_snapshot_id and not args.intel_store_dir:
        print("error: --intel-snapshot-id requires --intel-store-dir", file=err_stream)
        return 1

    try:
        stage_result = stage_windows_share_profile(
            source_profile=Path(args.source_profile),
            staging_root=Path(args.staging_root),
            snapshot_id=args.snapshot_id or None,
            output_dir=Path(args.output_dir) if args.output_dir else None,
            json_out=Path(args.json_out) if args.json_out else None,
            sarif_out=Path(args.sarif_out) if args.sarif_out else None,
            scan_snapshot_out=Path(args.scan_snapshot_out) if args.scan_snapshot_out else None,
            manifest_out=Path(args.manifest_out) if args.manifest_out else None,
            allow_active_profile=bool(args.allow_active_profile),
            keep_stage_writable=bool(args.keep_stage_writable),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=err_stream)
        return 1
    paths = stage_result.paths
    manifest_payload = stage_result.manifest_payload

    if args.dry_run:
        manifest_payload["scan"] = {
            "command": [],
            "exit_code": 0,
            "status": "SKIPPED",
        }
        _write_manifest(paths.manifest_out, manifest_payload)
        print(f"[share-scan] staged profile at: {paths.staged_profile}", file=out_stream)
        print(f"[share-scan] dry-run: manifest written to {paths.manifest_out}", file=out_stream)
        return 0

    try:
        cmd = _build_scan_command(
            args,
            paths.staged_profile,
            paths.json_out,
            paths.sarif_out,
            paths.scan_snapshot_out,
        )
    except RuntimeError as exc:
        print(f"error: failed to build scan command: {exc}", file=err_stream)
        return 1

    manifest_payload["scan"] = {
        "command": cmd,
        "exit_code": 0,
        "status": "PENDING",
    }

    # argv list only, shell=False, command is explicit.
    result = subprocess.run(  # nosec B603
        cmd, check=False, capture_output=True, text=True
    )
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
    _write_manifest(paths.manifest_out, manifest_payload)

    print(f"[share-scan] staged profile: {paths.staged_profile}", file=out_stream)
    print(f"[share-scan] artifacts: {paths.output_dir}", file=out_stream)
    print(f"[share-scan] manifest: {paths.manifest_out}", file=out_stream)

    if result.returncode == 2 and args.treat_high_findings_as_success:
        return 0

    if result.returncode not in (0, 2):
        print(f"error: foxclaw scan failed with exit code {result.returncode}", file=err_stream)

    return result.returncode


def run_windows_share_scan_from_argv(argv: list[str]) -> int:
    args = parse_windows_share_scan_args(argv)
    return run_windows_share_scan(args)
