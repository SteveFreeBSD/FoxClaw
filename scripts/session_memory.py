#!/usr/bin/env python3
"""Persistent session memory checkpoint helper."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MEMORY_DIR_ENV = "FOXCLAW_SESSION_MEMORY_DIR"
DEFAULT_MEMORY_DIR = ROOT / "artifacts" / "session_memory"
JOURNAL_PATH = (
    Path(os.environ[MEMORY_DIR_ENV]).expanduser()
    if MEMORY_DIR_ENV in os.environ and os.environ[MEMORY_DIR_ENV].strip()
    else DEFAULT_MEMORY_DIR
)
if not JOURNAL_PATH.is_absolute():
    JOURNAL_PATH = ROOT / JOURNAL_PATH
JOURNAL_PATH = JOURNAL_PATH / "SESSION_MEMORY.jsonl"
DOC_PATH = JOURNAL_PATH.with_name("SESSION_MEMORY.md")
MAX_RECENT = 20


@dataclass
class Checkpoint:
    timestamp_utc: str
    branch: str
    commit: str
    focus: str
    next_actions: str
    risks: str | None = None
    decisions: str | None = None


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _read_journal() -> list[Checkpoint]:
    if not JOURNAL_PATH.exists():
        return []

    checkpoints: list[Checkpoint] = []
    for raw_line in JOURNAL_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        payload: dict[str, Any] = json.loads(line)
        checkpoints.append(Checkpoint(**payload))
    return checkpoints


def _write_doc(checkpoints: list[Checkpoint]) -> None:
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = [
        "# Session Memory",
        "",
        "Persistent handoff context between sessions.",
        "",
        "## Usage",
        "",
        "```bash",
        "python scripts/session_memory.py show",
        "python scripts/session_memory.py checkpoint \\",
        "  --focus \"<what changed>\" \\",
        "  --next \"<next action>\"",
        "```",
        "",
    ]

    if not checkpoints:
        lines.extend(
            [
                "## Current Snapshot",
                "",
                "No checkpoints yet. Create one with `scripts/session_memory.py checkpoint`.",
                "",
            ]
        )
    else:
        latest = checkpoints[-1]
        lines.extend(
            [
                "## Current Snapshot",
                "",
                f"- Updated: {latest.timestamp_utc}",
                f"- Branch: {latest.branch}",
                f"- Commit: `{latest.commit}`",
                f"- Focus: {latest.focus}",
                f"- Next: {latest.next_actions}",
            ]
        )
        if latest.risks:
            lines.append(f"- Risks: {latest.risks}")
        if latest.decisions:
            lines.append(f"- Decisions: {latest.decisions}")
        lines.append("")

    lines.extend(["## Recent Checkpoints", ""])

    for entry in reversed(checkpoints[-MAX_RECENT:]):
        lines.append(f"### {entry.timestamp_utc}")
        lines.append(f"- Branch: {entry.branch}")
        lines.append(f"- Commit: `{entry.commit}`")
        lines.append(f"- Focus: {entry.focus}")
        lines.append(f"- Next: {entry.next_actions}")
        if entry.risks:
            lines.append(f"- Risks: {entry.risks}")
        if entry.decisions:
            lines.append(f"- Decisions: {entry.decisions}")
        lines.append("")

    DOC_PATH.write_text("\n".join(lines), encoding="utf-8")


def cmd_checkpoint(args: argparse.Namespace) -> int:
    JOURNAL_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = Checkpoint(
        timestamp_utc=datetime.now(tz=UTC).isoformat(),
        branch=_git("rev-parse", "--abbrev-ref", "HEAD"),
        commit=_git("rev-parse", "HEAD"),
        focus=args.focus.strip(),
        next_actions=args.next.strip(),
        risks=args.risks.strip() if args.risks else None,
        decisions=args.decisions.strip() if args.decisions else None,
    )

    with JOURNAL_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(entry), sort_keys=True))
        handle.write("\n")

    checkpoints = _read_journal()
    _write_doc(checkpoints)

    print(f"[session-memory] checkpoint recorded at {entry.timestamp_utc}")
    return 0


def cmd_show(_args: argparse.Namespace) -> int:
    checkpoints = _read_journal()
    if not checkpoints:
        print("[session-memory] no checkpoints recorded")
        return 1

    latest = checkpoints[-1]
    print("[session-memory] latest checkpoint")
    print(f" - timestamp: {latest.timestamp_utc}")
    print(f" - branch: {latest.branch}")
    print(f" - commit: {latest.commit}")
    print(f" - focus: {latest.focus}")
    print(f" - next: {latest.next_actions}")
    if latest.risks:
        print(f" - risks: {latest.risks}")
    if latest.decisions:
        print(f" - decisions: {latest.decisions}")
    return 0


def cmd_validate(_args: argparse.Namespace) -> int:
    checkpoints = _read_journal()
    if not checkpoints:
        print("[session-memory] no checkpoints found (run checkpoint command)")
        return 1
    if not DOC_PATH.exists():
        try:
            relative_doc = DOC_PATH.relative_to(ROOT)
        except ValueError:
            relative_doc = DOC_PATH
        print(f"[session-memory] missing {relative_doc}")
        return 1
    print(f"[session-memory] OK ({len(checkpoints)} checkpoints)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    checkpoint = sub.add_parser("checkpoint", help="record a new checkpoint")
    checkpoint.add_argument("--focus", required=True, help="what changed this session")
    checkpoint.add_argument("--next", required=True, help="next concrete action")
    checkpoint.add_argument("--risks", default="", help="optional risk/watch-outs")
    checkpoint.add_argument("--decisions", default="", help="optional decisions made")
    checkpoint.set_defaults(func=cmd_checkpoint)

    show = sub.add_parser("show", help="show latest checkpoint")
    show.set_defaults(func=cmd_show)

    validate = sub.add_parser("validate", help="validate memory artifacts exist")
    validate.set_defaults(func=cmd_validate)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
