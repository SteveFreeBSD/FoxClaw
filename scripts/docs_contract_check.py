#!/usr/bin/env python3
"""Validate markdown docs contract references and emit a traceability report."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

LINK_RE = re.compile(r"\[[^\]]*]\(([^)]+)\)")
PATH_REF_RE = re.compile(
    r"`((?:docs|scripts|assets|DIFFS|\.github)/[A-Za-z0-9_./-]+|requirements-dev\.lock)`"
)


@dataclass(frozen=True)
class Issue:
    issue_type: str
    file: str
    line: int
    reference: str
    message: str


def _iter_markdown_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.md"):
        if ".git" in path.parts or ".venv" in path.parts:
            continue
        files.append(path)
    return sorted(files)


def _resolve_markdown_target(root: Path, owner: Path, target: str) -> Path:
    if target.startswith("/"):
        return (root / target.lstrip("/")).resolve()
    return (owner.parent / target).resolve()


def _is_external_link(target: str) -> bool:
    return target.startswith(("http://", "https://", "mailto:", "#", "data:"))


def _normalize_target(raw: str) -> str:
    target = raw.strip().split()[0]
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    target = target.split("#", 1)[0]
    return target.strip()


def _collect_issues(root: Path) -> tuple[list[Issue], int]:
    issues: list[Issue] = []
    markdown_files = _iter_markdown_files(root)

    for md_file in markdown_files:
        text = md_file.read_text(encoding="utf-8", errors="ignore")

        for match in LINK_RE.finditer(text):
            raw = match.group(1).strip()
            line = text.count("\n", 0, match.start()) + 1

            if not raw or _is_external_link(raw):
                continue

            if raw.startswith("file://"):
                issues.append(
                    Issue(
                        issue_type="file_uri_link",
                        file=str(md_file.relative_to(root)),
                        line=line,
                        reference=raw,
                        message="non-portable file:// link; use repository-relative path",
                    )
                )
                continue

            normalized = _normalize_target(raw)
            if not normalized:
                continue
            resolved = _resolve_markdown_target(root, md_file, normalized)
            if not resolved.exists():
                issues.append(
                    Issue(
                        issue_type="missing_link_target",
                        file=str(md_file.relative_to(root)),
                        line=line,
                        reference=raw,
                        message="markdown link target does not exist",
                    )
                )

        for match in PATH_REF_RE.finditer(text):
            raw = match.group(1).strip()
            line = text.count("\n", 0, match.start()) + 1
            candidate = raw.rstrip(".,:;")
            if "*" in candidate or candidate.endswith("/"):
                continue

            resolved = (root / candidate).resolve()
            if not resolved.exists():
                issues.append(
                    Issue(
                        issue_type="missing_path_reference",
                        file=str(md_file.relative_to(root)),
                        line=line,
                        reference=raw,
                        message="referenced repository path does not exist",
                    )
                )

    deduped = list(
        {
            (i.issue_type, i.file, i.line, i.reference, i.message): i
            for i in issues
        }.values()
    )
    return sorted(deduped, key=lambda i: (i.file, i.line, i.issue_type, i.reference)), len(
        markdown_files
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--report-out",
        default="docs/traceability/docs-contract-report.json",
        help="Path to JSON report output.",
    )
    args = parser.parse_args()

    root = Path.cwd().resolve()
    issues, checked_files = _collect_issues(root)
    report_out = (root / args.report_out).resolve()
    report_out.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "checked_markdown_files": checked_files,
        "issues_count": len(issues),
        "issues": [asdict(issue) for issue in issues],
    }
    report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if issues:
        print(f"[docs-contract] issues found: {len(issues)}")
        for issue in issues:
            print(f" - {issue.file}:{issue.line}: {issue.issue_type}: {issue.reference}")
        if args.strict:
            return 1
    else:
        print(f"[docs-contract] OK ({checked_files} markdown files checked)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
