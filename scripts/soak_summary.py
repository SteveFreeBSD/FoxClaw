#!/usr/bin/env python3
"""Build a machine-readable summary for a FoxClaw soak run."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="Soak run directory.")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path for the JSON summary (defaults to <run-dir>/soak-summary.json).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_dir = args.run_dir.expanduser().resolve()
    output_path = args.output.expanduser().resolve() if args.output else run_dir / "soak-summary.json"
    payload = build_soak_summary(run_dir)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def build_soak_summary(run_dir: Path) -> dict[str, Any]:
    manifest = _read_key_value_file(run_dir / "manifest.txt")
    summary = _read_key_value_file(run_dir / "summary.txt")
    rows = _read_results(run_dir / "results.tsv")

    stage_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"pass": 0, "fail": 0})
    failed_artifact_paths: list[str] = []
    for row in rows:
        stage = row.get("stage", "-")
        status = row.get("status", "FAIL")
        artifact_path = row.get("artifact_path", "-")
        if status == "PASS":
            stage_counts[stage]["pass"] += 1
        else:
            stage_counts[stage]["fail"] += 1
            if artifact_path and artifact_path != "-":
                failed_artifact_paths.append(artifact_path)

    ndjson_event_counts: Counter[str] = Counter()
    rule_id_counts: Counter[str] = Counter()
    wazuh_images: set[str] = set()

    for ndjson_path in sorted(run_dir.glob("siem-wazuh/**/foxclaw.ndjson")):
        for line in ndjson_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            event_type = str(event.get("event_type", ""))
            if event_type:
                ndjson_event_counts[event_type] += 1
            rule_id = event.get("rule_id")
            if isinstance(rule_id, str) and rule_id:
                rule_id_counts[rule_id] += 1

    for manifest_path in sorted(run_dir.glob("siem-wazuh/**/manifest.json")):
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        wazuh_image = payload.get("wazuh_image")
        if isinstance(wazuh_image, str) and wazuh_image:
            wazuh_images.add(wazuh_image)

    top_rule_ids = [
        {"rule_id": rule_id, "count": count}
        for rule_id, count in sorted(rule_id_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
    ]

    ordered_stage_counts = {
        stage: stage_counts[stage]
        for stage in sorted(stage_counts)
    }
    return {
        "schema_version": "1.0.0",
        "git_sha": manifest.get("commit", "unknown"),
        "artifact_root_path": str(run_dir),
        "overall_status": summary.get("overall_status", "unknown"),
        "total_cycles": _int_value(summary.get("cycles_completed")),
        "steps_total": _int_value(summary.get("steps_total")),
        "steps_passed": _int_value(summary.get("steps_passed")),
        "steps_failed": _int_value(summary.get("steps_failed")),
        "stage_counts": ordered_stage_counts,
        "wazuh_image": sorted(wazuh_images)[0] if wazuh_images else None,
        "ndjson_event_counts": {
            event_type: ndjson_event_counts[event_type]
            for event_type in sorted(ndjson_event_counts)
        },
        "top_rule_ids": top_rule_ids,
        "failed_artifact_paths": sorted(dict.fromkeys(failed_artifact_paths)),
    }


def _read_key_value_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value
    return data


def _read_results(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        return [dict(row) for row in reader]


def _int_value(value: str | None) -> int:
    if value is None or value == "":
        return 0
    return int(value)


if __name__ == "__main__":
    raise SystemExit(main())
