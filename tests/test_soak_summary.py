from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_soak_summary_builds_machine_readable_rollup(tmp_path: Path) -> None:
    run_dir = tmp_path / "soak-run"
    run_dir.mkdir()
    (run_dir / "manifest.txt").write_text(
        "\n".join(
            [
                "run_id=20260227T000000Z",
                "run_dir=/tmp/soak-run",
                "commit=deadbeefcafebabe",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "summary.txt").write_text(
        "\n".join(
            [
                "cycles_completed=2",
                "steps_total=3",
                "steps_passed=2",
                "steps_failed=1",
                "overall_status=FAIL",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "results.tsv").write_text(
        "\n".join(
            [
                "cycle\tstage\titeration\texit_code\tstatus\tduration_sec\tstarted_at\tended_at\tlog_path\tartifact_path",
                "1\tintegration\t1\t0\tPASS\t1\t2026-02-27T00:00:00Z\t2026-02-27T00:00:01Z\t/tmp/integration.log\t-",
                "1\tsiem_wazuh\t1\t0\tPASS\t14\t2026-02-27T00:00:01Z\t2026-02-27T00:00:15Z\t/tmp/siem.log\t/tmp/run/siem-wazuh/cycle-1-run-1",
                "2\tsiem_wazuh\t1\t124\tFAIL\t30\t2026-02-27T00:01:01Z\t2026-02-27T00:01:31Z\t/tmp/siem2.log\t/tmp/run/siem-wazuh/cycle-2-run-1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    siem_dir = run_dir / "siem-wazuh" / "cycle-1-run-1"
    siem_dir.mkdir(parents=True)
    (siem_dir / "foxclaw.ndjson").write_text(
        "\n".join(
            [
                '{"event_type":"foxclaw.finding","rule_id":"TB-POL-001"}',
                '{"event_type":"foxclaw.finding","rule_id":"TB-POL-001"}',
                '{"event_type":"foxclaw.finding","rule_id":"TB-POL-002"}',
                '{"event_type":"foxclaw.scan.summary"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (siem_dir / "manifest.json").write_text(
        json.dumps({"wazuh_image": "wazuh/wazuh-manager:4.14.3"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    output_path = run_dir / "soak-summary.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/soak_summary.py",
            "--run-dir",
            str(run_dir),
            "--output",
            str(output_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["git_sha"] == "deadbeefcafebabe"
    assert payload["total_cycles"] == 2
    assert payload["artifact_root_path"] == str(run_dir)
    assert payload["wazuh_image"] == "wazuh/wazuh-manager:4.14.3"
    assert payload["ndjson_event_counts"] == {
        "foxclaw.finding": 3,
        "foxclaw.scan.summary": 1,
    }
    assert payload["stage_counts"] == {
        "integration": {"fail": 0, "pass": 1},
        "siem_wazuh": {"fail": 1, "pass": 1},
    }
    assert payload["top_rule_ids"] == [
        {"count": 2, "rule_id": "TB-POL-001"},
        {"count": 1, "rule_id": "TB-POL-002"},
    ]
    assert payload["failed_artifact_paths"] == ["/tmp/run/siem-wazuh/cycle-2-run-1"]
