#!/usr/bin/env python3
"""Native FoxClaw Wazuh NDJSON smoke runner."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_WAZUH_IMAGE = "wazuh/wazuh-manager:4.14.3"
LOGTEST_RULE_ID = "100510"
POLL_INTERVAL_SECONDS = 1.0
OSSEC_LOG_TAIL_LINES = 80

LOCALFILE_BLOCK = """\
  <localfile>
    <location>/var/log/foxclaw/foxclaw.ndjson</location>
    <log_format>json</log_format>
    <label key="@source">foxclaw</label>
    <label key="observer.vendor">FoxClaw</label>
  </localfile>
"""

LOCAL_RULES_XML = """\
<group name="foxclaw,">
  <rule id="100510" level="8">
    <if_sid>86600</if_sid>
    <field name="event_type">^foxclaw.finding$</field>
    <description>FoxClaw finding event</description>
  </rule>

  <rule id="100511" level="3">
    <if_sid>86600</if_sid>
    <field name="event_type">^foxclaw.scan.summary$</field>
    <description>FoxClaw scan summary event</description>
  </rule>
</group>
"""


class SmokeError(Exception):
    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


def parse_args(argv: list[str]) -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory for NDJSON, Wazuh logtest output, and alert excerpts.",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=root / "tests" / "fixtures" / "testbed" / "profile_baseline",
        help="Firefox profile path used to generate NDJSON.",
    )
    parser.add_argument(
        "--ruleset",
        type=Path,
        default=root / "tests" / "fixtures" / "testbed" / "rulesets" / "integration.yml",
        help="Ruleset path used for the smoke scan.",
    )
    parser.add_argument(
        "--python-bin",
        type=Path,
        default=root / ".venv" / "bin" / "python",
        help="Python interpreter used when --foxclaw-cmd is not provided.",
    )
    parser.add_argument(
        "--foxclaw-cmd",
        default="",
        help='Optional explicit FoxClaw command prefix, e.g. "/path/to/python -m foxclaw".',
    )
    parser.add_argument(
        "--docker-cmd",
        default="docker",
        help='Docker command prefix, e.g. "docker" or "sudo docker".',
    )
    parser.add_argument(
        "--wazuh-image",
        default=DEFAULT_WAZUH_IMAGE,
        help="Pinned Wazuh manager image expected locally.",
    )
    parser.add_argument(
        "--container-name",
        default="",
        help="Optional container name override.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=90,
        help="Global timeout budget for Wazuh readiness, logtest, and alert polling.",
    )
    parser.add_argument(
        "--keep-container",
        action="store_true",
        help="Keep the Wazuh container after a successful run for manual inspection.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.timeout_seconds <= 0:
        print("error: --timeout-seconds must be greater than zero", file=sys.stderr)
        return 2

    profile = args.profile.expanduser().resolve()
    ruleset = args.ruleset.expanduser().resolve()
    if not profile.is_dir():
        print(f"error: profile not found: {profile}", file=sys.stderr)
        return 2
    if not ruleset.is_file():
        print(f"error: ruleset not found: {ruleset}", file=sys.stderr)
        return 2

    docker_cmd = shlex.split(args.docker_cmd)
    if not docker_cmd:
        print("error: --docker-cmd must not be empty", file=sys.stderr)
        return 2

    if args.foxclaw_cmd:
        foxclaw_cmd = shlex.split(args.foxclaw_cmd)
    else:
        python_bin = _absolute_path_without_resolving_symlinks(args.python_bin)
        if not python_bin.is_file():
            print(f"error: python binary not found: {python_bin}", file=sys.stderr)
            return 2
        foxclaw_cmd = [str(python_bin), "-m", "foxclaw"]

    ndjson_path = output_dir / "foxclaw.ndjson"
    scan_log = output_dir / "foxclaw-scan.log"
    logtest_path = output_dir / "wazuh-logtest.txt"
    alerts_excerpt_path = output_dir / "alerts-excerpt.jsonl"
    ossec_log_tail_path = output_dir / "ossec-log-tail.txt"
    manifest_path = output_dir / "manifest.json"
    local_rules_path = output_dir / "local_rules.xml"

    local_rules_path.write_text(LOCAL_RULES_XML, encoding="utf-8")
    logtest_path.write_text("not captured\n", encoding="utf-8")
    alerts_excerpt_path.write_text("not captured\n", encoding="utf-8")
    ossec_log_tail_path.write_text("not captured\n", encoding="utf-8")

    container_name = args.container_name or f"foxclaw-wazuh-smoke-{int(time.time())}"
    cleanup_container = not args.keep_container
    container_started = False

    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at_utc": _utc_now(),
        "status": "FAIL",
        "exit_code": 1,
        "error": None,
        "profile": str(profile),
        "ruleset": str(ruleset),
        "wazuh_image": args.wazuh_image,
        "timeout_seconds": args.timeout_seconds,
        "container_name": container_name,
        "container_id": "",
        "artifacts": {
            "ndjson": str(ndjson_path),
            "foxclaw_scan_log": str(scan_log),
            "wazuh_logtest": str(logtest_path),
            "alerts_excerpt": str(alerts_excerpt_path),
            "ossec_log_tail": str(ossec_log_tail_path),
            "local_rules": str(local_rules_path),
        },
    }

    try:
        image_check = _run_result(
            [*docker_cmd, "image", "inspect", args.wazuh_image],
            timeout_seconds=args.timeout_seconds,
            capture_output=True,
        )
        if image_check.returncode != 0:
            raise SmokeError(
                "error: pinned Wazuh image not present locally; "
                f"pre-pull {args.wazuh_image} before production testing.",
                exit_code=2,
            )

        scan_cmd = [
            *foxclaw_cmd,
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--ndjson-out",
            str(ndjson_path),
            "--deterministic",
        ]
        scan_result = _run_result(
            scan_cmd,
            timeout_seconds=args.timeout_seconds,
            capture_output=True,
        )
        scan_log.write_text(scan_result.stdout + scan_result.stderr, encoding="utf-8")
        if scan_result.returncode not in (0, 2):
            raise SmokeError(
                f"error: foxclaw scan failed with exit code {scan_result.returncode}",
                exit_code=scan_result.returncode or 1,
            )
        if not ndjson_path.is_file() or not ndjson_path.read_text(encoding="utf-8").strip():
            raise SmokeError("error: NDJSON output was not created")

        ndjson_stats = _collect_ndjson_stats(ndjson_path)

        run_result = _run(
            [*docker_cmd, "run", "-d", "--name", container_name, args.wazuh_image],
            timeout_seconds=args.timeout_seconds,
            capture_output=True,
            error_message="failed to start Wazuh container",
        )
        manifest["container_id"] = run_result.stdout.strip()
        container_started = True

        _wait_for_wazuh_ready(docker_cmd, container_name, timeout_seconds=args.timeout_seconds)
        _run(
            [*docker_cmd, "exec", container_name, "sh", "-lc", "mkdir -p /var/log/foxclaw"],
            timeout_seconds=args.timeout_seconds,
            error_message="failed to prepare Wazuh log directory",
        )
        _run(
            [*docker_cmd, "cp", str(ndjson_path), f"{container_name}:/var/log/foxclaw/foxclaw.ndjson"],
            timeout_seconds=args.timeout_seconds,
            error_message="failed to copy NDJSON into Wazuh container",
        )
        _inject_localfile_block(docker_cmd, container_name, timeout_seconds=args.timeout_seconds)
        _run(
            [*docker_cmd, "cp", str(local_rules_path), f"{container_name}:/var/ossec/etc/rules/local_rules.xml"],
            timeout_seconds=args.timeout_seconds,
            error_message="failed to install Wazuh local rules",
        )
        _run(
            [*docker_cmd, "exec", container_name, "/var/ossec/bin/wazuh-control", "restart"],
            timeout_seconds=args.timeout_seconds,
            error_message="failed to restart Wazuh manager",
        )
        _run_logtest_until_match(
            docker_cmd,
            container_name,
            logtest_path=logtest_path,
            timeout_seconds=args.timeout_seconds,
        )
        _run(
            [
                *docker_cmd,
                "exec",
                container_name,
                "sh",
                "-lc",
                'tmp=$(mktemp); cp /var/log/foxclaw/foxclaw.ndjson "$tmp"; cat "$tmp" >> /var/log/foxclaw/foxclaw.ndjson; rm -f "$tmp"',
            ],
            timeout_seconds=args.timeout_seconds,
            error_message="failed to trigger Wazuh logcollector tail update",
        )
        _poll_alerts(
            docker_cmd,
            container_name,
            alerts_excerpt_path=alerts_excerpt_path,
            timeout_seconds=args.timeout_seconds,
        )

        manifest["status"] = "PASS"
        manifest["exit_code"] = 0
        manifest["ndjson_event_counts"] = ndjson_stats["event_counts"]
        manifest["top_rule_ids"] = ndjson_stats["top_rule_ids"]
        manifest["generated_at_utc"] = _utc_now()
        _write_manifest(manifest_path, manifest)
        print(f"[wazuh-smoke] complete: {output_dir}")
        return 0
    except SmokeError as exc:
        manifest["error"] = exc.message
        manifest["exit_code"] = exc.exit_code
        print(exc.message, file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # pragma: no cover - defensive boundary
        message = f"error: unexpected Wazuh smoke failure: {exc}"
        manifest["error"] = message
        manifest["exit_code"] = 1
        print(message, file=sys.stderr)
        return 1
    finally:
        if manifest["status"] != "PASS":
            _collect_failure_artifacts(
                docker_cmd,
                container_name,
                container_started=container_started,
                logtest_path=logtest_path,
                alerts_excerpt_path=alerts_excerpt_path,
                ossec_log_tail_path=ossec_log_tail_path,
                timeout_seconds=args.timeout_seconds,
            )
        manifest["generated_at_utc"] = _utc_now()
        _write_manifest(manifest_path, manifest)
        if cleanup_container:
            _cleanup_container(docker_cmd, container_name, timeout_seconds=min(args.timeout_seconds, 20))


def _inject_localfile_block(docker_cmd: list[str], container_name: str, *, timeout_seconds: int) -> None:
    script = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "conf = Path('/var/ossec/etc/ossec.conf')\n"
        "text = conf.read_text(encoding='utf-8')\n"
        "block = '''"
        + LOCALFILE_BLOCK
        + "'''\n"
        "needle = '</ossec_config>'\n"
        "if block not in text:\n"
        "    text = text.replace(needle, block + needle)\n"
        "    conf.write_text(text, encoding='utf-8')\n"
        "PY"
    )
    _run(
        [*docker_cmd, "exec", container_name, "sh", "-lc", script],
        timeout_seconds=timeout_seconds,
        error_message="failed to inject Wazuh localfile configuration",
    )


def _wait_for_wazuh_ready(docker_cmd: list[str], container_name: str, *, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    probe_cmd = [*docker_cmd, "exec", container_name, "test", "-x", "/var/ossec/bin/wazuh-logtest"]
    last_output = ""
    while time.monotonic() < deadline:
        result = _run_result(
            probe_cmd,
            timeout_seconds=_remaining_timeout(deadline),
            capture_output=True,
        )
        if result.returncode == 0:
            return
        last_output = (result.stdout or "") + (result.stderr or "")
        time.sleep(POLL_INTERVAL_SECONDS)
    detail = f": {last_output.strip()}" if last_output.strip() else ""
    raise SmokeError(
        f"error: Wazuh container did not become ready within {timeout_seconds}s{detail}",
        exit_code=124,
    )


def _poll_alerts(
    docker_cmd: list[str],
    container_name: str,
    *,
    alerts_excerpt_path: Path,
    timeout_seconds: int,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    grep_cmd = [
        *docker_cmd,
        "exec",
        container_name,
        "sh",
        "-lc",
        "grep -n '\\\"event_type\\\":\\\"foxclaw.finding\\\"' /var/ossec/logs/alerts/alerts.json | tail -n 3",
    ]
    last_output = ""
    while time.monotonic() < deadline:
        result = _run_result(
            grep_cmd,
            timeout_seconds=_remaining_timeout(deadline),
            capture_output=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 and result.stdout.strip():
            alerts_excerpt_path.write_text(result.stdout, encoding="utf-8")
            return
        last_output = output
        time.sleep(POLL_INTERVAL_SECONDS)
    alerts_excerpt_path.write_text(last_output or "no alerts matched\n", encoding="utf-8")
    raise SmokeError(
        f"error: timed out waiting for FoxClaw alerts in Wazuh alerts.json after {timeout_seconds}s",
        exit_code=124,
    )


def _run_logtest_until_match(
    docker_cmd: list[str],
    container_name: str,
    *,
    logtest_path: Path,
    timeout_seconds: int,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    attempt_path = logtest_path.with_name(logtest_path.name + ".attempt")
    docker_prefix = " ".join(shlex.quote(part) for part in docker_cmd)
    inner_cmd = (
        "line=$(head -n 1 /var/log/foxclaw/foxclaw.ndjson); "
        "tmp=$(mktemp); "
        "printf '%s\\n' \"$line\" > \"$tmp\"; "
        "/var/ossec/bin/wazuh-logtest < \"$tmp\"; "
        "rc=$?; "
        "rm -f \"$tmp\"; "
        "exit \"$rc\""
    )
    logtest_cmd = [
        "/bin/sh",
        "-lc",
        (
            f"{docker_prefix} exec {shlex.quote(container_name)} "
            f"sh -lc {shlex.quote(inner_cmd)} > {shlex.quote(str(attempt_path))} 2>&1"
        ),
    ]
    last_output = ""
    while time.monotonic() < deadline:
        attempt_path.write_text("", encoding="utf-8")
        try:
            result = subprocess.run(
                logtest_cmd,
                check=False,
                stdin=subprocess.DEVNULL,
                timeout=_remaining_timeout(deadline),
            )
        except subprocess.TimeoutExpired:
            last_output = attempt_path.read_text(encoding="utf-8").strip()
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        output = attempt_path.read_text(encoding="utf-8")
        if result.returncode == 0 and f"id: '{LOGTEST_RULE_ID}'" in output:
            logtest_path.write_text(output, encoding="utf-8")
            attempt_path.unlink(missing_ok=True)
            return
        last_output = output
        time.sleep(POLL_INTERVAL_SECONDS)
    logtest_path.write_text(last_output or "no logtest output captured\n", encoding="utf-8")
    attempt_path.unlink(missing_ok=True)
    raise SmokeError(
        f"error: wazuh-logtest did not match FoxClaw finding rule {LOGTEST_RULE_ID} within {timeout_seconds}s",
        exit_code=124,
    )


def _collect_failure_artifacts(
    docker_cmd: list[str],
    container_name: str,
    *,
    container_started: bool,
    logtest_path: Path,
    alerts_excerpt_path: Path,
    ossec_log_tail_path: Path,
    timeout_seconds: int,
) -> None:
    if not container_started:
        ossec_log_tail_path.write_text("container not started\n", encoding="utf-8")
        return

    _capture_optional_output(
        [
            *docker_cmd,
            "exec",
            container_name,
            "sh",
            "-lc",
            f"tail -n {OSSEC_LOG_TAIL_LINES} /var/ossec/logs/ossec.log",
        ],
        output_path=ossec_log_tail_path,
        timeout_seconds=min(timeout_seconds, 15),
        default_text="ossec.log tail unavailable\n",
    )
    if alerts_excerpt_path.read_text(encoding="utf-8").strip() == "not captured":
        _capture_optional_output(
            [
                *docker_cmd,
                "exec",
                container_name,
                "sh",
                "-lc",
                "grep -n '\\\"event_type\\\":\\\"foxclaw.finding\\\"' /var/ossec/logs/alerts/alerts.json | tail -n 3",
            ],
            output_path=alerts_excerpt_path,
            timeout_seconds=min(timeout_seconds, 15),
            default_text="alerts excerpt unavailable\n",
        )
    if not logtest_path.read_text(encoding="utf-8").strip():
        logtest_path.write_text("no logtest output captured\n", encoding="utf-8")


def _capture_optional_output(
    cmd: list[str],
    *,
    output_path: Path,
    timeout_seconds: int,
    default_text: str,
) -> None:
    try:
        result = _run_result(cmd, timeout_seconds=timeout_seconds, capture_output=True)
        payload = (result.stdout or "") + (result.stderr or "")
        output_path.write_text(payload or default_text, encoding="utf-8")
    except SmokeError as exc:
        output_path.write_text(exc.message + "\n", encoding="utf-8")


def _cleanup_container(docker_cmd: list[str], container_name: str, *, timeout_seconds: int) -> None:
    try:
        subprocess.run(
            [*docker_cmd, "rm", "-f", container_name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        pass


def _run(
    cmd: list[str],
    *,
    timeout_seconds: int,
    input_text: str | None = None,
    capture_output: bool = False,
    error_message: str,
) -> subprocess.CompletedProcess[str]:
    result = _run_result(
        cmd,
        timeout_seconds=timeout_seconds,
        input_text=input_text,
        capture_output=capture_output,
    )
    if result.returncode != 0:
        detail = ((result.stdout or "") + (result.stderr or "")).strip()
        if detail:
            raise SmokeError(f"error: {error_message}: {detail}")
        raise SmokeError(f"error: {error_message}")
    return result


def _run_result(
    cmd: list[str],
    *,
    timeout_seconds: int,
    input_text: str | None = None,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            check=False,
            capture_output=capture_output,
            input=input_text,
            stdin=subprocess.DEVNULL if input_text is None else None,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        detail = ((exc.stdout or "") + (exc.stderr or "")).strip()
        suffix = f": {detail}" if detail else ""
        raise SmokeError(f"error: command timed out after {timeout_seconds}s{suffix}", exit_code=124) from exc


def _collect_ndjson_stats(path: Path) -> dict[str, Any]:
    event_counts: Counter[str] = Counter()
    rule_id_counts: Counter[str] = Counter()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        event_type = payload.get("event_type")
        if isinstance(event_type, str) and event_type:
            event_counts[event_type] += 1
        rule_id = payload.get("rule_id")
        if isinstance(rule_id, str) and rule_id:
            rule_id_counts[rule_id] += 1
    return {
        "event_counts": {key: event_counts[key] for key in sorted(event_counts)},
        "top_rule_ids": [
            {"rule_id": rule_id, "count": count}
            for rule_id, count in sorted(rule_id_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
    }


def _remaining_timeout(deadline: float) -> int:
    remaining = max(1, int(deadline - time.monotonic()))
    return remaining


def _absolute_path_without_resolving_symlinks(path: Path) -> Path:
    """Preserve venv interpreter symlinks instead of collapsing to the base interpreter."""
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return Path.cwd() / expanded


def _write_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _utc_now() -> str:
    return datetime.now(tz=UTC).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
