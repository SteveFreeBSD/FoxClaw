#!/usr/bin/env python3
"""Native FoxClaw Wazuh NDJSON smoke runner."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_WAZUH_IMAGE = "wazuh/wazuh-manager:4.14.3"

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
        help="Timeout for container readiness and alert polling.",
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
    manifest_path = output_dir / "manifest.json"
    local_rules_path = output_dir / "local_rules.xml"
    local_rules_path.write_text(LOCAL_RULES_XML, encoding="utf-8")

    container_name = args.container_name or f"foxclaw-wazuh-smoke-{int(time.time())}"
    cleanup_container = not args.keep_container

    try:
        image_check = subprocess.run(
            [*docker_cmd, "image", "inspect", args.wazuh_image],
            check=False,
            capture_output=True,
            text=True,
        )
        if image_check.returncode != 0:
            print(
                "error: pinned Wazuh image not present locally; "
                f"pre-pull {args.wazuh_image} before production testing.",
                file=sys.stderr,
            )
            return 2

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
        scan_result = subprocess.run(scan_cmd, check=False, capture_output=True, text=True)
        scan_log.write_text(scan_result.stdout + scan_result.stderr, encoding="utf-8")
        if scan_result.returncode not in (0, 2):
            print(
                f"error: foxclaw scan failed with exit code {scan_result.returncode}",
                file=sys.stderr,
            )
            return scan_result.returncode or 1
        if not ndjson_path.is_file() or not ndjson_path.read_text(encoding="utf-8").strip():
            print("error: NDJSON output was not created", file=sys.stderr)
            return 1

        run_result = _run(
            [*docker_cmd, "run", "-d", "--name", container_name, args.wazuh_image],
            capture_output=True,
            error_message="failed to start Wazuh container",
        )
        container_id = run_result.stdout.strip()

        _wait_until(
            lambda: subprocess.run(
                [*docker_cmd, "exec", container_name, "test", "-x", "/var/ossec/bin/wazuh-logtest"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0,
            timeout_seconds=args.timeout_seconds,
            error_message="Wazuh container did not become ready in time",
        )

        _run(
            [*docker_cmd, "exec", container_name, "sh", "-lc", "mkdir -p /var/log/foxclaw"],
            error_message="failed to prepare Wazuh log directory",
        )
        _run(
            [*docker_cmd, "cp", str(ndjson_path), f"{container_name}:/var/log/foxclaw/foxclaw.ndjson"],
            error_message="failed to copy NDJSON into Wazuh container",
        )
        _inject_localfile_block(docker_cmd, container_name)
        _run(
            [*docker_cmd, "cp", str(local_rules_path), f"{container_name}:/var/ossec/etc/rules/local_rules.xml"],
            error_message="failed to install Wazuh local rules",
        )
        _run(
            [*docker_cmd, "exec", container_name, "/var/ossec/bin/wazuh-control", "restart"],
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
            error_message="failed to trigger Wazuh logcollector tail update",
        )
        alerts_excerpt = _poll_alerts(docker_cmd, container_name, timeout_seconds=args.timeout_seconds)
        alerts_excerpt_path.write_text(alerts_excerpt, encoding="utf-8")

        manifest = {
            "schema_version": "1.0.0",
            "generated_at_utc": datetime.now(tz=UTC).replace(microsecond=0).isoformat(),
            "profile": str(profile),
            "ruleset": str(ruleset),
            "wazuh_image": args.wazuh_image,
            "container_name": container_name,
            "container_id": container_id,
            "artifacts": {
                "ndjson": str(ndjson_path),
                "foxclaw_scan_log": str(scan_log),
                "wazuh_logtest": str(logtest_path),
                "alerts_excerpt": str(alerts_excerpt_path),
                "local_rules": str(local_rules_path),
            },
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[wazuh-smoke] complete: {output_dir}")
        return 0
    finally:
        if cleanup_container:
            subprocess.run(
                [*docker_cmd, "rm", "-f", container_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


def _inject_localfile_block(docker_cmd: list[str], container_name: str) -> None:
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
        error_message="failed to inject Wazuh localfile configuration",
    )


def _absolute_path_without_resolving_symlinks(path: Path) -> Path:
    """Preserve venv interpreter symlinks instead of collapsing to the base interpreter."""
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return Path.cwd() / expanded


def _poll_alerts(docker_cmd: list[str], container_name: str, *, timeout_seconds: int) -> str:
    deadline = time.time() + timeout_seconds
    grep_cmd = [
        *docker_cmd,
        "exec",
        container_name,
        "sh",
        "-lc",
        "grep -n '\\\"event_type\\\":\\\"foxclaw.finding\\\"' /var/ossec/logs/alerts/alerts.json | tail -n 3",
    ]
    last_output = ""
    while time.time() < deadline:
        result = subprocess.run(grep_cmd, check=False, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        last_output = result.stdout + result.stderr
        time.sleep(1)
    print("error: timed out waiting for FoxClaw alerts in Wazuh alerts.json", file=sys.stderr)
    if last_output.strip():
        print(last_output.strip(), file=sys.stderr)
    raise SystemExit(1)


def _run_logtest_until_match(
    docker_cmd: list[str],
    container_name: str,
    *,
    logtest_path: Path,
    timeout_seconds: int,
) -> str:
    deadline = time.time() + timeout_seconds
    last_output = ""
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
    attempt_path = logtest_path.with_name(logtest_path.name + ".attempt")
    logtest_cmd = [
        "/bin/sh",
        "-lc",
        (
            f"{docker_prefix} exec {shlex.quote(container_name)} "
            f"sh -lc {shlex.quote(inner_cmd)} > {shlex.quote(str(attempt_path))} 2>&1"
        ),
    ]
    while time.time() < deadline:
        attempt_path.write_text("", encoding="utf-8")
        try:
            result = subprocess.run(
                logtest_cmd,
                check=False,
                stdin=subprocess.DEVNULL,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            last_output = attempt_path.read_text(encoding="utf-8").strip()
            time.sleep(1)
            continue
        output = attempt_path.read_text(encoding="utf-8")
        if result.returncode == 0 and "id: '100510'" in output:
            logtest_path.write_text(output, encoding="utf-8")
            attempt_path.unlink(missing_ok=True)
            return output
        last_output = output
        time.sleep(1)
    attempt_path.unlink(missing_ok=True)
    print("error: wazuh-logtest did not match FoxClaw finding rule 100510", file=sys.stderr)
    if last_output.strip():
        print(last_output.strip(), file=sys.stderr)
    raise SystemExit(1)


def _wait_until(predicate: Callable[[], bool], *, timeout_seconds: int, error_message: str) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(1)
    raise SystemExit(f"error: {error_message}")


def _run(
    cmd: list[str],
    *,
    input_text: str | None = None,
    capture_output: bool = False,
    error_message: str,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        cmd,
        check=False,
        capture_output=capture_output,
        input=input_text,
        stdin=subprocess.DEVNULL if input_text is None else None,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stdout or "") + (result.stderr or "")
        detail = detail.strip()
        if detail:
            raise SystemExit(f"error: {error_message}: {detail}")
        raise SystemExit(f"error: {error_message}")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
