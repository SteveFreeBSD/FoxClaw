#!/usr/bin/env python3
"""Native FoxClaw ECS smoke runner against a local Elastic Security stack."""

from __future__ import annotations

import argparse
import base64
import json
import shlex
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error, parse, request

DEFAULT_STACK_VERSION = "9.3.1"
DEFAULT_ELASTICSEARCH_IMAGE = (
    f"docker.elastic.co/elasticsearch/elasticsearch:{DEFAULT_STACK_VERSION}"
)
DEFAULT_KIBANA_IMAGE = f"docker.elastic.co/kibana/kibana:{DEFAULT_STACK_VERSION}"
DEFAULT_ELASTIC_PASSWORD = "foxclawelastic1"
DEFAULT_KIBANA_PASSWORD = "foxclawkibana1"
DEFAULT_INDEX_NAME = "logs-foxclaw.scan-default"
DEFAULT_ELASTICSEARCH_URL = "http://127.0.0.1:9200"
DEFAULT_KIBANA_URL = "http://127.0.0.1:5601"
POLL_INTERVAL_SECONDS = 1.0
LOG_TAIL_LINES = 120
REQUIRED_SECURITY_FIELDS: tuple[str, ...] = (
    "@timestamp",
    "ecs.version",
    "event.kind",
    "event.category",
    "event.type",
    "host.name",
    "host.id",
)
KIBANA_ENCRYPTION_KEY = "foxclawkibanasecurityproofkey0001"
KIBANA_REPORTING_KEY = "foxclawkibanareportingproofkey001"
KIBANA_SAVED_OBJECTS_KEY = "foxclawkibanasavedobjectsproof001"


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
        help="Directory for ECS NDJSON, Elastic API responses, and failure artifacts.",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=root / "tests" / "fixtures" / "testbed" / "profile_baseline",
        help="Firefox profile path used to generate ECS NDJSON.",
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
        "--elasticsearch-image",
        default=DEFAULT_ELASTICSEARCH_IMAGE,
        help="Pinned Elasticsearch image expected locally.",
    )
    parser.add_argument(
        "--kibana-image",
        default=DEFAULT_KIBANA_IMAGE,
        help="Pinned Kibana image expected locally.",
    )
    parser.add_argument(
        "--elasticsearch-url",
        default=DEFAULT_ELASTICSEARCH_URL,
        help="Host-visible Elasticsearch base URL.",
    )
    parser.add_argument(
        "--kibana-url",
        default=DEFAULT_KIBANA_URL,
        help="Host-visible Kibana base URL.",
    )
    parser.add_argument(
        "--index-name",
        default=DEFAULT_INDEX_NAME,
        help="Index used for the ECS ingest proof.",
    )
    parser.add_argument(
        "--elastic-password",
        default=DEFAULT_ELASTIC_PASSWORD,
        help="Password assigned to the elastic superuser for the local smoke stack.",
    )
    parser.add_argument(
        "--kibana-password",
        default=DEFAULT_KIBANA_PASSWORD,
        help="Password assigned to kibana_system for the local smoke stack.",
    )
    parser.add_argument(
        "--network-name",
        default="",
        help="Optional Docker network name override.",
    )
    parser.add_argument(
        "--elasticsearch-container-name",
        default="",
        help="Optional Elasticsearch container name override.",
    )
    parser.add_argument(
        "--kibana-container-name",
        default="",
        help="Optional Kibana container name override.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=180,
        help="Global timeout budget for Elastic readiness and API checks.",
    )
    parser.add_argument(
        "--keep-containers",
        action="store_true",
        help="Keep the Elastic containers and network after a successful run for manual inspection.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.timeout_seconds <= 0:
        print("error: --timeout-seconds must be greater than zero", file=sys.stderr)
        return 2
    if not args.elastic_password.isalnum() or len(args.elastic_password) < 8:
        print(
            "error: --elastic-password must be alphanumeric and at least 8 characters",
            file=sys.stderr,
        )
        return 2
    if not args.kibana_password.isalnum() or len(args.kibana_password) < 8:
        print(
            "error: --kibana-password must be alphanumeric and at least 8 characters",
            file=sys.stderr,
        )
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

    ecs_path = output_dir / "foxclaw.ecs.ndjson"
    scan_log = output_dir / "foxclaw-scan.log"
    search_path = output_dir / "elasticsearch-search.json"
    bulk_response_path = output_dir / "elasticsearch-bulk-response.json"
    field_caps_path = output_dir / "field-caps.json"
    kibana_status_path = output_dir / "kibana-status.json"
    detections_index_path = output_dir / "detections-index.json"
    rule_preview_path = output_dir / "rule-preview.json"
    es_log_tail_path = output_dir / "elasticsearch-log-tail.txt"
    kibana_log_tail_path = output_dir / "kibana-log-tail.txt"
    manifest_path = output_dir / "manifest.json"

    search_path.write_text("{}\n", encoding="utf-8")
    bulk_response_path.write_text("{}\n", encoding="utf-8")
    field_caps_path.write_text("{}\n", encoding="utf-8")
    kibana_status_path.write_text("{}\n", encoding="utf-8")
    detections_index_path.write_text("{}\n", encoding="utf-8")
    rule_preview_path.write_text("{}\n", encoding="utf-8")
    es_log_tail_path.write_text("not captured\n", encoding="utf-8")
    kibana_log_tail_path.write_text("not captured\n", encoding="utf-8")

    suffix = str(int(time.time()))
    network_name = args.network_name or f"foxclaw-elastic-smoke-{suffix}"
    es_container_name = args.elasticsearch_container_name or f"{network_name}-es"
    kibana_container_name = args.kibana_container_name or f"{network_name}-kibana"
    cleanup_resources = not args.keep_containers
    network_created = False
    es_started = False
    kibana_started = False

    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at_utc": _utc_now(),
        "status": "FAIL",
        "exit_code": 1,
        "error": None,
        "profile": str(profile),
        "ruleset": str(ruleset),
        "elasticsearch_image": args.elasticsearch_image,
        "kibana_image": args.kibana_image,
        "elasticsearch_url": args.elasticsearch_url,
        "kibana_url": args.kibana_url,
        "index_name": args.index_name,
        "timeout_seconds": args.timeout_seconds,
        "network_name": network_name,
        "elasticsearch_container_name": es_container_name,
        "kibana_container_name": kibana_container_name,
        "required_security_fields": list(REQUIRED_SECURITY_FIELDS),
        "artifacts": {
            "ecs_ndjson": str(ecs_path),
            "elasticsearch_bulk_response": str(bulk_response_path),
            "foxclaw_scan_log": str(scan_log),
            "elasticsearch_search": str(search_path),
            "field_caps": str(field_caps_path),
            "kibana_status": str(kibana_status_path),
            "detections_index": str(detections_index_path),
            "rule_preview": str(rule_preview_path),
            "elasticsearch_log_tail": str(es_log_tail_path),
            "kibana_log_tail": str(kibana_log_tail_path),
        },
    }

    elastic_auth = ("elastic", args.elastic_password)

    try:
        for image in (args.elasticsearch_image, args.kibana_image):
            image_check = _run_result(
                [*docker_cmd, "image", "inspect", image],
                timeout_seconds=args.timeout_seconds,
                capture_output=True,
            )
            if image_check.returncode != 0:
                raise SmokeError(
                    "error: pinned Elastic image not present locally; "
                    f"pre-pull {image} before production testing.",
                    exit_code=2,
                )

        scan_cmd = [
            *foxclaw_cmd,
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--ecs-out",
            str(ecs_path),
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
        if not ecs_path.is_file() or not ecs_path.read_text(encoding="utf-8").strip():
            raise SmokeError("error: ECS NDJSON output was not created")

        ecs_stats = _collect_ecs_stats(ecs_path)
        manifest["ecs_stats"] = ecs_stats

        _run(
            [*docker_cmd, "network", "create", network_name],
            timeout_seconds=args.timeout_seconds,
            capture_output=True,
            error_message="failed to create Elastic smoke network",
        )
        network_created = True

        _run(
            [
                *docker_cmd,
                "run",
                "-d",
                "--name",
                es_container_name,
                "--network",
                network_name,
                "-p",
                "127.0.0.1:9200:9200",
                "-m",
                "1GB",
                "-e",
                "discovery.type=single-node",
                "-e",
                f"ELASTIC_PASSWORD={args.elastic_password}",
                "-e",
                "xpack.security.enabled=true",
                "-e",
                "xpack.security.http.ssl.enabled=false",
                "-e",
                "xpack.license.self_generated.type=trial",
                args.elasticsearch_image,
            ],
            timeout_seconds=args.timeout_seconds,
            capture_output=True,
            error_message="failed to start Elasticsearch container",
        )
        es_started = True
        _wait_for_elasticsearch_ready(
            base_url=args.elasticsearch_url,
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
        )
        _set_kibana_system_password(
            base_url=args.elasticsearch_url,
            auth=elastic_auth,
            kibana_password=args.kibana_password,
            timeout_seconds=args.timeout_seconds,
        )

        _run(
            [
                *docker_cmd,
                "run",
                "-d",
                "--name",
                kibana_container_name,
                "--network",
                network_name,
                "-p",
                "127.0.0.1:5601:5601",
                "-e",
                f"ELASTICSEARCH_HOSTS=http://{es_container_name}:9200",
                "-e",
                "ELASTICSEARCH_USERNAME=kibana_system",
                "-e",
                f"ELASTICSEARCH_PASSWORD={args.kibana_password}",
                "-e",
                f"XPACK_SECURITY_ENCRYPTIONKEY={KIBANA_ENCRYPTION_KEY}",
                "-e",
                f"XPACK_REPORTING_ENCRYPTIONKEY={KIBANA_REPORTING_KEY}",
                "-e",
                f"XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY={KIBANA_SAVED_OBJECTS_KEY}",
                args.kibana_image,
            ],
            timeout_seconds=args.timeout_seconds,
            capture_output=True,
            error_message="failed to start Kibana container",
        )
        kibana_started = True

        kibana_status = _wait_for_kibana_ready(
            base_url=args.kibana_url,
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
        )
        kibana_status_path.write_text(
            json.dumps(kibana_status, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        bulk_response = _bulk_ingest_ecs(
            base_url=args.elasticsearch_url,
            index_name=args.index_name,
            ecs_path=ecs_path,
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
        )
        bulk_response_path.write_text(
            json.dumps(bulk_response, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        search_payload = _request_json(
            "GET",
            f"{args.elasticsearch_url.rstrip('/')}/{args.index_name}/_search?size=20&sort=%40timestamp:asc",
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
            error_message="failed to search Elastic ECS proof index",
        )
        search_path.write_text(
            json.dumps(search_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        total_hits = _extract_total_hits(search_payload)
        if total_hits < 1:
            raise SmokeError("error: Elastic search did not return any ECS hits")

        field_caps_payload = _request_json(
            "GET",
            _field_caps_url(args.elasticsearch_url, args.index_name, REQUIRED_SECURITY_FIELDS),
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
            error_message="failed to read Elastic field capabilities",
        )
        field_caps_path.write_text(
            json.dumps(field_caps_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        missing_fields = _missing_required_fields(field_caps_payload, REQUIRED_SECURITY_FIELDS)
        if missing_fields:
            raise SmokeError(
                "error: Elastic field caps missing required Security fields: "
                + ", ".join(sorted(missing_fields))
            )

        detections_index_payload = _request_json(
            "POST",
            f"{args.kibana_url.rstrip('/')}/api/detection_engine/index",
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
            error_message="failed to initialize Elastic detections index",
            headers={"kbn-xsrf": "foxclaw-smoke"},
            allow_statuses=(200, 201),
        )
        detections_index_path.write_text(
            json.dumps(detections_index_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        rule_preview_payload = _request_json(
            "POST",
            f"{args.kibana_url.rstrip('/')}/api/detection_engine/rules/preview",
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
            error_message="failed to preview Elastic detection rule",
            headers={"kbn-xsrf": "foxclaw-smoke"},
            data=_build_rule_preview_payload(index_name=args.index_name),
        )
        rule_preview_path.write_text(
            json.dumps(rule_preview_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        preview_errors = _preview_errors(rule_preview_payload)
        if preview_errors:
            raise SmokeError(
                "error: Elastic detection rule preview reported errors: "
                + "; ".join(preview_errors)
            )

        manifest["search_hits"] = total_hits
        manifest["required_fields_present"] = sorted(REQUIRED_SECURITY_FIELDS)
        manifest["rule_preview_log_entries"] = len(rule_preview_payload.get("logs", []))
        manifest["kibana_status"] = _kibana_overall_level(kibana_status)
        manifest["status"] = "PASS"
        manifest["exit_code"] = 0
        manifest["error"] = None
        _write_manifest(manifest_path, manifest)
        print(f"ok: Elastic Security ECS smoke passed: {manifest_path}")
        return 0
    except SmokeError as exc:
        manifest["status"] = "FAIL"
        manifest["exit_code"] = exc.exit_code
        manifest["error"] = exc.message
        _capture_log_tail(
            docker_cmd=docker_cmd,
            container_name=es_container_name,
            output_path=es_log_tail_path,
            timeout_seconds=args.timeout_seconds,
        )
        _capture_log_tail(
            docker_cmd=docker_cmd,
            container_name=kibana_container_name,
            output_path=kibana_log_tail_path,
            timeout_seconds=args.timeout_seconds,
        )
        _write_manifest(manifest_path, manifest)
        print(exc.message, file=sys.stderr)
        return exc.exit_code
    finally:
        if cleanup_resources:
            if kibana_started:
                _cleanup_container(docker_cmd, kibana_container_name, timeout_seconds=args.timeout_seconds)
            if es_started:
                _cleanup_container(docker_cmd, es_container_name, timeout_seconds=args.timeout_seconds)
            if network_created:
                _cleanup_network(docker_cmd, network_name, timeout_seconds=args.timeout_seconds)


def _build_rule_preview_payload(*, index_name: str) -> dict[str, object]:
    return {
        "author": ["FoxClaw"],
        "description": "Matches FoxClaw finding events emitted via native ECS output.",
        "enabled": False,
        "false_positives": [],
        "filters": [],
        "from": "now-1h",
        "index": [index_name],
        "interval": "1m",
        "invocationCount": 1,
        "language": "kuery",
        "max_signals": 100,
        "name": "FoxClaw ECS smoke preview",
        "query": 'event.action:"foxclaw.finding" and event.kind:"alert" and host.id:*',
        "references": [],
        "risk_score": 21,
        "rule_id": "foxclaw-ecs-smoke-preview",
        "severity": "low",
        "tags": ["foxclaw", "ecs", "smoke"],
        "threat": [],
        "timeframeEnd": _utc_now(),
        "to": "now",
        "type": "query",
        "version": 1,
    }


def _field_caps_url(base_url: str, index_name: str, fields: tuple[str, ...]) -> str:
    query = parse.urlencode({"fields": ",".join(fields)})
    return f"{base_url.rstrip('/')}/{index_name}/_field_caps?{query}"


def _kibana_overall_level(payload: dict[str, Any]) -> str:
    status = payload.get("status")
    if not isinstance(status, dict):
        return ""
    overall = status.get("overall")
    if not isinstance(overall, dict):
        return ""
    level = overall.get("level")
    return level if isinstance(level, str) else ""


def _preview_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    logs = payload.get("logs")
    if not isinstance(logs, list):
        return ["preview response missing logs"]
    for item in logs:
        if not isinstance(item, dict):
            continue
        for value in item.get("errors", []):
            if isinstance(value, str) and value:
                errors.append(value)
    return errors


def _missing_required_fields(
    payload: dict[str, Any], required_fields: tuple[str, ...]
) -> list[str]:
    fields = payload.get("fields")
    if not isinstance(fields, dict):
        return list(required_fields)
    missing: list[str] = []
    for field in required_fields:
        field_payload = fields.get(field)
        if not isinstance(field_payload, dict) or not field_payload:
            missing.append(field)
    return missing


def _extract_total_hits(payload: dict[str, Any]) -> int:
    hits = payload.get("hits")
    if not isinstance(hits, dict):
        return 0
    total = hits.get("total")
    if isinstance(total, dict):
        value = total.get("value")
        return value if isinstance(value, int) else 0
    if isinstance(total, int):
        return total
    return 0


def _collect_ecs_stats(path: Path) -> dict[str, object]:
    actions: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        payload = json.loads(line)
        event = payload.get("event", {})
        if isinstance(event, dict):
            action = event.get("action")
            kind = event.get("kind")
            if isinstance(action, str):
                actions[action] += 1
            if isinstance(kind, str):
                kinds[kind] += 1
    return {
        "line_count": len(lines),
        "event_actions": [
            {"action": action, "count": count}
            for action, count in sorted(actions.items(), key=lambda item: item[0])
        ],
        "event_kinds": [
            {"kind": kind, "count": count}
            for kind, count in sorted(kinds.items(), key=lambda item: item[0])
        ],
    }


def _bulk_ingest_ecs(
    *,
    base_url: str,
    index_name: str,
    ecs_path: Path,
    auth: tuple[str, str],
    timeout_seconds: int,
) -> dict[str, Any]:
    lines = [line for line in ecs_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        raise SmokeError("error: ECS NDJSON output was empty")
    payload_lines: list[str] = []
    for line in lines:
        payload_lines.append(json.dumps({"create": {"_index": index_name}}, separators=(",", ":")))
        payload_lines.append(line)
    body = ("\n".join(payload_lines) + "\n").encode("utf-8")
    bulk_response = _request_json(
        "POST",
        f"{base_url.rstrip('/')}/_bulk?refresh=true",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to bulk-ingest ECS NDJSON into Elasticsearch",
        data=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    if bool(bulk_response.get("errors")):
        raise SmokeError(
            "error: Elasticsearch bulk ingest reported errors: "
            + "; ".join(_bulk_error_messages(bulk_response))
        )
    return bulk_response


def _bulk_error_messages(payload: dict[str, Any]) -> list[str]:
    items = payload.get("items")
    if not isinstance(items, list):
        return ["unknown bulk error"]
    messages: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        index_payload = item.get("index")
        if not isinstance(index_payload, dict):
            continue
        error_payload = index_payload.get("error")
        if not isinstance(error_payload, dict):
            continue
        reason = error_payload.get("reason")
        if isinstance(reason, str) and reason:
            messages.append(reason)
        caused_by = error_payload.get("caused_by")
        if isinstance(caused_by, dict):
            caused_by_reason = caused_by.get("reason")
            if isinstance(caused_by_reason, str) and caused_by_reason:
                messages.append(caused_by_reason)
        if len(messages) >= 3:
            break
    return messages or ["unknown bulk error"]


def _set_kibana_system_password(
    *,
    base_url: str,
    auth: tuple[str, str],
    kibana_password: str,
    timeout_seconds: int,
) -> None:
    _request_json(
        "POST",
        f"{base_url.rstrip('/')}/_security/user/kibana_system/_password",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to configure kibana_system password",
        data={"password": kibana_password},
        allow_statuses=(200,),
    )


def _wait_for_elasticsearch_ready(
    *, base_url: str, auth: tuple[str, str], timeout_seconds: int
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            payload = _request_json(
                "GET",
                base_url,
                auth=auth,
                timeout_seconds=max(1, int(deadline - time.monotonic())),
                error_message="failed to reach Elasticsearch",
            )
        except SmokeError as exc:
            last_error = exc.message
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        if isinstance(payload, dict) and isinstance(payload.get("version"), dict):
            return
        last_error = "unexpected Elasticsearch readiness payload"
        time.sleep(POLL_INTERVAL_SECONDS)
    raise SmokeError(
        f"error: Elasticsearch did not become ready within {timeout_seconds}s ({last_error})",
        exit_code=124,
    )


def _wait_for_kibana_ready(
    *, base_url: str, auth: tuple[str, str], timeout_seconds: int
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            payload = _request_json(
                "GET",
                f"{base_url.rstrip('/')}/api/status",
                auth=auth,
                timeout_seconds=max(1, int(deadline - time.monotonic())),
                error_message="failed to reach Kibana",
            )
        except SmokeError as exc:
            last_error = exc.message
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        if _kibana_overall_level(payload) in {"available", "green"}:
            return payload
        last_error = "Kibana status not available yet"
        time.sleep(POLL_INTERVAL_SECONDS)
    raise SmokeError(
        f"error: Kibana did not become ready within {timeout_seconds}s ({last_error})",
        exit_code=124,
    )


def _request_json(
    method: str,
    url: str,
    *,
    auth: tuple[str, str],
    timeout_seconds: int,
    error_message: str,
    headers: dict[str, str] | None = None,
    data: dict[str, object] | bytes | None = None,
    allow_statuses: tuple[int, ...] = (200,),
) -> dict[str, Any]:
    payload: bytes | None
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    if isinstance(data, dict):
        payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    else:
        payload = data

    auth_token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode("ascii")
    request_headers["Authorization"] = f"Basic {auth_token}"
    req = request.Request(url, data=payload, headers=request_headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            if response.status not in allow_statuses:
                raise SmokeError(f"{error_message}: unexpected HTTP {response.status}")
            raw = response.read().decode("utf-8")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SmokeError(
            f"{error_message}: HTTP {exc.code} {body[:240]}".strip(),
            exit_code=1 if exc.code < 500 else 124,
        ) from exc
    except error.URLError as exc:
        raise SmokeError(f"{error_message}: {exc.reason}") from exc
    except OSError as exc:
        raise SmokeError(f"{error_message}: {exc.strerror or str(exc)}") from exc

    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SmokeError(f"{error_message}: invalid JSON response") from exc
    if not isinstance(parsed, dict):
        raise SmokeError(f"{error_message}: expected JSON object response")
    return parsed


def _capture_log_tail(
    *,
    docker_cmd: list[str],
    container_name: str,
    output_path: Path,
    timeout_seconds: int,
) -> None:
    if not container_name:
        return
    result = _run_result(
        [*docker_cmd, "logs", "--tail", str(LOG_TAIL_LINES), container_name],
        timeout_seconds=timeout_seconds,
        capture_output=True,
    )
    combined = (result.stdout + result.stderr).strip()
    if combined:
        output_path.write_text(combined + "\n", encoding="utf-8")


def _cleanup_container(docker_cmd: list[str], name: str, *, timeout_seconds: int) -> None:
    _run_result(
        [*docker_cmd, "rm", "-f", name],
        timeout_seconds=timeout_seconds,
        capture_output=True,
    )


def _cleanup_network(docker_cmd: list[str], name: str, *, timeout_seconds: int) -> None:
    _run_result(
        [*docker_cmd, "network", "rm", name],
        timeout_seconds=timeout_seconds,
        capture_output=True,
    )


def _write_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _absolute_path_without_resolving_symlinks(path: Path) -> Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else Path.cwd() / expanded


def _run(
    command: list[str],
    *,
    timeout_seconds: int,
    capture_output: bool,
    error_message: str,
) -> subprocess.CompletedProcess[str]:
    result = _run_result(
        command,
        timeout_seconds=timeout_seconds,
        capture_output=capture_output,
    )
    if result.returncode != 0:
        combined = (result.stdout + result.stderr).strip()
        detail = f": {combined}" if combined else ""
        raise SmokeError(f"{error_message}{detail}", exit_code=result.returncode or 1)
    return result


def _run_result(
    command: list[str], *, timeout_seconds: int, capture_output: bool
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=capture_output,
        text=True,
        timeout=timeout_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main())
