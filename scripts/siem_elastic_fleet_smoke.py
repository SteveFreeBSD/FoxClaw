#!/usr/bin/env python3
"""Managed Elastic Fleet ECS smoke runner against a local Fleet lab."""

from __future__ import annotations

import argparse
import base64
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error, request

DEFAULT_PACKAGE_NAME = "filestream"
DEFAULT_PACKAGE_VERSION = "1.2.0"
DEFAULT_AGENT_IMAGE = "docker.elastic.co/beats/elastic-agent:8.17.0"
DEFAULT_ELASTIC_PASSWORD = "changeme"  # pragma: allowlist secret
DEFAULT_ELASTICSEARCH_URL = "http://127.0.0.1:9200"
DEFAULT_KIBANA_URL = "http://127.0.0.1:5601"
DEFAULT_FLEET_SERVER_URL = "http://127.0.0.1:8220"
DEFAULT_FLEET_SERVER_ENROLL_URL = "http://fleet-server:8220"
DEFAULT_DATA_STREAM_DATASET = "foxclaw.scan"
DEFAULT_NAMESPACE = "default"
DEFAULT_FLEET_SERVER_CONTAINER_NAME = "fleet-server"
DEFAULT_FLEET_AGENT_CONTAINER_NAME = "foxclaw-agent"
DEFAULT_EXISTING_POLICY_NAME = "FoxClaw Agent Policy"
DEFAULT_ECS_HOST_PATH = "/var/log/foxclaw/foxclaw.ecs.ndjson"
POLL_INTERVAL_SECONDS = 1.0
LOG_TAIL_LINES = 120
REQUIRED_FIELDS: tuple[str, ...] = (
    "@timestamp",
    "ecs.version",
    "event.kind",
    "host.id",
    "observer.name",
    "foxclaw.event_type",
)
TARGET_AGENT_FIELD = "elastic_agent.id"


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
        help="Directory for ECS NDJSON, Fleet API responses, and failure artifacts.",
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
        "--fleet-server-url",
        default=DEFAULT_FLEET_SERVER_URL,
        help="Host-visible Fleet Server base URL.",
    )
    parser.add_argument(
        "--fleet-server-enroll-url",
        default=DEFAULT_FLEET_SERVER_ENROLL_URL,
        help="Fleet Server URL used by the enrolled Elastic Agent container.",
    )
    parser.add_argument(
        "--fleet-server-container-name",
        default=DEFAULT_FLEET_SERVER_CONTAINER_NAME,
        help="Container name used to auto-detect the Fleet lab Docker network.",
    )
    parser.add_argument(
        "--elastic-password",
        default=DEFAULT_ELASTIC_PASSWORD,
        help="Password assigned to the elastic superuser for the local Fleet lab.",
    )
    parser.add_argument(
        "--package-name",
        default=DEFAULT_PACKAGE_NAME,
        help="Fleet package used for FoxClaw ECS file ingestion.",
    )
    parser.add_argument(
        "--package-version",
        default=DEFAULT_PACKAGE_VERSION,
        help="Package version to install if the package is not already present.",
    )
    parser.add_argument(
        "--data-stream-dataset",
        default=DEFAULT_DATA_STREAM_DATASET,
        help="Dataset written by the Fleet-managed log input.",
    )
    parser.add_argument(
        "--namespace",
        default=DEFAULT_NAMESPACE,
        help="Fleet namespace used for the data stream.",
    )
    parser.add_argument(
        "--network-name",
        default="",
        help="Docker network used by the existing Fleet lab (auto-detected from --fleet-server-container-name when omitted).",
    )
    parser.add_argument(
        "--agent-network-mode",
        choices=("host", "bridge"),
        default="host",
        help="Network mode for the throwaway Elastic Agent container.",
    )
    parser.add_argument(
        "--agent-image",
        default=DEFAULT_AGENT_IMAGE,
        help="Elastic Agent image used for the throwaway Fleet enrollment.",
    )
    parser.add_argument(
        "--agent-container-name",
        default="",
        help="Optional explicit Elastic Agent container name override.",
    )
    parser.add_argument(
        "--policy-name",
        default="",
        help="Optional explicit Fleet agent policy name override.",
    )
    parser.add_argument(
        "--package-policy-name",
        default="",
        help="Optional explicit Fleet package policy name override.",
    )
    parser.add_argument(
        "--agent-mode",
        choices=("existing", "ephemeral"),
        default="existing",
        help="Use the existing enrolled Fleet lab agent or launch a throwaway agent.",
    )
    parser.add_argument(
        "--fleet-agent-container-name",
        default=DEFAULT_FLEET_AGENT_CONTAINER_NAME,
        help="Container name for the existing enrolled Fleet lab agent.",
    )
    parser.add_argument(
        "--agent-policy-name",
        default=DEFAULT_EXISTING_POLICY_NAME,
        help="Fleet agent policy name used when --agent-mode=existing.",
    )
    parser.add_argument(
        "--ecs-host-path",
        type=Path,
        default=Path(DEFAULT_ECS_HOST_PATH),
        help="Host-visible ECS NDJSON path tailed by the existing Fleet lab agent.",
    )
    parser.add_argument(
        "--fingerprint-length",
        type=int,
        default=64,
        help="filestream fingerprint length in bytes; keep small to avoid tiny-file ingest stalls.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=180,
        help="Global timeout budget for Fleet readiness, enrollment, and ingest checks.",
    )
    parser.add_argument(
        "--keep-resources",
        action="store_true",
        help="Keep the throwaway agent container and Fleet policy resources after a successful run.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.timeout_seconds <= 0:
        print("error: --timeout-seconds must be greater than zero", file=sys.stderr)
        return 2
    if args.fingerprint_length <= 0:
        print("error: --fingerprint-length must be greater than zero", file=sys.stderr)
        return 2
    if not args.elastic_password:
        print("error: --elastic-password must not be empty", file=sys.stderr)
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

    ecs_artifact_path = output_dir / "foxclaw.ecs.ndjson"
    scan_log = output_dir / "foxclaw-scan.log"
    package_install_path = output_dir / "fleet-package-install.json"
    agent_policy_path = output_dir / "fleet-agent-policy.json"
    package_policy_path = output_dir / "fleet-package-policy.json"
    enrollment_key_path = output_dir / "fleet-enrollment-key.json"
    agents_path = output_dir / "fleet-agents.json"
    search_path = output_dir / "elasticsearch-search.json"
    fleet_server_status_path = output_dir / "fleet-server-status.json"
    agent_log_tail_path = output_dir / "elastic-agent-log-tail.txt"
    manifest_path = output_dir / "manifest.json"

    for path in (
        package_install_path,
        agent_policy_path,
        package_policy_path,
        enrollment_key_path,
        agents_path,
        search_path,
        fleet_server_status_path,
    ):
        path.write_text("{}\n", encoding="utf-8")
    agent_log_tail_path.write_text("not captured\n", encoding="utf-8")

    expected_index_name = _expected_index_name(
        dataset=args.data_stream_dataset,
        namespace=args.namespace,
    )
    run_id = uuid.uuid4().hex
    run_suffix = run_id[:12]
    agent_container_name = (
        args.fleet_agent_container_name
        if args.agent_mode == "existing"
        else (args.agent_container_name or f"foxclaw-elastic-fleet-smoke-agent-{run_suffix}")
    )
    policy_name = (
        args.agent_policy_name
        if args.agent_mode == "existing"
        else (args.policy_name or f"foxclaw-elastic-fleet-smoke-{run_suffix}")
    )
    package_policy_name = args.package_policy_name or f"foxclaw-elastic-fleet-smoke-{run_suffix}"
    ecs_host_path = (
        _derive_run_specific_host_path(args.ecs_host_path, run_suffix)
        if args.agent_mode == "existing"
        else ecs_artifact_path
    )
    ecs_container_path = (
        _container_path_for_host_file(ecs_host_path)
        if args.agent_mode == "existing"
        else "/logs/foxclaw.ecs.ndjson"
    )
    cleanup_resources = not args.keep_resources
    agent_container_started = False
    created_policy_id = ""
    created_package_policy_id = ""
    active_policy_id = ""
    target_agent_id = ""

    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at_utc": _utc_now(),
        "status": "FAIL",
        "exit_code": 1,
        "error": None,
        "profile": str(profile),
        "ruleset": str(ruleset),
        "agent_mode": args.agent_mode,
        "package_name": args.package_name,
        "package_version": args.package_version,
        "run_id": run_id,
        "namespace": args.namespace,
        "data_stream_dataset": args.data_stream_dataset,
        "expected_index_name": expected_index_name,
        "elasticsearch_url": args.elasticsearch_url,
        "kibana_url": args.kibana_url,
        "fleet_server_url": args.fleet_server_url,
        "fleet_server_enroll_url": args.fleet_server_enroll_url,
        "agent_network_mode": args.agent_network_mode,
        "network_name": "",
        "agent_image": args.agent_image,
        "agent_container_name": agent_container_name,
        "policy_name": policy_name,
        "package_policy_name": package_policy_name,
        "target_agent_id": "",
        "target_agent_field": TARGET_AGENT_FIELD,
        "ecs_host_path": str(ecs_host_path),
        "ecs_container_path": ecs_container_path,
        "fingerprint_length": args.fingerprint_length,
        "timeout_seconds": args.timeout_seconds,
        "required_fields": list(REQUIRED_FIELDS),
        "artifacts": {
            "ecs_ndjson": str(ecs_artifact_path),
            "foxclaw_scan_log": str(scan_log),
            "fleet_package_install": str(package_install_path),
            "fleet_agent_policy": str(agent_policy_path),
            "fleet_package_policy": str(package_policy_path),
            "fleet_enrollment_key": str(enrollment_key_path),
            "fleet_agents": str(agents_path),
            "elasticsearch_search": str(search_path),
            "fleet_server_status": str(fleet_server_status_path),
            "elastic_agent_log_tail": str(agent_log_tail_path),
        },
        "cleanup_errors": [],
    }

    elastic_auth = ("elastic", args.elastic_password)

    try:
        if args.agent_mode == "ephemeral":
            image_check = _run_result(
                [*docker_cmd, "image", "inspect", args.agent_image],
                timeout_seconds=args.timeout_seconds,
                capture_output=True,
            )
            if image_check.returncode != 0:
                raise SmokeError(
                    "error: pinned Elastic Agent image not present locally; "
                    f"pre-pull {args.agent_image} before Fleet production testing.",
                    exit_code=2,
                )
        else:
            _assert_container_running(
                docker_cmd=docker_cmd,
                container_name=agent_container_name,
                timeout_seconds=args.timeout_seconds,
            )
            target_agent_id = _resolve_agent_id_from_container(
                docker_cmd=docker_cmd,
                container_name=agent_container_name,
                timeout_seconds=args.timeout_seconds,
            )
            manifest["target_agent_id"] = target_agent_id
            ecs_host_path.parent.mkdir(parents=True, exist_ok=True)

        _wait_for_elasticsearch_ready(
            base_url=args.elasticsearch_url,
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
        )
        _wait_for_kibana_ready(
            base_url=args.kibana_url,
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
        )
        fleet_server_status = _wait_for_fleet_server_ready(
            base_url=args.fleet_server_url,
            timeout_seconds=args.timeout_seconds,
        )
        fleet_server_status_path.write_text(
            json.dumps(fleet_server_status, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        package_install = _ensure_package_installed(
            kibana_url=args.kibana_url,
            auth=elastic_auth,
            package_name=args.package_name,
            package_version=args.package_version,
            timeout_seconds=args.timeout_seconds,
        )
        package_install_path.write_text(
            json.dumps(package_install, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        package_version = _resolved_package_version(package_install, fallback=args.package_version)
        manifest["package_version"] = package_version

        network_name = ""
        if args.agent_mode == "existing":
            selected_policy = _find_agent_policy_by_name(
                kibana_url=args.kibana_url,
                auth=elastic_auth,
                policy_name=policy_name,
                timeout_seconds=args.timeout_seconds,
            )
            active_policy_id = str(selected_policy["id"])
            agent_policy_path.write_text(
                json.dumps({"item": selected_policy}, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            enrollment_key_path.write_text("{}\n", encoding="utf-8")
        else:
            enroll_url = args.fleet_server_url
            if args.agent_network_mode == "bridge":
                network_name = args.network_name or _detect_container_network(
                    docker_cmd=docker_cmd,
                    container_name=args.fleet_server_container_name,
                    timeout_seconds=args.timeout_seconds,
                )
                enroll_url = args.fleet_server_enroll_url
            manifest["network_name"] = network_name

            created_policy = _create_agent_policy(
                kibana_url=args.kibana_url,
                auth=elastic_auth,
                policy_name=policy_name,
                namespace=args.namespace,
                timeout_seconds=args.timeout_seconds,
            )
            created_policy_id = str(created_policy["item"]["id"])
            active_policy_id = created_policy_id
            agent_policy_path.write_text(
                json.dumps(created_policy, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            enrollment_key = _create_enrollment_key(
                kibana_url=args.kibana_url,
                auth=elastic_auth,
                policy_id=created_policy_id,
                key_name=f"{policy_name}-key",
                timeout_seconds=args.timeout_seconds,
            )
            enrollment_key_path.write_text(
                json.dumps(_redact_enrollment_key_payload(enrollment_key), indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            enrollment_token = str(enrollment_key["item"]["api_key"])

            docker_run_cmd = [
                *docker_cmd,
                "run",
                "-d",
                "--name",
                agent_container_name,
            ]
            if args.agent_network_mode == "host":
                docker_run_cmd.extend(["--network", "host"])
            else:
                docker_run_cmd.extend(["--network", network_name])
            docker_run_cmd.extend(
                [
                    "-v",
                    f"{output_dir}:/logs:ro",
                    "-e",
                    "FLEET_ENROLL=1",
                    "-e",
                    f"FLEET_URL={enroll_url}",
                    "-e",
                    f"FLEET_ENROLLMENT_TOKEN={enrollment_token}",
                    "-e",
                    "FLEET_INSECURE=true",
                    "--user",
                    "root",
                    args.agent_image,
                ]
            )
            _run(
                docker_run_cmd,
                timeout_seconds=args.timeout_seconds,
                capture_output=True,
                error_message="failed to start Elastic Agent Fleet container",
            )
            agent_container_started = True

        created_package_policy = _create_package_policy(
            kibana_url=args.kibana_url,
            auth=elastic_auth,
            package_policy_name=package_policy_name,
            package_name=args.package_name,
            package_version=package_version,
            policy_id=active_policy_id,
            namespace=args.namespace,
            dataset=args.data_stream_dataset,
            paths=[ecs_container_path],
            fingerprint_length=args.fingerprint_length,
            timeout_seconds=args.timeout_seconds,
        )
        created_package_policy_id = str(created_package_policy["item"]["id"])
        package_policy_path.write_text(
            json.dumps(created_package_policy, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        agent_payload = _wait_for_agent_policy_ready(
            kibana_url=args.kibana_url,
            auth=elastic_auth,
            policy_id=active_policy_id,
            package_policy_id=created_package_policy_id,
            target_agent_id=target_agent_id or None,
            timeout_seconds=args.timeout_seconds,
        )
        if not target_agent_id:
            target_agent_id = str(agent_payload["item"]["id"])
            manifest["target_agent_id"] = target_agent_id
        agents_path.write_text(
            json.dumps(agent_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        validation_query = _validation_query(
            dataset=args.data_stream_dataset,
            run_id=run_id,
            target_agent_id=target_agent_id,
        )
        count_before = _count_documents_with_query(
            base_url=args.elasticsearch_url,
            index_name=expected_index_name,
            auth=elastic_auth,
            query=validation_query,
            timeout_seconds=args.timeout_seconds,
        )

        raw_ecs_path = _raw_ecs_path(ecs_host_path)
        scan_cmd = [
            *foxclaw_cmd,
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--ecs-out",
            str(raw_ecs_path),
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
        if not raw_ecs_path.is_file() or not raw_ecs_path.read_text(encoding="utf-8").strip():
            raise SmokeError("error: ECS NDJSON output was not created")
        _annotate_ecs_with_run_id(raw_ecs_path, ecs_host_path, run_id=run_id)
        if ecs_host_path != ecs_artifact_path:
            shutil.copyfile(ecs_host_path, ecs_artifact_path)
        file_size = ecs_host_path.stat().st_size
        if file_size < args.fingerprint_length:
            raise SmokeError(
                "error: ECS NDJSON output is smaller than the configured Fleet fingerprint length; "
                f"size={file_size} fingerprint_length={args.fingerprint_length}"
            )

        ecs_stats = _collect_ecs_stats(ecs_artifact_path)
        manifest["ecs_stats"] = ecs_stats
        expected_new_docs = int(ecs_stats["line_count"])

        count_after = _wait_for_document_count(
            base_url=args.elasticsearch_url,
            index_name=expected_index_name,
            auth=elastic_auth,
            query=validation_query,
            minimum_count=count_before + expected_new_docs,
            timeout_seconds=args.timeout_seconds,
        )

        search_payload = _request_json(
            "POST",
            f"{args.elasticsearch_url.rstrip('/')}/{expected_index_name}/_search",
            auth=elastic_auth,
            timeout_seconds=args.timeout_seconds,
            error_message="failed to search Fleet-managed ECS data stream",
            data={
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": validation_query,
            },
            allow_statuses=(200,),
        )
        search_path.write_text(
            json.dumps(search_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _assert_required_fields(
            search_payload,
            REQUIRED_FIELDS,
            run_id=run_id,
            target_agent_id=target_agent_id,
        )

        manifest["count_before"] = count_before
        manifest["count_after"] = count_after
        manifest["new_documents"] = count_after - count_before
        manifest["required_fields_present"] = sorted(REQUIRED_FIELDS)
        manifest["fleet_agent_id"] = str(agent_payload["item"]["id"])
        manifest["status"] = "PASS"
        manifest["exit_code"] = 0
        manifest["error"] = None
        _capture_log_tail(
            docker_cmd=docker_cmd,
            container_name=agent_container_name,
            output_path=agent_log_tail_path,
            timeout_seconds=args.timeout_seconds,
        )
        _write_manifest(manifest_path, manifest)
        print(f"ok: Elastic Fleet ECS smoke passed: {manifest_path}")
        return 0
    except SmokeError as exc:
        manifest["status"] = "FAIL"
        manifest["exit_code"] = exc.exit_code
        manifest["error"] = exc.message
        _capture_log_tail(
            docker_cmd=docker_cmd,
            container_name=agent_container_name,
            output_path=agent_log_tail_path,
            timeout_seconds=args.timeout_seconds,
        )
        _write_manifest(manifest_path, manifest)
        print(exc.message, file=sys.stderr)
        return exc.exit_code
    finally:
        if cleanup_resources:
            cleanup_errors = manifest["cleanup_errors"]
            if agent_container_started:
                error_message = _cleanup_container(
                    docker_cmd=docker_cmd,
                    name=agent_container_name,
                    timeout_seconds=args.timeout_seconds,
                )
                if error_message:
                    cleanup_errors.append(error_message)
            if args.agent_mode == "existing" and ecs_host_path != ecs_artifact_path:
                error_message = _cleanup_file(ecs_host_path)
                if error_message:
                    cleanup_errors.append(error_message)
            error_message = _cleanup_file(_raw_ecs_path(ecs_host_path))
            if error_message:
                cleanup_errors.append(error_message)
            if created_package_policy_id:
                error_message = _cleanup_package_policy(
                    kibana_url=args.kibana_url,
                    auth=elastic_auth,
                    package_policy_id=created_package_policy_id,
                    timeout_seconds=args.timeout_seconds,
                )
                if error_message:
                    cleanup_errors.append(error_message)
            if created_policy_id:
                error_message = _cleanup_agent_policy(
                    kibana_url=args.kibana_url,
                    auth=elastic_auth,
                    policy_id=created_policy_id,
                    timeout_seconds=args.timeout_seconds,
                )
                if error_message:
                    cleanup_errors.append(error_message)
            if cleanup_errors:
                _write_manifest(manifest_path, manifest)


def _expected_index_name(*, dataset: str, namespace: str) -> str:
    return f"logs-{dataset}-{namespace}"


def _resolved_package_version(payload: dict[str, Any], *, fallback: str) -> str:
    item = payload.get("item")
    if isinstance(item, dict):
        version = item.get("version")
        if isinstance(version, str) and version:
            return version
    items = payload.get("items")
    if isinstance(items, list) and items:
        first = items[0]
        if isinstance(first, dict):
            version = first.get("version")
            if isinstance(version, str) and version:
                return version
    return fallback


def _create_package_policy(
    *,
    kibana_url: str,
    auth: tuple[str, str],
    package_policy_name: str,
    package_name: str,
    package_version: str,
    policy_id: str,
    namespace: str,
    dataset: str,
    paths: list[str],
    fingerprint_length: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    return _request_json(
        "POST",
        f"{kibana_url.rstrip('/')}/api/fleet/package_policies",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to create Fleet package policy",
        headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
        data={
            "name": package_policy_name,
            "namespace": namespace,
            "description": f"Reads FoxClaw ECS NDJSON from {', '.join(paths)}",
            "package": {
                "name": package_name,
                "version": package_version,
            },
            "enabled": True,
            "policy_id": policy_id,
            "inputs": [
                {
                    "type": "filestream",
                    "policy_template": "filestream",
                    "enabled": True,
                    "streams": [
                        {
                            "enabled": True,
                            "data_stream": {
                                "type": "logs",
                                "dataset": "filestream.generic",
                                "elasticsearch": {
                                    "dynamic_dataset": True,
                                    "dynamic_namespace": True,
                                },
                            },
                            "vars": {
                                "paths": {
                                    "value": paths,
                                    "type": "text",
                                },
                                "data_stream.dataset": {
                                    "value": dataset,
                                    "type": "text",
                                },
                                "parsers": {
                                    "value": (
                                        "- ndjson:\n"
                                        '    target: ""\n'
                                        "    overwrite_keys: true\n"
                                        "    add_error_key: true"
                                    ),
                                    "type": "yaml",
                                },
                                "fingerprint": {
                                    "value": True,
                                    "type": "bool",
                                },
                                "fingerprint_length": {
                                    "value": fingerprint_length,
                                    "type": "integer",
                                },
                                "fingerprint_offset": {
                                    "value": 0,
                                    "type": "integer",
                                },
                            },
                        }
                    ],
                }
            ],
        },
        allow_statuses=(200, 201),
    )


def _create_agent_policy(
    *,
    kibana_url: str,
    auth: tuple[str, str],
    policy_name: str,
    namespace: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    return _request_json(
        "POST",
        f"{kibana_url.rstrip('/')}/api/fleet/agent_policies",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to create Fleet agent policy",
        headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
        data={
            "name": policy_name,
            "namespace": namespace,
            "monitoring_enabled": ["logs", "metrics"],
        },
        allow_statuses=(200,),
    )


def _create_enrollment_key(
    *,
    kibana_url: str,
    auth: tuple[str, str],
    policy_id: str,
    key_name: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    return _request_json(
        "POST",
        f"{kibana_url.rstrip('/')}/api/fleet/enrollment_api_keys",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to create Fleet enrollment token",
        headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
        data={
            "name": key_name,
            "policy_id": policy_id,
        },
        allow_statuses=(200, 201),
    )


def _redact_enrollment_key_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redacted = json.loads(json.dumps(payload))
    item = redacted.get("item")
    if isinstance(item, dict) and "api_key" in item:
        item["api_key"] = "<redacted>"
    return redacted


def _ensure_package_installed(
    *,
    kibana_url: str,
    auth: tuple[str, str],
    package_name: str,
    package_version: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    installed = _request_json(
        "GET",
        f"{kibana_url.rstrip('/')}/api/fleet/epm/packages/installed",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to read installed Fleet packages",
        headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
    )
    items = installed.get("items")
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("name") == package_name:
                return {"item": item, "status": "installed"}
    return _request_json(
        "POST",
        f"{kibana_url.rstrip('/')}/api/fleet/epm/packages/{package_name}/{package_version}",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to install Fleet package",
        headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
        data={"force": True},
        allow_statuses=(200, 201),
    )


def _wait_for_agent_policy_ready(
    *,
    kibana_url: str,
    auth: tuple[str, str],
    policy_id: str,
    package_policy_id: str,
    target_agent_id: str | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_status = "missing"
    while time.monotonic() < deadline:
        payload = _request_json(
            "GET",
            f"{kibana_url.rstrip('/')}/api/fleet/agents",
            auth=auth,
            timeout_seconds=max(1, int(deadline - time.monotonic())),
            error_message="failed to read Fleet agents",
                headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
        )
        matching = [
            item
            for item in _fleet_agent_items(payload)
            if isinstance(item, dict)
            and item.get("policy_id") == policy_id
            and (target_agent_id is None or item.get("id") == target_agent_id)
        ]
        if matching:
            current = matching[0]
            status = current.get("status") or current.get("last_checkin_status")
            last_status = status if isinstance(status, str) else "unknown"
            if last_status == "online" and _payload_contains_string(
                current.get("components"), package_policy_id
            ):
                return {"item": current, "list": matching}
        time.sleep(POLL_INTERVAL_SECONDS)
    raise SmokeError(
        "error: Fleet agent did not reach online status with the expected package policy "
        f"within {timeout_seconds}s (last status: {last_status}, package_policy_id={package_policy_id}, "
        f"target_agent_id={target_agent_id or '<auto>'})",
        exit_code=124,
    )


def _fleet_agent_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("list", "items"):
        items = payload.get(key)
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def _payload_contains_string(payload: Any, needle: str) -> bool:
    if isinstance(payload, dict):
        return any(_payload_contains_string(value, needle) for value in payload.values())
    if isinstance(payload, list):
        return any(_payload_contains_string(value, needle) for value in payload)
    return isinstance(payload, str) and needle in payload


def _find_agent_policy_by_name(
    *,
    kibana_url: str,
    auth: tuple[str, str],
    policy_name: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    payload = _request_json(
        "GET",
        f"{kibana_url.rstrip('/')}/api/fleet/agent_policies",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to read Fleet agent policies",
        headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
    )
    items = payload.get("items")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("name") == policy_name:
                return item
    raise SmokeError(f"error: Fleet agent policy not found: {policy_name}", exit_code=2)


def _wait_for_document_count(
    *,
    base_url: str,
    index_name: str,
    auth: tuple[str, str],
    query: dict[str, Any],
    minimum_count: int,
    timeout_seconds: int,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    last_count = 0
    while time.monotonic() < deadline:
        last_count = _count_documents_with_query(
            base_url=base_url,
            index_name=index_name,
            auth=auth,
            query=query,
            timeout_seconds=max(1, int(deadline - time.monotonic())),
        )
        if last_count >= minimum_count:
            return last_count
        time.sleep(POLL_INTERVAL_SECONDS)
    raise SmokeError(
        f"error: Fleet-managed ECS ingest did not reach the expected document count within {timeout_seconds}s "
        f"(count={last_count}, required={minimum_count})",
        exit_code=124,
    )


def _count_documents(
    *,
    base_url: str,
    index_name: str,
    auth: tuple[str, str],
    timeout_seconds: int,
) -> int:
    payload = _request_json(
        "GET",
        f"{base_url.rstrip('/')}/{index_name}/_count",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to count Fleet-managed ECS documents",
        allow_statuses=(200, 404),
    )
    count = payload.get("count")
    if isinstance(count, int):
        return count
    return 0


def _count_documents_with_query(
    *,
    base_url: str,
    index_name: str,
    auth: tuple[str, str],
    query: dict[str, Any],
    timeout_seconds: int,
) -> int:
    payload = _request_json(
        "POST",
        f"{base_url.rstrip('/')}/{index_name}/_count",
        auth=auth,
        timeout_seconds=timeout_seconds,
        error_message="failed to count Fleet-managed ECS documents for the current run",
        data={"query": query},
        allow_statuses=(200, 404),
    )
    count = payload.get("count")
    if isinstance(count, int):
        return count
    return 0


def _assert_required_fields(
    payload: dict[str, Any],
    required_fields: tuple[str, ...],
    *,
    run_id: str,
    target_agent_id: str,
) -> None:
    hits = payload.get("hits")
    if not isinstance(hits, dict):
        raise SmokeError("error: Fleet search response missing hits payload")
    hit_items = hits.get("hits")
    if not isinstance(hit_items, list) or not hit_items:
        raise SmokeError("error: Fleet search did not return any FoxClaw ECS documents")
    source = hit_items[0].get("_source")
    if not isinstance(source, dict):
        raise SmokeError("error: Fleet search hit missing _source")
    if _nested_value(source, "labels.foxclaw_run_id") != run_id:
        raise SmokeError("error: Fleet search hit is not bound to the current run_id")
    if _nested_value(source, TARGET_AGENT_FIELD) != target_agent_id:
        raise SmokeError("error: Fleet search hit is not bound to the target agent id")
    missing = [field for field in required_fields if _nested_value(source, field) in (None, "")]
    if missing:
        raise SmokeError(
            "error: Fleet-managed ECS documents are missing required fields: "
            + ", ".join(sorted(missing))
        )


def _nested_value(payload: dict[str, Any], dotted_key: str) -> Any:
    current: Any = payload
    for part in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


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
) -> None:
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
                headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
            )
        except SmokeError as exc:
            last_error = exc.message
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        status = payload.get("status")
        overall = status.get("overall") if isinstance(status, dict) else None
        level = overall.get("level") if isinstance(overall, dict) else None
        if level in {"available", "green"}:
            return
        last_error = "Kibana status not available yet"
        time.sleep(POLL_INTERVAL_SECONDS)
    raise SmokeError(
        f"error: Kibana did not become ready within {timeout_seconds}s ({last_error})",
        exit_code=124,
    )


def _wait_for_fleet_server_ready(*, base_url: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            payload = _request_json_no_auth(
                "GET",
                f"{base_url.rstrip('/')}/api/status",
                timeout_seconds=max(1, int(deadline - time.monotonic())),
                error_message="failed to reach Fleet Server",
            )
        except SmokeError as exc:
            last_error = exc.message
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        status = payload.get("status")
        if isinstance(status, str) and status.upper() == "HEALTHY":
            return payload
        last_error = "Fleet Server status not healthy yet"
        time.sleep(POLL_INTERVAL_SECONDS)
    raise SmokeError(
        f"error: Fleet Server did not become healthy within {timeout_seconds}s ({last_error})",
        exit_code=124,
    )


def _derive_run_specific_host_path(base_path: Path, run_suffix: str) -> Path:
    parent = _absolute_path_without_resolving_symlinks(base_path.parent)
    stem = base_path.stem
    suffix = "".join(base_path.suffixes)
    return parent / f"{stem}-{run_suffix}{suffix}"


def _raw_ecs_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.raw")


def _container_path_for_host_file(host_path: Path) -> str:
    return f"/logs/{host_path.name}"


def _annotate_ecs_with_run_id(source_path: Path, dest_path: Path, *, run_id: str) -> None:
    rendered_lines: list[str] = []
    for line in source_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        labels = payload.get("labels")
        if not isinstance(labels, dict):
            labels = {}
            payload["labels"] = labels
        labels["foxclaw_run_id"] = run_id
        rendered_lines.append(json.dumps(payload, separators=(",", ":")))
    dest_path.write_text("\n".join(rendered_lines) + "\n", encoding="utf-8")


def _validation_query(*, dataset: str, run_id: str, target_agent_id: str) -> dict[str, Any]:
    # Use elastic_agent.id as the stable managed-agent identity added by Elastic Agent.
    return {
        "bool": {
            "filter": [
                {"term": {"data_stream.dataset": dataset}},
                {"term": {"labels.foxclaw_run_id": run_id}},
                {"term": {TARGET_AGENT_FIELD: target_agent_id}},
                {"term": {"observer.name": "FoxClaw"}},
            ]
        }
    }


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
    return _urlopen_json(
        req=req,
        timeout_seconds=timeout_seconds,
        error_message=error_message,
        allow_statuses=allow_statuses,
    )


def _request_json_no_auth(
    method: str,
    url: str,
    *,
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
    req = request.Request(url, data=payload, headers=request_headers, method=method)
    return _urlopen_json(
        req=req,
        timeout_seconds=timeout_seconds,
        error_message=error_message,
        allow_statuses=allow_statuses,
    )


def _urlopen_json(
    *,
    req: request.Request,
    timeout_seconds: int,
    error_message: str,
    allow_statuses: tuple[int, ...],
) -> dict[str, Any]:
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            if response.status not in allow_statuses:
                raise SmokeError(f"{error_message}: unexpected HTTP {response.status}")
            raw = response.read().decode("utf-8")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code in allow_statuses:
            raw = body
        else:
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


def _resolve_agent_id_from_container(
    *,
    docker_cmd: list[str],
    container_name: str,
    timeout_seconds: int,
) -> str:
    result = _run_result(
        [
            *docker_cmd,
            "exec",
            container_name,
            "sh",
            "-lc",
            (
                "elastic-agent inspect 2>/dev/null | "
                "awk 'BEGIN{in_agent=0} /^agent:/{in_agent=1; next} "
                "in_agent && /^[^[:space:]]/{in_agent=0} "
                "in_agent && /^  id: /{print $2; exit}'"
            ),
        ],
        timeout_seconds=timeout_seconds,
        capture_output=True,
    )
    if result.returncode != 0:
        combined = (result.stdout + result.stderr).strip()
        raise SmokeError(
            f"error: failed to resolve Fleet agent id from container {container_name} "
            f"({combined or result.returncode})",
            exit_code=2,
        )
    agent_id = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    if not re.fullmatch(r"[0-9a-fA-F-]{8,}", agent_id):
        raise SmokeError(
            f"error: failed to parse Fleet agent id from container {container_name}",
            exit_code=2,
        )
    return agent_id


def _assert_container_running(
    *,
    docker_cmd: list[str],
    container_name: str,
    timeout_seconds: int,
) -> None:
    result = _run_result(
        [*docker_cmd, "inspect", container_name, "--format", "{{.State.Status}}"],
        timeout_seconds=timeout_seconds,
        capture_output=True,
    )
    if result.returncode != 0:
        combined = (result.stdout + result.stderr).strip()
        raise SmokeError(
            f"error: existing Fleet agent container not available: {container_name} "
            f"({combined or result.returncode})",
            exit_code=2,
        )
    status = result.stdout.strip()
    if status and status != "running":
        raise SmokeError(
            f"error: existing Fleet agent container is not running: {container_name} ({status})",
            exit_code=2,
        )


def _detect_container_network(
    *,
    docker_cmd: list[str],
    container_name: str,
    timeout_seconds: int,
) -> str:
    result = _run_result(
        [
            *docker_cmd,
            "inspect",
            container_name,
            "--format",
            "{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}",
        ],
        timeout_seconds=timeout_seconds,
        capture_output=True,
    )
    if result.returncode != 0:
        combined = (result.stdout + result.stderr).strip()
        raise SmokeError(
            "error: unable to auto-detect Fleet lab network from container "
            f"{container_name}: {combined or result.returncode}"
        )
    networks = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not networks:
        raise SmokeError(
            f"error: Fleet Server container {container_name} is not attached to any Docker network"
        )
    return sorted(networks)[0]


def _cleanup_container(docker_cmd: list[str], name: str, *, timeout_seconds: int) -> str | None:
    result = _run_result(
        [*docker_cmd, "rm", "-f", name],
        timeout_seconds=timeout_seconds,
        capture_output=True,
    )
    if result.returncode == 0:
        return None
    combined = (result.stdout + result.stderr).strip()
    return f"container cleanup failed for {name}: {combined or result.returncode}"


def _cleanup_file(path: Path) -> str | None:
    try:
        if path.exists():
            path.unlink()
    except OSError as exc:
        return f"file cleanup failed for {path}: {exc.strerror or str(exc)}"
    return None


def _cleanup_package_policy(
    *,
    kibana_url: str,
    auth: tuple[str, str],
    package_policy_id: str,
    timeout_seconds: int,
) -> str | None:
    try:
        _request_json(
            "DELETE",
            f"{kibana_url.rstrip('/')}/api/fleet/package_policies/{package_policy_id}",
            auth=auth,
            timeout_seconds=timeout_seconds,
            error_message="failed to delete Fleet package policy",
            headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
            allow_statuses=(200,),
        )
    except SmokeError as exc:
        return exc.message
    return None


def _cleanup_agent_policy(
    *,
    kibana_url: str,
    auth: tuple[str, str],
    policy_id: str,
    timeout_seconds: int,
) -> str | None:
    try:
        _request_json(
            "POST",
            f"{kibana_url.rstrip('/')}/api/fleet/agent_policies/delete",
            auth=auth,
            timeout_seconds=timeout_seconds,
            error_message="failed to delete Fleet agent policy",
            headers={"kbn-xsrf": "foxclaw-fleet-smoke"},
            data={"agentPolicyId": policy_id},
            allow_statuses=(200,),
        )
    except SmokeError as exc:
        return exc.message
    return None


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
