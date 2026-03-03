from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


def _write_fake_foxclaw(path: Path, *, exit_code: int = 0) -> None:
    script = f"""#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import sys

args = sys.argv[1:]
ecs_out = None
for idx, arg in enumerate(args):
    if arg == "--ecs-out" and idx + 1 < len(args):
        ecs_out = pathlib.Path(args[idx + 1])

if ecs_out is None:
    raise SystemExit(9)

ecs_out.parent.mkdir(parents=True, exist_ok=True)
lines = [
    {{
        "@timestamp":"2025-01-01T00:00:00Z",
        "data_stream":{{"dataset":"foxclaw.scan","namespace":"default","type":"logs"}},
        "ecs":{{"version":"9.2.0"}},
        "event":{{"action":"foxclaw.finding","category":["configuration","host"],"code":"TB-POL-001","dataset":"foxclaw.scan","id":"finding-id","kind":"alert","module":"foxclaw","provider":"foxclaw","type":["info"]}},
        "host":{{"id":"host-01","name":"host-01"}},
        "message":"finding",
        "observer":{{"name":"FoxClaw","vendor":"FoxClaw"}},
        "foxclaw":{{"event_type":"foxclaw.finding","schema_version":"1.0.0"}}
    }},
    {{
        "@timestamp":"2025-01-01T00:00:00Z",
        "data_stream":{{"dataset":"foxclaw.scan","namespace":"default","type":"logs"}},
        "ecs":{{"version":"9.2.0"}},
        "event":{{"action":"foxclaw.scan.summary","category":["host"],"code":"FOXCLAW_SCAN_SUMMARY","dataset":"foxclaw.scan","id":"summary-id","kind":"event","module":"foxclaw","provider":"foxclaw","type":["info"]}},
        "host":{{"id":"host-01","name":"host-01"}},
        "message":"summary",
        "observer":{{"name":"FoxClaw","vendor":"FoxClaw"}},
        "foxclaw":{{"event_type":"foxclaw.scan.summary","schema_version":"1.0.0","summary":{{"findings_total":1}}}}
    }}
]
ecs_out.write_text("\\n".join(json.dumps(item, separators=(',', ':')) for item in lines) + "\\n", encoding="utf-8")
raise SystemExit({exit_code})
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _write_fake_docker(path: Path, *, image_present: bool = True) -> None:
    script = f"""#!/usr/bin/env python3
from __future__ import annotations
import pathlib
import sys

state_dir = pathlib.Path(sys.argv[0]).with_suffix(".state")
state_dir.mkdir(parents=True, exist_ok=True)
log_path = state_dir / "docker-commands.log"
with log_path.open("a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")

args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    raise SystemExit(0 if {image_present!r} else 1)
if args[:1] == ["exec"]:
    print("d792bbea-a2b9-4324-aefa-4c3ab6b117e5")
    raise SystemExit(0)
if args[:1] == ["inspect"]:
    fmt = ""
    if "--format" in args:
        fmt = args[args.index("--format") + 1]
    if fmt == "{{{{.State.Status}}}}":
        print("running")
    else:
        print("elastic")
    raise SystemExit(0)
if args[:1] == ["run"]:
    print("fake-agent-container")
    raise SystemExit(0)
if args[:2] == ["logs", "--tail"]:
    print("fake fleet agent log tail")
    raise SystemExit(0)
if args[:1] == ["rm"]:
    raise SystemExit(0)
raise SystemExit(0)
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


@dataclass
class _FakeFleetState:
    log_source_dir: Path
    installed_package: bool = True
    agent_online_after: int = 1
    agent_requests: int = 0
    policy_id: str = "policy-1"
    policy_name: str = "FoxClaw Agent Policy"
    package_policy_id: str = "package-policy-1"
    target_agent_id: str = "d792bbea-a2b9-4324-aefa-4c3ab6b117e5"
    secondary_agent_id: str | None = None
    secondary_agent_status: str = "error"
    package_install_calls: int = 0
    package_policy_payloads: list[dict[str, object]] = field(default_factory=list)
    persisted_docs: list[dict[str, object]] = field(default_factory=list)
    ingested_paths: set[str] = field(default_factory=set)
    last_search_query: dict[str, object] | None = None
    last_count_query: dict[str, object] | None = None

    def ecs_path(self) -> Path:
        if self.package_policy_payloads:
            stream = self.package_policy_payloads[-1]["inputs"][0]["streams"][0]
            ecs_container_path = str(stream["vars"]["paths"]["value"][0])
            return self.log_source_dir / Path(ecs_container_path).name
        return self.log_source_dir / "foxclaw.ecs.ndjson"

    def _maybe_ingest_current_file(self) -> None:
        ecs_path = self.ecs_path()
        if not ecs_path.is_file():
            return
        key = str(ecs_path)
        if key in self.ingested_paths:
            return
        for line in ecs_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            payload.setdefault("elastic_agent", {})["id"] = self.target_agent_id
            payload.setdefault("agent", {})["id"] = self.target_agent_id
            self.persisted_docs.append(payload)
        self.ingested_paths.add(key)

    def filtered_docs(self, query: dict[str, object] | None) -> list[dict[str, object]]:
        self._maybe_ingest_current_file()
        docs = [copy.deepcopy(doc) for doc in self.persisted_docs]
        if not query:
            return docs
        return [doc for doc in docs if _matches_query(doc, query)]


class _FleetHandler(BaseHTTPRequestHandler):
    state: _FakeFleetState
    mode: str

    def log_message(self, _format: str, *_args) -> None:
        return

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _require_auth(self) -> None:
        header = self.headers.get("Authorization", "")
        assert header.startswith("Basic ")
        decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        assert decoded == "elastic:changeme"

    def _ecs_docs(self) -> list[dict[str, object]]:
        return self.state.filtered_docs(None)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if self.mode == "fleet":
            if parsed.path == "/api/status":
                self._send_json(200, {"name": "fleet-server", "status": "HEALTHY"})
                return
        self._require_auth()
        if self.mode == "es":
            if parsed.path == "/":
                self._send_json(200, {"version": {"number": "8.17.0"}})
                return
            if parsed.path.endswith("/_count"):
                self._send_json(200, {"count": len(self.state.filtered_docs(None))})
                return
        if self.mode == "kibana":
            if parsed.path == "/api/status":
                self._send_json(200, {"status": {"overall": {"level": "available"}}})
                return
            if parsed.path == "/api/fleet/epm/packages/installed":
                items: list[dict[str, object]] = []
                if self.state.installed_package:
                    items.append(
                        {
                            "name": "filestream",
                            "version": "1.2.0",
                            "status": "installed",
                        }
                    )
                self._send_json(200, {"items": items})
                return
            if parsed.path == "/api/fleet/agent_policies":
                self._send_json(
                    200,
                    {
                        "items": [
                            {
                                "id": self.state.policy_id,
                                "name": self.state.policy_name,
                                "namespace": "default",
                                "status": "active",
                            }
                        ]
                    },
                )
                return
            if parsed.path == "/api/fleet/agents":
                self.state.agent_requests += 1
                items: list[dict[str, object]] = []
                if self.state.agent_requests >= self.state.agent_online_after:
                    items.append(
                        {
                            "id": self.state.target_agent_id,
                            "policy_id": self.state.policy_id,
                            "status": "online",
                            "last_checkin_status": "online",
                            "components": [
                                {
                                    "id": "filestream-default",
                                    "units": [
                                        {
                                            "id": f"filestream-default-{self.state.package_policy_id}",
                                            "status": "HEALTHY",
                                        }
                                    ],
                                }
                            ]
                            if self.state.package_policy_payloads
                            else [],
                        }
                    )
                    if self.state.secondary_agent_id is not None:
                        items.append(
                            {
                                "id": self.state.secondary_agent_id,
                                "policy_id": self.state.policy_id,
                                "status": self.state.secondary_agent_status,
                                "last_checkin_status": self.state.secondary_agent_status,
                                "components": [],
                            }
                        )
                self._send_json(200, {"items": items, "list": items})
                return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b""
        if self.mode == "es":
            self._require_auth()
            if parsed.path.endswith("/_count"):
                payload = json.loads(body or b"{}")
                query = payload.get("query") if isinstance(payload, dict) else None
                self.state.last_count_query = query if isinstance(query, dict) else None
                self._send_json(200, {"count": len(self.state.filtered_docs(self.state.last_count_query))})
                return
            if parsed.path.endswith("/_search"):
                payload = json.loads(body or b"{}")
                query = payload.get("query") if isinstance(payload, dict) else None
                self.state.last_search_query = query if isinstance(query, dict) else None
                docs = self.state.filtered_docs(self.state.last_search_query)
                hits = [{"_source": item} for item in reversed(docs)]
                self._send_json(
                    200,
                    {"hits": {"total": {"value": len(hits)}, "hits": hits}},
                )
                return
        if self.mode == "kibana":
            self._require_auth()
            if parsed.path == "/api/fleet/epm/packages/filestream/1.2.0":
                self.state.installed_package = True
                self.state.package_install_calls += 1
                self._send_json(
                    200,
                    {"items": [{"id": "logs-filestream.generic-1.2.0", "type": "ingest_pipeline"}]},
                )
                return
            if parsed.path == "/api/fleet/agent_policies":
                payload = json.loads(body or b"{}")
                assert payload["namespace"] == "default"
                self._send_json(
                    200,
                    {"item": {"id": self.state.policy_id, "name": payload["name"]}},
                )
                return
            if parsed.path == "/api/fleet/package_policies":
                payload = json.loads(body or b"{}")
                self.state.package_policy_payloads.append(payload)
                stream = payload["inputs"][0]["streams"][0]
                assert payload["package"]["name"] == "filestream"
                assert stream["vars"]["data_stream.dataset"]["value"] == "foxclaw.scan"
                assert stream["vars"]["fingerprint_length"]["value"] == 64
                assert len(stream["vars"]["paths"]["value"]) == 1
                assert str(stream["vars"]["paths"]["value"][0]).startswith("/logs/")
                self._send_json(
                    200,
                    {
                        "item": {
                            "id": self.state.package_policy_id,
                            "package": {"name": "filestream", "version": "1.2.0"},
                        }
                    },
                )
                return
            if parsed.path == "/api/fleet/enrollment_api_keys":
                self._send_json(
                    200,
                    {"item": {"id": "enrollment-key-1", "api_key": "fleet-token"}},  # pragma: allowlist secret
                )
                return
            if parsed.path == "/api/fleet/agent_policies/delete":
                self._send_json(200, {"id": self.state.policy_id})
                return
        self._send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        self._require_auth()
        parsed = urlparse(self.path)
        if self.mode == "kibana" and parsed.path.startswith("/api/fleet/package_policies/"):
            self._send_json(200, {"id": parsed.path.rsplit("/", 1)[-1]})
            return
        self._send_json(404, {"error": "not found"})


class _ServerContext:
    def __init__(self, *, mode: str, state: _FakeFleetState) -> None:
        self.mode = mode
        self.state = state
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> str:
        handler = type(
            f"{self.mode.title()}Handler",
            (_FleetHandler,),
            {"mode": self.mode, "state": self.state},
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        assert self.server.server_address[1]
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __exit__(self, _exc_type, exc, _tb) -> None:
        assert self.server is not None
        self.server.shutdown()
        self.server.server_close()
        assert self.thread is not None
        self.thread.join(timeout=2)


def _run_smoke(
    tmp_path: Path,
    *,
    fake_foxclaw: Path,
    fake_docker: Path,
    elasticsearch_url: str,
    kibana_url: str,
    fleet_server_url: str,
    timeout_seconds: int = 5,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    profile = tmp_path / "profile"
    profile.mkdir(exist_ok=True)
    ruleset = tmp_path / "rules.yml"
    ruleset.write_text("name: test\nversion: 1.0.0\nrules: []\n", encoding="utf-8")
    output_dir = tmp_path / "artifacts"
    command = [
        sys.executable,
        "scripts/siem_elastic_fleet_smoke.py",
        "--output-dir",
        str(output_dir),
        "--profile",
        str(profile),
        "--ruleset",
        str(ruleset),
        "--foxclaw-cmd",
        f"{sys.executable} {fake_foxclaw}",
        "--docker-cmd",
        f"{sys.executable} {fake_docker}",
        "--elasticsearch-url",
        elasticsearch_url,
        "--kibana-url",
        kibana_url,
        "--fleet-server-url",
        fleet_server_url,
        "--elastic-password",
        "changeme",
        "--timeout-seconds",
        str(timeout_seconds),
    ]
    if extra_args:
        command.extend(extra_args)
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )


def test_siem_elastic_fleet_smoke_existing_agent_default_happy_path(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    output_dir = tmp_path / "artifacts"
    host_log_dir = tmp_path / "host-log"
    state = _FakeFleetState(log_source_dir=host_log_dir, installed_package=False)
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)

    with (
        _ServerContext(mode="es", state=state) as es_url,
        _ServerContext(mode="kibana", state=state) as kibana_url,
        _ServerContext(mode="fleet", state=state) as fleet_url,
    ):
        result = _run_smoke(
            tmp_path,
            fake_foxclaw=fake_foxclaw,
            fake_docker=fake_docker,
            elasticsearch_url=es_url,
            kibana_url=kibana_url,
            fleet_server_url=fleet_url,
            extra_args=[
                "--ecs-host-path",
                str(host_log_dir / "foxclaw.ecs.ndjson"),
            ],
        )

    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "PASS"
    assert manifest["agent_mode"] == "existing"
    assert manifest["package_name"] == "filestream"
    assert manifest["package_version"] == "1.2.0"
    assert manifest["expected_index_name"] == "logs-foxclaw.scan-default"
    assert manifest["run_id"]
    assert manifest["target_agent_id"] == state.target_agent_id
    assert manifest["target_agent_field"] == "elastic_agent.id"
    assert manifest["count_before"] == 0
    assert manifest["count_after"] == 2
    assert manifest["new_documents"] == 2
    assert manifest["fleet_agent_id"] == state.target_agent_id
    assert Path(manifest["ecs_host_path"]).parent == host_log_dir
    assert Path(manifest["ecs_host_path"]).name.startswith("foxclaw")
    assert not Path(manifest["ecs_host_path"]).exists()
    assert manifest["ecs_container_path"].startswith("/logs/foxclaw")
    assert manifest["required_fields_present"] == [
        "@timestamp",
        "ecs.version",
        "event.kind",
        "foxclaw.event_type",
        "host.id",
        "observer.name",
    ]
    assert (output_dir / "foxclaw.ecs.ndjson").is_file()
    assert "fake fleet agent log tail" in (output_dir / "elastic-agent-log-tail.txt").read_text(
        encoding="utf-8"
    )
    assert state.package_install_calls == 1
    docker_log = (fake_docker.with_suffix(".state") / "docker-commands.log").read_text(
        encoding="utf-8"
    )
    assert "inspect foxclaw-agent --format {{.State.Status}}" in docker_log
    assert "exec foxclaw-agent sh -lc" in docker_log
    assert " run " not in f" {docker_log} "
    assert "FLEET_ENROLLMENT_TOKEN=" not in docker_log
    assert state.package_policy_payloads[0]["policy_id"] == state.policy_id
    assert state.last_search_query is not None
    assert state.last_count_query is not None
    assert _query_term_value(state.last_search_query, "labels.foxclaw_run_id") == manifest["run_id"]
    assert _query_term_value(state.last_search_query, "elastic_agent.id") == state.target_agent_id


def test_siem_elastic_fleet_smoke_ephemeral_mode_happy_path(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    output_dir = tmp_path / "artifacts"
    state = _FakeFleetState(log_source_dir=output_dir, installed_package=True)
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)

    with (
        _ServerContext(mode="es", state=state) as es_url,
        _ServerContext(mode="kibana", state=state) as kibana_url,
        _ServerContext(mode="fleet", state=state) as fleet_url,
    ):
        result = _run_smoke(
            tmp_path,
            fake_foxclaw=fake_foxclaw,
            fake_docker=fake_docker,
            elasticsearch_url=es_url,
            kibana_url=kibana_url,
            fleet_server_url=fleet_url,
            extra_args=["--agent-mode", "ephemeral"],
        )

    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "PASS"
    assert manifest["agent_mode"] == "ephemeral"
    assert manifest["run_id"]
    enrollment_payload = json.loads((output_dir / "fleet-enrollment-key.json").read_text(encoding="utf-8"))
    assert enrollment_payload["item"]["api_key"] == "<redacted>"
    docker_log = (fake_docker.with_suffix(".state") / "docker-commands.log").read_text(
        encoding="utf-8"
    )
    assert "--network host" in docker_log
    assert "FLEET_ENROLLMENT_TOKEN=fleet-token" in docker_log
    assert "rm -f" in docker_log
    assert _query_term_value(state.last_search_query, "labels.foxclaw_run_id") == manifest["run_id"]


def test_siem_elastic_fleet_smoke_script_fails_when_agent_never_reaches_policy_ready(
    tmp_path: Path,
) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    host_log_dir = tmp_path / "host-log"
    state = _FakeFleetState(
        log_source_dir=host_log_dir,
        installed_package=True,
        agent_online_after=99,
    )
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)

    with (
        _ServerContext(mode="es", state=state) as es_url,
        _ServerContext(mode="kibana", state=state) as kibana_url,
        _ServerContext(mode="fleet", state=state) as fleet_url,
    ):
        result = _run_smoke(
            tmp_path,
            fake_foxclaw=fake_foxclaw,
            fake_docker=fake_docker,
            elasticsearch_url=es_url,
            kibana_url=kibana_url,
            fleet_server_url=fleet_url,
            timeout_seconds=1,
            extra_args=[
                "--ecs-host-path",
                str(host_log_dir / "foxclaw.ecs.ndjson"),
            ],
        )

    assert result.returncode == 124
    assert "expected package policy" in result.stderr
    manifest = json.loads((tmp_path / "artifacts" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "FAIL"
    assert manifest["exit_code"] == 124
    assert "expected package policy" in manifest["error"]
    assert (tmp_path / "artifacts" / "elastic-agent-log-tail.txt").read_text(encoding="utf-8")


def test_siem_elastic_fleet_smoke_back_to_back_run_ids_are_scoped(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    host_log_dir = tmp_path / "host-log"
    state = _FakeFleetState(log_source_dir=host_log_dir, installed_package=True)
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)

    with (
        _ServerContext(mode="es", state=state) as es_url,
        _ServerContext(mode="kibana", state=state) as kibana_url,
        _ServerContext(mode="fleet", state=state) as fleet_url,
    ):
        first = _run_smoke(
            tmp_path / "first",
            fake_foxclaw=fake_foxclaw,
            fake_docker=fake_docker,
            elasticsearch_url=es_url,
            kibana_url=kibana_url,
            fleet_server_url=fleet_url,
            extra_args=["--ecs-host-path", str(host_log_dir / "foxclaw.ecs.ndjson")],
        )
        second = _run_smoke(
            tmp_path / "second",
            fake_foxclaw=fake_foxclaw,
            fake_docker=fake_docker,
            elasticsearch_url=es_url,
            kibana_url=kibana_url,
            fleet_server_url=fleet_url,
            extra_args=["--ecs-host-path", str(host_log_dir / "foxclaw.ecs.ndjson")],
        )

    assert first.returncode == 0, first.stdout + first.stderr
    assert second.returncode == 0, second.stdout + second.stderr
    first_manifest = json.loads((tmp_path / "first" / "artifacts" / "manifest.json").read_text(encoding="utf-8"))
    second_manifest = json.loads((tmp_path / "second" / "artifacts" / "manifest.json").read_text(encoding="utf-8"))
    assert first_manifest["run_id"] != second_manifest["run_id"]
    assert first_manifest["count_after"] == 2
    assert second_manifest["count_before"] == 0
    assert second_manifest["count_after"] == 2
    assert len(state.filtered_docs({"term": {"labels.foxclaw_run_id": first_manifest["run_id"]}})) == 2
    assert len(state.filtered_docs({"term": {"labels.foxclaw_run_id": second_manifest["run_id"]}})) == 2
    assert _query_term_value(state.last_search_query, "labels.foxclaw_run_id") == second_manifest["run_id"]
    assert _query_term_value(state.last_search_query, "elastic_agent.id") == state.target_agent_id


def test_siem_elastic_fleet_smoke_existing_agent_targets_specific_agent_id(
    tmp_path: Path,
) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    host_log_dir = tmp_path / "host-log"
    state = _FakeFleetState(
        log_source_dir=host_log_dir,
        installed_package=True,
        secondary_agent_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        secondary_agent_status="error",
    )
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)

    with (
        _ServerContext(mode="es", state=state) as es_url,
        _ServerContext(mode="kibana", state=state) as kibana_url,
        _ServerContext(mode="fleet", state=state) as fleet_url,
    ):
        result = _run_smoke(
            tmp_path,
            fake_foxclaw=fake_foxclaw,
            fake_docker=fake_docker,
            elasticsearch_url=es_url,
            kibana_url=kibana_url,
            fleet_server_url=fleet_url,
            extra_args=["--ecs-host-path", str(host_log_dir / "foxclaw.ecs.ndjson")],
        )

    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((tmp_path / "artifacts" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["target_agent_id"] == state.target_agent_id
    assert manifest["fleet_agent_id"] == state.target_agent_id
    assert _query_term_value(state.last_count_query, "labels.foxclaw_run_id") == manifest["run_id"]
    assert _query_term_value(state.last_count_query, "elastic_agent.id") == state.target_agent_id
    assert _query_term_value(state.last_search_query, "labels.foxclaw_run_id") == manifest["run_id"]
    assert _query_term_value(state.last_search_query, "elastic_agent.id") == state.target_agent_id


def test_soak_runner_declares_siem_elastic_fleet_option() -> None:
    payload = Path("scripts/soak_runner.sh").read_text(encoding="utf-8")
    assert "--siem-elastic-fleet-runs <N>" in payload
    assert 'run_step_cmd "${cycle}" "siem_elastic_fleet"' in payload


def _query_term_value(query: dict[str, object] | None, field: str) -> str | None:
    if not isinstance(query, dict):
        return None
    if "term" in query:
        term = query["term"]
        if isinstance(term, dict):
            value = term.get(field)
            return value if isinstance(value, str) else None
        return None
    if "bool" in query:
        bool_query = query["bool"]
        if isinstance(bool_query, dict):
            filters = bool_query.get("filter")
            if isinstance(filters, list):
                for item in filters:
                    value = _query_term_value(item if isinstance(item, dict) else None, field)
                    if value is not None:
                        return value
    return None


def _nested_value(payload: dict[str, object], dotted_key: str):
    current: object = payload
    for part in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _matches_query(payload: dict[str, object], query: dict[str, object]) -> bool:
    if "term" in query:
        term = query["term"]
        if not isinstance(term, dict) or len(term) != 1:
            return False
        field, value = next(iter(term.items()))
        return _nested_value(payload, str(field)) == value
    if "bool" in query:
        bool_query = query["bool"]
        if not isinstance(bool_query, dict):
            return False
        filters = bool_query.get("filter", [])
        if not isinstance(filters, list):
            return False
        return all(
            _matches_query(payload, item)
            for item in filters
            if isinstance(item, dict)
        )
    return False
