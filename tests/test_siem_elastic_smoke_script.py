from __future__ import annotations

import base64
import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


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
        "observer":{{"vendor":"FoxClaw"}},
        "foxclaw":{{"event_type":"foxclaw.finding","schema_version":"1.0.0"}}
    }},
    {{
        "@timestamp":"2025-01-01T00:00:00Z",
        "data_stream":{{"dataset":"foxclaw.scan","namespace":"default","type":"logs"}},
        "ecs":{{"version":"9.2.0"}},
        "event":{{"action":"foxclaw.scan.summary","category":["host"],"code":"FOXCLAW_SCAN_SUMMARY","dataset":"foxclaw.scan","id":"summary-id","kind":"event","module":"foxclaw","provider":"foxclaw","type":["info"]}},
        "host":{{"id":"host-01","name":"host-01"}},
        "message":"summary",
        "observer":{{"vendor":"FoxClaw"}},
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
if args[:2] == ["network", "create"]:
    print("fake-network-id")
    raise SystemExit(0)
if args[:2] == ["network", "rm"]:
    raise SystemExit(0)
if args[:1] == ["run"]:
    print("fake-container-id")
    raise SystemExit(0)
if args[:2] == ["logs", "--tail"]:
    print("fake log tail")
    raise SystemExit(0)
if args[:1] == ["rm"]:
    raise SystemExit(0)
raise SystemExit(0)
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


@dataclass
class _FakeElasticState:
    docs: list[dict[str, object]] = field(default_factory=list)
    es_failures_before_ready: int = 0
    es_connection_resets_before_ready: int = 0
    kibana_failures_before_ready: int = 0
    es_attempts: int = 0
    kibana_attempts: int = 0
    missing_fields: set[str] = field(default_factory=set)
    preview_errors: list[str] = field(default_factory=list)


class _ElasticHandler(BaseHTTPRequestHandler):
    state: _FakeElasticState
    mode: str
    index_name: str

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
        assert ":" in decoded

    def do_GET(self) -> None:
        self._require_auth()
        parsed = urlparse(self.path)
        if self.mode == "es":
            if parsed.path == "/":
                self.state.es_attempts += 1
                if self.state.es_attempts <= self.state.es_connection_resets_before_ready:
                    self.connection.shutdown(2)
                    self.connection.close()
                    return
                if self.state.es_attempts <= self.state.es_failures_before_ready:
                    self._send_json(503, {"error": "starting"})
                    return
                self._send_json(200, {"version": {"number": "9.3.1"}})
                return
            if parsed.path == f"/{self.index_name}/_search":
                hits = [{"_source": item} for item in self.state.docs]
                self._send_json(
                    200,
                    {"hits": {"total": {"value": len(hits)}, "hits": hits}},
                )
                return
            if parsed.path == f"/{self.index_name}/_field_caps":
                requested = parse_qs(parsed.query).get("fields", [""])[0].split(",")
                fields: dict[str, object] = {}
                for field_name in requested:
                    if field_name and field_name not in self.state.missing_fields:
                        fields[field_name] = {"keyword": {"type": "keyword", "searchable": True}}
                self._send_json(200, {"fields": fields})
                return
        if self.mode == "kibana" and parsed.path == "/api/status":
            self.state.kibana_attempts += 1
            if self.state.kibana_attempts <= self.state.kibana_failures_before_ready:
                self._send_json(503, {"status": {"overall": {"level": "unavailable"}}})
                return
            self._send_json(200, {"status": {"overall": {"level": "available"}}})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        self._require_auth()
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b""
        if self.mode == "es":
            if parsed.path == "/_security/user/kibana_system/_password":
                self._send_json(200, {})
                return
            if parsed.path == "/_bulk":
                lines = [line for line in body.decode("utf-8").splitlines() if line.strip()]
                docs: list[dict[str, object]] = []
                for idx in range(1, len(lines), 2):
                    docs.append(json.loads(lines[idx]))
                self.state.docs = docs
                self._send_json(200, {"errors": False, "items": []})
                return
        if self.mode == "kibana":
            if parsed.path == "/api/detection_engine/index":
                self._send_json(200, {"acknowledged": True})
                return
            if parsed.path == "/api/detection_engine/rules/preview":
                self._send_json(
                    200,
                    {
                        "logs": [
                            {
                                "errors": list(self.state.preview_errors),
                                "warnings": [],
                            }
                        ]
                    },
                )
                return
        self._send_json(404, {"error": "not found"})


class _ServerContext:
    def __init__(self, *, mode: str, state: _FakeElasticState, index_name: str) -> None:
        self.mode = mode
        self.state = state
        self.index_name = index_name
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> str:
        handler = type(
            f"{self.mode.title()}Handler",
            (_ElasticHandler,),
            {"mode": self.mode, "state": self.state, "index_name": self.index_name},
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
    timeout_seconds: int = 5,
) -> subprocess.CompletedProcess[str]:
    profile = tmp_path / "profile"
    profile.mkdir(exist_ok=True)
    ruleset = tmp_path / "rules.yml"
    ruleset.write_text("name: test\nversion: 1.0.0\nrules: []\n", encoding="utf-8")
    output_dir = tmp_path / "artifacts"
    return subprocess.run(
        [
            sys.executable,
            "scripts/siem_elastic_smoke.py",
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
            "--network-name",
            "fake-elastic-network",
            "--elasticsearch-container-name",
            "fake-es",
            "--kibana-container-name",
            "fake-kibana",
            "--timeout-seconds",
            str(timeout_seconds),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_siem_elastic_smoke_script_happy_path(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)
    state = _FakeElasticState()

    with _ServerContext(mode="es", state=state, index_name="logs-foxclaw.scan-default") as es_url:
        with _ServerContext(mode="kibana", state=state, index_name="logs-foxclaw.scan-default") as kibana_url:
            result = _run_smoke(
                tmp_path,
                fake_foxclaw=fake_foxclaw,
                fake_docker=fake_docker,
                elasticsearch_url=es_url,
                kibana_url=kibana_url,
            )

    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((tmp_path / "artifacts" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "PASS"
    assert manifest["search_hits"] == 2
    assert manifest["required_fields_present"] == [
        "@timestamp",
        "ecs.version",
        "event.category",
        "event.kind",
        "event.type",
        "host.id",
        "host.name",
    ]


def test_siem_elastic_smoke_script_fails_when_image_missing(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker, image_present=False)
    profile = tmp_path / "profile"
    profile.mkdir()
    ruleset = tmp_path / "rules.yml"
    ruleset.write_text("name: test\nversion: 1.0.0\nrules: []\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/siem_elastic_smoke.py",
            "--output-dir",
            str(tmp_path / "artifacts"),
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--foxclaw-cmd",
            f"{sys.executable} {fake_foxclaw}",
            "--docker-cmd",
            f"{sys.executable} {fake_docker}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "pinned Elastic image not present locally" in result.stderr


def test_siem_elastic_smoke_script_retries_elastic_and_kibana_readiness(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)
    state = _FakeElasticState(es_failures_before_ready=2, kibana_failures_before_ready=2)

    with _ServerContext(mode="es", state=state, index_name="logs-foxclaw.scan-default") as es_url:
        with _ServerContext(mode="kibana", state=state, index_name="logs-foxclaw.scan-default") as kibana_url:
            result = _run_smoke(
                tmp_path,
                fake_foxclaw=fake_foxclaw,
                fake_docker=fake_docker,
                elasticsearch_url=es_url,
                kibana_url=kibana_url,
                timeout_seconds=10,
            )

    assert result.returncode == 0, result.stdout + result.stderr
    assert state.es_attempts >= 3
    assert state.kibana_attempts >= 3


def test_siem_elastic_smoke_script_retries_transient_connection_resets(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)
    state = _FakeElasticState(es_connection_resets_before_ready=2)

    with _ServerContext(mode="es", state=state, index_name="logs-foxclaw.scan-default") as es_url:
        with _ServerContext(mode="kibana", state=state, index_name="logs-foxclaw.scan-default") as kibana_url:
            result = _run_smoke(
                tmp_path,
                fake_foxclaw=fake_foxclaw,
                fake_docker=fake_docker,
                elasticsearch_url=es_url,
                kibana_url=kibana_url,
                timeout_seconds=10,
            )

    assert result.returncode == 0, result.stdout + result.stderr
    assert state.es_attempts >= 3


def test_siem_elastic_smoke_script_fails_when_required_fields_are_missing(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)
    state = _FakeElasticState(missing_fields={"host.id"})

    with _ServerContext(mode="es", state=state, index_name="logs-foxclaw.scan-default") as es_url:
        with _ServerContext(mode="kibana", state=state, index_name="logs-foxclaw.scan-default") as kibana_url:
            result = _run_smoke(
                tmp_path,
                fake_foxclaw=fake_foxclaw,
                fake_docker=fake_docker,
                elasticsearch_url=es_url,
                kibana_url=kibana_url,
            )

    assert result.returncode == 1
    assert "missing required Security fields: host.id" in result.stderr


def test_siem_elastic_smoke_script_fails_when_rule_preview_reports_errors(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)
    state = _FakeElasticState(preview_errors=["Field [event.kind] is not searchable"])

    with _ServerContext(mode="es", state=state, index_name="logs-foxclaw.scan-default") as es_url:
        with _ServerContext(mode="kibana", state=state, index_name="logs-foxclaw.scan-default") as kibana_url:
            result = _run_smoke(
                tmp_path,
                fake_foxclaw=fake_foxclaw,
                fake_docker=fake_docker,
                elasticsearch_url=es_url,
                kibana_url=kibana_url,
            )

    assert result.returncode == 1
    assert "rule preview reported errors" in result.stderr
