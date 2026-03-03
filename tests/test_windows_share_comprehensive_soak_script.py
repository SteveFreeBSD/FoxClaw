from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "windows_share_comprehensive_soak.py"


def _load_script_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_plan_corpus_generated_only_excludes_non_generated_profiles(tmp_path: Path) -> None:
    module = _load_script_module(
        SCRIPT_PATH,
        "test_windows_share_comprehensive_soak_policy",
    )
    source_root = tmp_path / "source-root"
    source_root.mkdir()
    for name in (
        "b67gz6f3.default",
        "foxclaw-gen-001.default",
        "foxclaw-gen-002.default",
        "foxclaw-seed.default",
        "pcxtdp18.default-esr",
    ):
        (source_root / name).mkdir()

    profiles = module._plan_corpus(
        source_root,
        corpus_mode="generated-only",
        excluded_names=set(),
    )

    assert [profile.name for profile in profiles if profile.included] == [
        "foxclaw-gen-001.default",
        "foxclaw-gen-002.default",
    ]
    assert [
        profile.name for profile in profiles if profile.performance_baseline_excluded
    ] == ["b67gz6f3.default", "foxclaw-seed.default"]


def test_windows_share_comprehensive_soak_cli_exit_codes() -> None:
    help_result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert help_result.returncode == 0

    invalid_result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--no-such-flag"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert invalid_result.returncode == 2


def test_windows_share_comprehensive_soak_writes_manifest_and_launches_run(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source-root"
    source_root.mkdir()
    for name in (
        "b67gz6f3.default",
        "foxclaw-gen-001.default",
        "foxclaw-gen-002.default",
        "foxclaw-seed.default",
        "pcxtdp18.default-esr",
    ):
        (source_root / name).mkdir()

    fake_preflight = tmp_path / "fake_preflight.py"
    fake_scan = tmp_path / "fake_scan.py"
    fake_batch = tmp_path / "fake_batch.py"
    fake_launcher = tmp_path / "fake_launcher.py"
    fake_soak_runner = tmp_path / "fake_soak_runner.sh"
    launcher_args = tmp_path / "launcher-args.json"

    _write_executable(
        fake_preflight,
        """#!/usr/bin/env python3
from __future__ import annotations
import pathlib
import sys

source_root = pathlib.Path(sys.argv[-1])
profiles_count = sum(1 for path in source_root.iterdir() if path.is_dir() and not path.name.startswith('.'))
print(f"[windows-share-preflight] source_root={source_root}")
print("[windows-share-preflight] fstype=autofs cifs")
print(f"[windows-share-preflight] profiles_count={profiles_count}")
""",
    )
    _write_executable(
        fake_scan,
        """#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import sys

args = sys.argv[1:]
output = pathlib.Path(args[args.index('--output') + 1])
sarif_out = pathlib.Path(args[args.index('--sarif-out') + 1])
snapshot_out = pathlib.Path(args[args.index('--snapshot-out') + 1])
stage_manifest_out = pathlib.Path(args[args.index('--stage-manifest-out') + 1])
for path in (output, sarif_out, snapshot_out, stage_manifest_out):
    path.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"summary": {"findings_high_count": 1}}), encoding='utf-8')
sarif_out.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding='utf-8')
snapshot_out.write_text(json.dumps({"schema_version": "1.0.0"}), encoding='utf-8')
stage_manifest_out.write_text(
    json.dumps({"staged_profile": "/tmp/foxclaw-windows-share/test/profile"}, sort_keys=True),
    encoding='utf-8',
)
raise SystemExit(2)
""",
    )
    _write_executable(
        fake_batch,
        """#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import sys

args = sys.argv[1:]
out_root = pathlib.Path(args[args.index('--out-root') + 1])
max_profiles = int(args[args.index('--max') + 1])
include_names = [
    args[idx + 1]
    for idx, value in enumerate(args)
    if value == '--include-profile-name'
]
selected = sorted(include_names)[:max_profiles]
out_root.mkdir(parents=True, exist_ok=True)
(out_root / 'batch-invocation.json').write_text(json.dumps(args, indent=2), encoding='utf-8')
(out_root / 'windows-share-batch-summary.json').write_text(
    json.dumps(
        {
            'attempted': len(selected),
            'clean_count': len(selected),
            'findings_count': 0,
            'operational_failure_count': 0,
            'runtime_seconds_total': 12.345,
            'per_profile': [{'profile': name, 'exit_code': 0, 'runtime_seconds': 1.0} for name in selected],
            'failures_by_error': {},
            'total_profiles_seen': len(include_names),
        },
        indent=2,
        sort_keys=True,
    ) + '\\n',
    encoding='utf-8',
)
raise SystemExit(0)
""",
    )
    _write_executable(
        fake_launcher,
        f"""#!/usr/bin/env python3
from __future__ import annotations
import json
import os
import pathlib
import re
import sys

def sanitize(label: str) -> str:
    lowered = label.lower()
    return re.sub(r'[^a-z0-9._-]+', '-', lowered).strip('-') or 'run'

args = sys.argv[1:]
unit_name = args[args.index('--unit') + 1]
label = args[args.index('--label') + 1]
output_root = pathlib.Path(args[args.index('--output-root') + 1])
pathlib.Path({str(launcher_args)!r}).write_text(
    json.dumps({{"argv": args, "soak_sudo_password": os.environ.get("SOAK_SUDO_PASSWORD")}}, indent=2),
    encoding='utf-8',
)
run_dir = output_root / f"20260302T000000Z-{{sanitize(label)}}"
run_dir.mkdir(parents=True, exist_ok=True)
(run_dir / 'manifest.txt').write_text('run_id=20260302T000000Z\\n', encoding='utf-8')
(run_dir / 'run.log').write_text('[fake] launched\\n', encoding='utf-8')
print(f'Running as unit: {{unit_name}}.service; invocation ID: fake-invocation')
""",
    )
    _write_executable(fake_soak_runner, "#!/usr/bin/env bash\nexit 0\n")

    staging_root = tmp_path / "staging-root"
    share_out_root = tmp_path / "share-out-root"
    presoak_root = tmp_path / "presoak-root"
    output_root = tmp_path / "soak-output-root"
    manifest_out = tmp_path / "workflow-manifest.json"

    env = os.environ.copy()
    env["SOAK_SUDO_PASSWORD"] = "top-secret-for-test"  # pragma: allowlist secret

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--source-root",
            str(source_root),
            "--staging-root",
            str(staging_root),
            "--share-out-root",
            str(share_out_root),
            "--presoak-root",
            str(presoak_root),
            "--output-root",
            str(output_root),
            "--manifest-out",
            str(manifest_out),
            "--corpus-mode",
            "mixed",
            "--lock-policy",
            "allow-active",
            "--label",
            "WS83 Test",
                "--launch-timeout-seconds",
                "1",
            "--preflight-cmd",
            str(fake_preflight),
            "--scan-cmd",
            str(fake_scan),
            "--batch-cmd",
            str(fake_batch),
            "--launcher-cmd",
            str(fake_launcher),
            "--soak-runner",
            str(fake_soak_runner),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, result.stdout + result.stderr

    manifest = json.loads(manifest_out.read_text(encoding="utf-8"))
    assert manifest["presoak_profile"] == "foxclaw-gen-001.default"
    assert manifest["corpus_counts"] == {
        "degenerate_stub": 1,
        "generated": 2,
        "other": 1,
        "seed": 1,
    }
    assert manifest["performance_baseline_excluded_profiles"] == [
        "b67gz6f3.default",
        "foxclaw-seed.default",
    ]
    assert manifest["steps"]["preflight"]["parsed"]["fstype"] == "autofs cifs"
    assert manifest["steps"]["presoak"]["exit_code"] == 2
    assert manifest["steps"]["batch"]["summary"]["attempted"] == 5
    assert manifest["steps"]["batch"]["summary"]["clean_count"] == 5
    assert manifest["steps"]["soak_launch"]["unit_name"].startswith(
        "foxclaw-soak-windows-share-"
    )
    assert manifest["steps"]["soak_launch"]["run_dir"].endswith(
        "20260302T000000Z-ws83-test"
    )
    recorded_launch_argv = manifest["steps"]["soak_launch"]["argv"]
    assert "top-secret-for-test" not in json.dumps(recorded_launch_argv)
    assert all("--setenv=SOAK_SUDO_PASSWORD=" not in arg for arg in recorded_launch_argv)
    assert "--property=EnvironmentFile=<redacted>" in recorded_launch_argv

    launcher_payload = json.loads(launcher_args.read_text(encoding="utf-8"))
    assert launcher_payload["soak_sudo_password"] is None
    env_file_args = [
        arg
        for arg in launcher_payload["argv"]
        if arg.startswith("--property=EnvironmentFile=")
    ]
    assert len(env_file_args) == 1
    assert "top-secret-for-test" not in env_file_args[0]
    env_file_path = Path(env_file_args[0].split("=", 2)[2])
    assert not env_file_path.exists()

    batch_invocation = json.loads((share_out_root / "batch-invocation.json").read_text(encoding="utf-8"))
    include_names = [
        batch_invocation[idx + 1]
        for idx, value in enumerate(batch_invocation)
        if value == "--include-profile-name"
    ]
    assert include_names == [
        "b67gz6f3.default",
        "foxclaw-gen-001.default",
        "foxclaw-gen-002.default",
        "foxclaw-seed.default",
        "pcxtdp18.default-esr",
    ]
    assert "--allow-active-profile" in batch_invocation
    assert "--treat-high-findings-as-success" in batch_invocation

    assert (presoak_root / "foxclaw-gen-001.default" / "foxclaw.json").is_file()
    assert (share_out_root / "windows-share-batch-summary.json").is_file()


def test_windows_share_comprehensive_soak_fleet_presoak_gates_detach(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source-root"
    source_root.mkdir()
    for name in ("foxclaw-gen-001.default", "foxclaw-gen-002.default"):
        (source_root / name).mkdir()

    fleet_profile = tmp_path / "fleet-profile"
    fleet_profile.mkdir()
    fleet_ruleset = tmp_path / "fleet-rules.yml"
    fleet_ruleset.write_text("name: fleet\nversion: 1.0.0\nrules: []\n", encoding="utf-8")

    fake_preflight = tmp_path / "fake_preflight.py"
    fake_scan = tmp_path / "fake_scan.py"
    fake_batch = tmp_path / "fake_batch.py"
    fake_fleet_smoke = tmp_path / "fake_fleet_smoke.py"
    fake_launcher = tmp_path / "fake_launcher.py"
    fake_soak_runner = tmp_path / "fake_soak_runner.sh"
    launcher_log = tmp_path / "launcher-log.json"

    _write_executable(
        fake_preflight,
        """#!/usr/bin/env python3
from __future__ import annotations
import pathlib
import sys

source_root = pathlib.Path(sys.argv[-1])
profiles_count = sum(1 for path in source_root.iterdir() if path.is_dir() and not path.name.startswith('.'))
print(f"[windows-share-preflight] source_root={source_root}")
print("[windows-share-preflight] fstype=autofs cifs")
print(f"[windows-share-preflight] profiles_count={profiles_count}")
""",
    )
    _write_executable(
        fake_scan,
        """#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import sys

args = sys.argv[1:]
output = pathlib.Path(args[args.index('--output') + 1])
sarif_out = pathlib.Path(args[args.index('--sarif-out') + 1])
snapshot_out = pathlib.Path(args[args.index('--snapshot-out') + 1])
stage_manifest_out = pathlib.Path(args[args.index('--stage-manifest-out') + 1])
for path in (output, sarif_out, snapshot_out, stage_manifest_out):
    path.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"summary": {"findings_high_count": 0}}), encoding='utf-8')
sarif_out.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding='utf-8')
snapshot_out.write_text(json.dumps({"schema_version": "1.0.0"}), encoding='utf-8')
stage_manifest_out.write_text(json.dumps({"staged_profile": "/tmp/profile"}), encoding='utf-8')
raise SystemExit(0)
""",
    )
    _write_executable(
        fake_batch,
        """#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import sys

args = sys.argv[1:]
out_root = pathlib.Path(args[args.index('--out-root') + 1])
out_root.mkdir(parents=True, exist_ok=True)
(out_root / 'windows-share-batch-summary.json').write_text(
    json.dumps(
        {
            'attempted': 2,
            'clean_count': 2,
            'findings_count': 0,
            'operational_failure_count': 0,
            'runtime_seconds_total': 2.0,
            'per_profile': [],
            'failures_by_error': {},
            'total_profiles_seen': 2,
        },
        indent=2,
        sort_keys=True,
    ) + '\\n',
    encoding='utf-8',
)
raise SystemExit(0)
""",
    )
    _write_executable(
        fake_fleet_smoke,
        """#!/usr/bin/env python3
from __future__ import annotations
import json
import os
import pathlib
import sys

args = sys.argv[1:]
output_dir = pathlib.Path(args[args.index('--output-dir') + 1])
output_dir.mkdir(parents=True, exist_ok=True)
mode = os.environ.get('FAKE_FLEET_PRESOAK_MODE', 'pass')
counter_path = output_dir / 'attempt-count.txt'
attempt = 1
if counter_path.exists():
    attempt = int(counter_path.read_text(encoding='utf-8')) + 1
counter_path.write_text(str(attempt), encoding='utf-8')
if mode == 'fail':
    print('error: Fleet agent offline', file=sys.stderr)
    raise SystemExit(124)
if mode == 'flaky' and attempt == 1:
    print('error: Fleet agent offline', file=sys.stderr)
    raise SystemExit(124)
manifest = {
    'status': 'PASS',
    'run_id': 'fleet-run-1234',
    'target_agent_id': 'agent-1234',
    'expected_index_name': 'logs-foxclaw.scan-default',
    'count_before': 0,
    'count_after': 2,
    'new_documents': 2,
}
(output_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf-8')
print('ok: fake fleet presoak passed')
raise SystemExit(0)
""",
    )
    _write_executable(
        fake_launcher,
        f"""#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import re
import sys

def sanitize(label: str) -> str:
    lowered = label.lower()
    return re.sub(r'[^a-z0-9._-]+', '-', lowered).strip('-') or 'run'

args = sys.argv[1:]
pathlib.Path({str(launcher_log)!r}).write_text(json.dumps(args, indent=2), encoding='utf-8')
label = args[args.index('--label') + 1]
output_root = pathlib.Path(args[args.index('--output-root') + 1])
run_dir = output_root / f"20260303T000000Z-{{sanitize(label)}}"
run_dir.mkdir(parents=True, exist_ok=True)
(run_dir / 'run.log').write_text('[fake] launched\\n', encoding='utf-8')
print('Running as unit: fake.service; invocation ID: fake')
""",
    )
    _write_executable(fake_soak_runner, "#!/usr/bin/env bash\nexit 0\n")

    common_args = [
        sys.executable,
        str(SCRIPT_PATH),
        "--source-root",
        str(source_root),
        "--staging-root",
        str(tmp_path / "staging-root"),
        "--share-out-root",
        str(tmp_path / "share-out-root"),
        "--presoak-root",
        str(tmp_path / "presoak-root"),
        "--output-root",
        str(tmp_path / "soak-output-root"),
        "--corpus-mode",
        "mixed",
        "--max-batch-profiles",
        "2",
        "--siem-elastic-fleet-runs",
        "1",
        "--fleet-smoke-cmd",
        str(fake_fleet_smoke),
        "--fleet-profile",
        str(fleet_profile),
        "--fleet-ruleset",
        str(fleet_ruleset),
        "--preflight-cmd",
        str(fake_preflight),
        "--scan-cmd",
        str(fake_scan),
        "--batch-cmd",
        str(fake_batch),
        "--launcher-cmd",
        str(fake_launcher),
        "--soak-runner",
        str(fake_soak_runner),
        "--launch-timeout-seconds",
        "1",
    ]

    fail_manifest_out = tmp_path / "fail-manifest.json"
    fail_env = os.environ.copy()
    fail_env["FAKE_FLEET_PRESOAK_MODE"] = "fail"
    fail_env["FOXCLAW_FLEET_PRESOAK_RETRY_DELAY_SECONDS"] = "0"
    fail_result = subprocess.run(
        [*common_args, "--manifest-out", str(fail_manifest_out)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=fail_env,
    )

    assert fail_result.returncode == 124
    fail_manifest = json.loads(fail_manifest_out.read_text(encoding="utf-8"))
    assert fail_manifest["steps"]["fleet_presoak"]["exit_code"] == 124
    assert len(fail_manifest["steps"]["fleet_presoak"]["attempts"]) == 2
    assert all(
        attempt["exit_code"] == 124
        for attempt in fail_manifest["steps"]["fleet_presoak"]["attempts"]
    )
    assert "soak_launch" not in fail_manifest["steps"]
    assert not launcher_log.exists()
    shutil.rmtree(tmp_path / "presoak-root" / "elastic-fleet")

    pass_manifest_out = tmp_path / "pass-manifest.json"
    pass_env = os.environ.copy()
    pass_env["FAKE_FLEET_PRESOAK_MODE"] = "flaky"
    pass_env["FOXCLAW_FLEET_PRESOAK_RETRY_DELAY_SECONDS"] = "0"
    pass_result = subprocess.run(
        [*common_args, "--manifest-out", str(pass_manifest_out), "--label", "fleet pass"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=pass_env,
    )

    assert pass_result.returncode == 0, pass_result.stdout + pass_result.stderr
    pass_manifest = json.loads(pass_manifest_out.read_text(encoding="utf-8"))
    assert pass_manifest["steps"]["fleet_presoak"]["exit_code"] == 0
    assert [attempt["exit_code"] for attempt in pass_manifest["steps"]["fleet_presoak"]["attempts"]] == [124, 0]
    assert pass_manifest["steps"]["fleet_presoak"]["summary"] == {
        "count_after": 2,
        "count_before": 0,
        "expected_index_name": "logs-foxclaw.scan-default",
        "new_documents": 2,
        "run_id": "fleet-run-1234",
        "status": "PASS",
        "target_agent_id": "agent-1234",
    }
    assert pass_manifest["steps"]["soak_launch"]["run_dir"].endswith(
        "20260303T000000Z-fleet-pass"
    )
    assert json.loads(launcher_log.read_text(encoding="utf-8"))
