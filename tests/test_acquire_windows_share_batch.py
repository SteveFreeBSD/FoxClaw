from __future__ import annotations

import json
import subprocess
from pathlib import Path

import foxclaw.acquire.windows_share_batch as windows_share_batch
import pytest
from foxclaw.acquire.windows_share_batch import run_windows_share_batch


def _arg_value(argv: list[str], flag: str) -> str:
    index = argv.index(flag)
    return argv[index + 1]


def test_run_windows_share_batch_continues_after_failure_and_writes_summary(tmp_path: Path) -> None:
    source_root = tmp_path / "source-root"
    source_root.mkdir(parents=True, exist_ok=True)

    for profile_name in ("profile-c", "profile-a", "profile-b"):
        profile_dir = source_root / profile_name
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "prefs.js").write_text(
            'user_pref("browser.startup.homepage", "about:home");\n', encoding="utf-8"
        )

    # Non-directory entries are ignored by the batch enumerator.
    (source_root / "README.txt").write_text("not a profile directory\n", encoding="utf-8")
    # Hidden directories are ignored by default.
    (source_root / ".foxclaw-ext-cache").mkdir(parents=True, exist_ok=True)

    out_root = tmp_path / "batch-out"
    staging_root = tmp_path / "staging-root"
    seen_profiles: list[str] = []

    def stub_runner(argv: list[str]) -> tuple[int, str, str]:
        profile_name = Path(_arg_value(argv, "--source-profile")).name
        profile_out = Path(_arg_value(argv, "--output-dir"))
        seen_profiles.append(profile_name)

        profile_out.mkdir(parents=True, exist_ok=True)
        (profile_out / "stage-manifest.json").write_text(
            json.dumps({"staged_profile": str(staging_root / f"{profile_name}-stage")}),
            encoding="utf-8",
        )

        if profile_name == "profile-b":
            return (
                1,
                "",
                "error: active-profile lock markers detected in source profile (parent.lock)\n",
            )
        if profile_name == "profile-c":
            return (2, "", "")
        return (0, "", "")

    exit_code = run_windows_share_batch(
        source_root=source_root,
        staging_root=staging_root,
        out_root=out_root,
        runner=stub_runner,
    )

    assert exit_code == 1
    assert seen_profiles == ["profile-a", "profile-b", "profile-c"]

    summary_path = out_root / "windows-share-batch-summary.json"
    assert summary_path.is_file()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    assert summary["total_profiles_seen"] == 3
    assert summary["attempted"] == 3
    assert summary["clean_count"] == 1
    assert summary["findings_count"] == 1
    assert summary["operational_failure_count"] == 1
    assert summary["failures_by_error"] == {
        "error: active-profile lock markers detected in source profile (parent.lock)": ["profile-b"]
    }
    assert summary["runtime_seconds_total"] >= 0

    profile_results = {entry["profile"]: entry for entry in summary["per_profile"]}
    assert profile_results["profile-a"]["exit_code"] == 0
    assert profile_results["profile-b"]["exit_code"] == 1
    assert profile_results["profile-c"]["exit_code"] == 2
    assert profile_results["profile-b"]["error"] == (
        "error: active-profile lock markers detected in source profile (parent.lock)"
    )

    for profile_name in ("profile-a", "profile-b", "profile-c"):
        assert (out_root / profile_name).is_dir()

def test_run_windows_share_batch_parallel_execution(tmp_path: Path) -> None:
    source_root = tmp_path / "source-root-parallel"
    source_root.mkdir(parents=True, exist_ok=True)

    test_profiles = ["profile-x", "profile-y", "profile-z"]
    for profile_name in test_profiles:
        profile_dir = source_root / profile_name
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "prefs.js").write_text(
            'user_pref("browser.startup.homepage", "about:home");\n', encoding="utf-8"
        )
        
    out_root = tmp_path / "batch-out-parallel"
    staging_root = tmp_path / "staging-root-parallel"
    
    import threading
    import time
    
    seen_profiles: list[str] = []
    lock = threading.Lock()

    def slow_stub_runner(argv: list[str]) -> tuple[int, str, str]:
        profile_name = Path(_arg_value(argv, "--source-profile")).name
        profile_out = Path(_arg_value(argv, "--output-dir"))
        
        with lock:
            seen_profiles.append(profile_name)

        profile_out.mkdir(parents=True, exist_ok=True)
        (profile_out / "stage-manifest.json").write_text(
            json.dumps({"staged_profile": str(staging_root / f"{profile_name}-stage")}),
            encoding="utf-8",
        )
        
        # Sleep for a fraction to ensure threads actually overlap
        time.sleep(0.1)
        
        if profile_name == "profile-x":
            return (1, "", "error: transient thread failure\n")
            
        return (0, "", "")

    exit_code = run_windows_share_batch(
        source_root=source_root,
        staging_root=staging_root,
        out_root=out_root,
        runner=slow_stub_runner,
        workers=3,
    )
    # The variable 'duration' is not needed, we just compute it or drop it entirely if not asserted.
    # 3 threads sleeping for 0.1s should finish in ~0.15s, much faster than sequential 0.3s
    assert exit_code == 1
    assert sorted(seen_profiles) == sorted(test_profiles)
    
    summary_path = out_root / "windows-share-batch-summary.json"
    assert summary_path.is_file()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    
    assert summary["attempted"] == 3
    assert summary["clean_count"] == 2
    assert summary["operational_failure_count"] == 1


def test_run_single_windows_share_scan_timeout_maps_to_operational_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Pipe:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class _HungProcess:
        def __init__(self) -> None:
            self.stdout = _Pipe()
            self.stderr = _Pipe()
            self.returncode = None
            self.killed = False

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            self.killed = True

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            if timeout is None:
                return ("", "")
            raise subprocess.TimeoutExpired(
                cmd=["foxclaw"],
                timeout=timeout,
                output="partial",
                stderr="warning",
            )

    hung_process = _HungProcess()

    monkeypatch.setattr(
        windows_share_batch.subprocess,
        "Popen",
        lambda *args, **kwargs: hung_process,
    )
    time_values = iter([0.0, 10.0])
    monkeypatch.setattr(windows_share_batch, "perf_counter", lambda: next(time_values))
    monkeypatch.setattr(windows_share_batch, "sleep", lambda *_args, **_kwargs: None)

    exit_code, stdout_payload, stderr_payload = windows_share_batch._run_single_windows_share_scan(
        ["--source-profile", "/tmp/profile"], timeout_seconds=5
    )

    assert exit_code == 1
    assert stdout_payload == "partial"
    assert "warning" in stderr_payload
    assert "error: profile scan timed out after 5 seconds" in stderr_payload
    assert hung_process.killed is True
    assert hung_process.stdout.closed is True
    assert hung_process.stderr.closed is True


def test_run_windows_share_batch_forwards_profile_timeout_to_default_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_root = tmp_path / "source-root-timeout-forwarding"
    source_root.mkdir(parents=True, exist_ok=True)
    profile_dir = source_root / "profile-a"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text(
        'user_pref("browser.startup.homepage", "about:home");\n', encoding="utf-8"
    )

    timeout_values: list[int] = []

    def fake_default_runner(
        argv: list[str], *, timeout_seconds: int = 900
    ) -> tuple[int, str, str]:
        timeout_values.append(timeout_seconds)
        profile_out = Path(_arg_value(argv, "--output-dir"))
        profile_out.mkdir(parents=True, exist_ok=True)
        (profile_out / "stage-manifest.json").write_text(
            json.dumps({"staged_profile": str(profile_out / "stage" / "profile")}),
            encoding="utf-8",
        )
        return (0, "", "")

    monkeypatch.setattr(windows_share_batch, "_run_single_windows_share_scan", fake_default_runner)

    exit_code = windows_share_batch.run_windows_share_batch(
        source_root=source_root,
        staging_root=tmp_path / "staging-root-timeout-forwarding",
        out_root=tmp_path / "batch-out-timeout-forwarding",
        runner=windows_share_batch._run_single_windows_share_scan,
        profile_timeout_seconds=123,
    )

    assert exit_code == 0
    assert timeout_values == [123]


def test_run_windows_share_batch_rejects_nonpositive_profile_timeout(tmp_path: Path) -> None:
    source_root = tmp_path / "source-root-invalid-timeout"
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "profile-a").mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="--profile-timeout-seconds"):
        run_windows_share_batch(
            source_root=source_root,
            staging_root=tmp_path / "staging-root-invalid-timeout",
            out_root=tmp_path / "batch-out-invalid-timeout",
            runner=lambda argv: (0, "", ""),
            profile_timeout_seconds=0,
        )


def test_run_windows_share_batch_fails_on_empty_source_root(tmp_path: Path) -> None:
    source_root = tmp_path / "source-root-empty"
    source_root.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="no profile directories found under source root"):
        run_windows_share_batch(
            source_root=source_root,
            staging_root=tmp_path / "staging-root-empty",
            out_root=tmp_path / "batch-out-empty",
            runner=lambda argv: (0, "", ""),
        )
