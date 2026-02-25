from __future__ import annotations

import json
from pathlib import Path

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

    start_time = time.perf_counter()
    exit_code = run_windows_share_batch(
        source_root=source_root,
        staging_root=staging_root,
        out_root=out_root,
        runner=slow_stub_runner,
        workers=3,
    )
    duration = time.perf_counter() - start_time
    
    # 3 threads sleeping for 0.1s should finish in ~0.15s, much faster than sequential 0.3s
    assert exit_code == 1
    assert sorted(seen_profiles) == sorted(test_profiles)
    
    summary_path = out_root / "windows-share-batch-summary.json"
    assert summary_path.is_file()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    
    assert summary["attempted"] == 3
    assert summary["clean_count"] == 2
    assert summary["operational_failure_count"] == 1
