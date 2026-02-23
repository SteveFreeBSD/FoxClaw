from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_COLLECT_ROOT = _REPO_ROOT / "foxclaw" / "collect"
_FORBIDDEN_PATTERNS = ("profile_dir /", ".rglob(", "os.walk(")
_ALLOW_MARKER = "# SAFE_PATHS_OK"


def test_collectors_must_use_safe_paths_guards() -> None:
    violations: list[str] = []

    for path in sorted(_COLLECT_ROOT.rglob("*.py")):
        if path.name == "safe_paths.py":
            continue

        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if _ALLOW_MARKER in line:
                continue

            for pattern in _FORBIDDEN_PATTERNS:
                if pattern in line:
                    rel_path = path.relative_to(_REPO_ROOT)
                    violations.append(f"{rel_path}:{lineno}: forbidden `{pattern}`")

    assert not violations, "collector safe-path guard violations:\n" + "\n".join(violations)
