"""Read-only PKCS#11 module path audit helpers (WS-49)."""

from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path

_WINDOWS_DRIVE_RE = re.compile(r"(?i)^[a-z]:[\\/]")
_WINDOWS_UNC_RE = re.compile(r"^\\\\")
_ALLOWED_LIBRARY_BASENAMES: set[str] = {
    "libsoftokn3.so",
    "softokn3.dll",
    "softokn3.dylib",
    "libnssckbi.so",
    "nssckbi.dll",
    "nssckbi.dylib",
    "p11-kit-proxy.so",
    "p11-kit-client.so",
}
_ALLOWED_PATH_PREFIXES: tuple[str, ...] = (
    "/usr/lib/",
    "/usr/lib64/",
    "/lib/",
    "/lib64/",
    "/system/library/",
    "/library/security/",
    "c:/windows/system32/",
    "c:/program files/mozilla firefox/",
    "c:/program files (x86)/mozilla firefox/",
    "c:/program files/common files/",
    "c:/program files (x86)/common files/",
)
_ALLOWED_PATH_MARKERS: tuple[str, ...] = (
    "/mozilla/",
    "/firefox/",
    "/nss/",
    "mozilla firefox",
)


@dataclass(frozen=True, slots=True)
class Pkcs11Module:
    """One PKCS#11 module entry from pkcs11.txt."""

    name: str
    library_path: str


@dataclass(frozen=True, slots=True)
class Pkcs11ModuleRisk:
    """One suspicious PKCS#11 module entry."""

    name: str
    library_path: str
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Pkcs11AuditResult:
    """Deterministic PKCS#11 audit output."""

    parse_error: str | None
    modules: tuple[Pkcs11Module, ...]
    suspicious_modules: tuple[Pkcs11ModuleRisk, ...]


def audit_pkcs11_modules(pkcs11_path: Path) -> Pkcs11AuditResult:
    """Audit pkcs11.txt module paths for non-standard library locations."""
    if not pkcs11_path.is_file():
        return Pkcs11AuditResult(parse_error=None, modules=(), suspicious_modules=())

    try:
        text = pkcs11_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return Pkcs11AuditResult(parse_error=str(exc), modules=(), suspicious_modules=())

    modules = _parse_pkcs11_text(text)
    suspicious_modules = tuple(
        sorted(
            (
                Pkcs11ModuleRisk(
                    name=module.name,
                    library_path=module.library_path,
                    reasons=_classify_library_path(module.library_path),
                )
                for module in modules
                if _classify_library_path(module.library_path)
            ),
            key=lambda item: (item.name.lower(), item.library_path.lower(), ",".join(item.reasons)),
        )
    )
    return Pkcs11AuditResult(
        parse_error=None,
        modules=modules,
        suspicious_modules=suspicious_modules,
    )


def _parse_pkcs11_text(text: str) -> tuple[Pkcs11Module, ...]:
    modules: list[Pkcs11Module] = []
    current_name = ""
    current_library = ""

    def flush_current() -> None:
        nonlocal current_name, current_library
        if not current_name and not current_library:
            return
        modules.append(Pkcs11Module(name=current_name, library_path=current_library))
        current_name = ""
        current_library = ""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            flush_current()
            continue
        if line.startswith("#") or line.startswith(";") or "=" not in line:
            continue

        key_raw, value_raw = line.split("=", 1)
        key = key_raw.strip().lower()
        value = value_raw.strip()
        if key not in {"name", "library"}:
            continue

        if key == "name":
            if current_name:
                flush_current()
            current_name = value
            continue

        if current_library:
            flush_current()
        current_library = value

    flush_current()
    return tuple(sorted(modules, key=lambda item: (item.name.lower(), item.library_path.lower())))


def _classify_library_path(library_path: str) -> tuple[str, ...]:
    normalized = _normalize_path(library_path)
    if not normalized:
        return ()

    basename = Path(normalized).name.lower()
    if basename in _ALLOWED_LIBRARY_BASENAMES:
        return ()

    if _is_absolute_like(normalized):
        if any(normalized.startswith(prefix) for prefix in _ALLOWED_PATH_PREFIXES):
            return ()
        if any(marker in normalized for marker in _ALLOWED_PATH_MARKERS):
            return ()
        return ("non_standard_library_path",)

    return ("relative_or_unqualified_library_path",)


def _normalize_path(value: str) -> str:
    return value.strip().strip('"').strip("'").replace("\\", "/").lower()


def _is_absolute_like(value: str) -> bool:
    if value.startswith("/"):
        return True
    if _WINDOWS_DRIVE_RE.match(value):
        return True
    if _WINDOWS_UNC_RE.match(value.replace("/", "\\")):
        return True
    return False

