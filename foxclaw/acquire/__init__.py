"""Profile acquisition and staging workflows."""

from foxclaw.acquire.windows_share import run_windows_share_scan_from_argv
from foxclaw.acquire.windows_share_batch import run_windows_share_batch

__all__ = ["run_windows_share_batch", "run_windows_share_scan_from_argv"]
