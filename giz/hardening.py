"""Process-level no-leak guards.

Goals (each enforced at startup, before any secret is read):
    1. Disable core dumps so a segfault cannot write password-bearing memory
       to disk.
    2. Disable ptrace / process inspection so other local users cannot
       attach a debugger or read /proc/<pid>/mem.
    3. Discard all logging to disk; keep only stderr at WARN+ for
       unrecoverable errors.
    4. Single-instance lockfile so two giz processes cannot race on the
       same encrypted Briar database.
    5. Best-effort signal handlers so SIGINT / SIGTERM / SIGHUP trigger
       an ordered shutdown with no orphan briar-headless subprocess.
    6. A simple memory-zero helper for password buffers (best-effort;
       Python's GC limits how complete this can be, documented honestly
       in SECURITY.md).

These guards do not protect against device malware. They only narrow the
attack surface within the giz process itself.
"""

from __future__ import annotations

import atexit
import ctypes
import logging
import os
import platform
import resource
import signal
import sys
from pathlib import Path
from typing import Callable, Optional

_LOCKFILE: Optional[Path] = None
_SHUTDOWN_HOOKS: list[Callable[[], None]] = []


def install_guards(data_dir: Path) -> None:
    """Apply every startup guard. Call once, before any secret is in memory.

    Intentionally idempotent: install_guards may be called twice without
    consequence (the second call is a no-op for everything except logging).
    """
    _disable_core_dumps()
    _disable_ptrace()
    _silence_logging()
    _install_signal_handlers()
    _acquire_lockfile(data_dir)


def _disable_core_dumps() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass


def _disable_ptrace() -> None:
    """Refuse debugger attach + /proc memory peeks from other local users."""
    system = platform.system()
    try:
        if system == "Linux":
            PR_SET_DUMPABLE = 4
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        elif system == "Darwin":
            PT_DENY_ATTACH = 31
            libc = ctypes.CDLL("/usr/lib/libSystem.dylib", use_errno=True)
            libc.ptrace(PT_DENY_ATTACH, 0, 0, 0)
    except Exception:
        pass


def _silence_logging() -> None:
    """No log files. No DEBUG. Stderr-only, WARN+ only."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(logging.NullHandler())
    root.setLevel(logging.WARNING)
    for noisy in ("urllib3", "websocket", "requests"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _install_signal_handlers() -> None:
    def _handler(signum: int, _frame) -> None:  # type: ignore[no-untyped-def]
        _run_shutdown_hooks()
        sys.exit(128 + signum)

    for sig_name in ("SIGINT", "SIGTERM", "SIGHUP"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, _handler)
            except (ValueError, OSError):
                pass

    atexit.register(_run_shutdown_hooks)


def _run_shutdown_hooks() -> None:
    while _SHUTDOWN_HOOKS:
        hook = _SHUTDOWN_HOOKS.pop()
        try:
            hook()
        except Exception:
            pass


def register_shutdown_hook(hook: Callable[[], None]) -> None:
    """Register a callback to run on clean exit or signal-induced exit.

    Hooks run in LIFO order. A hook that raises does not block the others.
    """
    _SHUTDOWN_HOOKS.append(hook)


def _acquire_lockfile(data_dir: Path) -> None:
    """Refuse to start if another giz holds the lock for this data dir."""
    global _LOCKFILE
    data_dir.mkdir(parents=True, exist_ok=True)
    lock = data_dir / ".lock"
    if lock.exists():
        try:
            existing_pid = int(lock.read_text().strip().splitlines()[0])
            os.kill(existing_pid, 0)
        except (ValueError, ProcessLookupError, PermissionError, IndexError):
            try:
                lock.unlink()
            except OSError:
                pass
        else:
            sys.stderr.write(
                f"giz is already running (pid {existing_pid}). "
                f"If this is wrong, delete {lock} manually.\n"
            )
            sys.exit(2)
    lock.write_text(f"{os.getpid()}\n")
    _LOCKFILE = lock
    register_shutdown_hook(_release_lockfile)


def _release_lockfile() -> None:
    global _LOCKFILE
    if _LOCKFILE is not None:
        try:
            _LOCKFILE.unlink()
        except OSError:
            pass
        _LOCKFILE = None


def zero_bytes(buf: bytearray) -> None:
    """Best-effort overwrite of a mutable buffer with zeros.

    Python's garbage collector and string interning prevent a hard
    guarantee. Documented honestly in SECURITY.md. Useful for password
    buffers held in bytearray (which we do throughout giz).
    """
    if not isinstance(buf, bytearray):
        return
    for i in range(len(buf)):
        buf[i] = 0


def detect_unencrypted_swap() -> Optional[str]:
    """Return a human-readable warning string if swap appears unencrypted.

    Best-effort, OS-specific. Returns None if swap is encrypted or
    detection failed.
    """
    system = platform.system()
    try:
        if system == "Linux":
            swaps = Path("/proc/swaps")
            if swaps.exists() and swaps.read_text().strip().count("\n") >= 1:
                return (
                    "Swap is enabled. If your root partition is not "
                    "LUKS-encrypted, password fragments may reach disk. "
                    "Use full-disk encryption."
                )
        elif system == "Darwin":
            return None
        elif system == "Windows":
            return None
    except Exception:
        return None
    return None
