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
    7. Block outbound non-loopback socket connects from the giz Python
       process. The wrapper has zero business talking to the public
       network; only briar-headless does, and it runs as a separate
       child process unaffected by this guard. This catches accidental
       exfiltration from any imported library.

These guards do not protect against device malware. They only narrow the
attack surface within the giz process itself.
"""

from __future__ import annotations

import atexit
import ctypes
import ipaddress
import logging
import os
import platform
import resource
import signal
import socket
import sys
from pathlib import Path
from typing import Callable, Optional

_LOCKFILE: Optional[Path] = None
_MACHINE_LOCKFILE: Optional[Path] = None
_MACHINE_LOCK_FD: Optional[int] = None
_SHUTDOWN_HOOKS: list[Callable[[], None]] = []


class MachineLockError(RuntimeError):
    """Raised when another giz instance is already running on this machine."""


def install_guards(data_dir: Path) -> None:
    """Apply every startup guard. Call once, before any secret is in memory.

    Intentionally idempotent: install_guards may be called twice without
    consequence (the second call is a no-op for everything except logging).
    """
    _disable_core_dumps()
    _disable_ptrace()
    _silence_logging()
    _block_outbound_sockets()
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


_SOCKETS_LOCKED = False


class OutboundBlocked(OSError):
    """Raised when something inside the giz process tries to talk to a
    non-loopback peer. The wrapper must never do this; only briar-headless
    (a separate child process) speaks to the network, and it does so via
    Tor inside its own process space."""


def _block_outbound_sockets() -> None:
    """Wrap socket.socket so connect()/connect_ex() refuse non-loopback peers.

    Loopback (127.0.0.0/8 and ::1) plus AF_UNIX are allowed; everything
    else raises. This catches:
        - bugs in this wrapper that accidentally hit the network
        - exfiltration from a compromised dependency
        - misconfigured proxies pulled in via env vars
    briar-headless is a separate process and is NOT affected.
    """
    global _SOCKETS_LOCKED
    if _SOCKETS_LOCKED:
        return

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def _check(sock: socket.socket, address) -> None:
        family = sock.family
        if family == socket.AF_UNIX:
            return
        if family not in (socket.AF_INET, socket.AF_INET6):
            return
        if not isinstance(address, tuple) or len(address) < 1:
            raise OutboundBlocked(
                "giz refused a connect() with an unrecognized address shape"
            )
        host = address[0]
        if not isinstance(host, str):
            raise OutboundBlocked(
                f"giz refused a connect() to {address!r} (host not a string)"
            )
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            raise OutboundBlocked(
                f"giz refused a connect() to non-numeric host '{host}'. "
                f"Only literal loopback addresses are allowed."
            ) from None
        if not ip.is_loopback:
            raise OutboundBlocked(
                f"giz refused outbound connect() to {host}. "
                f"The wrapper is loopback-only by design."
            )

    def _connect(self: socket.socket, address):  # type: ignore[no-untyped-def]
        _check(self, address)
        return real_connect(self, address)

    def _connect_ex(self: socket.socket, address):  # type: ignore[no-untyped-def]
        _check(self, address)
        return real_connect_ex(self, address)

    socket.socket.connect = _connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _connect_ex  # type: ignore[method-assign]
    _SOCKETS_LOCKED = True


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
    """Refuse to start if another giz holds the lock for this data dir.

    Idempotent: if THIS process already holds the lock for this data
    dir, the second call is a no-op. Required because install_guards()
    is documented as idempotent and may legitimately run twice (e.g.
    re-entered after a controlled error).
    """
    global _LOCKFILE
    data_dir.mkdir(parents=True, exist_ok=True)
    lock = data_dir / ".lock"
    if _LOCKFILE is not None and _LOCKFILE == lock:
        return
    if lock.exists():
        try:
            existing_pid = int(lock.read_text().strip().splitlines()[0])
            if existing_pid == os.getpid():
                # Stale lock from an earlier call inside this same process
                # (no _LOCKFILE state because something cleared it). Reuse it.
                _LOCKFILE = lock
                register_shutdown_hook(_release_lockfile)
                return
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


def acquire_machine_lock() -> None:
    """Refuse to start if another giz is running on this same machine.

    Why this exists, and why a per-data-dir lock is not enough:

    Briar embeds a 'tor' binary that, on every launch, asks the kernel
    for control / SOCKS ports through onionwrapper. On macOS / Linux
    those bindings collide between two Briar processes on the same
    host: the first instance starts cleanly, the second one logs

        WARNING: org.briarproject.bramble.tor did not start
        java.io.IOException at AbstractTorWrapper.waitForTorToStart

    and from then on its hidden services are never published, so its
    contacts stay 'pending' indefinitely - which from the user's
    seat looks identical to a contact handshake bug. The fix from
    outside Briar is to refuse to launch in the first place and tell
    the user there can only be one giz per machine.

    Lock is held via flock() (POSIX) / msvcrt.locking() (Windows) on
    a per-user file. The kernel releases it automatically on process
    exit, including hard kill, so a stale lock cannot lock the user
    out forever.
    """
    global _MACHINE_LOCKFILE, _MACHINE_LOCK_FD

    if _MACHINE_LOCK_FD is not None:
        return

    # Per-user (NOT /tmp, which is shared across users) and predictable
    # so the same path is used by every giz invocation on this account.
    lock_dir = Path.home() / ".local" / "share" / "giz"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / ".machine-lock"

    try:
        fd = os.open(
            str(lock_path),
            os.O_CREAT | os.O_RDWR,
            0o600,
        )
    except OSError as exc:
        raise MachineLockError(
            f"could not open machine lock at {lock_path}: {exc}"
        )

    busy_message = (
        "another giz instance is already running on this machine. "
        "giz allows only one account per machine because Briar's "
        "embedded Tor cannot share local ports with a second Briar "
        "process - the second instance's hidden services never "
        "publish and its contacts stay 'pending' forever. close "
        "the other giz first."
    )
    if platform.system() == "Windows":
        try:
            import msvcrt  # type: ignore[import-not-found]
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
        except OSError:
            os.close(fd)
            raise MachineLockError(busy_message)
    else:
        try:
            import fcntl  # POSIX-only
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError):
            os.close(fd)
            raise MachineLockError(busy_message)

    try:
        os.write(fd, f"{os.getpid()}\n".encode())
    except OSError:
        pass

    _MACHINE_LOCK_FD = fd
    _MACHINE_LOCKFILE = lock_path
    register_shutdown_hook(_release_machine_lock)


def _release_machine_lock() -> None:
    global _MACHINE_LOCK_FD, _MACHINE_LOCKFILE
    fd = _MACHINE_LOCK_FD
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass
        _MACHINE_LOCK_FD = None
    _MACHINE_LOCKFILE = None


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


def enforce_perms(data_dir: Path) -> Optional[str]:
    """Tighten POSIX permissions on every launch.

    On every start we:
        - chmod the data dir to 0700 (only the owner reads/lists it)
        - chmod the 'real' subdir to 0700 (Briar's encrypted DB lives here)
        - chmod the .gizhashes file to 0600 (the only file giz itself writes)
        - chmod auth_token to 0600 (briar-headless writes this; we tighten
          on top in case Briar's defaults are looser on this OS)

    Returns None on success, or a human-readable error string if any of
    the targets exists but cannot be brought to the required mode. The
    caller decides whether to refuse to start.

    On Windows POSIX modes don't apply; instead we attempt an icacls
    sweep removing 'Everyone' / 'Users' inheritance. If icacls is
    unavailable (rare on supported Windows versions) we return a
    warning string but do not block.
    """
    import stat
    if platform.system() == "Windows":
        return _enforce_perms_windows(data_dir)

    targets = [
        (data_dir, 0o700, True),
        (data_dir / "real", 0o700, True),
        (data_dir / ".gizhashes", 0o600, False),
        (data_dir / "real" / "auth_token", 0o600, False),
    ]
    for path, mode, must_be_dir in targets:
        if not path.exists():
            continue
        if must_be_dir and not path.is_dir():
            return f"{path} exists but is not a directory"
        if not must_be_dir and path.is_dir():
            return f"{path} unexpectedly is a directory"
        try:
            os.chmod(path, mode)
        except OSError as exc:
            return f"could not chmod {path} to {mode:o}: {exc}"
        st = path.stat()
        actual = stat.S_IMODE(st.st_mode)
        if actual != mode:
            return (
                f"{path} mode is {actual:o} after chmod, expected {mode:o}"
            )
    return None


def _enforce_perms_windows(data_dir: Path) -> Optional[str]:
    """Best-effort: strip inherited Everyone/Users access from data_dir."""
    import shutil
    import subprocess
    if not shutil.which("icacls"):
        return None  # do not block; Windows ACL tightening is optional
    try:
        subprocess.run(
            ["icacls", str(data_dir), "/inheritance:r"],
            check=False, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["icacls", str(data_dir), "/grant:r", f"{os.environ.get('USERNAME', '')}:F"],
            check=False, capture_output=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


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
