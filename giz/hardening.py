"""Process-level no-leak guards.

Goals (each enforced at startup, before any secret is read):
    1. Disable core dumps so a segfault cannot write password-bearing memory
       to disk.
    2. Disable ptrace / process inspection so other local users cannot
       attach a debugger or read /proc/<pid>/mem.
    3. Discard all logging to disk; keep only stderr at WARN+ for
       unrecoverable errors. Also neuter logging.basicConfig so a late
       import cannot re-attach a file handler behind our back.
    4. Single-instance lockfile so two giz processes cannot race on the
       same encrypted Briar database.
    5. Best-effort signal handlers so SIGINT / SIGTERM / SIGHUP trigger
       an ordered shutdown with no orphan briar-headless subprocess.
    6. A simple memory-zero helper for password buffers (best-effort;
       Python's GC limits how complete this can be, documented honestly
       in SECURITY.md). Helper raises TypeError on non-bytearray to
       catch programmer errors at audit time rather than silently
       failing to zero an immutable bytes copy.
    7. Block outbound non-loopback socket connects AND non-loopback
       getaddrinfo() calls from the giz Python process. The wrapper has
       zero business talking to the public network or even resolving
       public hostnames; only briar-headless does, and it runs as a
       separate child process unaffected by this guard. This catches
       accidental exfiltration from any imported library, including
       the DNS-leak variant where a name is resolved but never
       connected to.
    8. After briar-headless is up, the loopback whitelist is narrowed
       further to (127.0.0.1, briar_port) only, so even loopback-bound
       side-channels on other ports are refused.

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
from typing import Callable, Iterable, Optional, Set, Tuple

_LOCKFILE: Optional[Path] = None
_MACHINE_LOCKFILE: Optional[Path] = None
_MACHINE_LOCK_FD: Optional[int] = None
_SHUTDOWN_HOOKS: list[Callable[[], None]] = []
# When None: any loopback address/port is allowed (default after
# install_guards). When a set: only those exact (host, port) tuples
# are allowed - even other loopback ports are refused. Narrowed by
# restrict_loopback_to() once briar-headless's port is known.
_ALLOWED_LOOPBACK_TARGETS: Optional[Set[Tuple[str, int]]] = None


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
    """No log files. No DEBUG. Stderr-only, WARN+ only.

    Also neuter logging.basicConfig() so a late-imported library that
    calls it cannot re-attach a StreamHandler / FileHandler behind our
    back. Same for logging.FileHandler so 'just write to a file' is
    refused outright. logging.NullHandler is what we want everywhere.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(logging.NullHandler())
    root.setLevel(logging.WARNING)
    for noisy in ("urllib3", "websocket", "requests"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    def _basic_config_noop(**kwargs):  # type: ignore[no-untyped-def]
        return None
    logging.basicConfig = _basic_config_noop  # type: ignore[assignment]

    _real_file_handler_init = logging.FileHandler.__init__

    def _file_handler_blocked(self, *a, **kw):  # type: ignore[no-untyped-def]
        # Refuse: no log files, ever. We initialize as a bare Handler
        # and stub out emit/flush/close at the instance level so
        # *callers* never crash and no log content reaches disk.
        # NB: only initializing the base Handler (self.lock,
        # self.filters, ...) leaves self.stream unset; we therefore
        # MUST override emit on the instance because FileHandler.emit
        # would dereference self.stream and AttributeError.
        logging.Handler.__init__(self)
        # Instance-level no-ops shadow the FileHandler implementations.
        self.emit = lambda record: None  # type: ignore[method-assign]
        self.flush = lambda: None  # type: ignore[method-assign]
        self.close = lambda: None  # type: ignore[method-assign]

    logging.FileHandler.__init__ = _file_handler_blocked  # type: ignore[assignment]
    # Also kill the rotating / timed file variants if the stdlib has them
    # imported by anything yet.
    for cls_name in ("RotatingFileHandler", "TimedRotatingFileHandler", "WatchedFileHandler"):
        try:
            handlers_mod = __import__("logging.handlers", fromlist=[cls_name])
            cls = getattr(handlers_mod, cls_name, None)
            if cls is not None:
                cls.__init__ = _file_handler_blocked  # type: ignore[assignment]
        except Exception:
            pass
    _ = _real_file_handler_init  # retained reference, intentionally unused


_SOCKETS_LOCKED = False


class OutboundBlocked(OSError):
    """Raised when something inside the giz process tries to talk to a
    non-loopback peer. The wrapper must never do this; only briar-headless
    (a separate child process) speaks to the network, and it does so via
    Tor inside its own process space."""


def _block_outbound_sockets() -> None:
    """Wrap socket.socket and socket.getaddrinfo so all outbound network
    activity stays on the loopback interface.

    What's blocked:
        - connect() / connect_ex() to anything other than a numeric
          loopback address (127.0.0.0/8 or ::1)
        - getaddrinfo() for non-numeric hosts and for numeric
          non-loopback hosts (closes the DNS-leak variant where a
          library resolves a hostname but never actually connects)
        - once restrict_loopback_to() narrows the whitelist, even
          loopback ports outside that whitelist are refused

    What's allowed:
        - AF_UNIX is unrestricted (used by some Python internals)
        - getaddrinfo(None, ...) for binding our own listeners
        - everything on the loopback interface, until restricted

    briar-headless is a SEPARATE process and is NOT affected.
    """
    global _SOCKETS_LOCKED
    if _SOCKETS_LOCKED:
        return

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def _check_loopback_target(host: str, port: Optional[int]) -> None:
        targets = _ALLOWED_LOOPBACK_TARGETS
        if targets is None:
            return
        if port is None:
            raise OutboundBlocked(
                f"giz refused loopback connect() to {host} with no port "
                f"(narrowed whitelist requires (host, port) match)"
            )
        if (host, int(port)) not in targets:
            raise OutboundBlocked(
                f"giz refused loopback connect() to {host}:{port}; "
                f"only {sorted(targets)} are whitelisted in this run."
            )

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
        port = address[1] if len(address) >= 2 else None
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
        _check_loopback_target(host, port if isinstance(port, int) else None)

    def _connect(self: socket.socket, address):  # type: ignore[no-untyped-def]
        _check(self, address)
        return real_connect(self, address)

    def _connect_ex(self: socket.socket, address):  # type: ignore[no-untyped-def]
        _check(self, address)
        return real_connect_ex(self, address)

    def _getaddrinfo(host, *args, **kwargs):  # type: ignore[no-untyped-def]
        # host=None / "" is used by callers binding their OWN listeners;
        # those never leave the box, so we let them through.
        if host is None or host == "":
            return real_getaddrinfo(host, *args, **kwargs)
        if not isinstance(host, str):
            raise OutboundBlocked(
                f"giz refused getaddrinfo({host!r}) (host not a string)"
            )
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            raise OutboundBlocked(
                f"giz refused getaddrinfo for non-numeric host '{host}'. "
                f"DNS lookups for public hostnames are not allowed in the "
                f"wrapper; resolution would already leak the destination."
            ) from None
        if not ip.is_loopback:
            raise OutboundBlocked(
                f"giz refused getaddrinfo for non-loopback host '{host}'."
            )
        return real_getaddrinfo(host, *args, **kwargs)

    socket.socket.connect = _connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _connect_ex  # type: ignore[method-assign]
    socket.getaddrinfo = _getaddrinfo  # type: ignore[assignment]
    _SOCKETS_LOCKED = True


def restrict_loopback_to(targets: Iterable[Tuple[str, int]]) -> None:
    """Narrow the outbound-socket guard to a specific (host, port) set.

    Before this call, any 127.x.y.z address is allowed. After this
    call, only the supplied (host, port) tuples are allowed; everything
    else, including OTHER loopback ports, is refused.

    Called once per run, after we have learned the briar-headless
    listening port, so that a malicious dependency cannot connect to
    a sibling localhost listener (e.g. an exfil daemon planted by an
    earlier compromise).
    """
    global _ALLOWED_LOOPBACK_TARGETS
    _ALLOWED_LOOPBACK_TARGETS = {(str(h), int(p)) for h, p in targets}


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
    if _MACHINE_LOCK_FD is not None:
        return
    _acquire_machine_lock_at(_machine_lock_path())


def _machine_lock_path() -> Path:
    """Canonical machine-lock path. Factored out so tests can both
    (a) verify the path derivation in isolation, and (b) use a custom
    path via _acquire_machine_lock_at() so a unit test does not fight
    a live giz session on the developer's machine.

    On POSIX the path MUST NOT depend on $HOME: a hostile or accidental
    HOME override (e.g. `HOME=/tmp/x giz`) would land on a different
    lockfile and silently bypass the same-machine guard, which is the
    exact regression an audit found. We anchor on euid instead, which
    only root can spoof, on a path that's guaranteed to be identical
    for every giz launch by the same kernel-level user identity.
    """
    if platform.system() == "Windows":
        # Windows lacks a stable euid concept and the $HOME-spoof
        # vector here is mostly theoretical; keep the legacy path.
        lock_dir = Path.home() / ".local" / "share" / "giz"
        lock_dir.mkdir(parents=True, exist_ok=True)
        return lock_dir / ".machine-lock"
    # POSIX: /tmp/.giz-<euid>.machine-lock. /tmp is shared across
    # users so we MUST namespace by uid; the trailing numeric uid
    # is unspoofable for non-root processes. _acquire_machine_lock_at
    # guards the fd with O_NOFOLLOW + fstat ownership check.
    return Path("/tmp") / f".giz-{os.geteuid()}.machine-lock"  # nosec B108


def _acquire_machine_lock_at(lock_path: Path) -> None:
    """Internal: acquire the kernel-level same-machine lock at the
    exact path given. Production callers go through
    acquire_machine_lock(); tests use this entry point with a
    tmp_path-backed location for isolation."""
    global _MACHINE_LOCKFILE, _MACHINE_LOCK_FD

    if _MACHINE_LOCK_FD is not None:
        return

    try:
        fd = os.open(
            str(lock_path),
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise MachineLockError(
            f"could not open machine lock at {lock_path}: {exc}"
        )

    # Belt-and-braces: confirm the file we just opened is actually owned
    # by us. A co-tenant with brief write access could pre-create a
    # wrong-uid file in /tmp; O_NOFOLLOW handles the symlink case but a
    # hardlink/race pre-created file would still pass O_NOFOLLOW. The
    # ownership check closes that gap.
    if platform.system() != "Windows":
        try:
            st = os.fstat(fd)
        except OSError as exc:
            os.close(fd)
            raise MachineLockError(f"could not fstat lock fd: {exc}")
        if st.st_uid != os.geteuid():
            os.close(fd)
            raise MachineLockError(
                f"lock file at {lock_path} is owned by uid {st.st_uid}, "
                f"not by us (uid {os.geteuid()}); refusing to use it. "
                f"Inspect the file; this should never happen."
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

    Raises TypeError on non-bytearray input rather than silently
    no-op'ing: silently failing to zero an immutable bytes copy is the
    exact bug class this helper exists to prevent. We want it to
    crash loud at audit time, not quietly leak the password.
    """
    if not isinstance(buf, bytearray):
        raise TypeError(
            f"zero_bytes requires bytearray (got {type(buf).__name__}); "
            f"immutable bytes objects cannot be zeroed and must not be "
            f"passed here. Re-check the caller: passwords must live in "
            f"a bytearray for their entire lifetime."
        )
    for i in range(len(buf)):
        buf[i] = 0


def enforce_perms(data_dir: Path) -> Optional[str]:
    """Tighten POSIX permissions on every launch.

    Pinned targets (always):
        - data_dir              0700 (only the owner reads/lists it)
        - data_dir/real         0700 (Briar's encrypted DB lives here)
        - data_dir/.gizhashes   0600 (the only file giz itself writes)
        - data_dir/real/auth_token 0600 (briar-headless writes this)

    Defense-in-depth recursive sweep across data_dir/real:
        - directories          0700
        - regular files        0700 if the owner-execute bit is already
                               set or the file is a known-executable
                               Tor helper (tor, lyrebird, obfs4proxy,
                               snowflake); 0600 otherwise.
        - symlinks             refused (no chmod through them)

    Why preserve owner-execute: Briar bundles a tor binary plus the
    pluggable-transport helpers (lyrebird / obfs4proxy / snowflake)
    inside data_dir/real/tor/ and exec()s them at every launch. An
    earlier giz release force-chmod'd them to 0600, which silently
    killed the tor plugin (Briar logs 'error=13, Permission denied'
    exec'ing tor) and every contact stayed 'pending' forever. We
    keep the recursive sweep for defense-in-depth on the encrypted
    DB, but never strip owner-execute from a file that legitimately
    needs it.

    Why the recursive sweep at all: Briar creates db.key, db.key.bak,
    db.mv.db and tor/* with mode 0644 by default. The parent dir is
    0700 so a co-tenant cannot traverse to read them today, BUT if
    the parent perms ever loosen (a backup tool, a sync tool, an
    accidental chmod -R, a recovery rsync that doesn't preserve
    modes), the inner files become world-readable AND contain enough
    material (encrypted-key blobs + the encrypted database) to
    brute-force the password offline. Tighten everything to least
    privilege.

    Returns None on success, or a human-readable error string if any
    target exists but cannot be brought to the required mode. The
    caller decides whether to refuse to start.

    On Windows POSIX modes don't apply; instead we attempt an icacls
    sweep removing 'Everyone' / 'Users' inheritance.
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
        # Refuse symlinks outright. follow_symlinks=False on chmod is
        # not portable (Linux doesn't support it on regular files),
        # so we just check first and bail. A symlink at one of these
        # paths means something is wrong; we will not chmod the
        # symlink target on the user's behalf.
        if path.is_symlink():
            return (
                f"{path} is a symlink; refusing to chmod through it. "
                f"Inspect the data dir; this should never happen."
            )
        if not path.exists():
            continue
        if must_be_dir and not path.is_dir():
            return f"{path} exists but is not a directory"
        if not must_be_dir and path.is_dir():
            return f"{path} unexpectedly is a directory"
        try:
            # Prefer follow_symlinks=False where supported (some POSIX
            # systems support it on dirs but not files). We already
            # rejected symlinks above, so this is belt-and-braces.
            try:
                os.chmod(path, mode, follow_symlinks=False)
            except (NotImplementedError, OSError):
                os.chmod(path, mode)
        except OSError as exc:
            return f"could not chmod {path} to {mode:o}: {exc}"
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            return f"could not stat {path}: {exc}"
        actual = stat.S_IMODE(st.st_mode)
        if actual != mode:
            return (
                f"{path} mode is {actual:o} after chmod, expected {mode:o}"
            )

    # Defense-in-depth recursive sweep of data_dir/real. We use os.walk
    # with followlinks=False so a malicious symlink planted deep inside
    # cannot redirect our chmod to /etc/passwd or similar. Errors during
    # traversal (permissions, missing files mid-walk) are recorded but
    # do not abort: the pinned targets above are the security-critical
    # ones; this loop is a hardening best-effort.
    #
    # Files Briar bundles under real/tor/ that MUST stay executable for
    # the tor plugin to start. If we strip +x from any of these, Briar
    # fails with "error=13, Permission denied" and contacts hang in
    # 'pending' forever. We self-heal +x on this list even if a prior
    # bad sweep had already removed it.
    tor_executables = {"tor", "obfs4proxy", "lyrebird", "snowflake"}
    real_dir = data_dir / "real"
    if real_dir.is_dir() and not real_dir.is_symlink():
        for root, dirs, files in os.walk(real_dir, followlinks=False):
            root_path = Path(root)
            try:
                if not root_path.is_symlink():
                    os.chmod(root_path, 0o700)
            except OSError:
                pass  # best-effort; pinned target above already covered real/
            for name in files:
                p = root_path / name
                try:
                    if p.is_symlink():
                        continue  # never chmod through a symlink
                    # Decide target mode: keep owner-execute if the
                    # file already has it, or if it's a known Tor
                    # helper that Briar will exec(). Otherwise tighten
                    # to 0600.
                    target = 0o600
                    if name in tor_executables:
                        target = 0o700
                    else:
                        try:
                            cur = stat.S_IMODE(
                                os.stat(p, follow_symlinks=False).st_mode
                            )
                            if cur & 0o100:
                                target = 0o700
                        except OSError:
                            pass
                    os.chmod(p, target)
                except OSError:
                    # Common: file vanished mid-walk (Tor / Briar
                    # rotating state). Not a security failure; ignore.
                    continue
            for name in dirs:
                p = root_path / name
                try:
                    if p.is_symlink():
                        continue
                    os.chmod(p, 0o700)
                except OSError:
                    continue

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


def detect_briar_bind_host(briar_pid: int, port: int) -> Optional[str]:
    """Return a warning string iff briar-headless is bound to a wildcard
    or non-loopback address on `port`; return None if it's loopback-only,
    or if we can't determine the bind state (we never warn falsely).

    Why this check exists, in plain terms: briar-headless 0.6.x has no
    --host flag - it always binds its REST/WebSocket API to wildcard.
    On a machine with any active LAN interface, that means any peer on
    the same Wi-Fi / Ethernet broadcast domain can reach port 7001.
    The bearer token (256 bits, in ~/.giz/real/auth_token at mode 0600)
    still gates reads and writes, so message content and contact list
    are NOT exposed; but the daemon is fingerprintable (a hostile peer
    on the LAN can confirm "this user runs Briar") and DoS'able (TCP
    flood the listener and Briar stops accepting commands until the
    LAN attacker stops). For clients on hostile networks (cafes, hotel
    Wi-Fi, conference Wi-Fi) we surface this as a user-facing warning
    rather than silently start.

    Detection strategy: parse the kernel's listening-socket table via
    lsof / ss / netstat. We never make outbound network calls (the
    socket guard would block them anyway, and we want this probe to
    run BEFORE the user is even logged in to their account). If no
    tool is available we return None (cannot verify; do not warn).
    """

    binds = _list_listen_binds_for_pid(briar_pid, port)
    if binds is None:  # could not determine
        return None
    if not binds:
        return None  # not listening (yet); no warning

    # These are bind-string markers we *match against* in lsof/ss output
    # to warn the user when briar bound there; we never bind here.
    wildcard_markers = {"*", "0.0.0.0", "::", "[::]", "[*]", ""}  # noqa: S104  # nosec B104
    is_wildcard = any(b in wildcard_markers for b in binds)
    is_loopback_only = all(
        b == "127.0.0.1" or b == "::1" or b == "[::1]" for b in binds
    )
    if is_loopback_only:
        return None  # the safe case
    if is_wildcard:
        return (
            f"WARNING: briar-headless on port {port} is bound to a "
            f"wildcard address ({sorted(set(binds))}). Any device on "
            f"the same LAN can reach the API. Bearer-token auth "
            f"(in ~/.giz/real/auth_token, mode 0600) still gates "
            f"message access, but the daemon is fingerprintable and "
            f"DoS'able from the network. RECOMMENDED: only run giz "
            f"on a trusted network, OR add a system firewall rule "
            f"blocking inbound TCP to port {port} from any non-"
            f"loopback source. macOS: System Settings -> Network -> "
            f"Firewall, or 'pfctl' rule. Linux: 'iptables -A INPUT "
            f"-p tcp --dport {port} ! -i lo -j DROP'. See "
            f"SECURITY.md, section 'LAN reachability'."
        )
    # Bound to specific non-loopback IPs (rare). Treat as warning.
    return (
        f"WARNING: briar-headless on port {port} is bound to non-"
        f"loopback addresses ({sorted(set(binds))}). Same caveats "
        f"as wildcard binding apply. See SECURITY.md."
    )


def _list_listen_binds_for_pid(pid: int, port: int) -> Optional[list[str]]:
    """Return a list of bind hosts for `port` listened by `pid`.

    Returns None when we cannot determine (no tool available, or tool
    failed). Returns [] when the pid is not listening on `port` yet.
    """
    import shutil
    import subprocess

    if shutil.which("lsof"):
        try:
            r = subprocess.run(
                ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-a", "-p", str(pid)],
                capture_output=True, text=True, timeout=5.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return _parse_lsof_binds(r.stdout, port)

    if shutil.which("ss"):
        try:
            r = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=5.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return _parse_ss_binds(r.stdout, port, pid)

    return None


def _parse_lsof_binds(stdout: str, port: int) -> list[str]:
    """Parse `lsof -nP -iTCP -sTCP:LISTEN` output. NAME column looks
    like '127.0.0.1:7001 (LISTEN)' or '*:7001 (LISTEN)'."""
    binds: list[str] = []
    suffix = f":{port}"
    for line in stdout.splitlines():
        if "(LISTEN)" not in line:
            continue
        for tok in line.split():
            if tok.endswith(suffix):
                host = tok[: -len(suffix)]
                # IPv6 lsof format: [::]:7001 -> host = "[::]"
                binds.append(host)
                break
    return binds


def _parse_ss_binds(stdout: str, port: int, pid: int) -> list[str]:
    """Parse `ss -tlnp` output. Local Address column is host:port; pid
    appears in the Process column as 'pid=<n>'."""
    binds: list[str] = []
    suffix = f":{port}"
    pid_marker = f"pid={pid},"
    for line in stdout.splitlines():
        if pid_marker not in line and f"pid={pid})" not in line:
            continue
        for tok in line.split():
            if tok.endswith(suffix):
                host = tok[: -len(suffix)]
                binds.append(host)
                break
    return binds


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
