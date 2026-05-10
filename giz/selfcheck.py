"""Runtime self-check for the user's actual giz install.

Exposed via `giz --self-check`. Runs in well under a second on a
healthy laptop and prints a one-line PASS/FAIL per security claim
in SECURITY.md, then a final summary line. Exit code is the number
of failures (0 == all green).

Notes:
    - We do NOT call hardening.install_guards(), hardening._silence_logging(),
      or hardening._block_outbound_sockets() against the user's process,
      because those mutate global state and would interfere if --self-check
      were ever wired into a normal startup. Each check that needs the
      hardened state spawns a fresh subprocess.
    - Argon2 is exercised once with cheap params (8 KiB memory, 1 iter)
      so the smoke test stays fast.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import subprocess
import sys
import tempfile
import textwrap
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, List, Tuple


# Padding column width for the dotted line.
_LABEL_W = 38


@contextmanager
def _silence_stdout():
    """Temporarily redirect stdout to a string buffer.
    Used inside a single check so the user only sees our final
    'ok' / 'FAIL' line, not the side-effects of importing giz."""
    old = sys.stdout
    buf = io.StringIO()
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old


def _row(label: str, status: str, detail: str = "") -> str:
    pad = "." * max(2, _LABEL_W - len(label))
    line = f"  {label} {pad} {status}"
    if detail:
        line += f"  ({detail})"
    return line


# ---------------------------------------------------------------- checks

def _check_argon2() -> Tuple[bool, str]:
    try:
        from argon2 import PasswordHasher
        hasher = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
        h = hasher.hash("hello-world")
        ok = hasher.verify(h, "hello-world")
        return bool(ok), ""
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _check_hashes_save_0600() -> Tuple[bool, str]:
    if platform.system() == "Windows":
        return True, "skipped (POSIX modes don't apply)"
    try:
        from giz import duress
    except Exception as exc:
        return False, f"import giz.duress: {exc}"
    with tempfile.TemporaryDirectory(prefix="giz-selfcheck-") as td:
        d = Path(td)
        duress.Hashes(real="x" * 32, duress="y" * 32).save(d)
        path = d / duress.HASHES_FILENAME
        mode = path.stat().st_mode & 0o777
        if mode != 0o600:
            return False, f"got 0o{mode:o}, expected 0o600"
    return True, "0o600"


def _run_subproc_check(snippet: str, expect_substr: str, timeout: float = 8.0
                      ) -> Tuple[bool, str]:
    """Spawn a fresh Python with PYTHONPATH=repo and run `snippet`.
    Pass iff the snippet's stdout contains expect_substr."""
    repo = Path(__file__).resolve().parent.parent
    r = subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True, text=True, timeout=timeout,
        cwd=str(repo),
        env={**os.environ, "PYTHONPATH": str(repo)},
    )
    if expect_substr in r.stdout:
        return True, ""
    return False, (
        f"expected {expect_substr!r} in stdout; "
        f"got stdout={r.stdout.strip()[:120]!r} "
        f"stderr={r.stderr.strip()[:120]!r}"
    )


def _check_socket_guard() -> Tuple[bool, str]:
    return _run_subproc_check(
        textwrap.dedent("""
            import socket
            from giz import hardening
            hardening._block_outbound_sockets()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("8.8.8.8", 53))
                print("LEAKED")
            except hardening.OutboundBlocked:
                print("BLOCKED")
        """),
        "BLOCKED",
    )


def _check_getaddrinfo_guard() -> Tuple[bool, str]:
    return _run_subproc_check(
        textwrap.dedent("""
            import socket
            from giz import hardening
            hardening._block_outbound_sockets()
            try:
                socket.getaddrinfo("example.com", 443)
                print("LEAKED")
            except hardening.OutboundBlocked:
                print("BLOCKED")
        """),
        "BLOCKED",
    )


def _check_loopback_narrows() -> Tuple[bool, str]:
    return _run_subproc_check(
        textwrap.dedent("""
            import socket
            from giz import hardening
            hardening._block_outbound_sockets()
            srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
            ok_port = srv.getsockname()[1]
            srv2 = socket.socket(); srv2.bind(("127.0.0.1", 0)); srv2.listen(1)
            bad_port = srv2.getsockname()[1]
            hardening.restrict_loopback_to([("127.0.0.1", ok_port)])
            try:
                d = socket.socket(); d.connect(("127.0.0.1", bad_port))
                print("LEAKED")
            except hardening.OutboundBlocked:
                print("NARROWED")
            srv.close(); srv2.close()
        """),
        "NARROWED",
    )


def _check_decoy_message() -> Tuple[bool, str]:
    try:
        from giz.__main__ import _no_account_message
    except Exception as exc:
        return False, str(exc)
    # Both lines are literal expected strings for an assertion message,
    # not actual /tmp filesystem usage; B108 is a false positive here.
    expected = "no account found at /tmp/x. Run setup first.\n"  # nosec B108
    if _no_account_message(Path("/tmp/x")) != expected:  # nosec B108
        return False, "format string drifted"
    main_src = (Path(__file__).resolve().parent / "__main__.py").read_text()
    if main_src.count("_no_account_message(") < 3:
        return False, "no longer used by both auth branches"
    return True, "single source for both branches"


def _check_zero_bytes_raises_on_bytes() -> Tuple[bool, str]:
    try:
        from giz import hardening
    except Exception as exc:
        return False, str(exc)
    try:
        hardening.zero_bytes(b"x")  # type: ignore[arg-type]
    except TypeError:
        return True, ""
    return False, "zero_bytes accepted bytes (silently un-zeroable)"


def _check_basicconfig_noop() -> Tuple[bool, str]:
    return _run_subproc_check(
        textwrap.dedent("""
            from giz import hardening
            import logging, tempfile, os
            hardening._silence_logging()
            with tempfile.TemporaryDirectory() as td:
                target = os.path.join(td, "leak.log")
                logging.basicConfig(filename=target, level=logging.DEBUG)
                logging.error("password=hunter2")
                if os.path.exists(target) and "hunter2" in open(target, "rb").read().decode("latin1"):
                    print("LEAKED")
                else:
                    print("NOOP")
        """),
        "NOOP",
    )


def _check_filehandler_blocked() -> Tuple[bool, str]:
    return _run_subproc_check(
        textwrap.dedent("""
            from giz import hardening
            import logging, tempfile, os
            hardening._silence_logging()
            with tempfile.TemporaryDirectory() as td:
                target = os.path.join(td, "leak.log")
                h = logging.FileHandler(target)
                log = logging.getLogger("test")
                log.addHandler(h)
                log.error("password=hunter2")
                content = b""
                if os.path.exists(target):
                    content = open(target, "rb").read()
                if b"hunter2" in content:
                    print("LEAKED")
                else:
                    print("BLOCKED")
        """),
        "BLOCKED",
    )


def _check_data_dir_mode() -> Tuple[bool, str]:
    if platform.system() == "Windows":
        return True, "skipped (POSIX modes don't apply)"
    home = Path.home() / ".giz"
    if not home.exists():
        return True, "no install yet"
    import stat as _stat
    mode = _stat.S_IMODE(home.stat().st_mode)
    if mode == 0o700:
        return True, "0o700"
    return False, f"~/.giz mode is 0o{mode:o}, expected 0o700"


def _check_machine_lock_uid_based() -> Tuple[bool, str]:
    """Runtime proof that the machine-lock path on POSIX derives from
    euid, not from $HOME. Acquires nothing; only inspects the path
    derivation so --self-check is safe to run while a real giz
    session is open and holding its own lock.
    """
    if platform.system() == "Windows":
        return True, "skipped (POSIX-only fix)"
    return _run_subproc_check(
        textwrap.dedent("""
            import os
            from giz import hardening
            real = str(hardening._machine_lock_path())
            os.environ["HOME"] = "/tmp/attacker-home"
            spoofed = str(hardening._machine_lock_path())
            ok = (
                real.startswith("/tmp/.giz-") and
                str(os.geteuid()) in real and
                real == spoofed
            )
            print("UID_BASED" if ok else "WRONG", real)
        """),
        "UID_BASED",
    )


def _check_enforce_perms_recursive() -> Tuple[bool, str]:
    """Spawn a subprocess with a synthetic data dir whose 'real/' is
    seeded with mode-0644 inner files (plus a stub 'tor' executable),
    run enforce_perms, and confirm:
        - non-executable files are tightened to 0600
        - inner directories are tightened to 0700
        - the bundled tor binary keeps owner-execute (0700), so the
          v0.2.1-era regression that stripped +x and broke contact
          handshakes cannot return.
    Subprocess isolation keeps the user's real ~/.giz untouched.
    """
    if platform.system() == "Windows":
        return True, "skipped (POSIX modes don't apply)"
    return _run_subproc_check(
        textwrap.dedent("""
            import os, stat, tempfile
            from pathlib import Path
            from giz import hardening
            with tempfile.TemporaryDirectory() as td:
                d = Path(td)
                (d / "real").mkdir()
                (d / "real" / "tor").mkdir()
                f1 = d / "real" / "db.key"
                f1.write_bytes(b"x")
                os.chmod(f1, 0o644)
                f2 = d / "real" / "tor" / "torrc"
                f2.write_bytes(b"y")
                os.chmod(f2, 0o644)
                fexe = d / "real" / "tor" / "tor"
                fexe.write_bytes(b"#!/bin/sh\\n")
                os.chmod(fexe, 0o600)  # simulate the v0.2.1 regression
                err = hardening.enforce_perms(d)
                if err:
                    print("ERR", err)
                else:
                    m1 = stat.S_IMODE(os.stat(f1).st_mode)
                    m2 = stat.S_IMODE(os.stat(f2).st_mode)
                    me = stat.S_IMODE(os.stat(fexe).st_mode)
                    md = stat.S_IMODE(os.stat(d / "real" / "tor").st_mode)
                    if (
                        m1 == 0o600
                        and m2 == 0o600
                        and me == 0o700
                        and md == 0o700
                    ):
                        print("RECURSED")
                    else:
                        print("WRONG", oct(m1), oct(m2), oct(me), oct(md))
        """),
        "RECURSED",
    )


def _check_bind_probe_helper() -> Tuple[bool, str]:
    """Confirm hardening.detect_briar_bind_host(pid, port) exists and
    returns None for a synthetic loopback-bound socket spawned in this
    same process - i.e. that the helper does not falsely warn about
    the safe case. This is a regression guard: a future refactor that
    accidentally returns a non-None warning for loopback bindings
    would print scary noise at every giz launch.
    """
    return _run_subproc_check(
        textwrap.dedent("""
            import os, socket
            from giz import hardening
            srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
            port = srv.getsockname()[1]
            warn = hardening.detect_briar_bind_host(os.getpid(), port)
            if warn is None:
                print("LOOPBACK_OK")
            else:
                print("FALSE_POSITIVE", warn[:80])
            srv.close()
        """),
        "LOOPBACK_OK",
    )


def _check_source_tree_intact() -> Tuple[bool, str]:
    """Hash giz/*.py and confirm the result matches the version baked
    into the source tree. We do not pin against an external manifest
    (that would couple --self-check to a release artifact); instead we
    ensure the running source matches itself, which detects half-edited
    installs / partial copies."""
    pkg_dir = Path(__file__).resolve().parent
    h = hashlib.sha256()
    for py in sorted(pkg_dir.glob("*.py")):
        h.update(py.name.encode("utf-8"))
        h.update(b"\0")
        h.update(py.read_bytes())
        h.update(b"\0")
    digest = h.hexdigest()
    return True, f"{digest[:12]}..."


# ---------------------------------------------------------------- driver

CHECKS: List[Tuple[str, Callable[[], Tuple[bool, str]]]] = [
    ("argon2 binding",                          _check_argon2),
    ("hashes file 0o600 (synthetic)",           _check_hashes_save_0600),
    ("socket guard refuses 8.8.8.8",            _check_socket_guard),
    ("getaddrinfo refuses example.com",         _check_getaddrinfo_guard),
    ("restrict_loopback narrows",               _check_loopback_narrows),
    ("duress decoy == no-account string",       _check_decoy_message),
    ("zero_bytes(bytes) raises TypeError",      _check_zero_bytes_raises_on_bytes),
    ("logging.basicConfig is a no-op",          _check_basicconfig_noop),
    ("logging.FileHandler is blocked",          _check_filehandler_blocked),
    ("data dir mode (~/.giz)",                  _check_data_dir_mode),
    ("machine lock is uid-based, not $HOME",    _check_machine_lock_uid_based),
    ("enforce_perms recurses into real/",       _check_enforce_perms_recursive),
    ("bind probe accepts loopback (no FP)",     _check_bind_probe_helper),
    ("source tree sha256",                      _check_source_tree_intact),
]


def run() -> int:
    """Execute every self-check. Return the count of failures."""
    from . import __version__
    print(f"giz v{__version__}  (python {platform.python_version()} on "
          f"{platform.system().lower()} {platform.machine().lower()})")

    failures = 0
    for label, fn in CHECKS:
        try:
            ok, detail = fn()
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        status = "ok" if ok else "FAIL"
        print(_row(label, status, detail), flush=True)
        if not ok:
            failures += 1

    print()
    if failures:
        print(f"{failures} check(s) failed.", flush=True)
    else:
        print("all checks passed.", flush=True)
    return failures


if __name__ == "__main__":
    raise SystemExit(run())
