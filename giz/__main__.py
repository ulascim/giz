"""giz entry point - python -m giz [--setup]

Two modes:

    Normal run (no --setup):
        - read the on-disk hash file
        - prompt for password (silent, getpass)
        - if matches real    -> start briar-headless, launch TUI
        - if matches duress  -> silent wipe, fake error, exit 0
        - if matches neither -> retry with backoff

    First-run setup (--setup):
        - prompt for nickname, real password, duress password
        - create Briar account (lifecycle.setup_first_run)
        - persist Argon2 hashes
        - exit cleanly

The install scripts call us with --setup once, then create a launcher
that calls us without --setup for every subsequent run.

There is intentionally NO 'giz new <persona>' subcommand. Briar's
embedded Tor cannot share local ports between two instances on the
same machine, so a second persona's hidden services silently never
publish and its contacts stay 'pending' forever. Rather than ship
a feature that breaks in confusing ways, giz allows exactly one
account per machine. Use a different physical machine for a
separate identity.
"""

from __future__ import annotations

import argparse
import getpass
import os
import platform
import sys
import time
from pathlib import Path
from typing import Optional

from . import backup_check, briar, duress, hardening, lifecycle
from .app import GizApp


DEFAULT_DATA_DIR = Path.home() / ".giz"
DEFAULT_PORT = 7001


def _data_dir_default() -> Path:
    if platform.system() == "Windows":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "giz"
    return DEFAULT_DATA_DIR


def main(argv: Optional[list] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(prog="giz", add_help=True)
    parser.add_argument("--data-dir", type=Path, default=_data_dir_default())
    parser.add_argument("--jar", type=Path, default=None)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--setup", action="store_true",
                        help="first-run interactive setup")
    args = parser.parse_args(raw)

    data_dir = args.data_dir.expanduser()
    data_dir.mkdir(parents=True, exist_ok=True)

    hardening.install_guards(data_dir)
    # Machine-wide lock: refuse to start a second briar-headless on
    # the same host, because Briar's embedded Tor cannot share local
    # ports and the second one's hidden services silently never
    # publish. Exempt --setup so a re-run of first-time setup does
    # not get blocked by a stale lock from a crashed earlier run.
    if not args.setup:
        try:
            hardening.acquire_machine_lock()
        except hardening.MachineLockError as exc:
            sys.stderr.write(f"refused to start: {exc}\n")
            return 17
    perms_error = hardening.enforce_perms(data_dir)
    if perms_error:
        sys.stderr.write(f"refused to start: {perms_error}\n")
        return 16
    swap_warning = hardening.detect_unencrypted_swap()
    if swap_warning:
        sys.stderr.write(f"warning: {swap_warning}\n")

    if args.setup:
        return _setup(data_dir, _resolve_jar(args.jar), args.port)

    return _run(data_dir, _resolve_jar(args.jar), args.port)


def _resolve_jar(explicit: Optional[Path]) -> Path:
    """Find the briar-headless JAR.

    The installer places the JAR at <data_dir>/briar-headless.jar but
    callers may also pass --jar explicitly. We never search the wider
    filesystem; if neither path is set, we fail loud rather than guess.
    """
    if explicit is not None:
        return explicit.expanduser().resolve()
    candidates = [
        _data_dir_default() / "briar-headless.jar",
        Path.home() / ".local" / "share" / "giz" / "briar-headless.jar",
    ]
    for c in candidates:
        if c.exists():
            return c
    sys.stderr.write(
        "error: cannot find briar-headless JAR. "
        "Pass --jar <path> or run the installer.\n"
    )
    sys.exit(2)


def _setup(data_dir: Path, jar: Path, port: int) -> int:
    backup = backup_check.check(data_dir)
    if backup.blocked:
        for r in backup.reasons:
            sys.stderr.write(f"error: {r}\n")
        sys.stderr.write(
            "Pick a different --data-dir outside any cloud-synced folder, "
            "then re-run setup.\n"
        )
        return 3
    for w in backup.warnings:
        sys.stderr.write(f"warning: {w}\n")
    backup_check.exclude_from_backup(data_dir)

    if duress.Hashes.load(data_dir) is not None:
        sys.stderr.write(
            f"setup refused: hash file already exists at {data_dir}. "
            f"To start over, delete {data_dir}/{duress.HASHES_FILENAME} "
            f"and {data_dir}/{duress.REAL_DIR_NAME}/.\n"
        )
        return 4

    print("giz first-run setup\n")
    print("You will pick three things:")
    print("  1) a nickname (visible to your contacts)")
    print("  2) a real password (unlocks your account)")
    print("  3) a duress password (typing it WIPES all real data, irreversibly)")
    print()
    print("The duress password exists for situations where you are forced")
    print("to unlock giz. Type it and your real account is destroyed; the")
    print("app appears to have never been used. There is no recovery.\n")

    nickname = input("nickname: ").strip()
    if not nickname:
        sys.stderr.write("nickname cannot be empty\n")
        return 5
    if len(nickname) > 50:
        sys.stderr.write("nickname too long (max 50 chars)\n")
        return 5

    real_pw = _read_password_twice("real password")
    if real_pw is None:
        return 6
    duress_pw = _read_password_twice("duress password")
    if duress_pw is None:
        return 6

    if bytes(real_pw) == bytes(duress_pw):
        sys.stderr.write("real and duress passwords must differ\n")
        hardening.zero_bytes(real_pw)
        hardening.zero_bytes(duress_pw)
        return 7
    if len(real_pw) < 8 or len(duress_pw) < 8:
        sys.stderr.write("both passwords must be at least 8 characters\n")
        hardening.zero_bytes(real_pw)
        hardening.zero_bytes(duress_pw)
        return 7
    # Briar's password-strength estimator is min(1, unique_chars/12)
    # and demands >= 0.5 to accept an account-creation password.
    # We enforce >= 6 unique chars on our side so Briar never rejects.
    if len(set(bytes(real_pw))) < 6 or len(set(bytes(duress_pw))) < 6:
        sys.stderr.write(
            "both passwords must contain at least 6 different characters\n"
        )
        hardening.zero_bytes(real_pw)
        hardening.zero_bytes(duress_pw)
        return 7

    real_dir = data_dir / duress.REAL_DIR_NAME
    real_dir.mkdir(parents=True, exist_ok=True)

    print("\nCreating Briar account (this can take 60-120 seconds)...")
    try:
        lifecycle.setup_first_run(jar, real_dir, port, nickname, real_pw)
    except lifecycle.HeadlessProcessError as exc:
        sys.stderr.write(f"first-run setup failed: {exc}\n")
        hardening.zero_bytes(real_pw)
        hardening.zero_bytes(duress_pw)
        return 8

    real_hash = duress.hash_password(bytes(real_pw))
    duress_hash = duress.hash_password(bytes(duress_pw))
    duress.Hashes(real=real_hash, duress=duress_hash).save(data_dir)

    hardening.zero_bytes(real_pw)
    hardening.zero_bytes(duress_pw)

    # Re-tighten now that briar-headless has written auth_token and
    # the database. enforce_perms is idempotent and silent on success.
    perms_error = hardening.enforce_perms(data_dir)
    if perms_error:
        sys.stderr.write(f"warning: {perms_error}\n")

    print("\nsetup complete. run 'giz' to log in.")
    return 0


def _run(data_dir: Path, jar: Path, port: int) -> int:
    hashes = duress.Hashes.load(data_dir)
    if hashes is None:
        sys.stderr.write(
            f"no account found at {data_dir}. Run setup first.\n"
        )
        return 9

    real_dir = data_dir / duress.REAL_DIR_NAME
    if not real_dir.exists():
        sys.stderr.write(
            f"account directory missing at {real_dir}. Run setup again.\n"
        )
        return 10

    pw = _prompt_password()
    if pw is None:
        return 11

    verdict = duress.check(hashes, bytes(pw))

    if verdict == duress.PasswordCheck.DURESS:
        duress.secure_wipe(data_dir)
        hardening.zero_bytes(pw)
        duress.print_fake_error_and_exit()

    if verdict != duress.PasswordCheck.REAL:
        hardening.zero_bytes(pw)
        time.sleep(2.0)
        sys.stderr.write("authentication failed\n")
        return 12

    # Make this stage talk. Without progress output the user sees a black
    # screen for up to several minutes after typing the password (Tor
    # bootstrap + hidden-service publish + API listener) and concludes
    # giz is broken. Print to STDOUT, flush, so the message survives
    # even if a child process is buffering.
    sys.stdout.write(
        "\nstarting Briar daemon...\n"
        "  first run on this machine: 1-5 minutes (Tor bootstrap + hidden service publish)\n"
        "  later runs: usually under 30 seconds\n"
    )
    sys.stdout.flush()

    free_port = lifecycle.find_free_port(port)
    proc = lifecycle.HeadlessProcess(jar, real_dir, free_port, pw)
    try:
        proc.start()
    except lifecycle.HeadlessProcessError as exc:
        hardening.zero_bytes(pw)
        sys.stderr.write(f"failed to start daemon: {exc}\n")
        return 13

    hardening.zero_bytes(pw)

    try:
        token = _wait_for_token(
            real_dir, timeout_seconds=180.0, status_writer=sys.stdout, proc=proc,
        )
    except TimeoutError as exc:
        # Surface the most common cause loud and early: Briar's
        # embedded Tor failed to bind because another giz / Briar
        # is running on this machine. Without this, the user just
        # sits at 'still loading...' for 3 minutes.
        if _daemon_log_contains(proc, "did not start") or _daemon_log_contains(
            proc, "AbstractTorWrapper.waitForTorToStart"
        ):
            sys.stderr.write(
                "\ndaemon's embedded Tor failed to start. The most common\n"
                "cause is another giz / Briar process already running on\n"
                "this machine - Briar's embedded Tor cannot share local\n"
                "ports between two instances. close the other giz, then\n"
                "try again. on a different machine, this just works.\n\n"
            )
            _dump_daemon_log(proc, sys.stderr)
            proc.stop()
            return 18
        sys.stderr.write(
            f"\ndaemon did not produce auth token: {exc}\n"
            f"this usually means Java did not start, the wrong Java\n"
            f"version is on PATH, or Tor is being blocked.\n"
            f"quick checks:\n"
            f"  java -version    # need 17; 21/24 sometimes break Briar\n"
            f"  ls {jar}\n\n"
        )
        _dump_daemon_log(proc, sys.stderr)
        proc.stop()
        return 14
    except _DaemonDiedError as exc:
        sys.stderr.write(f"\ndaemon exited before producing auth token: {exc}\n\n")
        _dump_daemon_log(proc, sys.stderr)
        proc.stop()
        return 14

    # Re-tighten after briar-headless wrote auth_token. enforce_perms is
    # silent on success and reports any path it could not lock down.
    perms_error = hardening.enforce_perms(data_dir)
    if perms_error:
        sys.stderr.write(f"warning: {perms_error}\n")

    sys.stdout.write("daemon up. waiting for API to come online (Tor circuit)...\n")
    sys.stdout.flush()

    client = briar.BriarClient("127.0.0.1", free_port, token)
    try:
        _wait_for_api(client, proc, timeout_seconds=300.0, status_writer=sys.stdout)
    except briar.BriarError as exc:
        sys.stderr.write(f"\ndaemon never became ready: {exc}\n\n")
        _dump_daemon_log(proc, sys.stderr)
        proc.stop()
        client.close()
        return 15
    except _DaemonDiedError as exc:
        sys.stderr.write(f"\ndaemon exited while waiting for API: {exc}\n\n")
        _dump_daemon_log(proc, sys.stderr)
        client.close()
        return 15

    sys.stdout.write("ready. opening UI.\n")
    sys.stdout.flush()

    app = GizApp(
        client,
        nickname="you",
        daemon_pid=proc.pid,
        daemon_port=free_port,
        started_at=time.time(),
        daemon_proc=proc,
    )
    sub = briar.EventSubscription(
        "127.0.0.1", free_port, token,
        app.handle_briar_event, app.handle_briar_disconnect,
    )
    sub.start()

    rc = 0
    try:
        result = app.run()
        if isinstance(result, int):
            rc = result
    finally:
        sub.stop()
        client.close()
        proc.stop()
    return rc


def _read_password_twice(label: str) -> Optional[bytearray]:
    while True:
        try:
            a = bytearray(getpass.getpass(f"{label}: ").encode("utf-8"))
            b = bytearray(getpass.getpass(f"{label} (again): ").encode("utf-8"))
        except (EOFError, KeyboardInterrupt):
            sys.stderr.write("\naborted\n")
            return None
        if bytes(a) == bytes(b):
            hardening.zero_bytes(b)
            return a
        hardening.zero_bytes(a)
        hardening.zero_bytes(b)
        print("passwords did not match, try again")


def _prompt_password() -> Optional[bytearray]:
    try:
        return bytearray(getpass.getpass("password: ").encode("utf-8"))
    except (EOFError, KeyboardInterrupt):
        sys.stderr.write("\n")
        return None


class _DaemonDiedError(RuntimeError):
    pass


def _wait_for_token(
    real_dir: Path,
    timeout_seconds: float = 180.0,
    *,
    status_writer=None,
    proc: Optional[lifecycle.HeadlessProcess] = None,
) -> str:
    """Poll real_dir/auth_token until briar-headless writes it.

    A first-run Tor bootstrap can legitimately use most of the timeout,
    which from the user's seat looks identical to a hang. We print
    '...still loading (Ns elapsed)' every 5 seconds so the user knows
    giz is alive and waiting. We also abort early if the daemon exited.
    """
    deadline = time.monotonic() + timeout_seconds
    token_path = real_dir / "auth_token"
    next_status = time.monotonic() + 5.0
    started = time.monotonic()
    while time.monotonic() < deadline:
        if token_path.exists():
            tok = token_path.read_text().strip()
            if tok:
                return tok
        if proc is not None and not proc.is_alive():
            raise _DaemonDiedError("briar-headless exited before opening API")
        if status_writer is not None and time.monotonic() >= next_status:
            elapsed = int(time.monotonic() - started)
            status_writer.write(f"  ...still loading ({elapsed}s elapsed)\n")
            status_writer.flush()
            next_status += 5.0
        time.sleep(0.5)
    raise TimeoutError(f"no auth token at {token_path}")


def _wait_for_api(
    client: "briar.BriarClient",
    proc: lifecycle.HeadlessProcess,
    timeout_seconds: float = 300.0,
    *,
    status_writer=None,
) -> None:
    """Block until the daemon's REST API answers, or raise.

    First-run Tor circuit + hidden service publish can take 1-5 minutes
    on the slow end (constrained networks, ISP-level Tor friction).
    We poll every second, print progress every 10 seconds, and abort
    immediately if the daemon dies.
    """
    deadline = time.monotonic() + timeout_seconds
    started = time.monotonic()
    next_status = time.monotonic() + 10.0
    last_err: Optional[Exception] = None
    while time.monotonic() < deadline:
        if not proc.is_alive():
            raise _DaemonDiedError("briar-headless exited while we were waiting")
        try:
            client.list_contacts()
            return
        except Exception as exc:  # noqa: BLE001
            last_err = exc
        if status_writer is not None and time.monotonic() >= next_status:
            elapsed = int(time.monotonic() - started)
            status_writer.write(
                f"  ...still waiting for Tor / API ({elapsed}s elapsed)\n"
            )
            status_writer.flush()
            next_status += 10.0
        time.sleep(1.0)
    raise briar.BriarError(
        f"briar-headless did not become ready within {timeout_seconds:.0f}s"
        + (f" (last error: {last_err})" if last_err else "")
    )


def _daemon_log_contains(proc: lifecycle.HeadlessProcess, needle: str) -> bool:
    try:
        for line in proc.tail_logs(200):
            if needle in line:
                return True
    except Exception:
        pass
    return False


def _dump_daemon_log(
    proc: lifecycle.HeadlessProcess,
    writer,
    n: int = 40,
) -> None:
    """Pretty-print the last n lines of daemon output for diagnosis."""
    lines = proc.tail_logs(n)
    if not lines:
        writer.write(
            "(no daemon output captured. java may not have started, or it\n"
            " produced output too late to be flushed before we asked.)\n"
        )
        writer.flush()
        return
    writer.write("--- last lines from briar-headless ---\n")
    for line in lines:
        writer.write(f"  {line}\n")
    writer.write("--- end ---\n")
    writer.flush()


if __name__ == "__main__":
    sys.exit(main())
