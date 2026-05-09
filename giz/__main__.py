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

    Persona spawn (giz new <name>):
        - validate persona name
        - compute a fresh data dir (~/.giz-<name> or LOCALAPPDATA\\giz-<name>)
        - subprocess into 'giz --setup --data-dir ... --port ...'
        - drop a 'giz-<name>' launcher onto PATH
        - exit cleanly
        Personas are NEVER listed inside any running giz process; the
        only way to discover them is filesystem inspection. This keeps
        the duress-wipe model intact.

The install scripts call us with --setup once, then create a launcher
that calls us without --setup for every subsequent run.
"""

from __future__ import annotations

import argparse
import getpass
import os
import platform
import re
import subprocess
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

    # Build the argparse once and use parse_known_args so flag/value
    # pairs (e.g. '--data-dir /path') are consumed properly. Whatever
    # positional tokens remain are real subcommand args.
    parser = argparse.ArgumentParser(prog="giz", add_help=True)
    parser.add_argument("--data-dir", type=Path, default=_data_dir_default())
    parser.add_argument("--jar", type=Path, default=None)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--setup", action="store_true",
                        help="first-run interactive setup")
    parser.add_argument(
        "command", nargs="?", default=None,
        help="subcommand: 'new' to create an additional persona",
    )
    parser.add_argument(
        "command_args", nargs=argparse.REMAINDER,
        help="arguments to the subcommand",
    )
    args = parser.parse_args(raw)

    # Subcommand routing. Runs BEFORE install_guards so the parent
    # holds no lockfile and never touches the new persona's data dir;
    # the child subprocess does its own hardening.
    if args.command == "new":
        if not args.command_args:
            sys.stderr.write("usage: giz new <persona-name>\n")
            return 19
        return _new_persona(args.command_args[0], args.jar)
    if args.command is not None:
        sys.stderr.write(f"unknown command: {args.command}\n")
        return 23

    data_dir = args.data_dir.expanduser()
    data_dir.mkdir(parents=True, exist_ok=True)

    hardening.install_guards(data_dir)
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
        token = _wait_for_token(real_dir)
    except TimeoutError as exc:
        proc.stop()
        sys.stderr.write(f"daemon did not produce auth token: {exc}\n")
        return 14

    # Re-tighten after briar-headless wrote auth_token. enforce_perms is
    # silent on success and reports any path it could not lock down.
    perms_error = hardening.enforce_perms(data_dir)
    if perms_error:
        sys.stderr.write(f"warning: {perms_error}\n")

    client = briar.BriarClient("127.0.0.1", free_port, token)
    try:
        client.wait_until_ready()
    except briar.BriarError as exc:
        proc.stop()
        client.close()
        sys.stderr.write(f"daemon never became ready: {exc}\n")
        return 15

    app = GizApp(
        client,
        nickname="you",
        daemon_pid=proc.pid,
        daemon_port=free_port,
        started_at=time.time(),
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


_PERSONA_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_RESERVED_PERSONAS = {"new", "main", "default", "setup", "help"}


def _extract_flag(argv: list, flag: str) -> Optional[Path]:
    """Return the value of --flag <value> from argv, or None."""
    for i, tok in enumerate(argv):
        if tok == flag and i + 1 < len(argv):
            return Path(argv[i + 1]).expanduser()
        if tok.startswith(flag + "="):
            return Path(tok[len(flag) + 1:]).expanduser()
    return None


def _persona_data_dir(persona: str) -> Path:
    if platform.system() == "Windows":
        local = os.environ.get("LOCALAPPDATA")
        root = Path(local) if local else Path.home()
        return root / f"giz-{persona}"
    return Path.home() / f".giz-{persona}"


def _new_persona(persona: str, jar: Optional[Path]) -> int:
    """Create an additional persona alongside the primary account.

    Personas are independent: separate keypairs, separate Briar databases,
    separate duress passwords, separate launchers. No giz process ever
    sees more than one persona at a time, so unlocking one does not
    reveal the others' existence inside the app. Discovery requires
    filesystem access, which is the same threat-model boundary as
    everything else giz protects.
    """
    if not _PERSONA_RE.fullmatch(persona) or persona in _RESERVED_PERSONAS:
        sys.stderr.write(
            "persona must be lowercase letters/digits/dash, start with a "
            "letter, max 32 chars, and not 'new'/'main'/'default'/'setup'/'help'.\n"
        )
        return 20

    data_dir = _persona_data_dir(persona)
    if (data_dir / duress.HASHES_FILENAME).exists():
        sys.stderr.write(
            f"persona '{persona}' already exists at {data_dir}.\n"
            f"to recreate it, delete that directory and rerun.\n"
        )
        return 21

    if jar is None or not jar.exists():
        sys.stderr.write(
            "internal error: no JAR path passed to 'giz new'. "
            "are you running giz directly instead of via the launcher?\n"
        )
        return 22

    port = lifecycle.find_free_port(7002)

    print(f"creating persona '{persona}' at {data_dir} on port {port}")
    rc = subprocess.call(
        [sys.executable, "-m", "giz",
         "--setup",
         "--data-dir", str(data_dir),
         "--port", str(port),
         "--jar", str(jar)],
    )
    if rc != 0:
        return rc

    launcher = _write_persona_launcher(persona, data_dir, jar, port)
    print(f"\nready. run '{launcher.name}' to log in as '{persona}'.")
    return 0


def _write_persona_launcher(
    persona: str, data_dir: Path, jar: Path, port: int,
) -> Path:
    venv_giz = Path(sys.executable).parent / (
        "giz.exe" if platform.system() == "Windows" else "giz"
    )
    if platform.system() == "Windows":
        bin_dir = jar.parent / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        launcher = bin_dir / f"giz-{persona}.cmd"
        launcher.write_text(
            "@echo off\n"
            f'"{venv_giz}" --data-dir "{data_dir}" --jar "{jar}" '
            f'--port {port} %*\n',
            encoding="ascii",
        )
    else:
        bin_dir = Path.home() / ".local" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        launcher = bin_dir / f"giz-{persona}"
        launcher.write_text(
            "#!/usr/bin/env bash\n"
            "set -e\n"
            f'exec "{venv_giz}" \\\n'
            f'    --data-dir "{data_dir}" \\\n'
            f'    --jar "{jar}" \\\n'
            f'    --port {port} \\\n'
            f'    "$@"\n',
        )
        os.chmod(launcher, 0o755)
    return launcher


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


def _wait_for_token(real_dir: Path, timeout_seconds: float = 90.0) -> str:
    deadline = time.monotonic() + timeout_seconds
    token_path = real_dir / "auth_token"
    while time.monotonic() < deadline:
        if token_path.exists():
            tok = token_path.read_text().strip()
            if tok:
                return tok
        time.sleep(0.5)
    raise TimeoutError(f"no auth token at {token_path}")


if __name__ == "__main__":
    sys.exit(main())
