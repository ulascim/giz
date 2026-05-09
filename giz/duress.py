"""Password handling and duress wipe.

Two passwords are stored at first-run setup, both as Argon2id hashes:

    - real_hash:    matches the user's real password. On match, giz unlocks
                    the real Briar account and proceeds normally.
    - duress_hash:  matches the user's duress password. On match, giz
                    silently and irreversibly destroys the real account
                    directory, removes the hash files, prints the SAME
                    error a fresh-installed-but-not-set-up giz would
                    print, and exits with the SAME exit code. The
                    decoy is byte-for-byte identical to the genuine
                    no-account state so an attacker who has previously
                    seen 'giz' cannot tell which they are looking at.

The hashes are stored in the same data dir as the Briar database, so
the wipe path also removes the hashes themselves.

Argon2id parameters are chosen for interactive login on a laptop:
    time_cost=3, memory_cost=64 MiB, parallelism=2. This produces a
    sub-second hash on modern hardware while making offline brute force
    expensive.

The "did you type the duress password?" comparison is constant-time on
the verifier side. The wall-clock duration of the wipe path is
neutralized two ways:
    1) The slow part of the wipe (rmtree of the encrypted DB) is
       handed off to a detached child process so the giz parent can
       print the decoy error and exit immediately.
    2) The caller in __main__ time-pads every non-real-password
       outcome to a common floor, so wrong-password and duress-password
       look identical to a wall-clock observer.

`Hashes.load` distinguishes "no hash file" (returns None) from
"hash file exists but is unreadable" (raises HashesCorruptError) so
the caller can refuse to silently treat a corrupted file as a
fresh install.
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    _ARGON2_OK = True
except ImportError:
    _ARGON2_OK = False
    PasswordHasher = None  # type: ignore
    VerifyMismatchError = Exception  # type: ignore

HASHES_FILENAME = ".gizhashes"
REAL_DIR_NAME = "real"


class HashesCorruptError(RuntimeError):
    """Raised when the on-disk hash file exists but cannot be parsed.

    The caller MUST distinguish this from 'no hash file at all': a
    corrupt hash file means an account exists but is unreachable; a
    missing hash file means no account was ever created. Treating the
    first as the second would silently invite the user to overwrite a
    half-broken real account.
    """


class Hashes:
    """Persisted on-disk: { real: <argon2 hash>, duress: <argon2 hash> }"""

    def __init__(self, real: str, duress: str) -> None:
        self.real = real
        self.duress = duress

    @classmethod
    def load(cls, data_dir: Path) -> Optional["Hashes"]:
        """Return the loaded Hashes, or None if no hash file exists.

        Raises HashesCorruptError if the file exists but does not parse
        or is missing required keys. Callers MUST handle that case
        (typically by refusing to start) rather than treating it as a
        clean 'no account' state.
        """
        path = data_dir / HASHES_FILENAME
        if not path.exists():
            return None
        try:
            raw = path.read_text()
        except OSError as exc:
            raise HashesCorruptError(
                f"could not read {path}: {exc}"
            ) from None
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HashesCorruptError(
                f"hash file {path} exists but is not valid JSON: {exc}"
            ) from None
        try:
            real = obj["real"]
            duress = obj["duress"]
        except (KeyError, TypeError) as exc:
            raise HashesCorruptError(
                f"hash file {path} is missing required keys: {exc}"
            ) from None
        if not isinstance(real, str) or not isinstance(duress, str):
            raise HashesCorruptError(
                f"hash file {path} has wrong value types"
            )
        return cls(real, duress)

    def save(self, data_dir: Path) -> None:
        """Write the hash file at mode 0600 atomically.

        We open with O_CREAT|O_WRONLY|O_TRUNC|O_EXCL on a temp path with
        mode 0600, write, fsync, then rename over the destination. This
        eliminates the TOCTOU window where path.write_text() leaves the
        file world-readable until our chmod runs.
        """
        path = data_dir / HASHES_FILENAME
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp.unlink()
        except OSError:
            pass
        # 0o600 at create time. O_NOFOLLOW so a pre-placed symlink at
        # the temp name cannot redirect our write.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(tmp), flags, 0o600)
        try:
            payload = json.dumps({"real": self.real, "duress": self.duress})
            os.write(fd, payload.encode("ascii"))
            try:
                os.fsync(fd)
            except OSError:
                pass
        finally:
            os.close(fd)
        os.replace(str(tmp), str(path))
        # Belt-and-braces re-chmod in case os.replace inherited perms
        # from a target we just overwrote (rare; depends on FS).
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def _hasher() -> "PasswordHasher":
    if not _ARGON2_OK:
        raise RuntimeError(
            "argon2-cffi is required. The installer should have installed it; "
            "if you are running giz directly, install with: pip install argon2-cffi"
        )
    return PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def hash_password(password: bytes) -> str:
    """Argon2id-hash a password (provided as a bytearray or bytes)."""
    return _hasher().hash(bytes(password))


# Captures the LAST non-VerifyMismatchError from verify_password() so a
# caller can surface a hint after a few failed attempts. Without this,
# corrupt-hash-file / missing-argon2-binding / etc. all look identical
# to "wrong password" and the user retries forever.
_last_verify_error: Optional[str] = None


def last_verify_error() -> Optional[str]:
    """Return the last unusual error from verify_password(), or None.

    Distinguishes "user typed the wrong password" (returns None) from
    "argon2 raised an unexpected error we silently fail-closed on"
    (returns the str). Used by the auth-failed branch to print a
    diagnostic hint instead of leaving the user retrying blindly.
    """
    return _last_verify_error


def verify_password(stored_hash: str, candidate: bytes) -> bool:
    """True iff candidate matches stored_hash. False on any mismatch or error."""
    global _last_verify_error
    try:
        ok = _hasher().verify(stored_hash, bytes(candidate))
        # Successful verify (or InvalidHash etc. won't reach here);
        # clear any prior unusual error so old hints don't linger.
        _last_verify_error = None
        return ok
    except VerifyMismatchError:
        return False
    except Exception as exc:
        _last_verify_error = f"{type(exc).__name__}: {exc}"
        return False


class PasswordCheck:
    """Result of comparing an entered password to the stored hashes."""

    REAL = "real"
    DURESS = "duress"
    NEITHER = "neither"


def check(stored: Hashes, candidate: bytes) -> str:
    """Compare candidate against both real and duress hashes.

    Both verifications are always performed (never short-circuited) so
    timing reveals only "Argon2 ran twice" rather than which side matched.
    """
    real_ok = verify_password(stored.real, candidate)
    duress_ok = verify_password(stored.duress, candidate)
    if real_ok and not duress_ok:
        return PasswordCheck.REAL
    if duress_ok and not real_ok:
        return PasswordCheck.DURESS
    return PasswordCheck.NEITHER


def secure_wipe(data_dir: Path) -> None:
    """Irreversibly destroy the real Briar account and the hash files.

    Order matters:
        1. .gizhashes and .lock are overwritten with random bytes and
           unlinked synchronously. After this returns, no future giz
           start can find a hash file - the DB is unopenable even if
           the rmtree is interrupted.
        2. Any macOS APFS local Time Machine snapshots that might
           contain a pre-wipe copy of the data dir are best-effort
           deleted (no privilege required).
        3. The slow part - rmtree of the encrypted DB directory - is
           handed off to a DETACHED child process so the parent can
           emit the decoy output and exit immediately. This makes the
           duress path indistinguishable from a wrong-password path
           in wall-clock time.

    The wipe path is intentionally silent: no progress, no logs, no
    confirmation. By the time it runs, the user has already typed the
    duress password and the choice is irrevocable.
    """
    hashes = data_dir / HASHES_FILENAME
    real = data_dir / REAL_DIR_NAME
    lock = data_dir / ".lock"

    # Phase 1: synchronous, fast, irreversible-on-its-own.
    for sensitive in (hashes, lock):
        try:
            if sensitive.exists():
                _overwrite_then_unlink(sensitive)
        except OSError:
            try:
                sensitive.unlink()
            except OSError:
                pass

    # Phase 2: macOS local snapshots. Even with Time Machine exclusion,
    # APFS may have created automatic local snapshots that contain the
    # pre-wipe state of ~/.giz. Deleting them requires no privilege,
    # but it does take a few seconds, so we run it in a detached
    # helper instead of blocking the caller.
    _purge_local_snapshots_async()

    # Phase 3: rmtree the encrypted DB in a detached child so we can
    # return to the caller (which will exit immediately) and the
    # wall-clock cost of the rmtree is invisible from the prompt.
    if real.exists():
        if platform.system() == "Windows":
            _detached_rmtree_windows(real)
        else:
            _detached_rmtree_posix(real)


def _overwrite_then_unlink(path: Path) -> None:
    """Best-effort overwrite of a small sensitive file before unlink.

    On modern SSDs the overwrite is largely symbolic (the controller
    may write to a different physical block); the real defense against
    forensic recovery is full-disk encryption. Documented in SECURITY.md.
    """
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except OSError:
        pass


def _detached_rmtree_posix(target: Path) -> None:
    """Fire-and-forget rmtree via double-fork. Survives parent exit."""
    try:
        pid = os.fork()
    except OSError:
        # No fork available (extremely unusual). Fall back to a thread
        # and hope the parent stays alive long enough; worst case the
        # rmtree is interrupted but Phase 1 has already broken the DB.
        threading.Thread(
            target=lambda: shutil.rmtree(target, ignore_errors=True),
            daemon=False,
        ).start()
        return

    if pid != 0:
        # Parent: reap the first child immediately so it doesn't zombie.
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
        return

    # First child: detach from the parent's session, double-fork, redirect
    # std fds to /dev/null, then do the actual rmtree.
    try:
        os.setsid()
    except OSError:
        pass
    try:
        if os.fork() != 0:
            os._exit(0)
    except OSError:
        pass
    try:
        fd = os.open(os.devnull, os.O_RDWR)
        os.dup2(fd, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        if fd > 2:
            os.close(fd)
    except OSError:
        pass
    try:
        shutil.rmtree(target, ignore_errors=True)
    finally:
        os._exit(0)


def _detached_rmtree_windows(target: Path) -> None:
    """Spawn a detached python -c that does the rmtree and returns."""
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    code = (
        "import shutil, sys; "
        "shutil.rmtree(sys.argv[1], ignore_errors=True)"
    )
    try:
        subprocess.Popen(
            [sys.executable, "-c", code, str(target)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
    except Exception:
        # Last-ditch: synchronous wipe in this process.
        shutil.rmtree(target, ignore_errors=True)


def _purge_local_snapshots_async() -> None:
    """Best-effort: tell macOS to delete APFS local Time Machine snapshots
    that may contain a pre-wipe copy of the data dir.

    Runs detached so the caller is not blocked. No-op on Linux/Windows.
    Requires no elevated privileges; tmutil deletelocalsnapshots takes
    a snapshot date as argument and returns quickly.
    """
    if platform.system() != "Darwin":
        return
    code = (
        "import subprocess; "
        "r = subprocess.run(['tmutil', 'listlocalsnapshotdates', '/'], "
        "capture_output=True, text=True, timeout=5); "
        "[subprocess.run(['tmutil', 'deletelocalsnapshots', d.strip()], "
        "capture_output=True, timeout=15) "
        "for d in r.stdout.splitlines() if d.strip() and d.strip()[0:1].isdigit()]"
    )
    try:
        subprocess.Popen(
            [sys.executable, "-c", code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except Exception:
        pass
