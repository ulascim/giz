"""Password handling and duress wipe.

Two passwords are stored at first-run setup, both as Argon2id hashes:

    - real_hash:    matches the user's real password. On match, giz unlocks
                    the real Briar account and proceeds normally.
    - duress_hash:  matches the user's duress password. On match, giz
                    silently and irreversibly destroys the real account
                    directory, removes the hash files, prints a generic
                    "account not found" line, and exits.

The hashes are stored in the same data dir as the Briar database, so
the wipe path also removes the hashes themselves.

Argon2id parameters are chosen for interactive login on a laptop:
    time_cost=3, memory_cost=64 MiB, parallelism=2. This produces a
    sub-second hash on modern hardware while making offline brute force
    expensive.

The "did you type the duress password?" comparison is constant-time on
the verifier side. The bigger timing concern is that the wipe path takes
longer than the unlock path (rm -rf vs starting Briar). We do not try to
mask this; an attacker who can measure wall-clock can already see far
more from the visible TUI behavior afterward.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import sys
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


class Hashes:
    """Persisted on-disk: { real: <argon2 hash>, duress: <argon2 hash> }"""

    def __init__(self, real: str, duress: str) -> None:
        self.real = real
        self.duress = duress

    @classmethod
    def load(cls, data_dir: Path) -> Optional["Hashes"]:
        path = data_dir / HASHES_FILENAME
        if not path.exists():
            return None
        try:
            obj = json.loads(path.read_text())
            return cls(obj["real"], obj["duress"])
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def save(self, data_dir: Path) -> None:
        path = data_dir / HASHES_FILENAME
        path.write_text(json.dumps({"real": self.real, "duress": self.duress}))
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


def verify_password(stored_hash: str, candidate: bytes) -> bool:
    """True iff candidate matches stored_hash. False on any mismatch or error."""
    try:
        return _hasher().verify(stored_hash, bytes(candidate))
    except VerifyMismatchError:
        return False
    except Exception:
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

    Order matters: hashes are removed first so even if the rm -rf is
    interrupted partway, the password file is gone and the partial
    DB is unusable without it. Then the data dir contents are removed.

    The wipe path is intentionally silent: no progress, no logs, no
    confirmation. By the time it runs, the user has already typed the
    duress password and the choice is irrevocable.
    """
    hashes = data_dir / HASHES_FILENAME
    real = data_dir / REAL_DIR_NAME
    lock = data_dir / ".lock"

    for sensitive in (hashes, lock):
        try:
            if sensitive.exists():
                _overwrite_then_unlink(sensitive)
        except OSError:
            try:
                sensitive.unlink()
            except OSError:
                pass

    if real.exists():
        try:
            shutil.rmtree(real, ignore_errors=True)
        except Exception:
            pass


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


def print_fake_error_and_exit() -> None:
    """The single line a duress wiper sees. Looks like a fresh-install state."""
    sys.stdout.write("Account not found. Run install to set up.\n")
    sys.stdout.flush()
    sys.exit(0)
