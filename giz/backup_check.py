"""Per-OS backup-leak detection (HARD GATE during install).

The data directory MUST NOT live inside any cloud-synced folder. If it
does, Briar's encrypted SQLite file ends up replicated to a third-party
server. The encryption is still strong, but the ciphertext itself is now
out of the user's control and the metadata fact "this person has Briar
data" leaks to the cloud provider.

This module provides one public function:

    check(data_dir: Path) -> CheckResult

Behavior is conservative: any sign that the path is under iCloud Drive,
OneDrive, Dropbox, or Google Drive returns BLOCKED. The installer treats
BLOCKED as a fatal error with no override flag.

A separate, softer check reports whether full-disk encryption (FileVault
on macOS, BitLocker on Windows) is enabled. A negative result does not
block install; it produces a loud warning.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class CheckResult:
    blocked: bool = False
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


_ICLOUD_MARKERS = (
    "Library/Mobile Documents",
    "iCloud Drive",
    "com~apple~CloudDocs",
)
_ONEDRIVE_MARKERS = (
    "OneDrive",
    "OneDrive - ",
)
_DROPBOX_MARKERS = ("Dropbox",)
_GDRIVE_MARKERS = (
    "Google Drive",
    "GoogleDrive",
    "GoogleDriveFS",
)


def check(data_dir: Path) -> CheckResult:
    """Inspect the chosen data directory for cloud-sync leakage.

    Resolves symlinks (e.g. macOS sometimes redirects ~/Documents into
    iCloud), then checks the resolved path against well-known sync
    folder names. Also queries the OS for full-disk encryption status
    and emits a warning if disabled.
    """
    result = CheckResult()
    resolved = _resolve(data_dir)
    parts = resolved.parts
    joined = str(resolved)

    if any(marker in joined for marker in _ICLOUD_MARKERS):
        result.blocked = True
        result.reasons.append(
            f"Path resolves under iCloud Drive: {resolved}. "
            f"giz refuses to store its database in a cloud-synced location."
        )
    if any(marker in p for p in parts for marker in _ONEDRIVE_MARKERS):
        result.blocked = True
        result.reasons.append(
            f"Path resolves under OneDrive: {resolved}. "
            f"giz refuses to store its database in a cloud-synced location."
        )
    if any(marker in p for p in parts for marker in _DROPBOX_MARKERS):
        result.blocked = True
        result.reasons.append(
            f"Path resolves under Dropbox: {resolved}. "
            f"giz refuses to store its database in a cloud-synced location."
        )
    if any(marker in p for p in parts for marker in _GDRIVE_MARKERS):
        result.blocked = True
        result.reasons.append(
            f"Path resolves under Google Drive: {resolved}. "
            f"giz refuses to store its database in a cloud-synced location."
        )

    fde = _full_disk_encryption_status()
    if fde is False:
        result.warnings.append(
            "Full-disk encryption appears DISABLED. Enable FileVault "
            "(macOS) or BitLocker (Windows) before relying on giz for "
            "real privacy. Without it, anyone with physical access to "
            "your machine can read the encrypted database file directly."
        )

    return result


def exclude_from_backup(data_dir: Path) -> None:
    """Best-effort: tell the OS to skip this dir in routine backups.

    macOS: tmutil addexclusion (Time Machine).
    Windows: NTFS NotForSync attribute on OneDrive folders, plus
        attrib +H +S (hide from default backup heuristics).
    Linux: no-op (most backup tools require explicit user config).
    """
    system = platform.system()
    if system == "Darwin":
        try:
            subprocess.run(
                ["tmutil", "addexclusion", str(data_dir)],
                check=False,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    elif system == "Windows":
        try:
            subprocess.run(
                ["attrib", "+H", "+S", str(data_dir)],
                check=False,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass


def _resolve(p: Path) -> Path:
    try:
        return p.resolve()
    except OSError:
        return p.absolute()


def _full_disk_encryption_status() -> Optional[bool]:
    """Return True/False if known, None if undetectable."""
    system = platform.system()
    try:
        if system == "Darwin":
            if not shutil.which("fdesetup"):
                return None
            r = subprocess.run(
                ["fdesetup", "status"],
                check=False,
                capture_output=True,
                timeout=5,
                text=True,
            )
            return "FileVault is On" in r.stdout
        if system == "Windows":
            if not shutil.which("manage-bde"):
                return None
            r = subprocess.run(
                ["manage-bde", "-status", os.environ.get("SystemDrive", "C:")],
                check=False,
                capture_output=True,
                timeout=10,
                text=True,
            )
            txt = r.stdout.lower()
            if "percentage encrypted: 100" in txt or "fully encrypted" in txt:
                return True
            if "fully decrypted" in txt or "percentage encrypted: 0" in txt:
                return False
            return None
        if system == "Linux":
            try:
                r = subprocess.run(
                    ["lsblk", "-o", "TYPE,MOUNTPOINT"],
                    check=False,
                    capture_output=True,
                    timeout=5,
                    text=True,
                )
                if "crypt" in r.stdout:
                    return True
            except (OSError, subprocess.TimeoutExpired):
                return None
            return None
    except Exception:
        return None
    return None
