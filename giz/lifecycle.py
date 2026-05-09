"""Start, monitor, and cleanly stop the local briar-headless subprocess.

Briar-headless reads the account password from STDIN at start. We pipe
the password in as bytes, then close STDIN; from that point onward the
daemon listens on 127.0.0.1 with a bearer token written to the data
directory.

We launch the daemon with:
    java -jar <jar> --data-dir <dir> --port <port> --no-html

and monitor it via:
    1. periodic TCP probe of the API port (in BriarClient.wait_until_ready)
    2. exit-code watchdog that triggers a shutdown hook on early death
    3. atexit / signal handlers (registered by hardening.py) that send
       SIGTERM, wait briefly, then SIGKILL.

We intentionally do NOT redirect briar-headless logs to a file; they
are inherited by the parent's stderr, which the TUI re-captures and
discards above WARN. No persistent log file is ever created.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from . import hardening


class HeadlessProcessError(Exception):
    pass


class HeadlessProcess:
    def __init__(
        self,
        jar_path: Path,
        data_dir: Path,
        port: int,
        password: bytes,
    ) -> None:
        self._jar_path = jar_path
        self._data_dir = data_dir
        self._port = port
        self._password = password
        self._proc: Optional[subprocess.Popen] = None
        self._watchdog: Optional[threading.Thread] = None
        self._died_callback = None  # type: ignore[var-annotated]

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> None:
        java = _find_java()
        if java is None:
            raise HeadlessProcessError(
                "Java 17+ not found in PATH. The installer should have "
                "installed it; if you are running giz directly, install Java."
            )
        if not self._jar_path.exists():
            raise HeadlessProcessError(
                f"briar-headless JAR not found at {self._jar_path}"
            )

        env = os.environ.copy()
        env.pop("JAVA_TOOL_OPTIONS", None)
        env.pop("_JAVA_OPTIONS", None)

        cmd = [
            java,
            "-jar",
            str(self._jar_path),
            "--data-dir",
            str(self._data_dir),
            "--port",
            str(self._port),
        ]

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=str(self._data_dir),
            close_fds=True,
        )
        try:
            assert proc.stdin is not None
            proc.stdin.write(bytes(self._password) + b"\n")
            proc.stdin.flush()
            proc.stdin.close()
        except (BrokenPipeError, OSError) as exc:
            proc.kill()
            raise HeadlessProcessError(f"failed to send password to daemon: {exc}")

        self._proc = proc
        hardening.register_shutdown_hook(self.stop)

        self._watchdog = threading.Thread(target=self._watch, daemon=True)
        self._watchdog.start()

    def stop(self, timeout_seconds: float = 5.0) -> None:
        proc = self._proc
        if proc is None:
            return
        self._proc = None
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
        except Exception:
            pass

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def on_death(self, callback) -> None:
        self._died_callback = callback

    def _watch(self) -> None:
        if self._proc is None:
            return
        rc = self._proc.wait()
        if self._died_callback is not None:
            try:
                self._died_callback(rc)
            except Exception:
                pass


def _find_java() -> Optional[str]:
    java = shutil.which("java")
    if java:
        return java
    candidates = (
        Path("/opt/homebrew/opt/openjdk@17/bin/java"),
        Path("/usr/local/opt/openjdk@17/bin/java"),
        Path("/Library/Java/JavaVirtualMachines/openjdk-17.jdk/Contents/Home/bin/java"),
        Path("/usr/lib/jvm/java-17-openjdk-amd64/bin/java"),
        Path("/usr/lib/jvm/default-java/bin/java"),
    )
    for p in candidates:
        if p.exists():
            return str(p)
    return None


def find_free_port(preferred: int = 7001) -> int:
    """Try the preferred port; fall back to any free local port.

    Port 0 is treated as "ask the OS"; we never return 0 because callers
    pass the result back to subprocess.Popen / socket.connect where 0
    is meaningless.
    """
    if preferred and preferred > 0 and _port_free(preferred):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def setup_first_run(
    jar_path: Path,
    data_dir: Path,
    port: int,
    nickname: str,
    password: bytes,
) -> None:
    """Run briar-headless once with --create-account-only-if-needed semantics.

    briar-headless creates the account on first run if no DB exists,
    using the provided nickname and the password we pipe in. We start
    it, wait for the API to come up, then stop it. After this, the
    DB and auth_token exist on disk and normal login works.
    """
    java = _find_java()
    if java is None:
        raise HeadlessProcessError("Java 17+ not found in PATH")

    cmd = [
        java,
        "-jar",
        str(jar_path),
        "--data-dir",
        str(data_dir),
        "--port",
        str(port),
    ]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(data_dir),
        close_fds=True,
    )
    try:
        assert proc.stdin is not None
        # On first run briar-headless asks for nickname and password
        # twice; we provide both. On subsequent runs it asks for the
        # password only. We send three lines and let the daemon discard
        # what it does not need.
        payload = (
            f"{nickname}\n".encode()
            + bytes(password)
            + b"\n"
            + bytes(password)
            + b"\n"
        )
        proc.stdin.write(payload)
        proc.stdin.flush()
        proc.stdin.close()

        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if (data_dir / "auth_token").exists() and _api_responding(port):
                return
            if proc.poll() is not None:
                raise HeadlessProcessError(
                    f"briar-headless exited during first-run setup (rc={proc.returncode})"
                )
            time.sleep(0.5)
        raise HeadlessProcessError("first-run setup timed out after 90s")
    finally:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            pass


def _api_responding(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            return False
