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

We capture the daemon's stdout+stderr into an in-memory ring buffer
(no file is ever written). Callers can ask for the tail of that buffer
when something goes wrong, so the user sees the daemon's actual error
instead of just "Connection refused".
"""

from __future__ import annotations

import collections
import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Deque, List, Optional

from . import hardening


class HeadlessProcessError(Exception):
    pass


class HeadlessProcess:
    def __init__(
        self,
        jar_path: Path,
        data_dir: Path,
        port: int,
        password: bytearray,
    ) -> None:
        # password MUST be a bytearray so the caller can zero it after
        # we've handed it to the daemon. Refuse anything else loudly.
        if not isinstance(password, bytearray):
            raise TypeError(
                "HeadlessProcess password must be a bytearray (so it can "
                "be zeroed in place after use). Got "
                f"{type(password).__name__}."
            )
        self._jar_path = jar_path
        self._data_dir = data_dir
        self._port = port
        self._password = password
        self._proc: Optional[subprocess.Popen] = None
        self._watchdog: Optional[threading.Thread] = None
        self._stdout_pump: Optional[threading.Thread] = None
        self._stderr_pump: Optional[threading.Thread] = None
        self._log_buf: Deque[str] = collections.deque(maxlen=400)
        self._log_lock = threading.Lock()
        self._died_callback = None  # type: ignore[var-annotated]
        # Populated by detect_bind_warning() once the daemon is listening.
        # See SECURITY.md "LAN reachability": briar-headless 0.6.x has no
        # --host flag and binds wildcard. We surface that to the user
        # rather than silently start.
        self._bind_warning: Optional[str] = None

    @property
    def port(self) -> int:
        return self._port

    @property
    def pid(self) -> Optional[int]:
        """OS pid of the running daemon, or None if not started / dead."""
        if self._proc is None:
            return None
        return self._proc.pid

    @property
    def bind_warning(self) -> Optional[str]:
        """Human-readable warning iff the daemon is bound LAN-reachable.

        None means: loopback-only (safe), OR we couldn't determine the
        bind state (we never warn falsely). Populated by
        detect_bind_warning(), which the caller must invoke AFTER the
        API is reachable (i.e. after BriarClient.wait_until_ready).
        """
        return self._bind_warning

    def detect_bind_warning(self) -> Optional[str]:
        """Probe the daemon's bind addresses and cache the result.

        Idempotent and never raises. Returns the same string as the
        bind_warning property after this call returns.
        """
        if self._proc is None:
            return None
        try:
            warning = hardening.detect_briar_bind_host(self._proc.pid, self._port)
        except Exception:
            # Pure best-effort. We never let a bind probe failure
            # block the user from talking to their contacts.
            warning = None
        self._bind_warning = warning
        if warning:
            self._record_log(f"giz: {warning}")
        return warning

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

        self._record_log(f"giz: launching {' '.join(cmd)}")
        self._record_log(f"giz: java is {java}")

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(self._data_dir),
            close_fds=True,
        )
        try:
            assert proc.stdin is not None
            # Write directly from the bytearray (no `bytes(...)` copy)
            # and append the newline as a separate small write, so the
            # password never lives in an immutable Python bytes object
            # we cannot zero. The BufferedWriter will copy our bytes
            # into its own kernel-pipe buffer and that copy is short-
            # lived and outside our reach regardless.
            proc.stdin.write(self._password)
            proc.stdin.write(b"\n")
            proc.stdin.flush()
            proc.stdin.close()
        except (BrokenPipeError, OSError) as exc:
            proc.kill()
            raise HeadlessProcessError(f"failed to send password to daemon: {exc}")

        self._proc = proc
        hardening.register_shutdown_hook(self.stop)

        self._stdout_pump = threading.Thread(
            target=self._pump, args=(proc.stdout, "out"), daemon=True,
        )
        self._stderr_pump = threading.Thread(
            target=self._pump, args=(proc.stderr, "err"), daemon=True,
        )
        self._stdout_pump.start()
        self._stderr_pump.start()

        self._watchdog = threading.Thread(target=self._watch, daemon=True)
        self._watchdog.start()

    def _pump(self, stream, tag: str) -> None:
        if stream is None:
            return
        try:
            for raw in iter(stream.readline, b""):
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    self._record_log(f"{tag}: {line}")
        except Exception as exc:
            self._record_log(f"giz: pump({tag}) crashed: {exc}")
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def _record_log(self, line: str) -> None:
        with self._log_lock:
            self._log_buf.append(line)

    def tail_logs(self, n: int = 40) -> List[str]:
        with self._log_lock:
            buf = list(self._log_buf)
        return buf[-n:]

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
    """Locate a Java 17 binary, preferring exact 17 over whatever is on PATH.

    Briar's headless JAR is built and tested against Java 17. Newer
    Javas (21, 24) sometimes work and sometimes throw module-access
    or reflection errors that look like a hung daemon. We therefore
    prefer Homebrew's openjdk@17 (and the standard Linux package
    paths) ahead of 'java' on PATH.
    """
    explicit_seventeen = (
        Path("/opt/homebrew/opt/openjdk@17/bin/java"),
        Path("/usr/local/opt/openjdk@17/bin/java"),
        Path("/Library/Java/JavaVirtualMachines/openjdk-17.jdk/Contents/Home/bin/java"),
        Path("/usr/lib/jvm/java-17-openjdk-amd64/bin/java"),
        Path("/usr/lib/jvm/java-17-openjdk/bin/java"),
        Path("/usr/lib/jvm/temurin-17-jdk-amd64/bin/java"),
    )
    for p in explicit_seventeen:
        if p.exists():
            return str(p)
    java = shutil.which("java")
    if java:
        return java
    fallback = (
        Path("/usr/lib/jvm/default-java/bin/java"),
    )
    for p in fallback:
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
    password: bytearray,
) -> None:
    """Run briar-headless once with --create-account-only-if-needed semantics.

    briar-headless creates the account on first run if no DB exists,
    using the provided nickname and the password we pipe in. We start
    it, wait for the API to come up, then stop it. After this, the
    DB and auth_token exist on disk and normal login works.

    password MUST be a bytearray so the caller can zero it after
    setup completes. We refuse anything else.
    """
    if not isinstance(password, bytearray):
        raise TypeError(
            "setup_first_run password must be a bytearray. "
            f"Got {type(password).__name__}."
        )
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
    log_buf: Deque[str] = collections.deque(maxlen=400)
    log_lock = threading.Lock()

    def record(line: str) -> None:
        with log_lock:
            log_buf.append(line)

    def pump(stream, tag: str) -> None:
        if stream is None:
            return
        try:
            for raw in iter(stream.readline, b""):
                if not raw:
                    break
                txt = raw.decode("utf-8", errors="replace").rstrip()
                if txt:
                    record(f"{tag}: {txt}")
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    record(f"giz: java is {java}")
    record(f"giz: launching {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(data_dir),
        close_fds=True,
    )
    threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True).start()
    threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True).start()
    try:
        assert proc.stdin is not None
        # On first run briar-headless asks for nickname and password
        # twice; we provide both. On subsequent runs it asks for the
        # password only. We stream the bytes directly - no concatenated
        # immutable bytes object that would hold the password on the
        # Python heap until GC. The BufferedWriter still copies into
        # its own buffer, but that copy is outside our reach regardless,
        # and is overwritten on close().
        proc.stdin.write(f"{nickname}\n".encode("utf-8"))
        proc.stdin.write(password)
        proc.stdin.write(b"\n")
        proc.stdin.write(password)
        proc.stdin.write(b"\n")
        proc.stdin.flush()
        proc.stdin.close()

        # First-run = brand-new identity + Tor bootstrap + descriptor
        # publish; on slow networks the original 90s budget was tight.
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if (data_dir / "auth_token").exists() and _api_responding(port):
                return
            if proc.poll() is not None:
                with log_lock:
                    tail = list(log_buf)[-40:]
                detail = "\n".join(tail) if tail else "(no daemon output)"
                raise HeadlessProcessError(
                    f"briar-headless exited during first-run setup "
                    f"(rc={proc.returncode}). last lines:\n{detail}"
                )
            time.sleep(0.5)
        with log_lock:
            tail = list(log_buf)[-40:]
        detail = "\n".join(tail) if tail else "(no daemon output)"
        raise HeadlessProcessError(
            "first-run setup timed out after 240s. last lines from "
            f"briar-headless:\n{detail}"
        )
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
