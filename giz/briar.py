"""REST + WebSocket client for the local briar-headless daemon.

briar-headless exposes its API on 127.0.0.1 only and authenticates
every request with a bearer token written by Briar to the data
directory. We never make network calls outside the loopback interface;
all real network traffic is Briar's own Tor-routed traffic, which
happens inside the daemon process and is invisible to this client.

Endpoints we use (from briar-headless/README.md):
    GET    /v1/contacts                    list contacts
    GET    /v1/contacts/add/link           our own briar:// link
    POST   /v1/contacts/add/pending        add a pending contact
    PUT    /v1/contacts/{id}/alias         set alias
    DELETE /v1/contacts/{id}               remove contact
    GET    /v1/messages/{contactId}        history with one contact
    POST   /v1/messages/{contactId}        send a private message
    POST   /v1/messages/{contactId}/read   mark messages as read
    WS     /v1/ws                          real-time event stream

We deliberately do NOT touch blogs, forums, groups, file transfer, or
introduction protocols. Less surface, less to audit.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import requests
import websocket  # websocket-client


@dataclass
class Contact:
    id: int
    author_id: str
    name: str
    alias: Optional[str]
    handshake_pubkey: Optional[str]
    verified: bool
    connected: bool

    @property
    def display(self) -> str:
        return self.alias or self.name


@dataclass
class Message:
    contact_id: int
    text: str
    timestamp: int
    local: bool
    read: bool
    seen: bool

    @property
    def is_outgoing(self) -> bool:
        return self.local


class BriarError(Exception):
    """Raised when briar-headless returns a non-2xx response or is unreachable."""


class BriarClient:
    """Synchronous REST wrapper. Use one instance per giz process."""

    def __init__(self, host: str, port: int, token: str) -> None:
        self._base = f"http://{host}:{port}"
        self._headers = {"Authorization": f"Bearer {token}"}
        self._session = requests.Session()
        self._session.trust_env = False  # never use HTTP(S)_PROXY env

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass

    def wait_until_ready(self, timeout_seconds: float = 90.0) -> None:
        """Block until the daemon answers /v1/contacts.

        First-launch usually completes inside 60s (Tor bootstrap +
        hidden-service publish). We give an extra buffer.
        """
        deadline = time.monotonic() + timeout_seconds
        last_err: Optional[Exception] = None
        while time.monotonic() < deadline:
            try:
                self.list_contacts()
                return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                time.sleep(1.0)
        raise BriarError(
            f"briar-headless did not become ready within {timeout_seconds:.0f}s"
            + (f" (last error: {last_err})" if last_err else "")
        )

    def my_link(self) -> str:
        return self._get("/v1/contacts/add/link")["link"]

    def list_contacts(self) -> List[Contact]:
        return [_parse_contact(c) for c in self._get("/v1/contacts")]

    def list_pending_contacts(self) -> List[Dict[str, Any]]:
        try:
            return self._get("/v1/contacts/add/pending")
        except BriarError:
            return []

    def add_pending(self, link: str, alias: str) -> None:
        self._post(
            "/v1/contacts/add/pending",
            json_body={"link": link, "alias": alias},
        )

    def set_alias(self, contact_id: int, alias: str) -> None:
        self._put(f"/v1/contacts/{contact_id}/alias", json_body={"alias": alias})

    def delete_contact(self, contact_id: int) -> None:
        self._delete(f"/v1/contacts/{contact_id}")

    def remove_pending(self, pending_id: str) -> None:
        """Cancel a pending contact (one we added but Tor handshake hasn't
        finished).

        Briar's headless API takes the id in the JSON BODY, not the path:
            DELETE /v1/contacts/add/pending
            { "pendingContactId": "<base64>" }
        (verified against briar-headless ContactControllerImpl.kt)."""
        self._request(
            "DELETE",
            "/v1/contacts/add/pending",
            json_body={"pendingContactId": pending_id},
        )

    def messages(self, contact_id: int) -> List[Message]:
        return [
            _parse_message(m, contact_id) for m in self._get(f"/v1/messages/{contact_id}")
        ]

    def send_message(self, contact_id: int, text: str) -> None:
        self._post(f"/v1/messages/{contact_id}", json_body={"text": text})

    def mark_read(self, contact_id: int) -> None:
        try:
            self._post(f"/v1/messages/{contact_id}/read", json_body={})
        except BriarError:
            pass

    def _get(self, path: str) -> Any:
        return self._request("GET", path)

    def _post(self, path: str, json_body: Optional[Dict[str, Any]] = None) -> Any:
        return self._request("POST", path, json_body=json_body)

    def _put(self, path: str, json_body: Optional[Dict[str, Any]] = None) -> Any:
        return self._request("PUT", path, json_body=json_body)

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    def _request(
        self,
        method: str,
        path: str,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = self._base + path
        try:
            r = self._session.request(
                method,
                url,
                headers=self._headers,
                json=json_body,
                timeout=15,
            )
        except requests.RequestException as exc:
            raise BriarError(f"{method} {path}: {exc}") from None
        if not r.ok:
            raise BriarError(f"{method} {path}: HTTP {r.status_code} {r.text[:200]}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            return r.text


def _parse_contact(obj: Dict[str, Any]) -> Contact:
    return Contact(
        id=int(obj.get("contactId", obj.get("id", 0))),
        author_id=str(obj.get("authorId", obj.get("author", {}).get("id", ""))),
        name=str(obj.get("author", {}).get("name", obj.get("name", ""))),
        alias=obj.get("alias") or None,
        handshake_pubkey=obj.get("handshakePublicKey"),
        verified=bool(obj.get("verified", False)),
        connected=bool(obj.get("connected", False)),
    )


def _parse_message(obj: Dict[str, Any], contact_id: int) -> Message:
    return Message(
        contact_id=contact_id,
        text=str(obj.get("text", "")),
        timestamp=int(obj.get("timestamp", 0)),
        local=bool(obj.get("local", False)),
        read=bool(obj.get("read", False)),
        seen=bool(obj.get("seen", False)),
    )


class EventSubscription:
    """Background thread that streams /v1/ws events.

    Callers register a single callback that runs on the WS thread.
    Reconnect is bounded; permanent disconnects raise into the callback
    so the TUI can show "daemon stopped" rather than silently lying.
    """

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        on_event: Callable[[Dict[str, Any]], None],
        on_disconnect: Callable[[Optional[Exception]], None],
    ) -> None:
        self._url = f"ws://{host}:{port}/v1/ws"
        self._token = token
        self._on_event = on_event
        self._on_disconnect = on_disconnect
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        retries = 0
        last_exc: Optional[Exception] = None
        while not self._stop.is_set() and retries < 5:
            try:
                ws = websocket.create_connection(self._url, timeout=10)
                try:
                    ws.send(self._token)
                    retries = 0
                    while not self._stop.is_set():
                        ws.settimeout(30)
                        raw = ws.recv()
                        if not raw:
                            continue
                        try:
                            event = json.loads(raw)
                        except ValueError:
                            continue
                        try:
                            self._on_event(event)
                        except Exception:
                            pass
                finally:
                    try:
                        ws.close()
                    except Exception:
                        pass
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                retries += 1
                time.sleep(min(2 ** retries, 30))
        if not self._stop.is_set():
            try:
                self._on_disconnect(last_exc)
            except Exception:
                pass


def read_token(data_dir: Path) -> str:
    """The token file is written by briar-headless on first launch."""
    path = data_dir / "auth_token"
    if not path.exists():
        raise BriarError(f"missing auth token at {path}")
    return path.read_text().strip()
