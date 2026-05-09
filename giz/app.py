"""GizApp - the Textual application that hosts the three screens.

Threading model:
    - The Textual event loop owns all UI state and runs on the main thread.
    - The websocket subscription runs on its own thread (briar.EventSubscription).
    - The WS thread calls our on_event/on_disconnect, which use
      app.call_from_thread() to dispatch onto the Textual loop.

We never touch widgets from the WS thread directly.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from textual.app import App

from .briar import BriarClient, Contact
from .screens import (
    AddContactScreen,
    ChatScreen,
    ContactsScreen,
    MyLinkScreen,
)


CSS_PATH = str(Path(__file__).with_name("styles.tcss"))


class GizApp(App):
    """Top-level Textual app for giz."""

    CSS_PATH = CSS_PATH
    TITLE = "giz"

    def __init__(
        self,
        client: BriarClient,
        nickname: str,
        *,
        daemon_pid: Optional[int] = None,
        daemon_port: Optional[int] = None,
        started_at: Optional[float] = None,
        daemon_proc: Optional[Any] = None,
    ) -> None:
        super().__init__()
        self.client = client
        self.nickname = nickname
        self.contacts_cache: List[Contact] = []
        self.unread: Dict[int, int] = {}
        self._daemon_alive = True

        # Diagnostics: surfaced by DiagnosticsScreen (key 'd' on Contacts).
        # Tests do not pass these and just see None / 0 / empty, which the
        # diagnostics screen renders as "unknown" rather than crashing.
        self.daemon_pid: Optional[int] = daemon_pid
        self.daemon_port: Optional[int] = daemon_port
        self.started_at: float = started_at if started_at is not None else time.time()
        # Reference to the live HeadlessProcess so the diagnostics
        # screen can pull tail_logs() and the user can see what
        # briar-headless is actually saying without leaving the TUI.
        self.daemon_proc = daemon_proc
        # last (timestamp, state) per pendingContactId. Updated from
        # PendingContactStateChangedEvent on the WS thread (forwarded
        # to the main thread via call_from_thread). Concrete proof
        # that briar is actively retrying the Tor handshake.
        self.pending_state_log: Dict[str, Tuple[float, str]] = {}
        # Ring buffer of the last N raw event names received from the
        # WS, for the diagnostics screen. Helps confirm the daemon is
        # talking and surfaces wonky events we don't yet handle.
        self.event_log: List[Tuple[float, str]] = []

    def on_mount(self) -> None:
        self.push_screen(ContactsScreen())

    # -------- WS callbacks (called from the websocket thread) --------
    # These names deliberately do NOT start with "on_" because Textual
    # treats on_* as message handlers and would try to await our return.

    def handle_briar_event(self, event: Dict[str, Any]) -> None:
        try:
            self.call_from_thread(self._handle_event, event)
        except Exception:
            pass

    def handle_briar_disconnect(self, exc: Optional[Exception]) -> None:
        try:
            self.call_from_thread(self._handle_disconnect, exc)
        except Exception:
            pass

    # -------- main-thread handlers --------

    def _handle_event(self, event: Dict[str, Any]) -> None:
        if not isinstance(event, dict):
            return
        # briar-headless wraps events differently across versions:
        #   {"name": "X", "data": {...}}        (older docs)
        #   {"type": "X", "data": {...}}        (some builds)
        #   {"type": "X", "event": {...}}       (other builds)
        # Be tolerant. Without this, PrivateMessageReceivedEvent
        # arrived but data ended up pointing at the OUTER object,
        # so contactId was None and the chat never refreshed live.
        name = event.get("name") or event.get("type") or ""
        data: Dict[str, Any] = {}
        for key in ("data", "event"):
            v = event.get(key)
            if isinstance(v, dict):
                data = v
                break
        if not data:
            data = event

        # Record everything for diagnostics so the user can see
        # exactly what Briar is emitting (and we can identify wonky
        # events we don't yet understand).
        if name:
            self.event_log.append((time.time(), name))
            if len(self.event_log) > 200:
                self.event_log = self.event_log[-200:]

        if "PrivateMessageReceived" in name or "PrivateMessageAdded" in name:
            self._on_private_message(data)
        elif "MessagesAck" in name or "MessagesSent" in name:
            # Outgoing message was delivered; refresh the visible chat
            # so 'sent' / 'seen' flags update.
            self._refresh_visible_chat_messages()
        elif "ContactConnected" in name or "ContactDisconnected" in name:
            self._refresh_contacts_cache()
            self._refresh_visible_contacts_screen()
            self._refresh_visible_chat_screen()
        elif "ContactAdded" in name or "ContactRemoved" in name:
            self._refresh_contacts_cache()
            self._refresh_visible_contacts_screen()
        elif "PendingContactStateChanged" in name:
            # Briar emits this every time it tries (and fails or succeeds)
            # to find the peer's Tor hidden-service descriptor. Used by
            # DiagnosticsScreen as a heartbeat proving Tor is doing work.
            pid = data.get("pendingContactId")
            state = str(data.get("state") or "")
            if pid:
                self.pending_state_log[str(pid)] = (time.time(), state)
            self._refresh_visible_contacts_screen()
        elif "PendingContactAdded" in name or "PendingContactRemoved" in name:
            self._refresh_visible_contacts_screen()

    def _handle_disconnect(self, exc: Optional[Exception]) -> None:
        self._daemon_alive = False
        self.notify(
            "briar-headless disconnected. press q on the contacts screen to exit.",
            severity="error",
            timeout=10,
        )

    def _on_private_message(self, data: Dict[str, Any]) -> None:
        # Briar's private-message events vary in shape: some carry the
        # message text, some don't. Rather than depend on that, treat
        # the event as 'something changed for this contact's thread'
        # and re-pull from /v1/messages so the daemon is always the
        # source of truth. Cheap (loopback REST) and version-proof.
        cid = data.get("contactId")
        if cid is None:
            # Some payloads nest contactId under a wrapper.
            for key in ("message", "privateMessage", "msg"):
                inner = data.get(key)
                if isinstance(inner, dict) and "contactId" in inner:
                    cid = inner["contactId"]
                    break
        if cid is None:
            # Last resort: refresh whatever chat the user is looking at.
            self._refresh_visible_chat_messages()
            return
        try:
            cid = int(cid)
        except (TypeError, ValueError):
            return
        screen = self.screen
        if isinstance(screen, ChatScreen) and screen.contact.id == cid:
            screen.reload_history()
            try:
                self.client.mark_read(cid)
            except Exception:
                pass
            return
        self.unread[cid] = self.unread.get(cid, 0) + 1
        self._refresh_visible_contacts_screen()

    def _refresh_visible_chat_messages(self) -> None:
        screen = self.screen
        if isinstance(screen, ChatScreen):
            screen.reload_history()

    def _refresh_contacts_cache(self) -> None:
        try:
            self.contacts_cache = self.client.list_contacts()
        except Exception:
            return

    def _refresh_visible_contacts_screen(self) -> None:
        screen = self.screen
        if isinstance(screen, ContactsScreen):
            screen.refresh_contacts()

    def _refresh_visible_chat_screen(self) -> None:
        screen = self.screen
        if not isinstance(screen, ChatScreen):
            return
        for c in self.contacts_cache:
            if c.id == screen.contact.id:
                screen.update_contact_state(c)
                return
