"""GizApp - the Textual application that hosts the three screens.

Threading model:
    - The Textual event loop owns all UI state and runs on the main thread.
    - The websocket subscription runs on its own thread (briar.EventSubscription).
    - The WS thread calls our on_event/on_disconnect, which use
      app.call_from_thread() to dispatch onto the Textual loop.

We never touch widgets from the WS thread directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from textual.app import App

from .briar import BriarClient, Contact
from .screens import ChatScreen, ContactsScreen, ExchangeLinksScreen


CSS_PATH = str(Path(__file__).with_name("styles.tcss"))


class GizApp(App):
    """Top-level Textual app for giz."""

    CSS_PATH = CSS_PATH
    TITLE = "giz"

    def __init__(self, client: BriarClient, nickname: str) -> None:
        super().__init__()
        self.client = client
        self.nickname = nickname
        self.contacts_cache: List[Contact] = []
        self.unread: Dict[int, int] = {}
        self._daemon_alive = True

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
        name = event.get("name") or event.get("type") or ""
        data = event.get("data", event) if isinstance(event, dict) else {}
        if "PrivateMessageReceived" in name:
            self._on_private_message(data)
        elif "ContactConnected" in name or "ContactDisconnected" in name:
            self._refresh_contacts_cache()
            self._refresh_visible_contacts_screen()
            self._refresh_visible_chat_screen()
        elif "ContactAdded" in name or "ContactRemoved" in name:
            self._refresh_contacts_cache()
            self._refresh_visible_contacts_screen()

    def _handle_disconnect(self, exc: Optional[Exception]) -> None:
        self._daemon_alive = False
        self.notify(
            "briar-headless disconnected. press q on the contacts screen to exit.",
            severity="error",
            timeout=10,
        )

    def _on_private_message(self, data: Dict[str, Any]) -> None:
        cid = data.get("contactId")
        text = data.get("text") or data.get("body") or ""
        ts = int(data.get("timestamp", 0)) or 0
        if cid is None:
            return
        try:
            cid = int(cid)
        except (TypeError, ValueError):
            return
        screen = self.screen
        if isinstance(screen, ChatScreen) and screen.contact.id == cid:
            screen.add_message_inbound(text, ts)
            return
        self.unread[cid] = self.unread.get(cid, 0) + 1
        self._refresh_visible_contacts_screen()

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
