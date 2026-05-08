"""Three screens: Contacts, Chat, Exchange Links.

The whole UI is a stack of these three screens. ContactsScreen is the
home screen and is always at the bottom of the stack. Pushing onto it
navigates to a new screen; popping returns home. We never put more
than one screen on top of Contacts, so navigation is shallow and
predictable.

Keyboard model:
    Contacts:        Up/Down -> select   Enter -> chat   a -> exchange   q -> quit
    Chat:            Enter on input bar sends   Esc -> back
    Exchange Links:  t/q/c toggle your-link format   Esc -> back
                     Tab moves focus through paste-link / alias / Add button

We never use the mouse; every action has a single-key binding visible
in the bottom hint bar. Slash commands and scrolling-prompt model are
both gone; this is a proper screened TUI.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, List, Optional, TYPE_CHECKING

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import (
    Button,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
)

from . import handshake
from .briar import BriarClient, Contact

if TYPE_CHECKING:
    from .app import GizApp


# ---------------------------------------------------------------- Contacts

class ContactsScreen(Screen):
    """Home screen: list of contacts with online dot.

    Up/Down to select; Enter opens chat with that contact; 'a' opens
    the Exchange-Links screen; 'q' quits. Nothing else.
    """

    BINDINGS = [
        Binding("a", "add_contact", "add contact", show=True),
        Binding("r", "refresh", "refresh", show=True),
        Binding("q", "quit", "quit", show=True),
        Binding("enter", "open_chat", "chat", show=False, priority=True),
    ]

    app: "GizApp"  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self._contacts: List[Contact] = []

    def compose(self) -> ComposeResult:
        yield Static("giz / contacts", id="title")
        yield ListView(id="contacts-list")
        yield Static(id="empty")
        yield Static(
            "[enter] chat   [a] add contact   [r] refresh   [q] quit",
            id="hint",
        )

    def on_mount(self) -> None:
        self.refresh_contacts()
        self.set_focus(self.query_one(ListView))

    def on_screen_resume(self) -> None:
        self.refresh_contacts()
        self.set_focus(self.query_one(ListView))

    def refresh_contacts(self) -> None:
        try:
            contacts = self.app.client.list_contacts()
        except Exception:
            return
        contacts.sort(key=lambda c: (not c.connected, c.display.lower()))
        self._contacts = contacts
        self.app.contacts_cache = contacts
        list_view = self.query_one(ListView)
        list_view.clear()
        empty = self.query_one("#empty", Static)
        if not contacts:
            empty.update(
                "no contacts yet. press [bold]a[/bold] to exchange links."
            )
            empty.display = True
            list_view.display = False
            return
        empty.display = False
        list_view.display = True
        for c in contacts:
            unread = self.app.unread.get(c.id, 0)
            list_view.append(_contact_item(c, unread))
        if contacts:
            list_view.index = 0

    def action_add_contact(self) -> None:
        self.app.push_screen(ExchangeLinksScreen())

    def action_refresh(self) -> None:
        self.refresh_contacts()

    def action_quit(self) -> None:
        self.app.exit(0)

    def action_open_chat(self) -> None:
        self._open_highlighted()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self._open_highlighted()

    def _open_highlighted(self) -> None:
        list_view = self.query_one(ListView)
        idx = list_view.index
        if idx is None or idx < 0 or idx >= len(self._contacts):
            return
        contact = self._contacts[idx]
        self.app.unread[contact.id] = 0
        self.app.push_screen(ChatScreen(contact))


def _contact_item(c: Contact, unread: int) -> ListItem:
    online = "online" if c.connected else "offline"
    css_class = "online" if c.connected else ""
    if not c.verified and c.connected:
        online = "unverified"
        css_class = "unverified"
    name_text = c.display
    if unread:
        name_text = f"{c.display}  ({unread} new)"
    row = Horizontal(
        Label(name_text, classes="contact-name"),
        Label(online, classes=f"contact-status {css_class}".strip()),
        classes="contact-row",
    )
    return ListItem(row)


# ---------------------------------------------------------------- Chat

class ChatScreen(Screen):
    """Chat with one contact. RichLog of history + Input bar."""

    BINDINGS = [
        Binding("escape", "back", "back", show=True),
    ]

    app: "GizApp"  # type: ignore[assignment]

    def __init__(self, contact: Contact) -> None:
        super().__init__()
        self.contact = contact

    def compose(self) -> ComposeResult:
        title = self._title()
        yield Static(title, id="title")
        yield RichLog(highlight=False, markup=True, wrap=True, id="log")
        yield Input(placeholder=f"message {self.contact.display}...", id="msg")
        yield Static(
            "[enter] send   [esc] back",
            id="hint",
        )

    def on_mount(self) -> None:
        self._load_history()
        self.set_focus(self.query_one(Input))
        try:
            self.app.client.mark_read(self.contact.id)
        except Exception:
            pass

    def _title(self) -> str:
        state = "online" if self.contact.connected else "offline"
        if self.contact.connected and not self.contact.verified:
            state = "online, unverified"
        return f"giz / chat / {self.contact.display}  ({state})"

    def _load_history(self) -> None:
        log = self.query_one("#log", RichLog)
        log.clear()
        try:
            msgs = self.app.client.messages(self.contact.id)
        except Exception as exc:
            log.write(f"[red]could not load history: {exc}[/red]")
            return
        if not msgs:
            log.write("[dim](no messages yet. type below to send.)[/dim]")
            return
        for m in msgs:
            self._write_message(m.text, m.timestamp, outgoing=m.is_outgoing)

    def _write_message(self, text: str, ts_ms: int, *, outgoing: bool) -> None:
        log = self.query_one("#log", RichLog)
        when = _fmt_time(ts_ms)
        if outgoing:
            log.write(f"[dim]{when}[/dim] [green]me:[/green] {text}")
        else:
            log.write(f"[dim]{when}[/dim] [cyan]{self.contact.display}:[/cyan] {text}")

    def add_message_inbound(self, text: str, ts_ms: int) -> None:
        self._write_message(text, ts_ms, outgoing=False)
        try:
            self.app.client.mark_read(self.contact.id)
        except Exception:
            pass

    def update_contact_state(self, contact: Contact) -> None:
        self.contact = contact
        self.query_one("#title", Static).update(self._title())

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        try:
            self.app.client.send_message(self.contact.id, text)
        except Exception as exc:
            log = self.query_one("#log", RichLog)
            log.write(f"[red]send failed: {exc}[/red]")
            return
        self._write_message(text, int(time.time() * 1000), outgoing=True)
        self.query_one(Input).value = ""

    def action_back(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------- Exchange

class ExchangeLinksScreen(Screen):
    """Two-way link exchange.

    Top: your own link, in three formats (t=text, q=qr, c=code).
    Bottom: paste a friend's link, give it an alias, press Enter
    (or click Add). Esc returns to Contacts.

    The toggle bindings (t/q/c) only fire when the inputs are not
    focused, since Inputs consume printable characters. Tab moves
    focus between toggle area, paste-link, alias, and Add button.
    """

    BINDINGS = [
        Binding("escape", "back", "back", show=True),
        Binding("t", "show_text", "text", show=False),
        Binding("q", "show_qr", "QR", show=False),
        Binding("c", "show_code", "code", show=False),
    ]

    app: "GizApp"  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self._mode = "text"
        self._link: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Static("giz / exchange links", id="title")
        yield Vertical(
            Static(
                "your link.  toggle: [t] text   [q] QR   [c] short-code",
                id="my-toggle",
            ),
            Static("loading...", id="my-link"),
            id="my-pane",
        )
        yield Vertical(
            Label("paste a friend's briar:// link:"),
            Input(placeholder="briar://...", id="paste-link"),
            Label("name for this contact:"),
            Input(placeholder="alias", id="paste-alias"),
            Horizontal(
                Button("Add contact", id="add-btn", variant="primary"),
            ),
            Static("", id="add-status"),
            id="add-pane",
        )
        yield Static(
            "[t/q/c] toggle format   [tab] next field   [enter] add   [esc] back",
            id="hint",
        )

    def on_mount(self) -> None:
        self._load_link()
        self._render_link()
        self.set_focus(self.query_one("#paste-link", Input))

    def _load_link(self) -> None:
        try:
            self._link = self.app.client.my_link()
        except Exception as exc:
            self._link = None
            self.query_one("#my-link", Static).update(
                Text(f"could not get link: {exc}", style="red")
            )

    def _render_link(self) -> None:
        if self._link is None:
            return
        widget = self.query_one("#my-link", Static)
        if self._mode == "text":
            widget.update(Text(self._link, style="cyan", no_wrap=True))
        elif self._mode == "qr":
            widget.update(Text(handshake.qr_block(self._link, large=False), no_wrap=True))
        elif self._mode == "code":
            widget.update(Text(
                handshake.short_code(self._link),
                style="bold cyan",
                no_wrap=True,
            ))

    def action_show_text(self) -> None:
        self._mode = "text"
        self._render_link()

    def action_show_qr(self) -> None:
        self._mode = "qr"
        self._render_link()

    def action_show_code(self) -> None:
        self._mode = "code"
        self._render_link()

    def action_back(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "add-btn":
            self._submit_add()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit_add()

    def _submit_add(self) -> None:
        link = self.query_one("#paste-link", Input).value.strip()
        alias = self.query_one("#paste-alias", Input).value.strip()
        status = self.query_one("#add-status", Static)
        if not link.startswith("briar://"):
            status.update(Text("that does not look like a briar:// link.", style="red"))
            return
        if not alias:
            status.update(Text("please give this contact a name.", style="yellow"))
            return
        try:
            self.app.client.add_pending(link, alias)
        except Exception as exc:
            status.update(Text(f"add failed: {exc}", style="red"))
            return
        self.query_one("#paste-link", Input).value = ""
        self.query_one("#paste-alias", Input).value = ""
        status.update(Text(
            f"pending: '{alias}'. handshake completes when both sides are online. "
            f"press [esc] to return to contacts.",
            style="green",
        ))


def _fmt_time(ts_ms: int) -> str:
    try:
        return datetime.fromtimestamp(ts_ms / 1000.0).strftime("%H:%M")
    except (ValueError, OSError):
        return "--:--"
