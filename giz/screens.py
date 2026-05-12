"""Three screens: Contacts, Chat, Exchange Links.

Pure text. No mouse. No buttons. No colored boxes. Each screen is:

    line 1                  title
    line 2..N-1             content
    last line               hint (single dim line of available keys)

Keyboard model:
    Contacts:  Up/Down -> select   Enter -> chat   a -> add   r -> refresh   q -> quit
    Chat:      Enter on input -> send   Esc -> back
    Exchange:  t/q/c toggle your-link format   y -> copy to clipboard
               Tab -> next field   Enter on link -> jump to alias
               Enter on alias -> submit   Esc -> back
"""

from __future__ import annotations

import platform
import re
import shutil as _shutil
import subprocess
import time
from typing import Any, List, Optional, Tuple, TYPE_CHECKING

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
)

from . import handshake
from .briar import Contact

if TYPE_CHECKING:
    from .app import GizApp


# ---------------------------------------------------------------- Contacts

class ContactsScreen(Screen):
    BINDINGS = [
        Binding("a", "add_contact", "add friend", show=True),
        Binding("s", "share_link", "share my link", show=True),
        Binding("n", "rename", "rename", show=True),
        Binding("x", "remove", "remove", show=True),
        Binding("r", "refresh", "refresh", show=True),
        Binding("d", "diagnostics", "diagnostics", show=True),
        Binding("i", "info", "info", show=True),
        Binding("q", "quit", "quit", show=True),
        Binding("enter", "open_chat", "chat", show=False, priority=True),
    ]

    app: "GizApp"  # type: ignore[assignment]

    # Removal is two-tap: first 'x' arms; second 'x' on the same row
    # within REMOVE_CONFIRM_S executes. Anything else (move, refresh,
    # different row) cancels.
    REMOVE_CONFIRM_S = 5.0

    def __init__(self) -> None:
        super().__init__()
        # Mixed list: each entry is ("contact", Contact) or ("pending", dict).
        self._items: List[tuple] = []
        self._remove_armed_idx: Optional[int] = None
        self._remove_armed_at: float = 0.0

    def compose(self) -> ComposeResult:
        yield Static("giz / contacts", id="title")
        yield ListView(id="contacts-list")
        yield Static(id="empty")
        yield Static(
            "enter chat   a add   s share   n rename   x remove   "
            "d diagnostics   r refresh   i info   q quit",
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
        try:
            pending = self.app.client.list_pending_contacts()
        except Exception:
            pending = []
        contacts.sort(key=lambda c: (not c.connected, c.display.lower()))
        self.app.contacts_cache = contacts

        items: List[tuple] = [("contact", c) for c in contacts]
        items.extend(("pending", p) for p in pending)

        # Try to preserve the current cursor across the rebuild so a
        # message arriving in the background does not yank the user's
        # selection back to the top mid-scroll. We key on contact id
        # for confirmed contacts (stable across reorders by connected
        # state) and on the pendingContactId field for pending rows.
        prior_key: Optional[Tuple[str, Any]] = None
        try:
            old_view = self.query_one(ListView)
            old_idx = old_view.index
            if (
                old_idx is not None
                and 0 <= old_idx < len(self._items)
            ):
                kind, payload = self._items[old_idx]
                if kind == "contact":
                    prior_key = ("contact", payload.id)
                else:
                    pc = payload.get("pendingContact", {}) if isinstance(payload, dict) else {}
                    prior_key = ("pending", pc.get("pendingContactId"))
        except Exception:
            prior_key = None

        self._items = items

        list_view = self.query_one(ListView)
        list_view.clear()
        empty = self.query_one("#empty", Static)
        if not items:
            empty.update("no contacts. press a to add one.")
            empty.display = True
            list_view.display = False
            return
        empty.display = False
        list_view.display = True
        new_idx = 0
        for i, (kind, payload) in enumerate(items):
            if kind == "contact":
                unread = self.app.unread.get(payload.id, 0)
                list_view.append(_contact_item(payload, unread))
                if prior_key == ("contact", payload.id):
                    new_idx = i
            else:
                list_view.append(_pending_item(payload))
                pc = payload.get("pendingContact", {}) if isinstance(payload, dict) else {}
                if prior_key == ("pending", pc.get("pendingContactId")):
                    new_idx = i
        list_view.index = new_idx

    def action_add_contact(self) -> None:
        self.app.push_screen(AddContactScreen())

    def action_share_link(self) -> None:
        self.app.push_screen(MyLinkScreen())

    def action_refresh(self) -> None:
        self.refresh_contacts()

    def action_info(self) -> None:
        self.app.push_screen(InfoScreen())

    def action_diagnostics(self) -> None:
        self.app.push_screen(DiagnosticsScreen())

    def action_quit(self) -> None:
        self.app.exit(0)

    def action_open_chat(self) -> None:
        self._open_highlighted()

    def action_rename(self) -> None:
        list_view = self.query_one(ListView)
        idx = list_view.index
        if idx is None or idx < 0 or idx >= len(self._items):
            return
        kind, payload = self._items[idx]
        if kind != "contact":
            self.app.notify(
                "rename only applies to confirmed contacts.",
                severity="warning",
                timeout=4,
            )
            return
        # Cancel any armed delete; renaming a row should not also delete it
        # if the user happened to press 'x' a moment ago.
        self._remove_armed_idx = None
        self.app.push_screen(RenameContactScreen(payload))

    def action_remove(self) -> None:
        list_view = self.query_one(ListView)
        idx = list_view.index
        if idx is None or idx < 0 or idx >= len(self._items):
            return
        kind, payload = self._items[idx]
        name = payload.display if kind == "contact" else (
            (payload.get("pendingContact") or {}).get("alias") or "(no alias)"
        )

        now = time.time()
        # Second tap within the window on the same row -> commit.
        if (
            self._remove_armed_idx == idx
            and now - self._remove_armed_at <= self.REMOVE_CONFIRM_S
        ):
            self._remove_armed_idx = None
            self._do_remove(kind, payload, name)
            return

        # First tap (or a stale arm) -> arm and warn.
        self._remove_armed_idx = idx
        self._remove_armed_at = now
        self.app.notify(
            f"press x again within {int(self.REMOVE_CONFIRM_S)}s to remove "
            f"'{name}'. anything else cancels.",
            severity="warning",
            timeout=self.REMOVE_CONFIRM_S,
        )

    def _do_remove(self, kind: str, payload, name: str) -> None:
        try:
            if kind == "contact":
                self.app.client.delete_contact(payload.id)
                self.app.unread.pop(payload.id, None)
            else:
                pid = (payload.get("pendingContact") or {}).get("pendingContactId")
                if not pid:
                    raise RuntimeError("no pendingContactId on pending contact")
                self.app.client.remove_pending(pid)
        except Exception as exc:
            self.app.notify(
                f"could not remove '{name}': {exc}",
                severity="error", timeout=8,
            )
            return
        self.app.notify(
            f"removed '{name}'.",
            severity="information", timeout=4,
        )
        self.refresh_contacts()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self._open_highlighted()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        # Moving the highlight cancels any armed removal so the user
        # cannot navigate to a different row and accidentally delete it.
        self._remove_armed_idx = None

    def _open_highlighted(self) -> None:
        list_view = self.query_one(ListView)
        idx = list_view.index
        if idx is None or idx < 0 or idx >= len(self._items):
            return
        kind, payload = self._items[idx]
        if kind == "pending":
            self.app.notify(
                "still handshaking with this contact over Tor. "
                "first contact is usually under a minute on a healthy "
                "network, but can be longer. press d for diagnostics.",
                severity="warning",
                timeout=8,
            )
            return
        contact = payload
        self.app.unread[contact.id] = 0
        self.app.push_screen(ChatScreen(contact))


def _contact_item(c: Contact, unread: int) -> ListItem:
    if c.connected:
        dot = "[bright_green]●[/]"
        status = "online" if c.verified else "online, unverified"
    else:
        dot = "[dim]○[/]"
        status = "offline"
    # Visible unread cue, terminal-agnostic. A CSS background change
    # alone is invisible on many themes because Textual's $boost can
    # be perceptually identical to $surface. A bright yellow dot in
    # the row text always renders, on every terminal, regardless of
    # color scheme. The CSS .unread rule still applies in addition
    # for themes where the background tint is visible.
    name_text = (
        f"[bright_yellow]●[/] {c.display}" if unread else c.display
    )
    row = Horizontal(
        Label(name_text, classes="contact-name"),
        Label(f"{dot} {status}", classes="contact-status"),
        classes="contact-row",
    )
    item = ListItem(row)
    if unread:
        item.add_class("unread")
    return item


def _pending_item(p: dict) -> ListItem:
    """A pending contact is one we added but Briar hasn't finished
    the Tor handshake for yet.

    Briar's actual PendingContactState enum (verified against
    briar-headless OutputPendingContact.kt) is one of:
        'waiting_for_connection' | 'offline' | 'connecting'
        | 'adding_contact' | 'failed'

    The first three all mean the same thing to a user ('still doing
    the Tor handshake'); they only differ in which phase of Briar's
    own retry loop the daemon happens to be in at the moment of the
    poll. Showing them verbatim caused a false asymmetry between two
    machines (one would say 'waiting' while the other said 'offline'
    even though neither was more connected than the other), so we
    collapse them into a single honest line. Only the terminal
    'adding_contact' / 'failed' states get distinct messages, because
    those actually mean something different to the user.
    """
    pc = p.get("pendingContact", {}) if isinstance(p, dict) else {}
    alias = pc.get("alias") or "(no alias)"
    state = p.get("state", "pending") if isinstance(p, dict) else "pending"
    if state in ("waiting_for_connection", "offline", "connecting"):
        state_pretty = f"pending: handshaking over Tor ({state})"
    elif state == "adding_contact":
        state_pretty = "pending: finalizing"
    elif state == "failed":
        state_pretty = "pending: failed; remove and retry"
    else:
        state_pretty = f"pending: {state}"
    row = Horizontal(
        Label(str(alias), classes="contact-name"),
        Label(state_pretty, classes="contact-status"),
        classes="contact-row",
    )
    return ListItem(row)


# ---------------------------------------------------------------- Chat

class ChatScreen(Screen):
    BINDINGS = [
        Binding("escape", "back", "back", show=True),
        # Pressing enter or i from anywhere on this screen jumps the
        # cursor back to the message input. People who scrolled the
        # log with arrows / mouse otherwise have no obvious way to
        # get back to typing.
        Binding("i", "focus_input", "type", show=False),
    ]

    app: "GizApp"  # type: ignore[assignment]

    def __init__(self, contact: Contact) -> None:
        super().__init__()
        self.contact = contact
        # Tracks the (count, last_timestamp) of the last successful
        # render so the periodic poll can skip redraws when the
        # daemon's view of the thread hasn't changed. Without this
        # we'd flicker the whole log every poll tick.
        self._last_render_key: tuple = (-1, -1)

    def compose(self) -> ComposeResult:
        yield Static(self._title(), id="title")
        yield RichLog(highlight=False, markup=False, wrap=True, id="log")
        # Two widgets with dock:bottom + height:1 collapse onto the
        # same row in Textual; with the original compose order the
        # hint was painted directly on top of the message input,
        # which is why the chat screen looked like a read-only log.
        # Group them inside a single docked Vertical so each gets
        # its own row.
        with Vertical(id="chat-bottom"):
            yield Input(
                id="msg",
                placeholder="type a message and press enter",
            )
            yield Static("enter send   esc back", id="hint")

    def on_mount(self) -> None:
        self._load_history()
        self.set_focus(self.query_one(Input))
        try:
            self.app.client.mark_read(self.contact.id)
        except Exception:
            pass
        # Belt-and-braces: even with the websocket event-driven path,
        # poll the daemon every 4s to pick up anything we missed (event
        # JSON shape changes between briar versions; better to be late
        # than to silently drop messages). Side effect: also keeps
        # 'online/offline' fresh in the title.
        self._poll_timer = self.set_interval(4.0, self._poll)

    def on_unmount(self) -> None:
        timer = getattr(self, "_poll_timer", None)
        if timer is not None:
            try:
                timer.stop()
            except Exception:
                pass

    def _poll(self) -> None:
        # Cheap loopback call. If it fails, swallow; the disconnect
        # path on the WS thread will surface the real error.
        try:
            self.reload_history()
        except Exception:
            pass
        try:
            for c in self.app.client.list_contacts():
                if c.id == self.contact.id:
                    self.update_contact_state(c)
                    break
        except Exception:
            pass

    def on_screen_resume(self) -> None:
        # If the user pushed and popped a sub-screen, focus may have
        # been left on the log; aggressively put it back on the input.
        try:
            self.set_focus(self.query_one(Input))
        except Exception:
            pass

    def action_focus_input(self) -> None:
        try:
            self.set_focus(self.query_one(Input))
        except Exception:
            pass

    def _title(self) -> str:
        # Briar tags a contact 'verified' only after an in-person QR
        # exchange; giz currently only supports link exchange, so every
        # contact will be 'unverified' forever. Surfacing that in the
        # title just confuses users into thinking the connection is
        # weaker than it is. Messages are end-to-end encrypted and
        # signed regardless. Keep the title to plain online/offline.
        state = "online" if self.contact.connected else "offline"
        return f"giz / {self.contact.display} ({state})"

    def _load_history(self, *, force: bool = True) -> None:
        log = self.query_one("#log", RichLog)
        try:
            msgs = self.app.client.messages(self.contact.id)
        except Exception as exc:
            if force:
                log.clear()
                log.write(f"could not load history: {exc}")
                self._last_render_key = (-1, -1)
            return
        last_ts = msgs[-1].timestamp if msgs else 0
        key = (len(msgs), last_ts)
        if not force and key == self._last_render_key:
            return
        self._last_render_key = key
        log.clear()
        if not msgs:
            log.write("(no messages yet)")
            return
        for m in msgs:
            self._write_message(m.text, m.timestamp, outgoing=m.is_outgoing)

    def reload_history(self) -> None:
        """Re-render the chat from the daemon's authoritative copy.

        Called whenever a websocket event reports a change for this
        thread (inbound message, ack, delivery). Re-renders only if
        the message count or last timestamp changed, so the periodic
        safety-net poll does not flicker the log.
        """
        self._load_history(force=False)

    def _write_message(self, text: str, ts_ms: int, *, outgoing: bool) -> None:
        log = self.query_one("#log", RichLog)
        who = "me" if outgoing else self.contact.display
        log.write(f"{who}: {text}")

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
            self.query_one("#log", RichLog).write(f"send failed: {exc}")
            return
        self._write_message(text, int(time.time() * 1000), outgoing=True)
        self.query_one(Input).value = ""

    def action_back(self) -> None:
        self.app.pop_screen()


def _copy_to_clipboard(text: str) -> bool:
    """Best-effort copy to the OS clipboard. Zero new dependencies.

    Tries platform-native binaries:
        macOS:    pbcopy
        Windows:  clip
        Linux:    wl-copy (Wayland) -> xclip -> xsel (X11)

    Returns True if at least one tool accepted the text. We never raise;
    a failure just means the caller will show "copy unavailable".
    """
    candidates: list[list[str]] = []
    sys_name = platform.system()
    if sys_name == "Darwin":
        candidates.append(["pbcopy"])
    elif sys_name == "Windows":
        candidates.append(["clip"])
    else:
        for cmd in (
            ["wl-copy"],
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
        ):
            if _shutil.which(cmd[0]):
                candidates.append(cmd)
    for cmd in candidates:
        if not _shutil.which(cmd[0]):
            continue
        try:
            p = subprocess.run(
                cmd,
                input=text.encode("utf-8"),
                check=False,
                timeout=3,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if p.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            continue
    return False


# ---------------------------------------------------------------- My Link

class MyLinkScreen(Screen):
    """Show your OWN briar:// link, with copy/QR/short-code views.

    This screen does ONE thing: display your link so you can send it
    to a friend. There are no inputs anywhere. esc just goes back.

    Format toggles (t/q/c) and the copy key (y) all act on the same
    target: your own link.
    """

    BINDINGS = [
        Binding("escape", "back", "back", show=True),
        Binding("t", "show_text", "text", show=False),
        Binding("q", "show_qr", "qr", show=False),
        Binding("c", "show_code", "code", show=False),
        Binding("y", "yank", "copy", show=True),
    ]

    # No inputs on this screen, so auto-focus doesn't matter. The default
    # focus is fine; t/q/c/y all hit screen-level bindings.

    app: "GizApp"  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self._mode = "text"
        self._link: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Static("giz / share my link", id="title")
        yield Static("loading your link...", id="my-link")
        yield Static("", id="my-status")
        yield Static(
            "y copy   t text   q qr   c short-code   esc back",
            id="hint",
        )

    def on_mount(self) -> None:
        self._load_link()
        self._render_link()

    def _load_link(self) -> None:
        try:
            self._link = self.app.client.my_link()
        except Exception as exc:
            self._link = None
            self.query_one("#my-link", Static).update(
                f"could not get link: {exc}"
            )

    def _render_link(self) -> None:
        if self._link is None:
            return
        widget = self.query_one("#my-link", Static)
        if self._mode == "text":
            widget.update(self._link)
        elif self._mode == "qr":
            widget.update(
                Text(handshake.qr_block(self._link, large=False), no_wrap=True)
            )
        elif self._mode == "code":
            widget.update(handshake.short_code(self._link))

    def action_show_text(self) -> None:
        self._mode = "text"
        self._render_link()

    def action_show_qr(self) -> None:
        self._mode = "qr"
        self._render_link()

    def action_show_code(self) -> None:
        self._mode = "code"
        self._render_link()

    def action_yank(self) -> None:
        status = self.query_one("#my-status", Static)
        if self._link is None:
            status.update("nothing to copy yet.")
            return
        if self._mode == "code":
            payload, label = handshake.short_code(self._link), "short-code"
        else:
            payload, label = self._link, "briar:// link"
        if _copy_to_clipboard(payload):
            status.update(f"copied {label} to clipboard. paste it to your friend.")
            self.app.notify(
                f"copied {label}. paste it into iMessage / WhatsApp / etc.",
                severity="information", timeout=5,
            )
        else:
            status.update(
                "no clipboard tool found "
                "(install pbcopy / xclip / wl-copy / clip)."
            )

    def action_back(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------- Add Contact

class AddContactScreen(Screen):
    """Add a friend by pasting THEIR briar:// link.

    This screen does ONE thing: take a link + a name, hand them to
    Briar, show a toast on success. No your-link section, no t/q/c
    keys, no y key, no focus puzzle. The link input is focused on
    entry so cmd-V works immediately. esc always goes back.
    """

    BINDINGS = [
        Binding("escape", "back", "back", show=True),
    ]

    app: "GizApp"  # type: ignore[assignment]

    def compose(self) -> ComposeResult:
        yield Static("giz / add a friend", id="title")
        yield Label("paste your friend's briar:// link, then press enter:")
        yield Input(placeholder="briar://...", id="paste-link")
        yield Static("", id="paste-code")
        yield Label("name for this contact, then press enter to add:")
        yield Input(placeholder="type a name and press enter", id="paste-alias")
        yield Static("", id="add-status")
        yield Static(
            "type / paste   tab next field   enter advance   esc back",
            id="hint",
        )

    def on_mount(self) -> None:
        # Single screen, single purpose: focus the link input immediately
        # so cmd-V drops the link straight in. There is nothing else to
        # collide with on this screen.
        self.set_focus(self.query_one("#paste-link", Input))

    def on_input_changed(self, event: Input.Changed) -> None:
        # Live short-code of the pasted link, for phone-call MITM check.
        if event.input.id != "paste-link":
            return
        code_widget = self.query_one("#paste-code", Static)
        link = event.value.strip()
        if not link.startswith("briar://"):
            code_widget.update("")
            return
        code_widget.update(
            f"short-code of this link: {handshake.short_code(link)}\n"
            f"(if your friend reads their 'c' code, the two must match)"
        )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "paste-link":
            link = event.input.value.strip()
            status = self.query_one("#add-status", Static)
            if not link:
                return
            if not link.startswith("briar://"):
                status.update("not a briar:// link.")
                return
            status.update("")
            self.set_focus(self.query_one("#paste-alias", Input))
            return
        self._submit_add()

    def _submit_add(self) -> None:
        link = self.query_one("#paste-link", Input).value.strip()
        alias = self.query_one("#paste-alias", Input).value.strip()
        status = self.query_one("#add-status", Static)
        if not link.startswith("briar://"):
            status.update("not a briar:// link.")
            return
        if not alias:
            status.update("name cannot be empty.")
            return
        try:
            self.app.client.add_pending(link, alias)
        except Exception as exc:
            status.update(f"add failed: {exc}")
            self.app.notify(f"add failed: {exc}", severity="error", timeout=8)
            return
        self.query_one("#paste-link", Input).value = ""
        self.query_one("#paste-alias", Input).value = ""
        self.query_one("#paste-code", Static).update("")
        status.update(
            f"added '{alias}'. now waiting for the Tor handshake. "
            f"usually under a minute on a healthy network. esc to go back."
        )
        self.app.notify(
            f"added '{alias}'. it will appear on the contacts screen as "
            f"'pending' until both sides finish handshaking over Tor.",
            severity="information",
            timeout=8,
        )
        # Re-focus the link input in case the user wants to add another.
        self.set_focus(self.query_one("#paste-link", Input))

    def action_back(self) -> None:
        self.app.pop_screen()


# Backwards-compatible alias: existing tests / callers that imported
# ExchangeLinksScreen still work. The new screen is AddContactScreen
# (just the paste-friend-link half; the share-MY-link half lives in
# MyLinkScreen now).
ExchangeLinksScreen = AddContactScreen


class RenameContactScreen(Screen):
    """Change a confirmed contact's local alias.

    The alias is stored only on this device and is never sent to the
    contact. Briar's PUT /v1/contacts/{id}/alias accepts the new
    string and returns no body. We do not persist anything on giz's
    side; the next refresh of the contacts list shows the new name
    because briar-headless is the source of truth.
    """

    BINDINGS = [
        Binding("escape", "back", "back", show=True),
    ]

    app: "GizApp"  # type: ignore[assignment]

    def __init__(self, contact: Contact) -> None:
        super().__init__()
        self.contact = contact

    def compose(self) -> ComposeResult:
        yield Static(f"giz / rename '{self.contact.display}'", id="title")
        yield Label("type a new local name and press enter (only you see this):")
        yield Input(value=self.contact.display, id="rename-input")
        yield Static("", id="rename-status")
        yield Static("enter rename   esc back", id="hint")

    def on_mount(self) -> None:
        self.set_focus(self.query_one("#rename-input", Input))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        new_alias = event.value.strip()
        status = self.query_one("#rename-status", Static)
        if not new_alias:
            status.update("name cannot be empty.")
            return
        if new_alias == self.contact.display:
            self.app.pop_screen()
            return
        try:
            self.app.client.set_alias(self.contact.id, new_alias)
        except Exception as exc:
            status.update(f"rename failed: {exc}")
            self.app.notify(
                f"rename failed: {exc}", severity="error", timeout=8,
            )
            return
        self.app.notify(
            f"renamed to '{new_alias}'.",
            severity="information",
            timeout=4,
        )
        self.app.pop_screen()

    def action_back(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------- Info

INFO_TEXT = """\
how adding a contact works:

  every user has ONE unique briar:// link generated locally on their
  device. it is a long Tor-hidden-service address derived from your
  Ed25519 keypair. nobody else can produce the same link.

  to chat with a friend you must each give the other your link. you
  send yours to them; they send theirs to you. the screen offers
  three views of YOUR link:

    t  the URL as plain text - paste into iMessage, email, paste-bin
    q  the same URL as a QR code  - show on a video call or in person
    c  a 12-digit hash of YOUR link - read aloud over a phone call

  the 12-digit code is NOT a way to send the link. you cannot
  reconstruct the link from 12 digits. it is a fingerprint, used to
  detect tampering on the channel you used to actually send the link.

  the verification flow:

    1. alice sends bob her briar:// link via SMS or WhatsApp.
    2. alice presses 'c', sees "1234 5678 9012".
    3. alice phones bob, reads "1234 5678 9012" aloud.
    4. bob pastes the link he received into giz. giz immediately
       shows him the 12-digit hash of the link he just pasted.
    5. if bob's hash matches what alice read out, the link survived
       the SMS / WhatsApp trip untouched. if it does not match,
       someone in the middle swapped the link and adding it would
       hand the conversation to that attacker.

  if you handed the QR over a video call or showed it in person,
  this verification step is not necessary - the channel itself is
  hard to tamper with.


trust model, from outside in:

  hardware    same as Signal. if your CPU or firmware is compromised
              (Pegasus, baseband, etc.), every messenger loses. only
              mitigation is a clean device.

  OS          same as Signal. Apple / Microsoft / Google can read
              whatever they want at this layer. only mitigation is a
              clean OS.

  app         giz is open source, ~1500 lines of Python around
              Briar. you can audit it in one sitting. Briar's crypto
              is upstream, peer-reviewed, and unchanged by us.
              the giz wrapper itself is supply-chain hardened:
              GPG-signed git tags, source archive pinned by SHA-256,
              every Python dep + transitive dep pinned by SHA-256,
              installer aborts on any mismatch. at runtime the giz
              process refuses outbound connects to anything that is
              not loopback, runs with core dumps off and ptrace deny,
              and chmods its own data dir 0700 / hash files 0600 on
              every launch.

  account     no phone, no email, no central server. nobody has a
              "giz account database" because there isn't one.
              Signal needs a phone number. WhatsApp needs a phone
              number. Telegram needs a phone number.

  network     every byte goes through Tor. nobody, not even Briar
              the project, sees your IP or who you talk to. Signal
              and WhatsApp see both endpoints of every conversation.

  message     end-to-end encrypted with the Bramble protocol
              (Curve25519 + XSalsa20-Poly1305). same strength
              category as Signal. forward-secret per session.

  at rest     local database encrypted with a key derived from your
              password (Argon2id). typing the duress password wipes
              that database irreversibly.


one account per machine:

  giz allows exactly one giz account per physical machine and ships
  no 'add another account' or 'persona' command. this is on purpose.
  Briar's embedded Tor cannot share local ports with a second Briar
  process, so a second account on the same machine would silently
  fail to publish its hidden services and every contact it added
  would stay 'pending' forever - a subtle, hard-to-explain failure
  mode. removing the feature also reduces attack surface: there is
  no per-account discovery to leak, no extra launchers on PATH, and
  the duress-wipe model has only one secret door to defend.

  if you need a separate identity, run giz on a separate physical
  machine.


what giz does NOT protect you from:

  - malware on the machine you are typing on. screen recorders,
    keyloggers, accessibility-API spies all win.
  - a compromised OS or firmware. see "hardware" / "OS" above.
  - the duress wipe is observable: an attacker who saw you using
    giz five minutes ago and now sees "no account" can guess.
  - sharing your link via a leaky channel (SMS, plain email)
    without verifying the short-code over the phone afterward.
  - subpoena of the metadata your friend's device locally stores
    (timestamps, message text, contact name).


comparison:

                    phone#  central   open    e2ee   tor    duress
                    needed  server    source  msgs   route  wipe
  giz               no      no        yes     yes    yes    yes
  Signal            yes     yes       yes     yes    no     no
  WhatsApp          yes     yes       no*     yes    no     no
  Telegram (cloud)  yes     yes       partial no     no     no
  iMessage          yes     yes       no      yes    no     no

  *WhatsApp's protocol is open (Signal Protocol); the client is not.


adversaries, ranked by capability (and what each can do to you):

  curious neighbor / random stranger
    cannot read your messages, cannot see who you talk to, cannot
    even tell you are using giz unless they look at your screen.

  ISP / public wifi operator / corporate VPN
    sees encrypted Tor traffic going to a guard relay. learns
    nothing about content, contacts, or who is on the other end.

  giz itself / the people behind your messenger
    giz: there is no server, no account database, no operator, no
    subpoena address. the source is public and the install chain is
    hash-pinned end to end:
      - the git tag is GPG-signed; auditors verify with
        'git verify-tag v0.1.1'
      - the source archive is verified against a SHA-256 pinned in
        the installer before extraction
      - every Python dep, including all transitive ones, is
        installed via 'pip install --require-hashes' against a
        committed lockfile; pip refuses any tarball that does not
        match
      - the briar-headless JAR is verified against a SHA-256 pinned
        in the installer
    even a compromise of the maintainer's GitHub account is not
    enough on its own; the attacker would also need the GPG signing
    key (kept off GitHub) to mint a tag auditors trust.
    Signal: the Signal Foundation knows your phone number and can
    see traffic timing. WhatsApp / iMessage: Meta / Apple know your
    phone number, see traffic, and hold the keys to legally-mandated
    backdoors in some jurisdictions.

  one government acting alone, with full legal powers
    can subpoena the local telco for browsing metadata. through
    Tor they see "this user used Tor at this time" but not who
    you talked to or what you said. cannot subpoena giz or Briar,
    because there is no central operator. cannot subpoena your
    contact list, because it lives only on your two devices.

  one well-funded national intelligence service (NSA, FSB, MSS,
  Mossad, GCHQ, etc.) targeting you specifically
    can run Tor relays and try traffic-correlation attacks if you
    are a high-value target. Briar's long-lived hidden services
    + Tor's guard rotation make this expensive but not impossible.
    expect months of targeted effort. you are still alive without
    them reading your messages, but they may eventually map who
    you talk to.

  multiple cooperating intelligence services (Five Eyes, etc.)
  with unlimited budget, focused on you by name, for years
    they win. running enough Tor relays simultaneously makes
    end-to-end traffic correlation feasible against a sustained
    target. this is the documented upper limit of Tor itself,
    not of giz. no commodity messenger - not Signal, not Briar,
    not Session, not Cwtch - survives this case.
    your defense at this level is operational, not technical:
    change device, change network, change identity, communicate
    less.

  your phone / laptop has malware on it RIGHT NOW
    they win instantly, regardless of which messenger you pick.
    a screen recorder reads your chat. a keylogger reads your
    password. the encryption is irrelevant. solve this first,
    then worry about messengers.


what giz is realistically good for:

  - privacy from advertisers, ISPs, employers, schools, family
    members, nosy roommates, vendor analytics teams.
  - protection from one hostile state acting alone, as long as you
    are not a sustained named target of theirs.
  - keeping conversation evidence off your disk if your device is
    seized while locked, or if you type the duress password.

what giz is NOT for:

  - hiding from a coalition of major intelligence services that
    has you specifically in their crosshairs for years.
  - communicating from a device you already suspect is hacked.
  - long-term operational anonymity if you keep reusing the same
    identity on the same network forever.


bottom line:

  giz now closes the wrapper-itself gap that every other "secure
  messenger" leaves open. the protocol (Briar) was already at the
  Signal level. with v0.1.1 the supply chain that delivers the
  wrapper is at the same level: signed tag, hash-pinned source,
  hash-pinned deps, runtime-locked-down process. there is no piece
  of code anywhere in the install chain that can change without
  breaking a SHA-256 you can verify yourself.

  on a clean device, giz is private from EVERYONE on this list
  except the last two:

    1. coordinated multi-state intelligence services running enough
       Tor relays simultaneously to do end-to-end timing correlation
       on a sustained, named target, over years. this is the
       documented upper bound of Tor itself, not of giz, and no
       commodity messenger on earth survives it.

    2. malware on the actual device you are typing on. screen
       recorders and keyloggers read what you type before any
       encryption happens. solving this is not giz's job; it is
       the job of the OS / hardware you chose.

  in practice (1) requires you to be a state-level target by name,
  for years, with no operational discipline. (2) requires your
  laptop to already be hacked.

  for a normal person, including activists, journalists, and people
  who simply do not want Apple / Meta / Google reading their chats:
  on a clean device, giz is the highest privacy bar you can hit
  with off-the-shelf tooling. it is not infinite. it is calibrated.
"""


class InfoScreen(Screen):
    BINDINGS = [
        Binding("escape", "back", "back", show=True),
        Binding("q", "back", "back", show=False),
    ]

    app: "GizApp"  # type: ignore[assignment]

    def compose(self) -> ComposeResult:
        yield Static("giz / info", id="title")
        yield VerticalScroll(
            Static(INFO_TEXT, id="info-body"),
            id="info-scroll",
        )
        yield Static(
            "up/down or pgup/pgdn to scroll   esc back",
            id="hint",
        )

    def action_back(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------- Diagnostics

def _count_outbound_connections(pid: Optional[int]) -> Optional[int]:
    """Count ESTABLISHED outbound TCP connections from the given pid.

    These are Tor circuits. A briar-headless that is actively talking
    to the Tor network typically holds 5-15 of them. Zero usually
    means Tor has not bootstrapped yet (or never will, on a captive
    network). We do not crash on platforms where the inspection tool
    is missing; we just return None and let the UI say 'unknown'.
    """
    if pid is None:
        return None
    sys_name = platform.system()
    try:
        if sys_name in ("Darwin", "Linux"):
            if not _shutil.which("lsof"):
                return None
            r = subprocess.run(
                ["lsof", "-nP", "-p", str(pid), "-iTCP", "-sTCP:ESTABLISHED"],
                check=False, timeout=4,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            if r.returncode != 0:
                return 0
            lines = [
                ln for ln in r.stdout.decode("utf-8", "ignore").splitlines()
                if ln and not ln.startswith("COMMAND")
            ]
            count = 0
            for ln in lines:
                # Filter out loopback (briar-headless's own API socket).
                if "127.0.0.1" in ln or "[::1]" in ln:
                    continue
                count += 1
            return count
        if sys_name == "Windows":
            if not _shutil.which("netstat"):
                return None
            r = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                check=False, timeout=4,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            if r.returncode != 0:
                return None
            count = 0
            tag = str(pid)
            for ln in r.stdout.decode("utf-8", "ignore").splitlines():
                if "ESTABLISHED" not in ln:
                    continue
                if not ln.rstrip().endswith(tag):
                    continue
                if "127.0.0.1" in ln or "[::1]" in ln:
                    continue
                count += 1
            return count
    except (OSError, subprocess.TimeoutExpired):
        return None
    return None


def _fmt_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    return f"{h}h {m}m"


# Anything looking like a long random opaque token (auth_token, briar://
# link, Ed25519 key blob) is replaced with a placeholder before display.
# briar-headless is not known to log such values today, but this is a
# cheap belt-and-braces step in case a future Briar build does.
_TOKEN_SHAPED = re.compile(r"[A-Za-z0-9+/_=-]{32,}")


def _scrub_log_line(line: str) -> str:
    """Replace long random-looking blobs in a daemon log line.

    Used by DiagnosticsScreen so a hypothetical future Briar build that
    logs the auth_token, a private key, or a contact link cannot leak
    that value through the diagnostics panel. False positives (legitimate
    long IDs) get redacted too; the user keeps the rest of the line for
    debugging.
    """
    return _TOKEN_SHAPED.sub("<redacted>", line)


class DiagnosticsScreen(Screen):
    """Live, read-only health view. Answers 'is Tor doing anything?'.

    The cheapest, most direct signal that the Briar daemon is reaching
    Tor is its count of ESTABLISHED outbound TCP connections - those
    are Tor circuits to relays. We add the daemon uptime, the API
    port (loopback only), and the per-pending-contact 'last state
    change' age, which is how briar tells us 'I just retried this
    handshake'. None of this leaves the loopback interface.
    """

    BINDINGS = [
        Binding("escape", "back", "back", show=True),
        Binding("d", "back", "back", show=False),
        Binding("r", "refresh", "refresh", show=True),
        Binding("q", "back", "back", show=False),
    ]

    app: "GizApp"  # type: ignore[assignment]

    REFRESH_S = 2.0

    def compose(self) -> ComposeResult:
        yield Static("giz / diagnostics", id="title")
        yield VerticalScroll(
            Static("loading...", id="diag-body"),
            id="diag-scroll",
        )
        yield Static(
            "auto-refresh every 2s   r refresh now   esc back",
            id="hint",
        )

    def on_mount(self) -> None:
        self._redraw()
        # Auto-refresh while open. Cancelled on screen pop because the
        # interval is owned by this Screen instance.
        self.set_interval(self.REFRESH_S, self._redraw)

    def action_refresh(self) -> None:
        self._redraw()

    def action_back(self) -> None:
        self.app.pop_screen()

    def _redraw(self) -> None:
        # NOTE: do NOT name this _render; that shadows Widget._render and
        # makes Textual think the screen renders to None, crashing the
        # compositor with 'NoneType has no attribute render_strips'.
        try:
            text = self._build_text()
        except Exception as exc:
            text = f"diagnostics error: {exc}"
        try:
            self.query_one("#diag-body", Static).update(text)
        except Exception:
            # Screen torn down between interval ticks; harmless.
            pass

    def _build_text(self) -> str:
        pid = self.app.daemon_pid
        port = self.app.daemon_port
        uptime = time.time() - self.app.started_at
        outbound = _count_outbound_connections(pid)

        proc_for_bind = getattr(self.app, "daemon_proc", None)
        bind_warning = (
            getattr(proc_for_bind, "bind_warning", None)
            if proc_for_bind is not None
            else None
        )

        lines: List[str] = []
        lines.append("daemon")
        lines.append(
            f"  status   running (pid {pid if pid else '?'}, "
            f"up {_fmt_duration(uptime)})"
        )
        # API line: be honest about bind state. We DO NOT claim
        # "loopback only" if the bind probe says otherwise.
        if bind_warning is None:
            lines.append(
                f"  api      127.0.0.1:{port if port else '?'} "
                f"(loopback only, or bind state unknown)"
            )
        else:
            lines.append(
                f"  api      *:{port if port else '?'} "
                f"(LAN-REACHABLE - see network section below)"
            )
        if outbound is None:
            lines.append("  outbound unknown (lsof / netstat not available)")
        elif outbound == 0:
            lines.append(
                "  outbound 0 active TCP connections - Tor has NOT bootstrapped "
                "yet, or your network is blocking it"
            )
        else:
            lines.append(
                f"  outbound {outbound} active TCP connections "
                f"(these are Tor circuits to relays - good sign)"
            )
        lines.append("")

        # contacts
        try:
            confirmed = self.app.client.list_contacts()
        except Exception as exc:
            confirmed = []
            lines.append(f"contacts (could not list: {exc})")
        else:
            online = sum(1 for c in confirmed if c.connected)
            lines.append("contacts")
            lines.append(f"  confirmed   {len(confirmed)} ({online} online)")

        try:
            pending = self.app.client.list_pending_contacts()
        except Exception:
            pending = []
        lines.append(f"  pending     {len(pending)}")
        now = time.time()
        for p in pending:
            pc = p.get("pendingContact", {}) if isinstance(p, dict) else {}
            alias = pc.get("alias") or "(no alias)"
            ts_ms = int(pc.get("timestamp") or 0)
            age = now - (ts_ms / 1000.0) if ts_ms else None
            state = p.get("state", "?")
            pid_str = str(pc.get("pendingContactId") or "")
            log_entry = self.app.pending_state_log.get(pid_str)
            if log_entry:
                last_change_age = now - log_entry[0]
                churn = f"last state change {_fmt_duration(last_change_age)} ago"
            else:
                churn = "no state change observed yet on this session"
            age_str = _fmt_duration(age) if age else "?"
            lines.append(f"    - {alias}: state={state}, age={age_str}, {churn}")
        lines.append("")

        lines.append("interpretation")
        if outbound and outbound >= 3 and pending:
            lines.append(
                "  daemon is reaching Tor and at least one peer handshake is in "
                "progress. on a healthy network this usually completes in well "
                "under a minute; if a pending state has not changed in several "
                "minutes the dial is probably failing (look at recent events / "
                "log below)."
            )
        elif outbound == 0:
            lines.append(
                "  daemon has zero outbound connections. either Tor is still "
                "starting (give it 60-120s after launch) or your network is "
                "blocking outbound 443/9001/9030 to Tor relays."
            )
        elif outbound is None:
            lines.append(
                "  cannot inspect connections from this OS without lsof / "
                "netstat. install one of those for richer diagnostics."
            )
        else:
            lines.append(
                "  daemon is connected to Tor; nothing else to do here right now."
            )
        lines.append("")

        # ---- LAN reachability ----
        # briar-headless 0.6.x has no --host flag; it always binds the
        # API wildcard. We tell the user honestly and give them a
        # mitigation they can apply at the OS firewall level.
        lines.append("network exposure")
        if bind_warning is None:
            lines.append(
                "  api bind: loopback-only OR could not be determined "
                "(no warning surfaced)"
            )
            lines.append(
                "  recommendation: nothing to do; on a typical Linux/macOS "
                "host with lsof or ss available, an absent warning means "
                "we positively confirmed loopback-only binding."
            )
        else:
            for line in bind_warning.splitlines():
                lines.append(f"  {line}")
            lines.append("")
            lines.append(
                "  what an attacker on this LAN CAN do: confirm a Briar "
                "daemon is running on this host (fingerprinting); send "
                "TCP floods to slow or stall the API (DoS)."
            )
            lines.append(
                "  what an attacker on this LAN CANNOT do: read messages, "
                "list contacts, or impersonate you - the bearer token "
                "(256-bit, mode 0600) gates every authenticated route."
            )
        lines.append("")

        # ---- recent websocket events ----
        # Useful when a pending contact is stuck: tells us whether
        # Briar is firing PendingContactStateChanged at all (means it
        # is actively retrying) or has gone quiet (means we are
        # waiting on the network).
        ev_log = list(getattr(self.app, "event_log", []))[-20:]
        lines.append("recent briar events (last 20)")
        if not ev_log:
            lines.append("  (none yet - websocket may not be receiving)")
        else:
            for ts, ename in ev_log:
                age = now - ts
                lines.append(f"  {_fmt_duration(age):>8} ago  {ename}")
        lines.append("")

        # ---- recent daemon log ----
        # Last lines from briar-headless stderr / stdout so users can
        # spot a hidden-service publish failure, port bind failure,
        # or Tor circuit error without leaving the TUI.
        proc = getattr(self.app, "daemon_proc", None)
        log_lines: List[str] = []
        if proc is not None and hasattr(proc, "tail_logs"):
            try:
                log_lines = proc.tail_logs(20)
            except Exception:
                log_lines = []
        lines.append("recent briar-headless log (last 20 lines)")
        if not log_lines:
            lines.append("  (no daemon output captured yet)")
        else:
            for ll in log_lines:
                # truncate insanely long lines so the diag panel stays
                # readable; full log is still in memory if we ever need it.
                lines.append(f"  {_scrub_log_line(ll)[:200]}")
        return "\n".join(lines)
