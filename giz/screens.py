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
import shutil as _shutil
import subprocess
import time
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

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
        Binding("x", "remove", "remove", show=True),
        Binding("r", "refresh", "refresh", show=True),
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
            "enter chat   a add   s share   x remove   "
            "r refresh   i info   q quit",
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
        for kind, payload in items:
            if kind == "contact":
                unread = self.app.unread.get(payload.id, 0)
                list_view.append(_contact_item(payload, unread))
            else:
                list_view.append(_pending_item(payload))
        list_view.index = 0

    def action_add_contact(self) -> None:
        self.app.push_screen(AddContactScreen())

    def action_share_link(self) -> None:
        self.app.push_screen(MyLinkScreen())

    def action_refresh(self) -> None:
        self.refresh_contacts()

    def action_info(self) -> None:
        self.app.push_screen(InfoScreen())

    def action_quit(self) -> None:
        self.app.exit(0)

    def action_open_chat(self) -> None:
        self._open_highlighted()

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
                "the first connection between two new accounts "
                "usually takes 15-20 minutes. just leave giz open.",
                severity="warning",
                timeout=8,
            )
            return
        contact = payload
        self.app.unread[contact.id] = 0
        self.app.push_screen(ChatScreen(contact))


def _contact_item(c: Contact, unread: int) -> ListItem:
    if c.connected:
        status = "online" if c.verified else "online, unverified"
    else:
        status = "offline"
    name_text = c.display
    if unread:
        name_text = f"{c.display} ({unread} new)"
    row = Horizontal(
        Label(name_text, classes="contact-name"),
        Label(status, classes="contact-status"),
        classes="contact-row",
    )
    return ListItem(row)


def _pending_item(p: dict) -> ListItem:
    """A pending contact is one we added but Briar hasn't finished
    the Tor handshake for yet.

    Briar's internal state field is one of:
        'waiting_for_connection' | 'offline' | 'connecting'
        | 'added' | 'failed'

    The first three all mean the same thing to a user ('still doing
    the Tor handshake'); they only differ in which phase of Briar's
    own retry loop the daemon happens to be in at the moment of the
    poll. Showing them verbatim caused a false asymmetry between two
    machines (one would say 'waiting' while the other said 'offline'
    even though neither was more connected than the other), so we
    collapse them into a single honest line. Only the terminal
    'added' / 'failed' states get distinct messages, because those
    actually mean something different to the user.
    """
    pc = p.get("pendingContact", {}) if isinstance(p, dict) else {}
    alias = pc.get("alias") or "(no alias)"
    state = p.get("state", "pending") if isinstance(p, dict) else "pending"
    if state in ("waiting_for_connection", "offline", "connecting"):
        state_pretty = "pending: handshaking over Tor (15-20 min on first contact)"
    elif state == "added":
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
    ]

    app: "GizApp"  # type: ignore[assignment]

    def __init__(self, contact: Contact) -> None:
        super().__init__()
        self.contact = contact

    def compose(self) -> ComposeResult:
        yield Static(self._title(), id="title")
        yield RichLog(highlight=False, markup=False, wrap=True, id="log")
        yield Input(id="msg")
        yield Static("enter send   esc back", id="hint")

    def on_mount(self) -> None:
        self._load_history()
        self.set_focus(self.query_one(Input))
        try:
            self.app.client.mark_read(self.contact.id)
        except Exception:
            pass

    def _title(self) -> str:
        if self.contact.connected:
            state = "online" if self.contact.verified else "online, unverified"
        else:
            state = "offline"
        return f"giz / {self.contact.display} ({state})"

    def _load_history(self) -> None:
        log = self.query_one("#log", RichLog)
        log.clear()
        try:
            msgs = self.app.client.messages(self.contact.id)
        except Exception as exc:
            log.write(f"could not load history: {exc}")
            return
        if not msgs:
            log.write("(no messages yet)")
            return
        for m in msgs:
            self._write_message(m.text, m.timestamp, outgoing=m.is_outgoing)

    def _write_message(self, text: str, ts_ms: int, *, outgoing: bool) -> None:
        log = self.query_one("#log", RichLog)
        when = _fmt_time(ts_ms)
        who = "me" if outgoing else self.contact.display
        log.write(f"{when} {who}: {text}")

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
            f"added '{alias}'. now waiting for the Tor handshake "
            f"(15-20 minutes for a new pair of accounts). esc to go back."
        )
        self.app.notify(
            f"added '{alias}'. it will appear on the contacts screen as "
            f"'pending' until both sides finish handshaking over Tor "
            f"(usually 15-20 minutes for new accounts).",
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


def _fmt_time(ts_ms: int) -> str:
    try:
        return datetime.fromtimestamp(ts_ms / 1000.0).strftime("%H:%M")
    except (ValueError, OSError):
        return "--:--"


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
