"""Three screens: Contacts, Chat, Exchange Links.

Pure text. No mouse. No buttons. No colored boxes. Each screen is:

    line 1                  title
    line 2..N-1             content
    last line               hint (single dim line of available keys)

Keyboard model:
    Contacts:  Up/Down -> select   Enter -> chat   a -> add   r -> refresh   q -> quit
    Chat:      Enter on input -> send   Esc -> back
    Exchange:  t/q/c toggle your-link format   Tab -> next field
               Enter on link -> jump to alias   Enter on alias -> submit   Esc -> back
"""

from __future__ import annotations

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
        Binding("a", "add_contact", "add", show=True),
        Binding("r", "refresh", "refresh", show=True),
        Binding("i", "info", "info", show=True),
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
            "enter chat   a add   r refresh   i info   q quit",
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
            empty.update("no contacts. press a to add one.")
            empty.display = True
            list_view.display = False
            return
        empty.display = False
        list_view.display = True
        for c in contacts:
            unread = self.app.unread.get(c.id, 0)
            list_view.append(_contact_item(c, unread))
        list_view.index = 0

    def action_add_contact(self) -> None:
        self.app.push_screen(ExchangeLinksScreen())

    def action_refresh(self) -> None:
        self.refresh_contacts()

    def action_info(self) -> None:
        self.app.push_screen(InfoScreen())

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


# ---------------------------------------------------------------- Exchange

class ExchangeLinksScreen(Screen):
    """Two-way link exchange.

    Top: your own link, in three formats (t=text, q=qr, c=code).
    Bottom: paste a friend's link, give them a name. Esc returns home.

    The toggle bindings (t/q/c) only fire when the inputs are not
    focused, since Inputs consume printable characters. Tab moves
    focus between paste-link and alias.
    """

    BINDINGS = [
        Binding("escape", "back", "back", show=True),
        Binding("t", "show_text", "text", show=False),
        Binding("q", "show_qr", "qr", show=False),
        Binding("c", "show_code", "code", show=False),
    ]

    # Do not auto-focus any widget on mount; t/q/c bindings need to
    # win over the paste-link Input until the user explicitly tabs in.
    # Empty string is falsy so Screen._on_mount() skips auto-focus.
    AUTO_FOCUS = ""

    app: "GizApp"  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self._mode = "text"
        self._link: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Static("giz / exchange links", id="title")
        yield Vertical(
            Static("your link  (t text  q qr  c short-code)", id="my-toggle"),
            Static("loading...", id="my-link"),
            id="my-pane",
        )
        yield Vertical(
            Label("paste a friend's briar:// link, then enter:"),
            Input(placeholder="briar://...", id="paste-link"),
            Static("", id="paste-code"),
            Label("name for this contact, then enter to add:"),
            Input(placeholder="alias", id="paste-alias"),
            Static("", id="add-status"),
            id="add-pane",
        )
        yield Static(
            "t/q/c toggle   tab edit fields   enter advance   esc leave field / back",
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
            widget.update(Text(handshake.qr_block(self._link, large=False), no_wrap=True))
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

    def action_back(self) -> None:
        # First esc: leave any input we're typing in (so t/q/c work again).
        # Second esc (no input focused): actually go back to Contacts.
        focused = self.app.focused
        if isinstance(focused, Input):
            self.set_focus(None)
            return
        self.app.pop_screen()

    def on_input_changed(self, event: Input.Changed) -> None:
        # Live-update the short-code of whatever the user typed/pasted
        # so they can compare it on the phone with the friend who sent
        # this link. If the codes do not match, the link was tampered
        # with in transit and adding it would MITM the conversation.
        if event.input.id != "paste-link":
            return
        code_widget = self.query_one("#paste-code", Static)
        link = event.value.strip()
        if not link.startswith("briar://"):
            code_widget.update("")
            return
        code_widget.update(
            f"short-code of pasted link: {handshake.short_code(link)}\n"
            f"(have your friend read out their 'c' code; they must match)"
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
            return
        self.query_one("#paste-link", Input).value = ""
        self.query_one("#paste-alias", Input).value = ""
        self.query_one("#paste-code", Static).update("")
        self.set_focus(None)
        status.update(
            f"added '{alias}'. handshake completes when both are online. "
            f"esc to go back."
        )


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
    giz: there is no server, no account database, no operator,
    no subpoena address. nobody is in the loop to be compelled,
    bribed, or hacked. the source is public; whoever wrote it
    cannot push secret updates to you - your installer pulls
    from a public commit you can read.
    Signal: the Signal Foundation knows your phone number and
    can see traffic timing.
    WhatsApp / iMessage: Meta / Apple know your phone number,
    see traffic, and hold the keys to legally-mandated backdoors
    in some jurisdictions.

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

  giz + a clean device puts you above 99.9% of realistic adversaries.
  the remaining 0.1% - multiple major intelligence agencies all
  cooperating, targeting you by name, for years - cannot be defeated
  by any messenger on the market today. their counter is not crypto;
  it is operational discipline (different device, different network,
  less communication, no reused identity).

  giz protects the wire and the disk. it cannot protect the device.
  if your laptop is clean, your messages are private from everyone
  including Apple, your ISP, and the Briar project itself. if your
  laptop is not clean, no messenger on earth can save you.
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
