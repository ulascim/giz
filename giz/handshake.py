"""Channel-aware contact-add flow.

When the user runs /me, giz asks how they intend to share their link
and renders the link in the format optimal for that channel. When the
user runs /add, giz asks how the link reached them and uses that to
decide whether to nag for /verify afterward.

The leak ranking we present to the user matches the table in
SECURITY.md:

    in-person QR   |  voice phone call  |  video call (terminal QR)
    Tor channel    |  Signal (E2E)      |  WhatsApp/iMessage  |  SMS

The first three are MITM-resistant in practice. The middle two leak
metadata to a third party. The last two are actively dangerous and
giz emits a strong warning before complying.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional

import segno
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt
from rich.table import Table
from rich.text import Text


SEND = "send"
RECEIVE = "receive"


@dataclass
class Channel:
    key: str
    label: str
    leak: str
    mitm: str
    requires_verify: bool


CHANNELS: List[Channel] = [
    Channel("inperson", "In person (show QR)", "none", "strong", False),
    Channel("voice", "Voice phone call (read short-code)", "carrier knows you called", "strong", False),
    Channel("video", "Video call (show terminal QR)", "video provider sees pixels", "strong", False),
    Channel("tor", "Tor channel (Cwtch / OnionShare)", "none", "strong", False),
    Channel("signal", "Signal (or other E2E messenger)", "Signal Foundation knows you exchanged something", "theoretical", True),
    Channel("whatsapp", "WhatsApp / iMessage / Telegram", "Meta or Apple knows you are starting Briar", "theoretical", True),
    Channel("sms", "Plain SMS / unencrypted email", "everyone in transit", "trivial", True),
    Channel("all", "Show all formats (advanced)", "depends on what you use", "depends", True),
]


def short_code(blob: str) -> str:
    """A grouped 12-digit numeric code derived from any string.

    Used both for "this is my own link, read these digits to your
    friend" and for "this is the contact's verified fingerprint."

    The digits are decimal SHA-256 truncated to 40 bits, which is far
    shorter than Briar's full Ed25519 fingerprint and is meant only as
    a quick sanity check, not as a primary authentication. For full
    authentication use /verify which shows the entire fingerprint.
    """
    h = hashlib.sha256(blob.encode("utf-8", errors="ignore")).digest()
    n = int.from_bytes(h[:5], "big")
    s = f"{n:013d}"[-12:]
    return f"{s[0:4]} {s[4:8]} {s[8:12]}"


def long_fingerprint(blob: str) -> str:
    """A full SHA-256 hex fingerprint, grouped 4-4-4 for reading aloud.

    Suitable for /verify after a strong-enough channel exchange.
    Reading 64 hex chars over the phone takes ~30 seconds and rules
    out MITM with extremely high confidence.
    """
    h = hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest().upper()
    return " ".join(h[i : i + 4] for i in range(0, len(h), 4))


def qr_block(link: str, *, large: bool = False) -> str:
    """Render the link as a Unicode-block QR code suitable for a terminal."""
    qr = segno.make(link, error="m")
    if large:
        return qr.terminal(border=2, compact=False)
    return qr.terminal(border=1, compact=True)


def pick_channel(
    console: Console,
    direction: str = SEND,
) -> Channel:
    """Interactive channel picker. Returns the chosen Channel.

    direction is "send" (we are about to share our own link) or
    "receive" (we just received a link from a friend). The wording
    of the table changes; the underlying choices are the same.
    """
    table = Table(
        title="How are you sharing this link?" if direction == SEND
        else "How did this link reach you?",
        title_style="bold",
        show_lines=False,
        box=None,
    )
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Channel", no_wrap=False)
    table.add_column("Leaks to", no_wrap=False)
    table.add_column("MITM resistance", no_wrap=False)

    for i, c in enumerate(CHANNELS, start=1):
        table.add_row(str(i), c.label, c.leak, c.mitm)

    console.print(table)
    while True:
        choice = IntPrompt.ask("Pick", default=2, console=console)
        if 1 <= choice <= len(CHANNELS):
            return CHANNELS[choice - 1]


def render_for_channel(
    console: Console,
    link: str,
    channel: Channel,
) -> None:
    """Display our briar:// link in the format best suited to channel."""
    console.print()
    if channel.key == "inperson":
        console.print(Panel(
            Align.center(Text(qr_block(link, large=True), no_wrap=True)),
            title="Your link (point friend's camera)",
            border_style="cyan",
        ))
    elif channel.key == "voice":
        console.print(Panel(
            Align.center(Text(short_code(link), style="bold cyan")),
            title="Your short-code (read these digits aloud)",
            border_style="cyan",
        ))
        console.print(
            "[dim]Friend should run /add and pick 'Voice phone call' "
            "as the receive channel. They will see the same digits.[/dim]"
        )
    elif channel.key == "video":
        console.print(Panel(
            Align.center(Text(qr_block(link, large=False), no_wrap=True)),
            title="Your link (show this to the camera)",
            border_style="cyan",
        ))
    elif channel.key == "tor":
        console.print(Panel(
            link,
            title="Your link (paste into Cwtch / OnionShare / your Tor channel)",
            border_style="cyan",
        ))
    elif channel.key == "signal":
        console.print(Panel(
            link,
            title="Your link (paste into Signal)",
            border_style="cyan",
        ))
        console.print(
            "[yellow]Signal sees that you exchanged a Briar invite. "
            "Run /verify after the handshake to rule out MITM.[/yellow]"
        )
    elif channel.key == "whatsapp":
        console.print(Panel(
            "[red bold]Strongly discouraged.[/red bold] WhatsApp, iMessage, "
            "and Telegram all reveal to their operators that you are "
            "about to start using Briar. This defeats much of the point "
            "of giz. Use voice or video call instead if at all possible.\n",
            border_style="red",
        ))
        console.print(Panel(
            link,
            title="Your link (sending via a leaky channel)",
            border_style="red",
        ))
        console.print(
            "[red]After handshake completes you MUST run /verify "
            "over a different channel.[/red]"
        )
    elif channel.key == "sms":
        console.print(Panel(
            "[red bold]Refused: SMS is plaintext.[/red bold] Anyone in "
            "transit (including SS7 attackers) can read your link, "
            "substitute it, or correlate it with later traffic. Pick "
            "a different channel.",
            border_style="red",
        ))
        return
    elif channel.key == "all":
        _render_all_formats(console, link)


def _render_all_formats(console: Console, link: str) -> None:
    console.print(Panel(link, title="Plain text", border_style="cyan"))
    console.print(Panel(
        Align.center(Text(qr_block(link, large=False), no_wrap=True)),
        title="QR code",
        border_style="cyan",
    ))
    console.print(Panel(
        Align.center(Text(short_code(link), style="bold cyan")),
        title="Short-code (12 digits)",
        border_style="cyan",
    ))


def needs_verify(send_channel: Optional[Channel], receive_channel: Optional[Channel]) -> bool:
    """True if at least one side used a channel where MITM is plausible."""
    return any(
        c is not None and c.requires_verify
        for c in (send_channel, receive_channel)
    )
