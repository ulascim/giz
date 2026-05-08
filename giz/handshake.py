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
import io
from dataclasses import dataclass
from typing import List, Optional

import segno
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt
from rich.table import Table
from rich.text import Text


@dataclass
class Channel:
    label: str
    leak: str
    mitm: str
    requires_verify: bool


CHANNELS: List[Channel] = [
    Channel("In person (show QR)",                              "none",                                              "strong",       False),
    Channel("Voice phone call (read 12-digit code aloud)",      "carrier knows you called",                          "strong",       False),
    Channel("Video call (show QR to camera)",                   "video provider sees pixels",                        "strong",       False),
    Channel("Tor channel (Cwtch / OnionShare)",                 "none",                                              "strong",       False),
    Channel("Signal (or other E2E messenger)",                  "Signal Foundation sees that you exchanged a link",  "theoretical",  True),
    Channel("WhatsApp / iMessage / Telegram",                   "Meta or Apple sees that you are starting Briar",    "theoretical",  True),
    Channel("Plain SMS / unencrypted email",                    "everyone in transit",                               "trivial",      True),
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
    """Render the link as a Unicode-block QR code suitable for a terminal.

    segno.terminal() writes to its out= argument (stdout by default)
    and returns None. We pass an in-memory buffer so we get back a
    string we can hand to rich.Text without touching stdout directly.
    """
    qr = segno.make(link, error="m")
    buf = io.StringIO()
    if large:
        qr.terminal(out=buf, border=2, compact=False)
    else:
        qr.terminal(out=buf, border=1, compact=True)
    return buf.getvalue()


def render_text(console: Console, link: str) -> None:
    console.print(Panel(link, title="your link", border_style="cyan"))


def render_qr(console: Console, link: str) -> None:
    console.print(Panel(
        Align.center(Text(qr_block(link, large=True), no_wrap=True)),
        title="your link as QR",
        border_style="cyan",
    ))


def render_code(console: Console, link: str) -> None:
    console.print(Panel(
        Align.center(Text(short_code(link), style="bold cyan")),
        title="your link as 12-digit short-code (read aloud on a phone call)",
        border_style="cyan",
    ))


def render_all(console: Console, link: str) -> None:
    render_text(console, link)
    render_qr(console, link)
    render_code(console, link)


def render_channels_table(console: Console) -> None:
    """Show the leak/MITM table - on demand, never forced on the user."""
    table = Table(
        title="channels you might use to send a link, ranked by leak resistance",
        title_style="bold",
        show_lines=False,
        box=None,
    )
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Channel", no_wrap=False)
    table.add_column("Leaks to", no_wrap=False)
    table.add_column("MITM resistance", no_wrap=False)
    table.add_column("Run /verify after?", no_wrap=False)
    for i, c in enumerate(CHANNELS, start=1):
        table.add_row(
            str(i),
            c.label,
            c.leak,
            c.mitm,
            "yes" if c.requires_verify else "optional",
        )
    console.print(table)
    console.print(
        "\n[dim]reading: rows 1-4 are safe. row 5 is fine if you trust Signal. "
        "rows 6-7 are NOT recommended; if you must, run /verify <name> "
        "afterward over a phone call.[/dim]"
    )
