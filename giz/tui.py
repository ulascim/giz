"""Minimal scrolling terminal chat.

We deliberately avoid full-screen layouts (no rich.Live, no curses).
A simple scrolling transcript is the smallest possible UI surface
that can host two-person text chat, and it works in any terminal
without quirks (tmux, mosh, ssh, Windows Terminal, plain Terminal.app).

Slash commands:
    /me              - show your link (channel picker, QR, short-code)
    /add <link>      - add a contact from their briar:// link
    /list            - list contacts
    /select <name>   - switch active contact
    /verify <name>   - show the contact's full fingerprint
    /status          - daemon + Tor status
    /clear <name>    - delete message history with one contact (local only)
    /del <name>      - delete a contact entirely
    /quit  /q        - exit cleanly
    /help            - this list

Anything that does not start with / is sent as a private message to the
currently selected contact.
"""

from __future__ import annotations

import shlex
import sys
import threading
import time
from datetime import datetime
from queue import Queue, Empty
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import handshake
from .briar import BriarClient, Contact


class TUI:
    def __init__(
        self,
        client: BriarClient,
        nickname: str,
    ) -> None:
        self._client = client
        self._nickname = nickname
        self._console = Console(highlight=False)
        self._event_queue: Queue[Dict[str, Any]] = Queue()
        self._active: Optional[Contact] = None
        self._contacts: List[Contact] = []
        self._unverified: Dict[int, bool] = {}
        self._daemon_alive = True

    def run(self) -> int:
        self._events_setup()
        self._refresh_contacts()
        self._print_banner()
        self._print_help_brief()
        self._print_next_step_hint()
        try:
            self._main_loop()
        except (EOFError, KeyboardInterrupt):
            self._console.print("\n[dim]bye[/dim]")
        return 0

    def _print_next_step_hint(self) -> None:
        if not self._contacts:
            self._console.print(
                "\n[bold]first time? do this:[/bold]\n"
                "  [cyan]/me[/cyan]            print your link as text\n"
                "  [cyan]/me qr[/cyan]         print your link as a QR\n"
                "  [cyan]/me code[/cyan]       print your link as a 12-digit code\n"
                "  [cyan]/add <link>[/cyan]    paste a link you received\n"
                "  [cyan]/help[/cyan]          full command list\n"
            )
            return
        unverified = [c for c in self._contacts if self._unverified.get(c.id)]
        connected = [c for c in self._contacts if c.connected]
        if connected:
            target = connected[0]
            self._console.print(
                f"\n[dim]{target.display} is online. /select {target.display} "
                f"and type to chat.[/dim]\n"
            )
        elif self._contacts:
            names = ", ".join(c.display for c in self._contacts[:3])
            self._console.print(
                f"\n[dim]contacts: {names} (all offline). "
                f"messages will queue and deliver when both sides are online.[/dim]\n"
            )
        if unverified:
            names = ", ".join(c.display for c in unverified)
            self._console.print(
                f"[yellow]unverified contacts: {names}. "
                f"run /verify <name> over a phone call to rule out MITM.[/yellow]\n"
            )

    def _events_setup(self) -> None:
        self._events_thread = threading.Thread(
            target=self._drain_events, daemon=True
        )
        self._events_thread.start()

    def _drain_events(self) -> None:
        while True:
            try:
                ev = self._event_queue.get(timeout=0.5)
            except Empty:
                continue
            self._handle_event(ev)

    def on_event(self, event: Dict[str, Any]) -> None:
        """Called from the EventSubscription thread."""
        self._event_queue.put(event)

    def on_disconnect(self, exc: Optional[Exception]) -> None:
        self._daemon_alive = False
        self._console.print(
            "\n[red]briar-headless disconnected. "
            "Type /quit to exit cleanly.[/red]"
        )

    def _handle_event(self, ev: Dict[str, Any]) -> None:
        name = ev.get("name") or ev.get("type") or ""
        if "PrivateMessageReceived" in name or name == "PrivateMessageReceivedEvent":
            self._on_message_received(ev)
        elif "ContactConnectedEvent" in name or "ContactConnected" in name:
            cid = ev.get("data", {}).get("contactId") or ev.get("contactId")
            if cid is not None:
                self._mark_connected(int(cid), True)
        elif "ContactDisconnectedEvent" in name or "ContactDisconnected" in name:
            cid = ev.get("data", {}).get("contactId") or ev.get("contactId")
            if cid is not None:
                self._mark_connected(int(cid), False)
        elif "ContactAddedEvent" in name or "ContactAdded" in name:
            self._refresh_contacts()
            self._console.print("[dim]new contact added[/dim]")

    def _on_message_received(self, ev: Dict[str, Any]) -> None:
        data = ev.get("data", ev)
        contact_id = data.get("contactId")
        text = data.get("text") or data.get("body", "")
        ts = data.get("timestamp", int(time.time() * 1000))
        sender = self._lookup(contact_id) if contact_id is not None else None
        sender_name = sender.display if sender else f"#{contact_id}"
        when = _fmt_time(ts)
        self._console.print(
            f"[bold cyan]{when} {sender_name}:[/bold cyan] {text}"
        )

    def _mark_connected(self, contact_id: int, connected: bool) -> None:
        for c in self._contacts:
            if c.id == contact_id:
                c.connected = connected
                state = "online" if connected else "offline"
                self._console.print(
                    f"[dim]{c.display} is now {state}[/dim]"
                )
                return

    def _print_banner(self) -> None:
        try:
            link = self._client.my_link()
        except Exception:
            link = "(unavailable - daemon not ready)"
        body = Text()
        body.append(f"hello, {self._nickname}\n", style="bold")
        body.append("your link: ")
        body.append(link, style="cyan")
        self._console.print(Panel(body, border_style="cyan", title="giz"))

    def _print_help_brief(self) -> None:
        self._console.print(
            "[dim]/me  /add <link>  /list  /select <name>  /verify <name>  "
            "/channels  /quit  /help[/dim]"
        )

    def _print_help_full(self) -> None:
        t = Table(title="commands", show_lines=False, box=None)
        t.add_column("command", style="cyan", no_wrap=True)
        t.add_column("does")
        t.add_row("/me", "show your link as plain text")
        t.add_row("/me qr", "show your link as a QR code")
        t.add_row("/me code", "show your link as a 12-digit short-code")
        t.add_row("/me all", "show all three formats at once")
        t.add_row("/add <link>", "add a contact from their briar:// link")
        t.add_row("/list", "list contacts")
        t.add_row("/select <name>", "switch active contact")
        t.add_row("/verify <name>", "show full fingerprint for out-of-band check")
        t.add_row("/channels", "show the leak/MITM table for sharing channels")
        t.add_row("/status", "daemon + connection status")
        t.add_row("/history", "show message history with active contact")
        t.add_row("/clear <name>", "delete message history (local only)")
        t.add_row("/del <name>", "delete a contact entirely")
        t.add_row("/help", "this list")
        t.add_row("/quit, /q", "exit cleanly")
        t.add_row("(any text)", "send to active contact")
        self._console.print(t)

    def _main_loop(self) -> None:
        while True:
            prompt = self._format_prompt()
            try:
                line = input(prompt)
            except EOFError:
                return
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                if not self._dispatch(line):
                    return
            else:
                self._send(line)

    def _format_prompt(self) -> str:
        if self._active is None:
            return "giz> "
        badge = ""
        if self._unverified.get(self._active.id):
            badge = " [unverified]"
        state = "online" if self._active.connected else "offline"
        return f"[{self._active.display}{badge} {state}]> "

    def _dispatch(self, line: str) -> bool:
        try:
            argv = shlex.split(line)
        except ValueError:
            self._console.print("[red]parse error[/red]")
            return True
        cmd = argv[0].lower()
        rest = argv[1:]
        if cmd in ("/quit", "/q", "/exit"):
            return False
        if cmd == "/help":
            self._print_help_full()
            return True
        if cmd == "/me":
            self._cmd_me(rest)
            return True
        if cmd == "/channels":
            handshake.render_channels_table(self._console)
            return True
        if cmd == "/add":
            self._cmd_add(rest)
            return True
        if cmd == "/list":
            self._cmd_list()
            return True
        if cmd == "/select":
            self._cmd_select(rest)
            return True
        if cmd == "/verify":
            self._cmd_verify(rest)
            return True
        if cmd == "/status":
            self._cmd_status()
            return True
        if cmd == "/history":
            self._cmd_history()
            return True
        if cmd == "/clear":
            self._cmd_clear(rest)
            return True
        if cmd == "/del":
            self._cmd_del(rest)
            return True
        self._console.print(f"[yellow]unknown: {cmd}[/yellow] (try /help)")
        return True

    def _cmd_me(self, args: List[str]) -> None:
        try:
            link = self._client.my_link()
        except Exception as exc:
            self._console.print(f"[red]could not get link: {exc}[/red]")
            return
        mode = (args[0].lower() if args else "text")
        if mode == "qr":
            handshake.render_qr(self._console, link)
        elif mode in ("code", "digits", "short", "shortcode"):
            handshake.render_code(self._console, link)
        elif mode == "all":
            handshake.render_all(self._console, link)
        elif mode == "text":
            handshake.render_text(self._console, link)
        else:
            self._console.print(
                f"[yellow]unknown /me option: '{mode}'. "
                f"valid: /me, /me qr, /me code, /me all[/yellow]"
            )
            return
        self._console.print(
            "[dim]send this to your friend; they will run /add <link>. "
            "type /channels to see leak / MITM ranking of sharing methods.[/dim]"
        )

    def _cmd_add(self, args: List[str]) -> None:
        if not args:
            self._console.print("[yellow]usage: /add <briar://...> [alias][/yellow]")
            return
        link = args[0]
        if not link.startswith("briar://"):
            self._console.print(
                "[red]that does not look like a briar:// link[/red]"
            )
            return
        alias = args[1] if len(args) > 1 else _ask(self._console, "alias for this contact: ")
        if not alias:
            self._console.print("[yellow]aborted[/yellow]")
            return
        try:
            self._client.add_pending(link, alias)
        except Exception as exc:
            self._console.print(f"[red]add failed: {exc}[/red]")
            return
        self._console.print(
            f"[green]pending contact '{alias}' added. "
            f"handshake will complete when both sides are online.[/green]\n"
            f"[dim]if this link reached you via WhatsApp / iMessage / SMS, "
            f"run /verify {alias} over a phone call once the handshake "
            f"is done.[/dim]"
        )

    def _cmd_list(self) -> None:
        self._refresh_contacts()
        if not self._contacts:
            self._console.print("[dim](no contacts. share /me with a friend.)[/dim]")
            return
        t = Table(box=None, show_header=True)
        t.add_column("name", style="cyan", no_wrap=True)
        t.add_column("status")
        t.add_column("verified")
        for c in self._contacts:
            state = "online" if c.connected else "offline"
            verified = "yes" if c.verified else "no"
            t.add_row(c.display, state, verified)
        self._console.print(t)

    def _cmd_select(self, args: List[str]) -> None:
        if not args:
            self._console.print("[yellow]usage: /select <name>[/yellow]")
            return
        name = args[0]
        c = self._lookup_by_name(name)
        if c is None:
            self._console.print(f"[red]no contact named '{name}'[/red]")
            return
        self._active = c
        self._console.print(f"[dim]active: {c.display}[/dim]")
        try:
            self._client.mark_read(c.id)
        except Exception:
            pass

    def _cmd_verify(self, args: List[str]) -> None:
        if not args:
            self._console.print("[yellow]usage: /verify <name>[/yellow]")
            return
        c = self._lookup_by_name(args[0])
        if c is None:
            self._console.print(f"[red]no contact named '{args[0]}'[/red]")
            return
        material = c.handshake_pubkey or c.author_id or str(c.id)
        self._console.print(Panel(
            handshake.long_fingerprint(material),
            title=f"{c.display} - full fingerprint",
            border_style="cyan",
        ))
        self._console.print(
            "[dim]Read this aloud over a phone call. Friend reads theirs. "
            "If both match, MITM is ruled out.[/dim]"
        )

    def _cmd_status(self) -> None:
        self._console.print(
            f"daemon: {'alive' if self._daemon_alive else 'DEAD'}\n"
            f"contacts: {len(self._contacts)} "
            f"({sum(1 for c in self._contacts if c.connected)} online)\n"
            f"active: {self._active.display if self._active else '(none)'}"
        )

    def _cmd_history(self) -> None:
        if self._active is None:
            self._console.print("[yellow]no active contact. /select <name> first.[/yellow]")
            return
        try:
            msgs = self._client.messages(self._active.id)
        except Exception as exc:
            self._console.print(f"[red]history failed: {exc}[/red]")
            return
        if not msgs:
            self._console.print("[dim](no messages yet)[/dim]")
            return
        for m in msgs[-50:]:
            who = "me" if m.is_outgoing else self._active.display
            color = "green" if m.is_outgoing else "cyan"
            self._console.print(
                f"[{color}]{_fmt_time(m.timestamp)} {who}:[/] {m.text}"
            )

    def _cmd_clear(self, args: List[str]) -> None:
        if not args:
            self._console.print("[yellow]usage: /clear <name>[/yellow]")
            return
        c = self._lookup_by_name(args[0])
        if c is None:
            self._console.print(f"[red]no contact named '{args[0]}'[/red]")
            return
        confirm = _ask(self._console, f"delete history with {c.display}? type yes: ")
        if confirm.strip().lower() != "yes":
            self._console.print("[dim]aborted[/dim]")
            return
        try:
            self._client._delete(f"/v1/messages/{c.id}/all")
            self._console.print("[green]history cleared[/green]")
        except Exception as exc:
            self._console.print(f"[red]clear failed: {exc}[/red]")

    def _cmd_del(self, args: List[str]) -> None:
        if not args:
            self._console.print("[yellow]usage: /del <name>[/yellow]")
            return
        c = self._lookup_by_name(args[0])
        if c is None:
            self._console.print(f"[red]no contact named '{args[0]}'[/red]")
            return
        confirm = _ask(self._console, f"remove contact {c.display}? type yes: ")
        if confirm.strip().lower() != "yes":
            self._console.print("[dim]aborted[/dim]")
            return
        try:
            self._client.delete_contact(c.id)
            if self._active is not None and self._active.id == c.id:
                self._active = None
            self._refresh_contacts()
            self._console.print("[green]removed[/green]")
        except Exception as exc:
            self._console.print(f"[red]delete failed: {exc}[/red]")

    def _send(self, text: str) -> None:
        if self._active is None:
            self._console.print(
                "[yellow]no active contact. /select <name> first, "
                "or /list to see contacts.[/yellow]"
            )
            return
        try:
            self._client.send_message(self._active.id, text)
        except Exception as exc:
            self._console.print(f"[red]send failed: {exc}[/red]")
            return
        self._console.print(
            f"[green]{_fmt_time(int(time.time() * 1000))} me:[/green] {text}"
        )

    def _refresh_contacts(self) -> None:
        try:
            self._contacts = self._client.list_contacts()
        except Exception:
            return

    def _lookup(self, contact_id: int) -> Optional[Contact]:
        for c in self._contacts:
            if c.id == contact_id:
                return c
        self._refresh_contacts()
        for c in self._contacts:
            if c.id == contact_id:
                return c
        return None

    def _lookup_by_name(self, name: str) -> Optional[Contact]:
        nl = name.lower()
        for c in self._contacts:
            if (c.alias or "").lower() == nl or c.name.lower() == nl:
                return c
        return None


def _fmt_time(ts_ms: int) -> str:
    try:
        return datetime.fromtimestamp(ts_ms / 1000.0).strftime("%H:%M")
    except (ValueError, OSError):
        return "--:--"


def _ask(console: Console, prompt: str) -> str:
    console.print(prompt, end="")
    sys.stdout.flush()
    try:
        return input()
    except EOFError:
        return ""
