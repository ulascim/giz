# giz

Minimal, terminal-only, peer-to-peer encrypted messenger.

No phone numbers. No central server. No metadata leaks to any third party.
Just two friends, two terminals, end-to-end encryption over Tor.

`giz` is a thin auditable wrapper around [Briar's headless daemon][briar].
Briar's protocol is what protects your messages. `giz` adds a tiny terminal
UI, a one-line installer, a duress-password wipe, and hard backup-leak
prevention.

## Install

**macOS (Apple Silicon):**

```bash
curl -fsSL https://raw.githubusercontent.com/ulascim/giz/main/install.sh | bash
```

**Windows (PowerShell):**

```powershell
iwr -useb https://raw.githubusercontent.com/ulascim/giz/main/install.ps1 | iex
```

The installer:
- Refuses to run as root / Administrator.
- Refuses if your home directory is inside iCloud Drive, OneDrive, Dropbox,
  or Google Drive.
- Installs Java 17 and Python 3.9+ if missing.
- Verifies the SHA-256 of every downloaded artifact.
- Asks you for a nickname, a real password, and a duress password.

After it finishes, type `giz` in any terminal to log in.

## What giz does

- Generates a long-term Ed25519 identity for each user, locally, never
  uploaded anywhere.
- Routes all messages through a Tor v3 hidden service. Your IP and your
  friend's IP are never visible to anyone, including each other.
- Encrypts every message with Curve25519 + XSalsa20-Poly1305. Forward
  secrecy via the Bramble Transport Protocol.
- Stores the local message database encrypted at rest with Argon2id-derived
  keys. The database is unreadable without your password.

## The UI

Three screens, keyboard only, no mouse:

| screen   | what            | keys                                      |
|----------|-----------------|-------------------------------------------|
| Contacts | list of friends | up/down to navigate, enter to chat, `a` to add, `q` to quit |
| Chat     | one conversation | type to compose, enter to send, `esc` for back |
| Exchange | swap links     | `t`/`q`/`c` toggle your link as text/QR/code, paste a friend's link, enter to add, `esc` for back |

That's the whole UI. There are no slash commands.

## Multiple personas

By design, one running `giz` shows exactly one account. This protects
the duress-wipe model: an attacker who unlocks your app cannot see a
list of "other" accounts. Personas exist only on the filesystem, not
inside any running process.

To create a second persona alongside your primary account:

```bash
giz new bob
```

This creates `~/.giz-bob/` with its own keypair, its own real password,
its own duress password, and drops a `giz-bob` launcher in `~/.local/bin/`.
Run `giz` and `giz-bob` in two separate terminals to use them side by
side. Each persona is independent and reachable as a Briar contact in
its own right; you can even add `giz-bob` as a contact of your primary
account if you want to test locally.

Persona names are lowercase letters/digits/dash, max 32 chars.

## Adding a contact

1. Run `giz`, log in. You land on the Contacts screen.
2. Press `a` to open the Exchange-Links screen.
3. The top half shows **your** link. Press `t`/`q`/`c` to display it as
   plain text (paste-friendly), as a QR code (show on a video call or
   in person), or as a 12-digit short-code (read aloud over a phone
   call). Send it to your friend through whichever channel you trust.
4. When your friend sends back **their** link, paste it into the
   bottom-half input, give them a name, and press Enter.
5. When both of you are online, the Tor handshake completes
   automatically and the contact flips from offline to online on the
   Contacts screen.

For sharing the link, channels ranked by leak-resistance:

| rank | channel | leaks | mitm |
|------|---------|-------|------|
| best | in person (QR), voice call (short-code), video call (QR), Tor channel | none / negligible | resistant |
| ok   | Signal | Signal Foundation knows you exchanged something | theoretical |
| bad  | WhatsApp, iMessage, Telegram | Meta or Apple knows you are starting Briar | theoretical |
| no   | plain SMS, unencrypted email | everyone in transit | trivial |

## Recommended terminal

`giz` uses [Textual][textual] for its TUI. Any modern terminal works,
but for the cleanest rendering use:

- **macOS:** Terminal.app (built in) or [iTerm2][iterm2].
- **Windows:** [Windows Terminal][wt].

Avoid the legacy `cmd.exe` console - it does not handle Unicode block
characters well, which makes QR codes look broken.

## Duress password

At setup, `giz` asks for a real password and a duress password.

- Type the **real** password to log in normally.
- Type the **duress** password and `giz` silently destroys all real data,
  removes the hash files, and exits with a generic "account not found"
  message. The wipe is irreversible. There is no recovery.

This is for situations where you are forced to unlock `giz`. Use it at your
own discretion. If you mistype the duress password under stress, your data
is gone.

## Threat model in one sentence

`giz` protects your messages and the fact that you sent them against any
adversary that does not have malicious code running on the device you are
using.

For the full threat model, including what `giz` does NOT protect against
and why, see [SECURITY.md](SECURITY.md).

## Auditing

The full source is here, in this repository, and the installer downloads
exactly this code. The Python wrapper is intentionally small (~7 files,
~1200 lines) so it can be read in one sitting. The cryptography is in
Briar; we do not implement any.

## Caveats worth flagging

- First launch takes 60-120 seconds while Tor builds circuits and
  publishes the hidden service. Subsequent logins are fast.
- Both peers must be online at the same time for real-time delivery.
  Otherwise messages queue locally on the sender's side.
- Memory wiping in Python is best-effort; SECURITY.md is honest about
  the limits.
- The duress wipe is observable: a sophisticated attacker who saw you
  using `giz` five minutes ago and now sees "no account" knows you wiped.
  This is the trade-off vs. a decoy account approach.

## License

MIT. See [LICENSE](LICENSE).

[briar]: https://briarproject.org
[textual]: https://textual.textualize.io
[iterm2]: https://iterm2.com
[wt]: https://aka.ms/terminal
