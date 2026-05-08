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

## Adding a contact

1. Run `giz`, log in, then type `/me`.
2. Pick a channel for sharing your link. The TUI ranks channels by
   leak-resistance and tells you whether `/verify` is recommended afterward:

   | rank | channel | leaks | mitm | verify? |
   |------|---------|-------|------|---------|
   | best | in person, voice call, video call, Tor channel | none / negligible | resistant | optional |
   | ok   | Signal | Signal Foundation knows you exchanged something | theoretical | recommended |
   | bad  | WhatsApp, iMessage, Telegram | Meta or Apple knows you are starting Briar | theoretical | required |
   | no   | plain SMS, unencrypted email | everyone in transit | trivial | refused |

3. Send the link via the chosen channel. Friend runs `/add <link>` and
   picks how they received it.
4. When both of you are online, the Tor handshake completes automatically
   and the contact flips from `pending` to `online`. Now you can chat.
5. (Optional, recommended for any leaky channel.) Type `/verify <name>`,
   read the displayed fingerprint aloud over a phone call, and have your
   friend confirm theirs matches.

## Commands

```
/me              show your link (interactive channel picker)
/add <link>      add a contact from their briar:// link
/list            list contacts
/select <name>   switch active contact
/verify <name>   show contact fingerprint for out-of-band check
/status          daemon + connection status
/history         show message history with active contact
/clear <name>    delete history with one contact (local only)
/del <name>      delete a contact entirely
/quit  /q        exit cleanly
/help            full command list
(any text)       send to active contact
```

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
