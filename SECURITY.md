# SECURITY.md

This document describes what `giz` protects against, what it does not
protect against, and why. It is intentionally explicit so that you can
make a calibrated decision about whether `giz` matches your threat model.

## What giz is

`giz` is a thin Python wrapper around the Briar headless daemon. The
cryptography, the protocol, and the Tor integration are all Briar's
work. `giz` adds:

1. A first-run setup that picks a real password and a duress password.
2. Process-level no-leak guards (no core dumps, no ptrace, no logs to
   disk, no telemetry, single-instance lockfile).
3. A hard refusal to install if the data directory lives inside any
   cloud-synced folder.
4. A channel-aware contact-add flow that teaches the user about
   metadata leaks at the moment of decision.
5. A minimal scrolling terminal UI.

Briar itself has been audited by Cure53 and is in active production use
by activists in adversarial environments (Hong Kong, Belarus, Iran,
others). The cryptographic primitives (Ed25519, Curve25519,
XSalsa20-Poly1305) are peer-reviewed.

## Protected against

| Adversary | Why it fails |
|-----------|--------------|
| Your ISP reading your messages | Encrypted before leaving your machine. |
| Your ISP knowing who you talk to | Tor onion routing hides destination. |
| Apple, Microsoft, Google reading message content | Encrypted on your machine; OS sees only Tor packets. |
| Apple, Microsoft, Google knowing who you talk to | Same as above. |
| Hackers on the same WiFi | Encrypted before WiFi. |
| Government subpoenas a server for logs | There is no server. There is nothing to subpoena. |
| Government compels Briar Project to backdoor you | Briar Project has no keys, no servers, no relationship with any user. Even if a malicious release were pushed, the source is public and the install pins a SHA-256 hash. |
| Hacker steals your laptop disk | The Briar database is encrypted with an Argon2id-derived key from your password. A strong password (>= 12 random characters) is computationally infeasible to brute-force. |
| Forced password disclosure | Type the duress password instead. The real account is silently destroyed. |
| MITM during initial link exchange | Detected by `/verify`, which reads a SHA-256 fingerprint aloud over a different channel. With a strong exchange channel, MITM is not possible to begin with. |

## Not protected against

These are out of scope by design. They are out of scope for every other
secure messenger as well, including Signal, Briar, and Wire.

| Threat | Why no app can fix this |
|--------|-------------------------|
| Pegasus or other device-level malware | If the OS is compromised, the malware reads your screen and keyboard before encryption. No application-layer crypto helps. |
| Physical observation while screen is unlocked | Nobody can. |
| Coercion to type your password under direct observation | Your only defense is the duress password, and only against attackers who do not know about it. |
| Backups outside of giz's control | If you back up your `~/.giz` directory to a third party, the encrypted DB is now in a third party's hands. The encryption is still strong, but ciphertext exposure is real. The installer hard-refuses if the data dir is inside a known cloud-sync folder; routine backup tools (Time Machine, etc.) we exclude where possible but cannot prevent if you reconfigure them. |

### Specific caveats

**Memory wiping is best-effort.** Python's garbage collector and string
interning prevent a hard guarantee that password bytes are zeroed before
being reclaimed. We hold passwords in `bytearray` (mutable) and overwrite
them after use, but a determined forensic analyst with cold-boot RAM
access could in theory recover fragments. The kernel-level defenses
(`RLIMIT_CORE = 0` to disable core dumps, `prctl(PR_SET_DUMPABLE, 0)` /
`PT_DENY_ATTACH` to refuse debugger attach) are the binding guarantees;
they prevent any password fragment from ever reaching disk under normal
operation.

**The duress wipe is observable.** A sophisticated attacker who saw you
using `giz` five minutes ago and now sees "no account" knows you wiped.
This is the explicit trade-off chosen over a decoy-account approach: the
decoy is harder to maintain plausibly and keeping a fake account active
is operational overhead. The wipe is irreversible; if you mistype the
duress password under stress, your data is gone.

**SSD secure deletion is partial.** `secure_wipe` overwrites small
sensitive files (the password hash file, the lockfile) before unlinking
them. On modern SSDs the controller may write to a different physical
block, so the original ciphertext blocks may remain readable until the
firmware GCs them. The real defense against forensic recovery is
full-disk encryption (FileVault on macOS, BitLocker on Windows, LUKS on
Linux). The installer warns loudly if FDE is disabled but does not
refuse to install.

**Tor traffic correlation by global passive adversaries.** Known Tor
limitation. A nation-state actor that observes both your Tor entry guard
and your friend's Tor entry guard can in theory correlate traffic
patterns over time. Realistic for journalists working under nation-state
surveillance; irrelevant for two friends chatting.

**Post-quantum.** Briar uses forward secrecy, so each session has fresh
keys; future quantum computers cannot decrypt today's recorded traffic
even if they break Curve25519, because the ephemeral keys are gone.
Long-term identity keys (Ed25519) are not post-quantum, so a
hypothetical future quantum attacker could in principle impersonate you
to a contact you have not interacted with yet. Practical risk for two
friends chatting today: zero.

**Tor blocking.** Some networks block Tor entirely. Briar supports Tor
bridges, but `giz` does not yet expose a bridge configuration UI. If
your network blocks Tor, neither Briar nor `giz` can connect.

**The wrapper code itself.** `giz` is ~1200 lines of Python. I write
bugs. The cryptography cannot be broken by a wrapper bug, but a wrapper
bug could in theory leak local state - for example, by writing
something to a path I did not anticipate. Defenses: small surface,
public auditable code, the hardening guards above, no logging.

## What "auditable" means here

Every line of `giz` is in this repository. The installer downloads
exactly this source, verifies SHA-256 hashes of the briar-headless
binaries, and pins a specific Briar version. The Python wrapper is
intentionally short so a security-aware reader can finish auditing it
in an hour.

If you find a bug, please open an issue (or, if it is a sensitive
finding, contact the repo owner directly).

## Channel-leak ranking (for `/me` and `/add`)

| rank | channel | leaks to | MITM in practice | post-handshake `/verify` |
|------|---------|----------|------------------|--------------------------|
| A | in-person QR scan | nobody | impossible | optional |
| A | voice phone call + numeric short-code | carrier (knows you called) | infeasible (cannot substitute spoken digits in real time) | optional |
| A | video call showing terminal QR | video provider (sees pixels) | infeasible (real-time pixel substitution is impractical) | optional |
| A | Tor channel (Cwtch, OnionShare) | nobody | impossible | optional |
| B | Signal | Signal Foundation (knows you exchanged something) | theoretical | recommended |
| C | WhatsApp / iMessage / Telegram | Meta or Apple (knows you are starting Briar) | theoretical | required |
| F | plain SMS / unencrypted email | everyone in transit | trivial | refused (the TUI does not even render the link for this option) |

The TUI shows this table at the moment you run `/me` or `/add`. The
tradeoff is yours to make; `giz` makes the cost visible.
