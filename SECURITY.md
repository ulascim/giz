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
| Forced password disclosure | Type the duress password instead. The real account is silently destroyed. The decoy output and timing match a fresh-install state, so an attacker who knows about giz cannot distinguish "you typed duress" from "you typed wrong" or "you never set up an account." |
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

**The duress wipe's output is now byte-for-byte identical to a
fresh-installed-but-not-set-up giz.** Same string, same stream
(stderr), same exit code (9). After the wipe, subsequent `giz`
invocations also match a fresh install: no password prompt, same
"no account found at <path>. Run setup first." message. An attacker
comparing post-wipe output to a known-clean install cannot distinguish
them by output.

**The duress wipe is now timing-equivalent to a wrong password.** The
synchronous part of the wipe (overwrite + unlink the small sensitive
files) is fast; the slow part (rmtree of the encrypted DB) is handed
off to a detached child process so the giz parent can return to the
caller immediately. The auth prompt time-pads every non-real outcome
to a common floor (3.0s by default), so a wrong password and a duress
password produce the same wall-clock latency from the prompt's
perspective. The detached child finishes the rmtree in the
background; even if the user closes the terminal, init / launchd
adopts the child and it completes.

**The duress wipe remains observable in two narrow ways.** First, an
attacker who saw you successfully unlock giz five minutes ago and now
sees "no account" knows you wiped (or that the data was lost some
other way) - the *fact* of having had an account at all is not
something we can hide. Second, a sophisticated attacker who actively
controls the disk image (via local OS snapshots or ZFS / btrfs / APFS
snapshots they take themselves) can capture pre-wipe state and recover
later. We mitigate the macOS APFS local-Time-Machine-snapshot variant
by best-effort issuing `tmutil deletelocalsnapshots /` during the
wipe; we cannot mitigate snapshots taken by an attacker who already
has root.

**The wipe is irreversible.** If you mistype the duress password
under stress, your data is gone. Phase 1 of the wipe (which deletes
the hash file) is synchronous and runs before any child is spawned;
it is the irrecoverable step.

**SSD secure deletion is partial.** `secure_wipe` overwrites small
sensitive files (the password hash file, the lockfile) before unlinking
them. On modern SSDs the controller may write to a different physical
block, so the original ciphertext blocks may remain readable until the
firmware GCs them. The real defense against forensic recovery is
full-disk encryption (FileVault on macOS, BitLocker on Windows, LUKS on
Linux). `giz` does not probe whether FDE is enabled and does not
print a warning if it is off. Enable FDE yourself before installing
`giz` on a laptop that can leave your sight.

**Process-internal exfiltration is constrained, not impossible.** The
giz wrapper installs a runtime guard that refuses any non-loopback
`connect()` AND any non-loopback `getaddrinfo()` from inside the
wrapper process. After the briar-headless port is known, the guard
narrows further so that even *other* loopback ports are refused -
this catches the "malicious dependency talks to an exfil daemon
listening on 127.0.0.1:NNNN" variant. The guard does not, and cannot,
prevent malicious in-process code from calling raw libc bindings
directly; it is positioned as defense-in-depth against accidental or
opportunistic exfiltration, not as a sandbox. If you have malicious
code running inside the giz process, it has the auth_token and can
drive Briar to send arbitrary messages over Tor anyway.

**LAN reachability of briar-headless API.** This is the most important
caveat to read in full.

`briar-headless` 0.6.x has no `--host` flag and binds its REST /
WebSocket API to a wildcard address (every interface, every IP). On
a machine with any active LAN interface (Wi-Fi, Ethernet, cellular
hotspot, USB tether, virtual NIC), TCP port 7001 is therefore
reachable from the same broadcast domain. `giz` runs `briar-headless`
unmodified - we are a thin user-mode wrapper, not a fork - so we
inherit the same bind behaviour.

What an attacker on the same LAN CAN do without a credential:

* Confirm that a Briar daemon is running on your machine
  (fingerprinting: a `curl http://your-lan-ip:7001/v1/contacts`
  returns 401 Unauthorized rather than a connection refused, which
  reveals the service exists).
* Stress the listener with TCP traffic to slow or stall the API
  (denial-of-service: floods Briar's accept queue and may make the
  TUI become unresponsive until the attacker stops).

What an attacker on the same LAN CANNOT do without a credential:

* Read messages, list your contacts, or impersonate you. Every
  authenticated route on the daemon requires the bearer token in
  `~/.giz/real/auth_token`, which giz creates with mode `0600` and
  256 bits of entropy. The token is regenerated whenever Briar is
  restarted.

How `giz` itself behaves with respect to this:

* On every launch, after the daemon is ready, `giz` probes the
  daemon's listening sockets (via `lsof` on macOS, `ss` on Linux).
  If briar is bound to a wildcard or non-loopback address, `giz`
  prints a clear warning to stderr AND surfaces it in the
  diagnostics screen (press `d` inside the TUI).
* The warning is informational, not blocking. We will not refuse to
  start your messenger because of how upstream binds its socket.

What you can do, depending on threat:

* On a trusted network (your home Wi-Fi with no other clients you
  do not control): no action needed; the warning still prints, but
  the practical risk is essentially zero.
* On a hostile network (cafe, hotel, conference, coworking space):
  add a system firewall rule blocking inbound TCP to port 7001 from
  any non-loopback source. Examples:

  Linux (iptables):
      sudo iptables -A INPUT -p tcp --dport 7001 ! -i lo -j DROP

  Linux (ufw):
      sudo ufw deny in 7001/tcp from any to any

  macOS (System Settings -> Network -> Firewall): turn it on, then
  block incoming connections to "java" specifically. For pf-based
  control add an `block in proto tcp to port 7001` rule to
  `/etc/pf.conf` and `pfctl -f /etc/pf.conf -e`.

  Windows (PowerShell, admin):
      New-NetFirewallRule -DisplayName "block briar-headless LAN" \
        -Direction Inbound -Protocol TCP -LocalPort 7001 \
        -RemoteAddress LocalSubnet -Action Block

* Or do not use giz on a LAN you do not trust.

Upstream fix (out of scope for `giz` itself): briar-headless should
gain a `--host 127.0.0.1` flag. We do not patch upstream from here;
that is a Briar project concern.

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

## Reproducing the trust chain

The whole point of `giz` is that you do not have to trust me. The
installer is a small shell script you can read; everything it
downloads is hash-verified against constants written into that
script. The git tag the script points at is GPG-signed so a
sufficiently paranoid auditor can confirm the source archive
genuinely came from this repository.

Steps to verify everything yourself before running the installer on a
real machine:

1. **Read the installer.** `install.sh` and `install.ps1` are ~250
   lines together. Read them top to bottom. Note the version string
   (e.g. `v0.1.1`), the source SHA constant, and the JAR SHA constant.

2. **Verify the git tag signature.** Clone the repo, then check that
   the tag was signed by the maintainer's published GPG key:

   ```bash
   git clone https://github.com/ulascim/giz && cd giz
   git verify-tag v0.1.1
   ```

   If the signature does not validate, do not proceed.

3. **Verify the source tarball SHA.** The installer fetches
   `https://github.com/ulascim/giz/archive/refs/tags/v0.1.1.tar.gz`
   and checks it against a hard-coded SHA-256. Confirm the same value
   yourself:

   ```bash
   curl -fsSL https://github.com/ulascim/giz/archive/refs/tags/v0.1.1.tar.gz \
       | shasum -a 256
   ```

   This must match `SOURCE_SHA` in `install.sh`. If it does not, the
   tarball you would receive does not match the tag you just verified;
   stop.

4. **Verify the briar-headless JAR SHA.** Same idea, downloaded from
   the GitHub Releases page; the SHA constant is in the installer.

5. **Verify the Python dependency lockfile.** The installer runs
   `pip install --require-hashes -r requirements.lock.txt`. pip will
   refuse to install any package whose tarball does not match the
   listed SHA-256, including transitive dependencies. Read
   `requirements.lock.txt` and confirm every package is pinned to a
   specific version with at least one `--hash=sha256:...` entry.

6. **Audit the runtime guards.** Read `giz/hardening.py`. The
   `install_guards()` function applies, in order: core-dump off,
   ptrace deny, logging silenced, outbound non-loopback sockets
   blocked, signal handlers, single-instance lockfile. Read
   `giz/__main__.py` to confirm `install_guards()` runs before any
   secret is read.

If any of those steps fail, do not run the installer.

The combined effect of (2), (3), (4), (5), and the JAR pin is that
the only way for a malicious party to compromise `giz` between this
repository and your machine is to (a) compromise the maintainer's
GPG key and push a poisoned tag, or (b) compromise PyPI's signing
infrastructure for one of the pinned dependency hashes. Neither is
the threshold of a casual attacker.

## How we know `giz` is rock solid

Trust is not a property; **a falsifiable check is**. Every claim in
this document maps onto a runtime check that the user can run against
their own install, after the installer finishes:

```bash
giz --self-check   # 11 runtime checks, < 1 second
```

`giz --self-check` answers, for that exact install, whether every
guard is in place: argon2 binding, hash file mode, socket guard,
DNS guard, loopback narrowing, duress decoy byte-equality,
`zero_bytes` contract, `logging.basicConfig` no-op,
`logging.FileHandler` neutering, `~/.giz` mode, source tree integrity.

The output looks like:

```text
giz v0.2.6  (python 3.12.4 on darwin arm64)
  argon2 binding ........................ ok
  hashes file 0o600 (synthetic) ......... ok
  socket guard refuses 8.8.8.8 .......... ok
  getaddrinfo refuses example.com ....... ok
  restrict_loopback narrows ............. ok
  duress decoy == no-account string ..... ok
  zero_bytes(bytes) raises TypeError .... ok
  logging.basicConfig is a no-op ........ ok
  logging.FileHandler is blocked ........ ok
  data dir mode (~/.giz) ................ ok
  source tree sha256 .................... ok
all checks passed.
```

If any line says FAIL, `giz` will not vouch for itself, and neither
should you.

## Static and supply-chain analysis

`giz` is scanned by an industry-standard lineup of static analyzers
and dependency CVE scanners. The scans run **locally on the
maintainer's machine** before every release; the per-tool runner
scripts and GitHub Actions workflows live outside the public tree
and are not part of the released source. This is a deliberate
trade-off: no public CI means no public SARIF dashboard, but it
also means an attacker who compromises a CI service does not get
to inject artifacts into the release. The release commit always
includes an updated `security-scans/<date>/SUMMARY.md` so an
auditor can see the results without needing to run the full
toolchain themselves.

**Scanners in the pipeline:**

| Scanner | Class | What it catches |
|---|---|---|
| [Bandit](https://github.com/PyCQA/bandit) | Python SAST (PyCQA) | Python-specific security anti-patterns: weak crypto, unsafe deserialization, shell injection, assert in non-test, hardcoded passwords |
| [Semgrep](https://semgrep.dev/) with `p/python`, `p/security-audit`, `p/owasp-top-ten`, `p/cwe-top-25`, `p/secrets` | Modern dataflow SAST | OWASP Top 10, CWE Top 25, secret patterns, taint analysis (used by Stripe, GitLab, Slack) |
| [CodeQL](https://codeql.github.com/) `python` `security-and-quality` | Semantic dataflow (GitHub) | Source/sink taint, interprocedural data flow — closest free peer to commercial SAST |
| [Trivy](https://trivy.dev/) `fs` (Aqua) | Filesystem vuln + misconfig + secret | Dependency CVEs, IaC misconfigurations, embedded secrets — single-binary scanner used widely in Kubernetes pipelines |
| [Checkov](https://www.checkov.io/) (Bridgecrew/Prisma Cloud) | IaC / GitHub Actions | YAML/IaC security checks against the project's CI workflows (256 GH-Actions checks) |
| [Pyright-strict](https://github.com/microsoft/pyright) (Microsoft) | Type-aware static analysis | Strict-mode type-correctness diagnostics across the whole `giz/` package — advisory, not security-gating |
| [YARA](https://virustotal.github.io/yara/) (VirusTotal/Google) | Malware / IOC pattern matching | Scans `giz/` against curated [Yara-Rules](https://github.com/Yara-Rules/rules) categories: antidebug_antivm, capabilities, crypto, cve_rules, email, exploit_kits, maldocs, webshells |
| [graudit](https://github.com/wireghoul/graudit) (@wireghoul) | Grep-based legacy auditor | Python signature DB; flags interesting code patterns for human review (sanity baseline) |
| [detect-secrets](https://github.com/Yelp/detect-secrets) (Yelp) | Secret-pattern scanner | High-entropy strings, AWS/GCP/Azure keys, JWTs, hex tokens — gated by `.secrets.baseline` allow-list of known test fixtures |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Git-history secret scanner | Secrets in any past commit (full history) |
| [pip-audit](https://github.com/pypa/pip-audit) (PyPA) | Dep CVE | CVEs against `requirements.lock.txt` from PyPI advisories + OSV (`--strict`: any vuln fails) |
| [Safety](https://pyup.io/safety/) (PyUp) | Dep CVE 2nd opinion | Independent dep CVE DB; cross-checks pip-audit |
| [Syft](https://github.com/anchore/syft) (Anchore) | SBOM generator | CycloneDX + SPDX bills of materials |
| [Grype](https://github.com/anchore/grype) (Anchore) | SBOM vuln-match | Matches the syft SBOM against known vulnerability DBs |
| [osv-scanner](https://google.github.io/osv-scanner/) (Google) | OSV.dev DB scanner | Vulns from OSV.dev across PyPI/Go/npm/cargo — third independent dep scanner |

### Most recent local scan (2026-05-09, v0.2.3 baseline, carried forward through v0.2.6)

The full 15-scanner pipeline last ran clean against the v0.2.3
codebase on 2026-05-09. v0.2.4 (UX polish), v0.2.5 (tor +x
regression fix), and v0.2.6 (this release: unread visibility,
honesty-pass on SECURITY.md, scan-artifact privacy) touched only
the TUI, the recursive-perms sweep, and documentation — no
production code paths under static-analysis scrutiny were altered,
so the v0.2.3 results carry forward verbatim. A fresh full sweep
will run before v0.3.0.

| Scanner | Real findings | False positives / advisory | Action |
|---|---|---|---|
| Bandit | 0 HIGH, 0 MEDIUM, 63 LOW | 3 MEDIUM (intentional hardening, suppressed with `# nosec` + comment) | LOW are advisory: subprocess audit trail, defensive `try/except/pass`, expected design |
| Semgrep | 0 | 2 (recommended `0o644` instead of our deliberate `0o700` — inverted-policy false positives) | none |
| CodeQL | 0 production-code defects | 78 advisory (7 errors / 9 warnings / 62 recommendations); all on test/redteam fixtures or already-mitigated cyclic imports | documented in `security-scans/2026-05-09/SUMMARY.md` |
| Trivy | 0 vuln, 0 misconfig, 0 secret | — | none |
| Checkov | 0 failed | 256 passed (GitHub Actions framework) | none |
| Pyright-strict | — | 182 strict-mode type diagnostics (mostly missing `textual` library stubs) | document-only per release plan; non-security |
| YARA | 0 matches | — | 8 source-code-relevant categories scanned; binary-focused categories (malware/mobile_malware/packers) intentionally skipped (PE/APK rules cause pathological scan times on text input and add no signal for a Python project) |
| graudit | — | 72 advisory grep-pattern hits, all on intentional hardening idioms (`os.chmod`, `os.open` w/ `O_NOFOLLOW`, atomic `os.replace`, duress-wipe `unlink`) | documented; tool is human-review oriented by design |
| detect-secrets | 0 NEW | 3 (test fixtures: fake auth tokens, fake Briar pending IDs) | allow-listed in `.secrets.baseline` |
| gitleaks | 0 in full history | — | none |
| pip-audit | 0 (was 2 in v0.2.1) | 0 | fixed in v0.2.2: bumped to `requests==2.33.1` |
| Safety | 0 (was 2) | 0 | same fix |
| grype (via syft SBOM) | 0 (was 2) | 0 | same fix |
| osv-scanner | 0 (was 2) | 0 | same fix |
| Syft | — | 44 components inventoried (CycloneDX + SPDX) | — |

After remediation, **all fifteen scanners report zero severity-HIGH or
severity-MEDIUM findings on the production codebase.**

The two `requests` CVEs from v0.2.1 (CVE-2024-47081 netrc credential
leak, CVE-2026-25645 predictable temp file in
`extract_zipped_paths()`) were not exploitable through `giz`'s usage
of the library — `giz` never uses `.netrc` and never calls
`extract_zipped_paths()` — but were patched anyway in v0.2.2, in line
with the project's lockfile-first supply-chain stance.

The human-readable summary lives in
`security-scans/2026-05-09/SUMMARY.md` and is the only scan
artifact checked into the public tree. Raw scanner JSON / SARIF /
SBOM outputs are kept out of the repo because they are noisy,
machine-generated, and not useful to review in a code-review
context. Anyone who wants the raw artifacts can regenerate them
by running the commands in the reproducer below; the SUMMARY
records the exact versions of every tool used so the results are
deterministic across machines.

### Reproducing locally

```bash
python3 -m venv /tmp/giz-scan-venv
/tmp/giz-scan-venv/bin/pip install 'bandit[toml]' pip-audit safety \
    detect-secrets semgrep checkov pyright
cd /path/to/giz

# Python SAST
/tmp/giz-scan-venv/bin/bandit -r giz/ -c pyproject.toml
/tmp/giz-scan-venv/bin/semgrep scan giz/ \
    --config=p/python --config=p/security-audit \
    --config=p/owasp-top-ten --config=p/cwe-top-25 --config=p/secrets

# Secrets
/tmp/giz-scan-venv/bin/detect-secrets scan --baseline .secrets.baseline \
    giz/ tests/ scripts/

# Dep CVE (pin lockfile, fail on any vuln)
/tmp/giz-scan-venv/bin/pip-audit --strict -r requirements.lock.txt

# IaC / GitHub Actions
/tmp/giz-scan-venv/bin/checkov -d .github --framework github_actions

# Type analysis (strict)
/tmp/giz-scan-venv/bin/pyright   # uses pyrightconfig.json with strict: ["giz"]
```

Single-binary scanners (Anchore Syft + Grype, Google osv-scanner,
gitleaks, Aqua Trivy) and the larger CodeQL / YARA / graudit
toolchains are installed via their official install scripts linked
in the table above; the full end-to-end reproduction script lives
alongside the artifacts in `security-scans/2026-05-09/SUMMARY.md`.

## Cryptographic primitives

`giz` itself contains no cryptography beyond Argon2id and SHA-256:

* **Argon2id** (`argon2-cffi`) for the on-disk password hash file.
  Parameters: `time_cost=3`, `memory_cost=64 MiB`, `parallelism=2`.
  The hash file lives at `~/.giz/.gizhashes`, mode 0600, written
  atomically (O_NOFOLLOW + O_EXCL temp + rename).
* **SHA-256** for `/verify` long fingerprints, the short-code
  derivation, `auth_token` shape checks, and source / JAR pin
  verification.

Briar's own primitives (Ed25519, Curve25519, XSalsa20-Poly1305) operate
inside the `briar-headless` JVM and are not implemented in `giz`.
