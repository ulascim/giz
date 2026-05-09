# giz security scan — 2026-05-09

**Codebase:** giz v0.2.2 (post-fix)
**Scanners:** 9 independent tools (Bandit, Semgrep, detect-secrets, gitleaks, pip-audit, Safety, Syft, Grype, osv-scanner)
**Verdict:** zero HIGH or MEDIUM real findings on the production code.

## Final findings table (after fixes applied)

| Scanner | Class | HIGH | MEDIUM | LOW / WARN | Notes |
|---|---|---|---|---|---|
| Bandit | Python SAST (PyCQA) | 0 | 0 | 63 | All LOW are advisory: subprocess audit trail, defensive `try/except/pass`, etc. — intentional design |
| Semgrep | Dataflow SAST (5 rule packs) | 0 | 0 | 2 (FP) | Both warnings recommend `0o644` instead of giz's deliberate `0o700`; inverted-policy false positives |
| detect-secrets | Secret scanner (Yelp) | — | — | 0 NEW | 3 known test-fixture matches allow-listed in `.secrets.baseline` |
| gitleaks | Git-history secret scanner | — | — | 0 leaks | Scanned all commits in giz history |
| pip-audit | Dep CVE (PyPA, OSV) | — | — | 0 | Was 2 in `requests 2.32.3`; fixed by bumping to `requests==2.33.1` |
| Safety | Dep CVE (PyUp, second opinion) | — | — | 0 | Same; same fix |
| Syft | SBOM generator (Anchore) | — | — | — | 44 components inventoried (CycloneDX + SPDX) |
| Grype | SBOM vuln-match (Anchore) | — | — | 0 | Same `requests` CVEs; same fix |
| osv-scanner | OSV.dev DB (Google) | — | — | 0 | Same `requests` CVEs; same fix |

## What was fixed in this round

| Source of finding | Issue | Action |
|---|---|---|
| pip-audit + Safety + Grype + osv-scanner | `requests 2.32.3` → CVE-2024-47081 (netrc credential leak), CVE-2026-25645 (predictable temp file in `extract_zipped_paths()`) | Bumped to `requests==2.33.1` in `requirements.txt`; regenerated `requirements.lock.txt` with `pip-compile --generate-hashes`. Neither CVE was exploitable through giz's usage (giz uses neither `.netrc` nor `extract_zipped_paths`), but the lockfile-first stance demanded the bump. |
| Bandit B108 (`hardcoded_tmp_directory`) | `/tmp` use in `hardening.py:_machine_lock_path` and a string literal in `selfcheck.py` | Annotated with `# nosec B108` plus a comment explaining the intentional design (uid-namespaced lock with `O_NOFOLLOW` + `fstat` ownership check, see `_acquire_machine_lock_at`). |
| Bandit B104 (`hardcoded_bind_all_interfaces`) | A string set `{"*", "0.0.0.0", "::", "[::]", "[*]", ""}` that we *match against* to detect when briar-headless has bound to a wildcard | Annotated with `# nosec B104` and an explanation that we never bind, only detect. |
| detect-secrets | Three fake auth tokens / Briar pending IDs in tests and red-team scripts | Generated `.secrets.baseline` to allow-list the known fixtures. CI now fails only on *new* secrets. |

## Reproducing this scan

Single bash script. Requires a Python venv plus three single-binary tools fetched via their official install scripts (Anchore Syft, Anchore Grype, Google osv-scanner, gitleaks).

```bash
# Python tools
python3 -m venv /tmp/giz-scan-venv
/tmp/giz-scan-venv/bin/pip install 'bandit[toml]' pip-audit safety \
    detect-secrets semgrep pip-tools

# Single-binary tools (macOS arm64 example; adjust for your platform)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /tmp/syft-bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /tmp/grype-bin
curl -sSfL https://github.com/google/osv-scanner/releases/download/v2.2.4/osv-scanner_darwin_arm64 \
    -o /tmp/osv-scanner && chmod +x /tmp/osv-scanner
curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_darwin_arm64.tar.gz \
    | tar xz -C /tmp gitleaks && chmod +x /tmp/gitleaks
```

Then run each scanner against the source tree:

```bash
cd /path/to/giz
OUT=security-scans/2026-05-09

/tmp/giz-scan-venv/bin/bandit -r giz/ -c pyproject.toml \
    -f json -o $OUT/bandit.json --severity-level low --confidence-level low
/tmp/giz-scan-venv/bin/semgrep scan giz/ \
    --config=p/python --config=p/security-audit \
    --config=p/owasp-top-ten --config=p/cwe-top-25 --config=p/secrets \
    --json -o $OUT/semgrep.json --metrics=off
/tmp/giz-scan-venv/bin/detect-secrets scan --baseline .secrets.baseline \
    giz/ tests/ scripts/ > $OUT/detect-secrets.txt
/tmp/gitleaks detect --source . --report-format json \
    --report-path $OUT/gitleaks.json --redact --no-banner
/tmp/giz-scan-venv/bin/pip-audit --strict -r requirements.lock.txt \
    -f json -o $OUT/pip-audit.json
/tmp/giz-scan-venv/bin/safety check -r requirements.lock.txt \
    --output json --save-json $OUT/safety.json
/tmp/syft-bin/syft scan dir:. \
    -o cyclonedx-json=$OUT/sbom.cyclonedx.json \
    -o spdx-json=$OUT/sbom.spdx.json
/tmp/grype-bin/grype $OUT/sbom.cyclonedx.json -o json --file $OUT/grype.json
/tmp/osv-scanner --format json --output $OUT/osv.json -L requirements.lock.txt
```

## Why these specific scanners

The credibility argument: every one of them is independently maintained by a serious party, used in industry, and produces machine-readable output. Hitting them all and producing zero real findings is a stronger claim than any single commercial badge, because the readers can re-run all nine themselves and diff.

| Scanner | Maintainer | Notable users |
|---|---|---|
| Bandit | Python Code Quality Authority (PyCQA) | Default Python security linter; in OpenSSF Scorecards |
| Semgrep | Semgrep Inc. (formerly r2c) | Stripe, Slack, GitLab, Snowflake, Dropbox |
| detect-secrets | Yelp | Yelp's internal CI standard |
| gitleaks | Zricethezav | OpenSSF / SLSA reference toolchain |
| pip-audit | Python Packaging Authority (PyPA) | Official PyPI advisory consumer |
| Safety | PyUp | Independent CVE DB, oldest commercial Python scanner |
| Syft | Anchore | CycloneDX / SPDX reference impl, accepted by US gov SBOM mandates |
| Grype | Anchore | Default vuln scanner in many Kubernetes admission controllers |
| osv-scanner | Google | Backed by OSV.dev which is the canonical OSS vuln database |

## Files in this directory

| File | Format | Tool |
|---|---|---|
| `bandit.json` | JSON | Bandit |
| `semgrep.json` | JSON | Semgrep |
| `detect-secrets.txt` | text/JSON | detect-secrets (vs `.secrets.baseline`) |
| `gitleaks.json` | JSON | gitleaks (full git history) |
| `pip-audit.json` | JSON | pip-audit (against `requirements.lock.txt`) |
| `safety.json` | JSON | Safety |
| `sbom.cyclonedx.json` | CycloneDX | Syft |
| `sbom.spdx.json` | SPDX | Syft |
| `grype.json` | JSON | Grype |
| `osv.json` | JSON | osv-scanner |
| `SUMMARY.md` | markdown | (this file) |
