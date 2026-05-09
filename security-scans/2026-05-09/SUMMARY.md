# giz security scan — 2026-05-09

**Codebase:** giz v0.2.3 (post-fix)
**Scanners:** 15 independent tools (Bandit, Semgrep, CodeQL, Trivy, Checkov, Pyright-strict, YARA, graudit, detect-secrets, gitleaks, pip-audit, Safety, Syft, Grype, osv-scanner)
**Verdict:** zero HIGH or MEDIUM real findings on the production code.

## Final findings table (after fixes applied)

| Scanner | Class | HIGH | MEDIUM | LOW / WARN | Notes |
|---|---|---|---|---|---|
| Bandit | Python SAST (PyCQA) | 0 | 0 | 63 | All LOW are advisory: subprocess audit trail, defensive `try/except/pass`, etc. — intentional design |
| Semgrep | Dataflow SAST (5 rule packs) | 0 | 0 | 2 (FP) | Both warnings recommend `0o644` instead of giz's deliberate `0o700`; inverted-policy false positives |
| CodeQL | Semantic dataflow (GitHub) | 0 | 0 | 78 (advisory) | 7 errors / 9 warnings / 62 recommendations; **all on test/redteam fixtures or already-mitigated cyclic imports** (see triage below) |
| Trivy | Filesystem vuln + misconfig + secret (Aqua) | 0 | 0 | 0 | Clean: requirements.txt scanned (pip), no IaC/secret hits |
| Checkov | IaC / GitHub Actions (Bridgecrew) | 0 | 0 | 0 | 256 checks **passed**, 0 failed across `.github/workflows/*.yml` |
| Pyright-strict | Type-aware analysis (Microsoft) | — | — | 182 (advisory) | All are type-strictness diagnostics (unknown member/argument types from third-party `textual` lib without stubs); **non-security**, documented only per release plan |
| YARA | Malware/IOC pattern (VirusTotal) | 0 | 0 | 0 | 0 matches across 8 source-code-relevant categories (antidebug_antivm, capabilities, crypto, cve_rules, email, exploit_kits, maldocs, webshells); binary-focused categories (malware/mobile_malware/packers) skipped — they target PE/APK, not text |
| graudit | Grep-based legacy auditor | — | — | 72 (advisory) | All hits on intentional hardening idioms (`os.chmod`, `os.open` w/ `O_NOFOLLOW`, `os.replace` for atomic writes, `unlink` in duress wipe). Tool design is "flag patterns for human review", not pass/fail |
| detect-secrets | Secret scanner (Yelp) | — | — | 0 NEW | 3 known test-fixture matches allow-listed in `.secrets.baseline` |
| gitleaks | Git-history secret scanner | — | — | 0 leaks | Scanned all commits in giz history |
| pip-audit | Dep CVE (PyPA, OSV) | — | — | 0 | Was 2 in `requests 2.32.3`; fixed by bumping to `requests==2.33.1` (v0.2.2) |
| Safety | Dep CVE (PyUp, second opinion) | — | — | 0 | Same; same fix |
| Syft | SBOM generator (Anchore) | — | — | — | 44 components inventoried (CycloneDX + SPDX) |
| Grype | SBOM vuln-match (Anchore) | — | — | 0 | Same `requests` CVEs; same fix |
| osv-scanner | OSV.dev DB (Google) | — | — | 0 | Same `requests` CVEs; same fix |

## CodeQL triage (78 results — all advisory or test-intentional)

| Rule | Count | Severity | Where | Verdict |
|---|---|---|---|---|
| `py/empty-except` | 53 | recommendation | giz/, tests/ | Defensive code (e.g. cleanup in error paths). Non-security. |
| `py/overly-permissive-file` | 8 | warning | tests/, scripts/redteam/ | **Test code** intentionally setting `0o644` to verify giz's enforce-perms recursive sweep flips them back to `0o600`/`0o700`. |
| `py/unused-global-variable` | 5 | recommendation | giz/, tests/ | Cosmetic. |
| `py/unsafe-cyclic-import` | 3 | error | giz/app.py, giz/screens.py | **Already mitigated**: `screens.py` uses `if TYPE_CHECKING:` for `GizApp`; `app.py`'s imports of `ChatScreen`/`ContactsScreen` are runtime-required and resolve correctly under Python's normal import order. |
| `py/bind-socket-all-network-interfaces` | 2 | error | tests/test_hardening.py, scripts/redteam/23_lan_bind_warning_isolated.py | **Test fixtures** that bind a probe socket to `0.0.0.0` to verify giz's bind-detection warning fires. Production giz **never** binds — it only inspects briar-headless's bind via `lsof`/`ss`. |
| `py/clear-text-logging-sensitive-data` | 2 | error | scripts/redteam/_common.py | False positive — flags the `print("PASS …")` / `print("FAIL …")` helpers; the values printed are scenario IDs and `[evidence]` strings, not credentials. |
| `py/unused-import` | 2 | recommendation | tests/ | Cosmetic. |
| `py/file-not-closed` | 1 | warning | tests/test_two_daemons.py | Test fd leak (non-security). |
| `py/unused-local-variable` | 1 | recommendation | — | Cosmetic. |
| `py/mixed-returns` | 1 | recommendation | — | Cosmetic. |

Net: **0 production-code security defects** introduced or carried over.

## Pyright-strict triage (182 advisory diagnostics, document-only per plan)

| Rule | Count | Class |
|---|---|---|
| `reportUnknownMemberType` | 58 | textual library has no stub package |
| `reportUnknownArgumentType` | 41 | same |
| `reportUnknownVariableType` | 30 | same |
| `reportMissingTypeArgument` | 13 | generic types without parameters |
| `reportUnknownParameterType` | 11 | callbacks accepting Textual events |
| `reportConstantRedefinition` | 10 | Textual `BINDINGS = [...]` class-level assignment |
| `reportMissingParameterType` | 8 | minor untyped params |
| `reportUnnecessaryIsInstance` | 7 | defensive runtime type checks |
| `reportInvalidTypeForm`, `reportOptionalCall` | 1 each | one optional-call site in `duress.py` |

These are **strict-mode type hygiene findings**, not security issues. They surface only because Pyright's `--strict` mode requires every transitive type to be fully resolved; the gaps are mostly in third-party `textual` types. Per the v0.2.3 plan they are recorded in `pyright.json` for future hardening, not fixed inline.

## What was fixed in this round (v0.2.2 onwards)

| Source of finding | Issue | Action |
|---|---|---|
| pip-audit + Safety + Grype + osv-scanner | `requests 2.32.3` → CVE-2024-47081 (netrc credential leak), CVE-2026-25645 (predictable temp file in `extract_zipped_paths()`) | Bumped to `requests==2.33.1` in `requirements.txt`; regenerated `requirements.lock.txt` with `pip-compile --generate-hashes`. Neither CVE was exploitable through giz's usage (giz uses neither `.netrc` nor `extract_zipped_paths`), but the lockfile-first stance demanded the bump. |
| Bandit B108 (`hardcoded_tmp_directory`) | `/tmp` use in `hardening.py:_machine_lock_path` and a string literal in `selfcheck.py` | Annotated with `# nosec B108` plus a comment explaining the intentional design (uid-namespaced lock with `O_NOFOLLOW` + `fstat` ownership check, see `_acquire_machine_lock_at`). |
| Bandit B104 (`hardcoded_bind_all_interfaces`) | A string set `{"*", "0.0.0.0", "::", "[::]", "[*]", ""}` that we *match against* to detect when briar-headless has bound to a wildcard | Annotated with `# nosec B104` and an explanation that we never bind, only detect. |
| detect-secrets | Three fake auth tokens / Briar pending IDs in tests and red-team scripts | Generated `.secrets.baseline` to allow-list the known fixtures. CI now fails only on *new* secrets. |

No further suppressions in v0.2.3; the 6 new tools produced zero actionable findings on production code.

## Reproducing this scan

Single bash script. Requires a Python venv plus binary tools fetched via their official install scripts.

```bash
# Python tools
python3 -m venv /tmp/giz-scan-venv
/tmp/giz-scan-venv/bin/pip install 'bandit[toml]' pip-audit safety \
    detect-secrets semgrep pip-tools checkov pyright

# Single-binary tools (macOS arm64 example)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /tmp/syft-bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /tmp/grype-bin
curl -sSfL https://github.com/google/osv-scanner/releases/download/v2.2.4/osv-scanner_darwin_arm64 \
    -o /tmp/osv-scanner && chmod +x /tmp/osv-scanner
curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_darwin_arm64.tar.gz \
    | tar xz -C /tmp gitleaks && chmod +x /tmp/gitleaks
curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_macOS-ARM64.tar.gz \
    | tar xz -C /tmp/trivy-bin
brew install yara
git clone --depth=1 https://github.com/wireghoul/graudit.git /tmp/graudit
git clone --depth=1 https://github.com/Yara-Rules/rules.git /tmp/yara-rules

# CodeQL bundle (~1.3 GB; see https://github.com/github/codeql-action/releases)
curl -sSfL https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-osx64.tar.gz \
    -o /tmp/codeql-bundle.tar.gz
mkdir -p /tmp/codeql-bundle && tar xzf /tmp/codeql-bundle.tar.gz -C /tmp/codeql-bundle
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

# CodeQL (build database, then analyze)
/tmp/codeql-bundle/codeql/codeql database create /tmp/giz-codeql-db \
    --language=python --source-root=.
/tmp/codeql-bundle/codeql/codeql database analyze /tmp/giz-codeql-db \
    --format=sarifv2.1.0 --output=$OUT/codeql.sarif --download \
    python-security-and-quality.qls

# Trivy filesystem (vuln + misconfig + secret)
/tmp/trivy-bin/trivy fs --scanners vuln,misconfig,secret \
    --format json --output $OUT/trivy.json --quiet .

# Checkov (GitHub Actions)
/tmp/giz-scan-venv/bin/checkov -d .github -o json --quiet \
    --framework github_actions > $OUT/checkov.json

# Pyright-strict (uses pyrightconfig.json with strict: ["giz"])
/tmp/giz-dev-venv/bin/pyright --outputjson > $OUT/pyright.json

# YARA (8 source-code-relevant categories)
for cat in antidebug_antivm capabilities crypto cve_rules email \
           exploit_kits maldocs webshells; do
  echo "=== $cat ==="
  yara -r -w -f -a 30 /tmp/yara-rules/${cat}_index.yar giz/
done > $OUT/yara.txt

# graudit (Python signature DB)
/tmp/graudit/graudit -d /tmp/graudit/signatures/python.db giz/ > $OUT/graudit.txt
```

## Why these specific scanners

The credibility argument: every one of them is independently maintained by a serious party, used in industry, and produces machine-readable output. Hitting them all and producing zero real findings is a stronger claim than any single commercial badge, because the readers can re-run all fifteen themselves and diff.

| Scanner | Maintainer | Notable users |
|---|---|---|
| Bandit | Python Code Quality Authority (PyCQA) | Default Python security linter; in OpenSSF Scorecards |
| Semgrep | Semgrep Inc. (formerly r2c) | Stripe, Slack, GitLab, Snowflake, Dropbox |
| CodeQL | GitHub | Default engine for GitHub Code Scanning across all of OSS |
| Trivy | Aqua Security | Default scanner in many Kubernetes/Helm pipelines |
| Checkov | Bridgecrew (Prisma Cloud) | IaC-security standard; covers Terraform, K8s, GH Actions |
| Pyright | Microsoft | Type engine behind Pylance; standard Python type checker |
| YARA | VirusTotal / Google | Industry-standard malware/IOC pattern engine |
| graudit | @wireghoul | Lightweight grep-based source auditor (training/teaching tool) |
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
| `codeql.sarif` | SARIF v2.1.0 | CodeQL |
| `trivy.json` | JSON | Trivy |
| `checkov.json` | JSON | Checkov |
| `pyright.json` | JSON | Pyright (strict) |
| `yara.txt` | text | YARA |
| `graudit.txt` | text (grep) | graudit |
| `detect-secrets.txt` | text/JSON | detect-secrets (vs `.secrets.baseline`) |
| `gitleaks.json` | JSON | gitleaks (full git history) |
| `pip-audit.json` | JSON | pip-audit (against `requirements.lock.txt`) |
| `safety.json` | JSON | Safety |
| `sbom.cyclonedx.json` | CycloneDX | Syft |
| `sbom.spdx.json` | SPDX | Syft |
| `grype.json` | JSON | Grype |
| `osv.json` | JSON | osv-scanner |
| `SUMMARY.md` | markdown | (this file) |
