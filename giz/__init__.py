"""giz - minimal terminal-only secure messenger over Briar + Tor.

This package is a thin auditable wrapper around the Briar headless daemon.
All real cryptography and networking lives in Briar; giz adds:
    - first-run setup with real + duress passwords
    - process-level no-leak hardening
    - hard backup-leak prevention
    - a channel-aware contact-add flow
    - a minimal terminal UI

See SECURITY.md in the repo root for the full threat model.
"""

__version__ = "0.2.0"
