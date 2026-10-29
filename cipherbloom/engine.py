"""One shared scan pipeline used by both the CLI and the localhost web UI."""
from __future__ import annotations

import os
import time

from .deps import check_dependencies
from .gitcheck import check_git_hygiene
from .live import run_live
from .risky import scan_risky
from .secrets_scan import scan_secrets
from .syntaxcheck import check_syntax

STAGES = [
    ("secrets", "secrets", lambda root, o: scan_secrets(root)),
    ("git", "git hygiene", lambda root, o: check_git_hygiene(root, history=o.get("history", True))),
    ("syntax", "syntax", lambda root, o: check_syntax(root)),
    ("risky", "risky code", lambda root, o: scan_risky(root)),
    ("deps", "dependencies", lambda root, o: check_dependencies(root, audit=o.get("audit", False))),
]


def run_scan(root, options=None, live_target=None, staged=None):
    """Run every enabled check.

    options: {"checks": [...stage keys...], "history": bool, "audit": bool}
    live_target: an already-validated localhost URL whose owner has given consent, or None.
    staged: optional set of relative paths; when given, only secret findings in those files are kept.
    Returns (findings, checks_run, notes, seconds).
    """
    options = options or {}
    enabled = set(options.get("checks") or [k for k, _, _ in STAGES])
    started = time.time()
    findings, checks, notes = [], [], []
    for key, label, fn in STAGES:
        if key not in enabled:
            continue
        if staged is not None and key != "secrets":
            continue
        findings += fn(root, options)
        checks.append(label)
    if staged is not None:
        findings = [f for f in findings if f.file in staged]
    if live_target:
        live_findings, note = run_live(live_target, root if os.path.isdir(root) else None)
        findings += live_findings
        checks.append("live localhost")
        if note:
            notes.append(note)
    return findings, checks, notes, round(time.time() - started, 2)
