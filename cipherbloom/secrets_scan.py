from __future__ import annotations

import math
import os
import re

from .files import ignored_file, iter_files, read_text, rel
from .models import Finding

# (rule id, label, regex, severity, provider-specific fix hint)
PATTERNS = [
    ("aws-access-key", "AWS access key ID",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical",
     "Deactivate and delete this key in AWS IAM, then create a new one."),
    ("github-token", "GitHub token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
     "critical", "Delete the token at github.com/settings/tokens and make a new one."),
    ("telegram-bot-token", "Telegram bot token",
     re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), "critical",
     "Open @BotFather, run /revoke for this bot, and use the new token."),
    ("google-api-key", "Google API key",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high",
     "Delete or regenerate the key in Google Cloud Console and add an API/HTTP restriction."),
    ("slack-token", "Slack token",
     re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "critical",
     "Revoke the token in your Slack app settings and issue a new one."),
    ("stripe-live-key", "Stripe live key",
     re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"), "critical",
     "Roll the key in the Stripe dashboard right away."),
    ("openai-style-key", "AI provider style secret key (sk-...)",
     re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{32,}\b"), "critical",
     "Revoke the key in the provider's dashboard and set a spending limit on the new one."),
    ("discord-token", "Discord bot token",
     re.compile(r"\b[MNO][A-Za-z\d_\-]{23,25}\.[\w\-]{6}\.[\w\-]{27,}\b"), "critical",
     "Reset the token in the Discord Developer Portal."),
    ("private-key", "Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY"),
     "critical", "Treat this key as stolen: generate a new key pair and remove the old one."),
    ("db-url-password", "Database URL with a password",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@'\"]+:[^\s@'\"]{3,}@"),
     "high", "Change the database password and read the URL from an environment variable."),
]

GENERIC = re.compile(
    r"""(?ix)
    \b([a-z0-9_.\-]*(?:api[_\-]?key|secret|token|passwd|password|private[_\-]?key|access[_\-]?key)[a-z0-9_.\-]*)
    \s*[:=]\s*["']([^"'\s]{12,})["']"""
)
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
SECRETISH_KEY = re.compile(r"(?i)(key|secret|token|pass|pwd|auth|private|credential|dsn|url)")
PLACEHOLDER = re.compile(
    r"(?i)(example|your[_\-]|changeme|change_me|xxxx|placeholder|dummy|sample|<.+>|\$\{|\{\{|"
    r"os\.environ|getenv|process\.env|\*{3,}|test[_\-]?key|fake|todo|none|null|true|false)"
)
SKIP_EXT = {".md", ".rst", ".txt.example"}
EXAMPLE_ENV = re.compile(r"(?i)\.(example|sample|template|dist)$")


def entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(text))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def redact(value):
    if len(value) <= 8:
        return "*" * len(value)
    return "%s...%s" % (value[:4], value[-2:])


def _is_env_file(name):
    low = name.lower()
    return (low == ".env" or low.startswith(".env.") or low.endswith(".env")) and not EXAMPLE_ENV.search(low)


def scan_secrets(root):
    findings = []
    seen = set()

    def add(f):
        key = (f.file, f.line)
        if key in seen:
            return
        seen.add(key)
        findings.append(f)

    for path in iter_files(root):
        text = read_text(path)
        if text is None or ignored_file(text):
            continue
        name = os.path.basename(path)
        relpath = rel(path, root)
        env_file = _is_env_file(name)
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000 or "cipherbloom:ignore" in line:
                continue
            for rule, label, regex, sev, hint in PATTERNS:
                m = regex.search(line)
                if not m or "EXAMPLE" in m.group(0).upper():
                    continue
                add(Finding(
                    rule=rule, severity=sev, title="%s found in code" % label,
                    file=relpath, line=lineno, category="secret",
                    snippet=redact(m.group(0)),
                    why="Anyone who can read this file (or the repo history) can use this secret "
                        "to act as you and run up cost or steal data.",
                    fix="%s Then load it from an environment variable (os.environ / process.env) "
                        "and keep the real value only in a git-ignored .env file." % hint,
                ))
                break
            else:
                m = GENERIC.search(line)
                if m and not PLACEHOLDER.search(m.group(2)) and entropy(m.group(2)) >= 3.3:
                    add(Finding(
                        rule="hardcoded-secret", severity="high",
                        title="Possible hard-coded secret in '%s'" % m.group(1),
                        file=relpath, line=lineno, category="secret",
                        snippet=redact(m.group(2)),
                        why="A long random-looking value is assigned straight to a secret-like name.",
                        fix="Move the value to an environment variable, rotate it if it is real, "
                            "and add `# cipherbloom:ignore` on the line only if it is a safe test value.",
                    ))
                elif env_file:
                    em = ENV_LINE.match(line)
                    if em and not line.lstrip().startswith("#"):
                        val = em.group(2).strip("'\"")
                        if (SECRETISH_KEY.search(em.group(1)) and len(val) >= 8
                                and not PLACEHOLDER.search(val)):
                            add(Finding(
                                rule="env-file-secret", severity="high",
                                title="Real-looking secret inside %s (%s)" % (name, em.group(1)),
                                file=relpath, line=lineno, category="secret",
                                snippet=redact(val),
                                why="This is normal for a local .env, but it must never leave your "
                                    "machine. If this file is committed or shared, the secret is exposed.",
                                fix="Make sure %s is in .gitignore, never upload it in a zip, and "
                                    "ship a .env.example with fake values instead." % name,
                            ))
    return findings
