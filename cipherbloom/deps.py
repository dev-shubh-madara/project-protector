from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from .files import SKIP_DIRS, read_text, rel
from .models import Finding

REQ_PINNED = re.compile(r"^[A-Za-z0-9_.\-\[\]]+\s*(==|===)\s*[\w.\-+!*]+")


def _find(root, pred):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for n in filenames:
            if pred(n):
                yield os.path.join(dirpath, n)


def check_dependencies(root, audit=False):
    """Offline hygiene checks. With audit=True, also call pip-audit / npm audit if installed."""
    findings = []
    if not os.path.isdir(root):
        return findings
    for path in _find(root, lambda n: re.match(r"requirements.*\.txt$", n)):
        text = read_text(path) or ""
        relpath = rel(path, root)
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "http", "git+")) or REQ_PINNED.match(line):
                continue
            findings.append(Finding(
                rule="unpinned-dependency", severity="low", category="dependency",
                title="Dependency '%s' is not pinned to one version" % line.split(";")[0].strip(),
                file=relpath, line=lineno, snippet=line[:80],
                why="A new release (or a hijacked one) is installed silently on the next deploy.",
                fix="Pin it, e.g. `pip freeze > requirements.txt`, or write name==1.2.3.",
            ))
        if audit and shutil.which("pip-audit"):
            findings.extend(_pip_audit(path, relpath))
    for path in _find(root, lambda n: n == "package.json"):
        text = read_text(path) or ""
        relpath = rel(path, root)
        try:
            data = json.loads(text)
        except ValueError:
            continue
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section) or {}).items():
                if str(ver).strip() in ("*", "latest", "x", ""):
                    line = next((i for i, l in enumerate(text.splitlines(), 1) if '"%s"' % name in l), 1)
                    findings.append(Finding(
                        rule="wildcard-dependency", severity="medium", category="dependency",
                        title="'%s' uses version '%s'" % (name, ver), file=relpath, line=line,
                        why="Any future release, including a malicious one, is installed automatically.",
                        fix="Use a fixed range such as ^1.2.3 and commit your lock file.",
                    ))
        folder = os.path.dirname(path)
        if not any(os.path.isfile(os.path.join(folder, l)) for l in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
            findings.append(Finding(
                rule="no-lockfile", severity="low", category="dependency",
                title="No lock file next to package.json", file=relpath,
                why="Without a lock file, installs are not repeatable and can pick up bad versions.",
                fix="Run `npm install` once and commit package-lock.json.",
            ))
        elif audit and shutil.which("npm"):
            findings.extend(_npm_audit(folder, root))
    return findings


def _pip_audit(path, relpath):
    out = []
    try:
        res = subprocess.run(["pip-audit", "-r", path, "-f", "json", "--progress-spinner", "off"],
                             capture_output=True, text=True, timeout=180)
        data = json.loads(res.stdout or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return out
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            fixes = ", ".join(v.get("fix_versions") or []) or "no fix yet"
            out.append(Finding(
                rule="known-vulnerability", severity="high", category="dependency",
                title="%s %s has a known vulnerability (%s)" % (dep.get("name"), dep.get("version"), v.get("id")),
                file=relpath, why=(v.get("description") or "See the advisory for details.")[:200],
                fix="Upgrade to: %s" % fixes,
            ))
    return out


def _npm_audit(folder, root):
    out = []
    try:
        res = subprocess.run(["npm", "audit", "--json"], cwd=folder, capture_output=True, text=True, timeout=180)
        data = json.loads(res.stdout or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return out
    relpath = rel(os.path.join(folder, "package.json"), root)
    for name, info in (data.get("vulnerabilities") or {}).items():
        sev = info.get("severity", "medium")
        sev = sev if sev in ("critical", "high", "medium", "low") else "medium"
        out.append(Finding(
            rule="known-vulnerability", severity=sev, category="dependency",
            title="%s has a known vulnerability (%s)" % (name, sev), file=relpath,
            why="Reported by npm audit.", fix="Run `npm audit fix`, or upgrade %s manually." % name,
        ))
    return out
