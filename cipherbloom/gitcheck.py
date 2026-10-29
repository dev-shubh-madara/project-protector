from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess

from .files import SKIP_DIRS, rel
from .models import Finding

EXAMPLE_SUFFIX = (".example", ".sample", ".template", ".dist")


def _is_env_name(name):
    low = name.lower()
    if low.endswith(EXAMPLE_SUFFIX):
        return False
    return low == ".env" or low.startswith(".env.") or low.endswith(".env")


def _git(root, *args):
    if not shutil.which("git"):
        return None
    try:
        return subprocess.run(
            ["git", "-C", root] + list(args), capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _ignored_by_file(root, relpath):
    """Fallback .gitignore matching when git is not available."""
    gi = os.path.join(root, ".gitignore")
    if not os.path.isfile(gi):
        return False
    name = os.path.basename(relpath)
    try:
        with open(gi, encoding="utf-8", errors="replace") as fh:
            lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return False
    ignored = False
    for pat in lines:
        neg = pat.startswith("!")
        p = pat.lstrip("!").strip("/")
        hit = fnmatch.fnmatch(name, p) or fnmatch.fnmatch(relpath, p)
        if hit:
            ignored = not neg
    return ignored


def check_git_hygiene(root, history=True):
    findings = []
    if not os.path.isdir(root):
        return findings
    env_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if _is_env_name(name):
                env_files.append(os.path.join(dirpath, name))
    is_repo = os.path.isdir(os.path.join(root, ".git"))
    tracked = set()
    if is_repo:
        res = _git(root, "ls-files")
        if res is not None and res.returncode == 0:
            tracked = set(res.stdout.splitlines())

    for path in env_files:
        relpath = rel(path, root)
        if relpath in tracked:
            findings.append(Finding(
                rule="env-tracked", severity="critical", category="git",
                title="%s is tracked by git" % relpath, file=relpath,
                why="Every clone, fork and push now contains your secrets.",
                fix="Run: git rm --cached %s && echo '%s' >> .gitignore && git commit. "
                    "Then rotate every key inside it, because history keeps the old copy." % (relpath, os.path.basename(relpath)),
            ))
            continue
        ignored = False
        if is_repo:
            res = _git(root, "check-ignore", "-q", "--", relpath)
            ignored = bool(res is not None and res.returncode == 0)
        else:
            ignored = _ignored_by_file(root, relpath)
        if not ignored:
            findings.append(Finding(
                rule="env-not-ignored", severity="high", category="git",
                title="%s is not listed in .gitignore" % relpath, file=relpath,
                why="One careless `git add .` will publish your secrets.",
                fix="Add this line to .gitignore:  %s  (and keep a .env.example with fake values)." % os.path.basename(relpath),
            ))
    if env_files and not any(os.path.isfile(os.path.join(os.path.dirname(p), n))
                             for p in env_files for n in (".env.example", ".env.sample", ".env.template")):
        findings.append(Finding(
            rule="env-example-missing", severity="low", category="git",
            title="No .env.example file found",
            why="Users of your project will not know which variables they need to set.",
            fix="Create .env.example listing every variable name with a fake value.",
        ))
    if history and is_repo:
        res = _git(root, "log", "--all", "--pretty=format:", "--name-only", "--diff-filter=A")
        if res is not None and res.returncode == 0:
            seen = sorted({l for l in res.stdout.splitlines() if l and _is_env_name(os.path.basename(l))})
            for name in seen[:10]:
                findings.append(Finding(
                    rule="env-in-history", severity="high", category="git",
                    title="%s was committed in the past" % name, file=name,
                    why="Deleting the file does not remove it from git history; anyone can read old commits.",
                    fix="Rotate every key that was in it. To purge history use `git filter-repo --path %s --invert-paths`, "
                        "then force-push." % name,
                ))
    return findings
