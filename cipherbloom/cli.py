from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys

from . import __version__
from .archive import SourceError, prepare
from .engine import run_scan
from .live import ask_consent, validate_target
from .models import SEVERITY_ORDER
from .report import print_terminal, use_color, write_json
from .report_html import write_html

HOOK = """#!/bin/sh
# CipherBloom Guardian pre-commit hook: blocks commits that contain secrets.
cipherbloom scan . --staged --fail-on high --quiet --no-color || {
  echo "CipherBloom blocked this commit. Fix the issues above (or use git commit --no-verify at your own risk)."
  exit 1
}
"""


def _staged_files(root):
    try:
        res = subprocess.run(["git", "-C", root, "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return set(res.stdout.splitlines()) if res.returncode == 0 else None


def build_parser():
    p = argparse.ArgumentParser(
        prog="cipherbloom",
        description="CipherBloom Guardian - finds leaked keys, risky code and exposed files. "
                    "Offline. No AI. No API key.")
    p.add_argument("--version", action="version", version="cipherbloom-guardian " + __version__)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a folder, a .zip file or a public repo link")
    s.add_argument("source", nargs="?", default=".", help="folder, .zip or https repo link (default: .)")
    s.add_argument("--live", metavar="URL", help="also run the consent-based live check on YOUR localhost app")
    s.add_argument("--yes-i-own-this", action="store_true", help="give live-check consent non-interactively")
    s.add_argument("--audit", action="store_true", help="also run pip-audit / npm audit if installed (uses the network)")
    s.add_argument("--no-history", action="store_true", help="skip the git history check")
    s.add_argument("--staged", action="store_true", help="only scan files staged for commit (used by the hook)")
    s.add_argument("--html", metavar="FILE", help="write the animated HTML report")
    s.add_argument("--json", metavar="FILE", help="write a JSON report")
    s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if a finding at/above this level exists")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("--quiet", action="store_true", help="hide the banner")

    u = sub.add_parser("ui", help="open the glass dashboard in your browser (localhost only)")
    u.add_argument("--port", type=int, default=7878)
    u.add_argument("--no-open", action="store_true", help="do not open the browser automatically")

    h = sub.add_parser("hook", help="manage the git pre-commit hook")
    h.add_argument("action", choices=["install", "uninstall"])
    h.add_argument("path", nargs="?", default=".")
    return p


def cmd_hook(args):
    gitdir = os.path.join(os.path.abspath(args.path), ".git")
    if not os.path.isdir(gitdir):
        print("Not a git repository: %s" % args.path)
        return 2
    hook = os.path.join(gitdir, "hooks", "pre-commit")
    if args.action == "uninstall":
        if os.path.isfile(hook):
            with open(hook, encoding="utf-8", errors="replace") as fh:
                if "CipherBloom" not in fh.read():
                    print("That pre-commit hook was not installed by CipherBloom - leaving it alone.")
                    return 2
            os.remove(hook)
        print("Pre-commit hook removed.")
        return 0
    if os.path.exists(hook):
        print("A pre-commit hook already exists at %s - not overwriting it." % hook)
        return 2
    os.makedirs(os.path.dirname(hook), exist_ok=True)
    with open(hook, "w", encoding="utf-8") as fh:
        fh.write(HOOK)
    os.chmod(hook, os.stat(hook).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print("Installed. Every `git commit` now checks for leaked secrets first.")
    return 0


def cmd_scan(args):
    live_target = None
    if args.live:
        try:
            live_target = validate_target(args.live)
        except ValueError as exc:
            print("Error:", exc)
            return 2
    try:
        root, tmp = prepare(args.source)
    except SourceError as exc:
        print("Error:", exc)
        return 2
    try:
        staged = _staged_files(root) if args.staged else None
        if live_target and not ask_consent(live_target, args.yes_i_own_this):
            print("Consent not given - live check skipped.\n")
            live_target = None
        findings, checks, notes, secs = run_scan(
            root, {"history": not args.no_history, "audit": args.audit},
            live_target=live_target, staged=staged)
        print_terminal(findings, args.source, checks, color=use_color(args.no_color), quiet=args.quiet)
        for note in notes:
            print("\nNote:", note)
        if not args.quiet:
            print("Finished in %.2fs" % secs)
        if args.html:
            write_html(args.html, findings, args.source, checks)
            print("HTML report :", args.html)
        if args.json:
            write_json(args.json, findings, args.source, checks)
            print("JSON report :", args.json)
        if args.fail_on:
            limit = SEVERITY_ORDER[args.fail_on]
            if any(SEVERITY_ORDER[f.severity] <= limit for f in findings):
                return 1
        return 0
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def cmd_ui(args):
    from .server import serve
    return serve(port=args.port, open_browser=not args.no_open)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "hook":
        return cmd_hook(args)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "ui":
        return cmd_ui(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
