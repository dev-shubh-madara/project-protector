from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess

from .files import iter_files, read_text, rel
from .models import Finding

JS_EXT = {".js", ".mjs", ".cjs"}
NODE_ERR = re.compile(r":(\d+)\s*$")


def _make(rule, relpath, line, msg, source_line=""):
    return Finding(
        rule=rule, severity="high", category="syntax", file=relpath, line=line,
        title="Syntax error: %s" % msg, snippet=source_line.strip()[:120],
        why="This file cannot run until the syntax error is fixed.",
        fix="Open %s at line %d and fix: %s. Check the line above it too, because a missing "
            "bracket or quote is often reported on the next line." % (relpath, line, msg),
    )


def check_syntax(root):
    findings = []
    node = shutil.which("node")
    for path in iter_files(root):
        ext = os.path.splitext(path)[1].lower()
        name = os.path.basename(path)
        if ext not in {".py", ".json"} | JS_EXT:
            continue
        relpath = rel(path, root)
        if ext == ".py":
            text = read_text(path)
            if text is None:
                continue
            try:
                ast.parse(text, filename=relpath)
            except SyntaxError as exc:
                line = exc.lineno or 1
                lines = text.splitlines()
                src = lines[line - 1] if 0 < line <= len(lines) else ""
                findings.append(_make("py-syntax", relpath, line, exc.msg, src))
            except (ValueError, RecursionError):
                continue
        elif ext == ".json":
            if name in {"tsconfig.json", "jsconfig.json"}:
                continue
            text = read_text(path)
            if not text or not text.strip():
                continue
            try:
                json.loads(text)
            except json.JSONDecodeError as exc:
                findings.append(_make("json-syntax", relpath, exc.lineno, exc.msg))
        elif node:
            try:
                res = subprocess.run([node, "--check", path], capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                continue
            if res.returncode != 0:
                lines = res.stderr.splitlines()
                line_no, msg = 1, "invalid JavaScript"
                for l in lines:
                    m = NODE_ERR.search(l)
                    if m and path in l:
                        line_no = int(m.group(1))
                    if l.startswith("SyntaxError:"):
                        msg = l[len("SyntaxError:"):].strip()
                findings.append(_make("js-syntax", relpath, line_no, msg))
    return findings
