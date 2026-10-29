# cipherbloom:ignore-file  (this file contains rule descriptions, not real risky calls)
from __future__ import annotations

import os
import re

from .files import ignored_file, iter_files, read_text, rel
from .models import Finding

PY = (".py",)
JS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")

# (rule, severity, title, extensions, regex, why, fix)
RULES = [
    ("py-eval", "high", "eval() on dynamic input", PY,
     re.compile(r"(?<![\w.])eval\s*\((?!\s*[\"'])"),
     "eval runs any text as code. If a user can influence the text, they can run commands on your server.",
     "Use ast.literal_eval for data, or a dictionary/dispatch table instead of eval."),
    ("py-exec", "high", "exec() on dynamic input", PY,
     re.compile(r"(?<![\w.])exec\s*\((?!\s*[\"'])"),
     "exec runs any text as code, the same risk as eval.",
     "Remove exec and call real functions directly."),
    ("py-shell-true", "high", "subprocess with shell=True", PY,
     re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"),
     "With shell=True, a user-supplied value can inject extra shell commands.",
     "Pass the command as a list (['ls', path]) and drop shell=True."),
    ("py-os-system", "medium", "os.system() call", PY,
     re.compile(r"\bos\.system\s*\("),
     "os.system goes through the shell and is easy to inject into.",
     "Use subprocess.run([...]) with a list of arguments."),
    ("py-debug-true", "high", "Debug mode enabled", PY,
     re.compile(r"\.run\(.*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b"),
     "Debug mode can expose stack traces and, on Flask, an interactive console that runs code.",
     "Read it from an env var: debug = os.environ.get('DEBUG') == '1', and keep it off in production."),
    ("py-verify-false", "medium", "TLS certificate check disabled", PY,
     re.compile(r"verify\s*=\s*False"),
     "Turning off certificate checks lets an attacker on the network read or change your traffic.",
     "Remove verify=False and fix the certificate problem instead."),
    ("py-pickle-load", "high", "pickle.load on possibly untrusted data", PY,
     re.compile(r"\bpickle\.loads?\s*\("),
     "Loading a pickle can run arbitrary code. Never unpickle data from users or the internet.",
     "Use JSON for data exchange."),
    ("py-yaml-load", "medium", "yaml.load without a safe loader", PY,
     re.compile(r"\byaml\.load\s*\((?!.*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)"),
     "yaml.load without SafeLoader can build arbitrary Python objects.",
     "Use yaml.safe_load(...)."),
    ("py-sql-format", "high", "SQL built with string formatting (SQL injection risk)", PY,
     re.compile(r"\.execute\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+|\.format))"),
     "Putting user values straight into SQL text lets attackers change the query.",
     "Use placeholders: cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))."),
    ("py-cors-wildcard", "medium", "CORS allows every origin", PY,
     re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|CORS\(\s*\w+\s*\)"),
     "Any website can call your API from a visitor's browser.",
     "List only the exact origins you trust, e.g. allow_origins=['https://yourapp.com']."),
    ("js-eval", "high", "eval() / new Function() in JavaScript", JS,
     re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\("),
     "Running text as code allows script injection.",
     "Parse data with JSON.parse and call real functions instead."),
    ("js-innerhtml", "medium", "innerHTML assignment (XSS risk)", JS,
     re.compile(r"\.innerHTML\s*=(?!=)"),
     "If any part of the value comes from a user, they can inject a script into your page.",
     "Use textContent, or sanitize the HTML first."),
    ("js-cors-wildcard", "medium", "CORS allows every origin", JS,
     re.compile(r"origin\s*:\s*[\"']\*[\"']|(?<![\w.])cors\(\s*\)"),
     "Any website can call your API from a visitor's browser.",
     "Pass an explicit origin list: cors({ origin: ['https://yourapp.com'] })."),
    ("js-child-process-exec", "medium", "child_process.exec call", JS,
     re.compile(r"\bchild_process\b.*\bexec\s*\(|(?<![\w.])exec\s*\(\s*[`\"'].*\$\{"),
     "exec goes through a shell, so user input can inject commands.",
     "Use execFile / spawn with an argument array."),
]


def scan_risky(root):
    findings = []
    for path in iter_files(root):
        ext = os.path.splitext(path)[1].lower()
        if ext not in PY and ext not in JS:
            continue
        text = read_text(path)
        if text is None or ignored_file(text):
            continue
        relpath = rel(path, root)
        if "/tests/" in "/" + relpath or os.path.basename(path).startswith("test_"):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "*")) or "cipherbloom:ignore" in line:
                continue
            for rule, sev, title, exts, regex, why, fix in RULES:
                if ext in exts and regex.search(line):
                    findings.append(Finding(
                        rule=rule, severity=sev, title=title, file=relpath, line=lineno,
                        why=why, fix=fix, snippet=stripped[:120], category="code",
                    ))
    return findings
