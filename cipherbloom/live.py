"""Consent-based LIVE check. Localhost only. Read-only, harmless requests.

What it does: a handful of normal GET requests (about 25) to the app YOU are running
on your own computer. No attack payloads, no flooding, no login guessing, no writes.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

from .files import iter_files, read_text, rel
from .models import Finding

CONSENT_TEXT = """
CipherBloom Guardian - LIVE CHECK CONSENT
-----------------------------------------
Target : {target}
Mode   : read-only, localhost only

This will send about 25 ordinary GET requests to the address above to look for:
  * exposed files (.env, .git, backups)      * missing security headers
  * CORS that trusts every website           * debug pages / stack traces
  * directory listings and cookie flags

It will NOT: send attack payloads, flood the server, guess passwords, change or
delete data, or contact any address except the one above. Your code is never executed
by CipherBloom; the app must already be running by itself.
"""
PHRASE = "I OWN THIS"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def is_loopback(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0].split("%")[0]).is_loopback:
                return False
        except ValueError:
            return False
    return True


def validate_target(url):
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Target must look like http://localhost:8000")
    if not is_loopback(p.hostname):
        raise ValueError(
            "Refusing to test '%s'. Version 0.1 only tests localhost / 127.0.0.1 so it can never be "
            "used against someone else's site." % p.hostname)
    return "%s://%s" % (p.scheme, p.netloc)


def ask_consent(target, accepted_flag):
    print(CONSENT_TEXT.format(target=target))
    if accepted_flag:
        print("Consent given with --yes-i-own-this.\n")
        return True
    if not sys.stdin.isatty():
        print("No interactive terminal. Re-run with --yes-i-own-this to give consent.")
        return False
    answer = input("Type  %s  to confirm this is YOUR app on YOUR computer: " % PHRASE).strip()
    return answer == PHRASE


def fetch(url, headers=None, timeout=5):
    req = urllib.request.Request(url, headers=dict({"User-Agent": "CipherBloom-Guardian/0.1"}, **(headers or {})))
    try:
        resp = _OPENER.open(req, timeout=timeout)
        status, hdrs, body = resp.status, resp.headers, resp.read(4000)
    except urllib.error.HTTPError as e:
        status, hdrs = e.code, e.headers
        try:
            body = e.read(4000)
        except OSError:
            body = b""
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return status, {k.lower(): v for k, v in hdrs.items()}, body.decode("utf-8", "replace"), hdrs


def _not_html(h):
    return "html" not in h.get("content-type", "").lower()


# path, severity, title, validator(body, headers)
PROBES = [
    ("/.env", "critical", "Your .env file is downloadable",
     lambda b, h: _not_html(h) and re.search(r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=", b) is not None),
    ("/.env.local", "critical", "Your .env.local file is downloadable",
     lambda b, h: _not_html(h) and re.search(r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=", b) is not None),
    ("/.git/config", "high", "Your .git folder is public (source code can be rebuilt)",
     lambda b, h: "[core]" in b),
    ("/.git/HEAD", "high", "Your .git folder is public (source code can be rebuilt)",
     lambda b, h: b.startswith("ref:")),
    ("/backup.zip", "high", "A backup archive is downloadable", lambda b, h: _not_html(h) and b.startswith("PK")),
    ("/db.sqlite3", "high", "Your database file is downloadable", lambda b, h: b.startswith("SQLite format")),
    ("/.aws/credentials", "critical", "AWS credentials file is downloadable", lambda b, h: "aws_access_key_id" in b.lower()),
    ("/docker-compose.yml", "medium", "docker-compose.yml is downloadable",
     lambda b, h: _not_html(h) and ("services:" in b)),
    ("/.DS_Store", "low", ".DS_Store leaks your folder layout", lambda b, h: b.startswith("\x00\x00\x00\x01Bud1")),
]

# Where in the CODE this kind of problem usually comes from (best-effort hints).
LOCATE = {
    "static": r"StaticFiles\(|express\.static\(|send_from_directory\(|serve_static|SimpleHTTPRequestHandler|http\.server",
    "cors": r"allow_origins\s*=|CORS\(|(?<![\w.])cors\(|Access-Control-Allow-Origin",
    "app": r"FastAPI\(|Flask\(\s*__name__|express\(\)|createServer\(",
    "debug": r"debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\(",
    "cookie": r"set_cookie\(|res\.cookie\(|SESSION_COOKIE|cookie-session|express-session",
}


def locate(root, key):
    if not root or not os.path.isdir(root):
        return "", 0
    regex = re.compile(LOCATE[key])
    for path in iter_files(root):
        if os.path.splitext(path)[1].lower() not in {".py", ".js", ".mjs", ".cjs", ".ts"}:
            continue
        text = read_text(path)
        if not text:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                return rel(path, root), n
    return "", 0


def _add(findings, root, key, **kw):
    f = Finding(category="live", **kw)
    if key:
        file, line = locate(root, key)
        if file:
            f.file, f.line = file, line
            f.why += " (Code location is a best guess - verify it.)"
    findings.append(f)


def run_live(target_url, code_root=None):
    base = validate_target(target_url)
    findings = []
    root = fetch(base + "/")
    if root is None:
        return findings, "Could not connect to %s. Is your app running?" % base
    status, h, body, raw = root

    for path, sev, title, ok in PROBES:
        r = fetch(base + path)
        if r and r[0] == 200 and ok(r[2], r[1]):
            _add(findings, code_root, "static", rule="exposed-file", severity=sev,
                 title=title + " (%s)" % path,
                 why="Anyone who visits %s%s can download it." % (base, path),
                 fix="Stop serving that path: serve only a dedicated public/ folder, never the project root. "
                     "Then rotate any secret that was inside.")

    missing = [n for n, label in (("x-content-type-options", "X-Content-Type-Options: nosniff"),
                                  ("content-security-policy", "Content-Security-Policy"))
               if n not in h]
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        missing.append("X-Frame-Options: DENY")
    if missing:
        _add(findings, code_root, "app", rule="missing-security-headers", severity="low",
             title="Missing security headers: " + ", ".join(missing),
             why="Browsers have built-in protections (clickjacking, MIME sniffing, script injection) that these headers switch on.",
             fix="Add them in one place (Express: `helmet()`; FastAPI/Flask: a small middleware or `flask-talisman`).")

    for leak in ("server", "x-powered-by"):
        if leak in h and re.search(r"\d", h[leak]):
            _add(findings, code_root, "app", rule="version-disclosure", severity="low",
                 title="Server reveals its version (%s: %s)" % (leak, h[leak]),
                 why="Attackers search for known bugs in exactly that version.",
                 fix="Hide it (Express: `app.disable('x-powered-by')`; uvicorn: `--no-server-header`).")

    evil = "https://cipherbloom-test.invalid"
    c = fetch(base + "/", headers={"Origin": evil})
    if c:
        acao = c[1].get("access-control-allow-origin", "")
        creds = c[1].get("access-control-allow-credentials", "").lower() == "true"
        if acao == evil and creds:
            _add(findings, code_root, "cors", rule="cors-reflect-credentials", severity="high",
                 title="CORS trusts ANY website and allows cookies",
                 why="A malicious site can make a visitor's browser call your API with their login.",
                 fix="Replace the reflected origin with a fixed allow-list of your own domains.")
        elif acao in ("*", evil):
            _add(findings, code_root, "cors", rule="cors-wildcard", severity="medium",
                 title="CORS allows every website (Access-Control-Allow-Origin: %s)" % acao,
                 why="Any website can read responses from your API in a visitor's browser.",
                 fix="Allow only the exact origins you control, e.g. https://yourapp.com.")

    err = fetch(base + "/__cipherbloom_probe_404__")
    if err and re.search(r"Traceback \(most recent call last\)|Werkzeug Debugger|Whoops!|at Object\.<anonymous>|node_modules/", err[2]):
        _add(findings, code_root, "debug", rule="debug-page", severity="high",
             title="Error pages show internal stack traces (debug mode is on)",
             why="Stack traces reveal file paths and code, and some debug pages let visitors run code.",
             fix="Turn debug off outside development and return a plain 500/404 page.")
    cons = fetch(base + "/console")
    if cons and cons[0] == 200 and "Interactive Console" in cons[2]:
        _add(findings, code_root, "debug", rule="werkzeug-console", severity="critical",
             title="Interactive Python console is exposed at /console",
             why="Anyone who reaches it can run code on your machine.",
             fix="Set debug=False and never expose a debug server.")

    if re.search(r"<title>Index of /|Directory listing for /", body):
        _add(findings, code_root, "static", rule="directory-listing", severity="medium",
             title="Directory listing is enabled",
             why="Visitors can browse your files like a folder.",
             fix="Serve a specific folder with listing disabled, or add an index.html.")

    cookies = raw.get_all("Set-Cookie") or []
    for ck in cookies:
        low = ck.lower()
        miss = [n for n, t in (("HttpOnly", "httponly"), ("SameSite", "samesite")) if t not in low]
        if miss:
            _add(findings, code_root, "cookie", rule="weak-cookie", severity="low",
                 title="Cookie '%s' is missing %s" % (ck.split("=", 1)[0], ", ".join(miss)),
                 why="Scripts on the page can read it, or other sites can send it along with their requests.",
                 fix="Set HttpOnly, SameSite=Lax (or Strict), and Secure when you use HTTPS.")

    for p, title in (("/docs", "API docs"), ("/openapi.json", "OpenAPI schema"), ("/swagger", "Swagger UI")):
        r = fetch(base + p)
        if r and r[0] == 200 and ("swagger" in r[2].lower() or "openapi" in r[2].lower()):
            findings.append(Finding(
                rule="api-docs-public", severity="info", category="live",
                title="%s is public at %s" % (title, p),
                why="Fine while developing. In production it shows attackers every endpoint you have.",
                fix="Disable or protect it in production (FastAPI: FastAPI(docs_url=None, openapi_url=None))."))
            break
    return findings, ""
