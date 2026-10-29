"""Localhost-only web dashboard for CipherBloom Guardian.

Security model
--------------
* Binds to 127.0.0.1 only, so nothing on your network can reach it.
* Rejects any request whose Host header is not localhost / 127.0.0.1 (stops DNS-rebinding).
* Every API call must carry a random per-launch token that only the page served by this
  process knows, and cross-site Origins are refused (stops other websites driving it).
* Code is only ever READ, never executed. Uploaded zips are extracted with zip-slip and
  size protection into a temp folder that is deleted right after the scan.
* The live check still requires the typed consent phrase and a localhost target.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import tempfile
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .archive import SourceError, extract_zip, prepare
from .engine import STAGES, run_scan
from .live import PHRASE, validate_target
from .report import to_dict
from .report_html import TEMPLATE

MAX_UPLOAD = 100 * 1024 * 1024
MAX_JSON = 64 * 1024
MAX_RESULTS = 20
WEB_DIR = os.path.join(os.path.dirname(__file__), "web")


class State:
    def __init__(self, port):
        self.port = port
        self.token = secrets.token_urlsafe(32)
        self.results = {}
        self.lock = threading.Lock()

    def remember(self, data):
        rid = uuid.uuid4().hex[:12]
        with self.lock:
            self.results[rid] = data
            while len(self.results) > MAX_RESULTS:
                self.results.pop(next(iter(self.results)))
        return rid


def _options(raw):
    raw = raw or {}
    valid = {k for k, _, _ in STAGES}
    checks = [c for c in (raw.get("checks") or []) if c in valid] or sorted(valid)
    return {"checks": checks, "history": bool(raw.get("history", True)), "audit": bool(raw.get("audit", False))}


def _live(raw):
    """Return (validated_target_or_None, error_or_None)."""
    raw = raw or {}
    url = (raw.get("url") or "").strip()
    if not url:
        return None, None
    if (raw.get("phrase") or "").strip() != PHRASE:
        return None, "Live check needs your consent: type %s exactly." % PHRASE
    try:
        return validate_target(url), None
    except ValueError as exc:
        return None, str(exc)


def make_handler(state):
    allowed_hosts = {"127.0.0.1:%d" % state.port, "localhost:%d" % state.port}
    allowed_origins = {"http://" + h for h in allowed_hosts}

    class Handler(BaseHTTPRequestHandler):
        server_version = "CipherBloom/" + __version__
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        # ---------- helpers ----------
        def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                             "img-src 'self' data:; connect-src 'self'; font-src 'self' data:; "
                             "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _err(self, code, msg):
            self._send(code, {"error": msg})

        def _host_ok(self):
            return self.headers.get("Host", "") in allowed_hosts

        def _api_ok(self):
            if not self._host_ok():
                self._err(403, "Bad host")
                return False
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                self._err(403, "Cross-site request refused")
                return False
            if not secrets.compare_digest(self.headers.get("X-CB-Token", ""), state.token):
                self._err(403, "Missing or wrong session token. Reload the page.")
                return False
            return True

        def _body(self, limit):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > limit:
                return None
            return self.rfile.read(length)

        def _result(self, findings, checks, notes, secs, target):
            data = to_dict(findings, target, checks)
            data.update({"seconds": secs, "notes": notes})
            data["id"] = state.remember(data)
            return data

        # ---------- routes ----------
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if not self._host_ok():
                return self._err(403, "Bad host")
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                with open(os.path.join(WEB_DIR, "index.html"), encoding="utf-8") as fh:
                    page = fh.read().replace("__CB_TOKEN__", state.token).replace("__CB_VERSION__", __version__)
                return self._send(200, page, "text/html; charset=utf-8")
            if path == "/favicon.svg":
                with open(os.path.join(WEB_DIR, "favicon.svg"), "rb") as fh:
                    return self._send(200, fh.read(), "image/svg+xml")
            if path == "/api/health":
                return self._send(200, {"ok": True, "version": __version__, "ai": False, "api_key_needed": False})
            if path.startswith("/api/report/"):
                if not self._api_ok():
                    return
                name = path.rsplit("/", 1)[-1]
                rid, _, ext = name.partition(".")
                data = state.results.get(rid)
                if not data:
                    return self._err(404, "Report not found (the dashboard keeps the last %d scans)." % MAX_RESULTS)
                if ext == "json":
                    return self._send(200, json.dumps(data, indent=2), "application/json; charset=utf-8",
                                      {"Content-Disposition": 'attachment; filename="cipherbloom-report.json"'})
                if ext == "html":
                    html = TEMPLATE.replace("__DATA__", json.dumps(data).replace("</", "<\\/"))
                    return self._send(200, html, "text/html; charset=utf-8",
                                      {"Content-Disposition": 'attachment; filename="cipherbloom-report.html"'})
                return self._err(404, "Unknown report format")
            self._err(404, "Not found")

        def do_POST(self):
            if not self._api_ok():
                return
            parsed = urlparse(self.path)
            if parsed.path == "/api/scan":
                return self._scan_source()
            if parsed.path == "/api/scan-zip":
                return self._scan_zip(parse_qs(parsed.query))
            self._err(404, "Not found")

        def _scan_source(self):
            raw = self._body(MAX_JSON)
            if raw is None:
                return self._err(413, "Request too large")
            try:
                req = json.loads(raw.decode("utf-8") or "{}")
            except ValueError:
                return self._err(400, "Invalid JSON")
            source = (req.get("source") or "").strip()
            if not source:
                return self._err(400, "Give a folder path or a public repo link.")
            if not source.startswith("http"):
                source = os.path.expanduser(source)
            live_target, live_err = _live(req.get("live"))
            if live_err:
                return self._err(400, live_err)
            try:
                root, tmp = prepare(source)
            except SourceError as exc:
                return self._err(400, str(exc))
            try:
                findings, checks, notes, secs = run_scan(root, _options(req.get("options")), live_target)
            finally:
                if tmp:
                    shutil.rmtree(tmp, ignore_errors=True)
            self._send(200, self._result(findings, checks, notes, secs, req.get("source")))

        def _scan_zip(self, query):
            try:
                opts = json.loads((query.get("opts") or ["{}"])[0])
            except ValueError:
                opts = {}
            live_target, live_err = _live(opts.get("live"))
            if live_err:
                return self._err(400, live_err)
            data = self._body(MAX_UPLOAD)
            if data is None:
                return self._err(413, "Zip is larger than %d MB." % (MAX_UPLOAD // (1024 * 1024)))
            fd, zpath = tempfile.mkstemp(prefix="cipherbloom-upload-", suffix=".zip")
            tmp = None
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                try:
                    root, tmp = extract_zip(zpath)
                except SourceError as exc:
                    return self._err(400, str(exc))
                findings, checks, notes, secs = run_scan(root, _options(opts.get("options")), live_target)
            finally:
                try:
                    os.remove(zpath)
                except OSError:
                    pass
                if tmp:
                    shutil.rmtree(tmp, ignore_errors=True)
            name = os.path.basename((query.get("name") or ["upload.zip"])[0])[:120]
            self._send(200, self._result(findings, checks, notes, secs, name))

    return Handler


def build_server(port=7878):
    srv = ThreadingHTTPServer(("127.0.0.1", port), None)
    state = State(srv.server_address[1])
    srv.RequestHandlerClass = make_handler(state)
    srv.daemon_threads = True
    return srv, state


def serve(port=7878, open_browser=True):
    try:
        srv, state = build_server(port)
    except OSError as exc:
        print("Could not start on port %d (%s). Try: cipherbloom ui --port 7879" % (port, exc))
        return 2
    url = "http://127.0.0.1:%d/" % state.port
    print("CipherBloom Guardian dashboard running at %s" % url)
    print("Localhost only - no AI, no API key, nothing leaves this computer. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    serve()
