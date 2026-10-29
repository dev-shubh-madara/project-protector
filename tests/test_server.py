import io
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile

from cipherbloom.server import build_server

FAKE_AWS = "AKIA" + "QWERTYUIOP123456"


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.state = build_server(port=0)
        cls.port = cls.state.port
        cls.base = "http://127.0.0.1:%d" % cls.port
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "app.py"), "w") as fh:
            fh.write("KEY = '%s'\n" % FAKE_AWS)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def call(self, path, body=None, headers=None, method=None, ctype="application/json"):
        h = {"X-CB-Token": self.state.token}
        if body is not None:
            h["Content-Type"] = ctype
        h.update(headers or {})
        data = json.dumps(body).encode() if isinstance(body, dict) else body
        req = urllib.request.Request(self.base + path, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_page_has_token_and_security_headers(self):
        with urllib.request.urlopen(self.base + "/", timeout=10) as r:
            page = r.read().decode()
            self.assertIn(self.state.token, page)
            self.assertEqual(r.headers["X-Frame-Options"], "DENY")
            self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])

    def test_health_says_no_ai(self):
        code, body = self.call("/api/health")
        self.assertEqual(code, 200)
        self.assertFalse(json.loads(body)["api_key_needed"])

    def test_rejects_missing_token(self):
        code, _ = self.call("/api/scan", {"source": self.dir}, headers={"X-CB-Token": "nope"})
        self.assertEqual(code, 403)

    def test_rejects_foreign_origin(self):
        code, _ = self.call("/api/scan", {"source": self.dir}, headers={"Origin": "https://evil.example"})
        self.assertEqual(code, 403)

    def test_rejects_bad_host(self):
        req = urllib.request.Request(self.base + "/", headers={"Host": "evil.example"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(cm.exception.code, 403)

    def test_folder_scan_and_reports(self):
        code, body = self.call("/api/scan", {"source": self.dir})
        self.assertEqual(code, 200)
        data = json.loads(body)
        self.assertEqual(data["findings"][0]["rule"], "aws-access-key")
        self.assertNotIn(FAKE_AWS, body.decode())  # secret is masked in the API too
        code, html = self.call("/api/report/%s.html" % data["id"])
        self.assertEqual(code, 200)
        self.assertIn(b"CipherBloom Guardian", html)
        code, js = self.call("/api/report/%s.json" % data["id"])
        self.assertEqual(json.loads(js)["id"], data["id"])

    def test_zip_scan(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("proj/app.py", "KEY = '%s'\n" % FAKE_AWS)
        code, body = self.call("/api/scan-zip?name=proj.zip", buf.getvalue(), ctype="application/zip")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["findings"][0]["file"], "app.py")

    def test_live_requires_phrase(self):
        code, body = self.call("/api/scan", {"source": self.dir, "live": {"url": "http://127.0.0.1:1", "phrase": "yes"}})
        self.assertEqual(code, 400)
        self.assertIn("I OWN THIS", json.loads(body)["error"])

    def test_live_refuses_public_host(self):
        code, _ = self.call("/api/scan", {"source": self.dir, "live": {"url": "http://example.com", "phrase": "I OWN THIS"}})
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
