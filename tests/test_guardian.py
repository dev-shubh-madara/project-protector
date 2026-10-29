import http.server
import json
import os
import shutil
import tempfile
import threading
import unittest
import zipfile

from cipherbloom.archive import SourceError, extract_zip
from cipherbloom.deps import check_dependencies
from cipherbloom.gitcheck import check_git_hygiene
from cipherbloom.live import run_live, validate_target
from cipherbloom.risky import scan_risky
from cipherbloom.secrets_scan import scan_secrets
from cipherbloom.syntaxcheck import check_syntax

# Fake secrets are assembled at runtime so this test file never contains a real-looking token.
FAKE_AWS = "AKIA" + "QWERTYUIOP123456"
FAKE_TG = "123456789" + ":" + "AAH" + "x9Zk2Lm4Qw8Rt6Yp1Vb3Nc5Xd7Fg0Hj2Kl4"[:32]
FAKE_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path


class SecretTests(Base):
    def test_finds_aws_key_with_line_number(self):
        self.write("app.py", "import os\n\nKEY = '%s'\n" % FAKE_AWS)
        f = scan_secrets(self.dir)
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0].file, f[0].line, f[0].rule), ("app.py", 3, "aws-access-key"))
        self.assertNotIn(FAKE_AWS, f[0].snippet)  # redacted

    def test_telegram_and_github_tokens(self):
        self.write("bot.py", "TOKEN='%s'\nGH='%s'\n" % (FAKE_TG, FAKE_GH))
        rules = {x.rule for x in scan_secrets(self.dir)}
        self.assertIn("telegram-bot-token", rules)
        self.assertIn("github-token", rules)

    def test_env_vars_and_placeholders_are_ignored(self):
        self.write("ok.py", "TOKEN = os.environ['TOKEN']\napi_key = 'your_api_key_here'\n")
        self.assertEqual(scan_secrets(self.dir), [])

    def test_env_example_not_flagged(self):
        self.write(".env.example", "API_KEY=changeme\nSECRET=xxxxxxxxxxxx\n")
        self.assertEqual(scan_secrets(self.dir), [])

    def test_env_file_secret(self):
        self.write(".env", "BOT_TOKEN=k9Zq2LmW8RtY6pVb3NcX7Fg\n")
        self.assertEqual(scan_secrets(self.dir)[0].rule, "env-file-secret")

    def test_ignore_file_marker(self):
        self.write("fixture.py", "# cipherbloom:ignore-file\nK='%s'\nx = eval(y)\n" % FAKE_AWS)
        self.assertEqual(scan_secrets(self.dir), [])
        self.assertEqual(scan_risky(self.dir), [])

    def test_inline_ignore(self):
        self.write("t.py", "K='%s'  # cipherbloom:ignore\n" % FAKE_AWS)
        self.assertEqual(scan_secrets(self.dir), [])


class GitTests(Base):
    def test_env_not_ignored(self):
        self.write(".env", "A=1\n")
        rules = {f.rule for f in check_git_hygiene(self.dir)}
        self.assertIn("env-not-ignored", rules)

    def test_env_ignored_is_clean(self):
        self.write(".env", "A=1\n")
        self.write(".gitignore", ".env\n")
        self.write(".env.example", "A=\n")
        self.assertEqual(check_git_hygiene(self.dir), [])


class SyntaxAndRiskTests(Base):
    def test_python_syntax_error_line(self):
        self.write("bad.py", "x = 1\nprint('hi'\ny = 2\n")
        f = check_syntax(self.dir)
        self.assertEqual(f[0].rule, "py-syntax")
        self.assertGreaterEqual(f[0].line, 2)

    def test_json_syntax_error(self):
        self.write("c.json", '{"a": 1,}')
        self.assertEqual(check_syntax(self.dir)[0].rule, "json-syntax")

    def test_valid_files_clean(self):
        self.write("a.py", "print('ok')\n")
        self.write("a.json", '{"a": 1}')
        self.assertEqual(check_syntax(self.dir), [])

    def test_risky_patterns(self):
        self.write("r.py", "import subprocess\nsubprocess.run(cmd, shell=True)\nx = eval(user)\n"
                           "cur.execute(f\"SELECT * FROM t WHERE id={uid}\")\n")
        rules = {f.rule for f in scan_risky(self.dir)}
        self.assertTrue({"py-shell-true", "py-eval", "py-sql-format"} <= rules)


class DepsTests(Base):
    def test_unpinned_and_wildcard(self):
        self.write("requirements.txt", "flask\nrequests==2.31.0\n# c\n")
        self.write("package.json", json.dumps({"dependencies": {"left-pad": "*"}}))
        rules = {f.rule for f in check_dependencies(self.dir)}
        self.assertTrue({"unpinned-dependency", "wildcard-dependency", "no-lockfile"} <= rules)


class ArchiveTests(Base):
    def test_zip_slip_blocked(self):
        z = os.path.join(self.dir, "evil.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("../../escape.txt", "x")
        with self.assertRaises(SourceError):
            extract_zip(z)

    def test_zip_ok(self):
        z = os.path.join(self.dir, "ok.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("proj/a.py", "print(1)")
        root, tmp = extract_zip(z)
        self.assertTrue(os.path.isfile(os.path.join(root, "a.py")))
        shutil.rmtree(tmp)


class LiveTests(Base):
    def test_refuses_non_localhost(self):
        with self.assertRaises(ValueError):
            validate_target("http://example.com")

    def test_live_detects_exposed_env_and_cors(self):
        self.write(".env", "SECRET_KEY=abc123def456\n")
        self.write("app.py", "from fastapi import FastAPI\napp = FastAPI()\nallow_origins=['*']\n")
        root = self.dir

        class H(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=root, **k)

            def end_headers(self):
                self.send_header("Access-Control-Allow-Origin", "*")
                super().end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            findings, note = run_live("http://127.0.0.1:%d" % srv.server_address[1], self.dir)
        finally:
            srv.shutdown()
            srv.server_close()
        rules = {f.rule for f in findings}
        self.assertIn("exposed-file", rules)
        self.assertIn("cors-wildcard", rules)
        self.assertIn("missing-security-headers", rules)


if __name__ == "__main__":
    unittest.main()
