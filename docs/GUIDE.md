# CipherBloom Guardian: Complete User Guide

This guide covers everything from installing to fixing every kind of finding. You don't need security experience to follow it.

**Contents**

1. [What it is and what it does](#1-what-it-is-and-what-it-does)
2. [Pros and benefits](#2-pros-and-benefits)
3. [Install](#3-install)
4. [Your first scan](#4-your-first-scan)
5. [Three ways to give it your project](#5-three-ways-to-give-it-your-project)
6. [Using the dashboard](#6-using-the-dashboard)
7. [The live check (localhost only)](#7-the-live-check-localhost-only)
8. [Reading the results](#8-reading-the-results)
9. [How to fix each kind of finding](#9-how-to-fix-each-kind-of-finding)
10. [I leaked a key. What now?](#10-i-leaked-a-key-what-now)
11. [Stop leaks automatically (pre-commit hook)](#11-stop-leaks-automatically-pre-commit-hook)
12. [Use it in CI / GitHub Actions](#12-use-it-in-ci--github-actions)
13. [Reports, exit codes and ignoring lines](#13-reports-exit-codes-and-ignoring-lines)
14. [Privacy and safety](#14-privacy-and-safety)
15. [Limitations](#15-limitations)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. What it is and what it does

CipherBloom Guardian is a security checker for your projects. You point it at your code, and it tells you:

- **What is wrong** (for example: "Telegram bot token found in code")
- **Where it is** (the file and the line number, like `bot.py:12`)
- **Why it matters** (in plain words, such as who could abuse it and how)
- **How to fix it** (the exact command or code change)

It runs six groups of checks:

| Group | In one sentence |
|---|---|
| Secrets | Finds API keys, tokens, passwords and private keys written into your code or config. |
| .env & git | Makes sure your `.env` is ignored, not committed, and not hiding in old git history. |
| Risky code | Spots code patterns attackers love: `eval`, `shell=True`, SQL injection, debug mode, open CORS. |
| Syntax | Finds Python, JSON and JavaScript syntax errors so the project actually runs. |
| Dependencies | Warns about unpinned or wildcard versions and missing lock files. |
| Live check | With your permission, checks your running localhost app for files and settings that anyone could abuse. |

**It needs no AI and no API key.** Every check is a rule (a pattern or a parser) written in plain Python, so it is free, private, fast and gives the same answer every time.

## 2. Pros and benefits

- **Saves real money.** A leaked cloud or AI key can be abused within minutes and run up a large bill. Catching it before the push costs nothing.
- **Protects your users.** Exposed database passwords, debug consoles and downloadable `.env` files can leak user data.
- **Beginner friendly.** Every finding includes a "why" and a "fix", so you learn while you fix.
- **Private by design.** Nothing leaves your computer. No account, no telemetry, no upload.
- **Zero setup.** Pure Python standard library: no `pip install` chain, no Docker, no config file.
- **Works everywhere.** Windows, macOS, Linux, Termux; Python 3.9 or newer.
- **Fits your workflow.** Terminal, visual dashboard, git pre-commit hook and GitHub Actions.
- **Ethical by default.** It can never be pointed at someone else's website.
- **Shareable reports.** Secret values are masked, so you can send a report to a teammate safely.

## 3. Install

You need **Python 3.9+**. Check with `python --version` (or `python3 --version`).

**Option A: install the command (recommended)**

```bash
pip install git+https://github.com/dev-shubh-madara/project-protector
cipherbloom --version
```

**Option B: run from a clone, no install**

```bash
git clone https://github.com/dev-shubh-madara/project-protector
cd project-protector
python -m cipherbloom --version
```

Optional extras (only if you want them):

- **Node.js** lets CipherBloom check JavaScript files for syntax errors.
- **git** enables the git and history checks, and scanning repo links.
- **pip-audit** / **npm** enable known-vulnerability lookups with `--audit` (this one uses the internet).

> On Windows, if `cipherbloom` is "not recognized", use `python -m cipherbloom` instead, or add Python's `Scripts` folder to your PATH.

## 4. Your first scan

Go to your project folder and run:

```bash
cipherbloom scan .
```

You'll see each finding with a colored severity tag, the location, why it matters and how to fix it, then a summary and a health score. Fix the **CRITICAL** and **HIGH** items first.

Save a report you can open in a browser:

```bash
cipherbloom scan . --html report.html
```

## 5. Three ways to give it your project

| You have... | Command | Notes |
|---|---|---|
| A folder on your computer | `cipherbloom scan C:\path\to\project` | Fastest. Includes git checks if it is a repo. |
| A `.zip` of the code | `cipherbloom scan project.zip` | Extracted to a temp folder with zip-slip protection, deleted afterwards. |
| A public repo link | `cipherbloom scan https://github.com/owner/repo` | Needs git. Downloads the last 50 commits so history checks work. |

The code is **never executed**, whichever way you choose.

## 6. Using the dashboard

```bash
cipherbloom ui
```

Your browser opens `http://127.0.0.1:7878`. (Use `--port 7879` if that port is busy, or `--no-open` to open it yourself.)

1. **Choose the source:** *Folder path*, *Upload .zip* (drag and drop works) or *Public repo*.
2. **Pick checks:** everything is on by default. Untick what you don't need.
3. **Optional live check:** switch it on, enter your app's address (like `http://127.0.0.1:8000`) and type `I OWN THIS`.
4. Click **Start protection scan** (or press **Ctrl + Enter**).
5. **Read the results:**
   - The **health ring** shows the score and a grade.
   - Click a **severity tile** (Critical, High...) to show only those findings.
   - Use the **search box** to filter by file name, rule or text.
   - Click a finding to expand **Where / Found / Why / How to fix**, then use **Copy fix** or **Copy location**.
   - Download the **HTML** or **JSON** report.

Stop the dashboard with **Ctrl + C** in the terminal.

## 7. The live check (localhost only)

Some problems only show up when the app is running, for example a web server that lets anyone download your `.env`. The live check finds those.

**How to use it**

1. Start **your own** app as you normally would (for example `uvicorn main:app --port 8000`, `npm run dev` or `python bot_api.py`).
2. Run:

   ```bash
   cipherbloom scan . --live http://127.0.0.1:8000
   ```

3. Read the consent screen and type `I OWN THIS`.

**What it does:** about 25 ordinary read-only GET requests that look for downloadable `.env`, `.git`, backup and database files, CORS that trusts any website, missing security headers, stack traces on error pages, an exposed Werkzeug console, directory listings, and weak cookie flags.

**What it never does:** send attack payloads, flood the server, guess passwords, change or delete data, or contact any address other than the one you gave.

**Why localhost only?** Testing a server you don't own can be illegal. CipherBloom refuses any address that does not resolve to `127.0.0.1` / `::1`, so it can't be misused against someone else's site.

For live findings, CipherBloom also points to the most likely place in your code (for example the line where CORS or static files are configured). This is a best guess, so double-check it.

## 8. Reading the results

**Severity levels**

| Level | Meaning | Act |
|---|---|---|
| CRITICAL | A working secret is exposed, or anyone can run code or read secrets. | Right now. Rotate keys first. |
| HIGH | Very likely to be abused, or the project can't run. | Today. |
| MEDIUM | A real weakness, but it needs extra conditions to exploit. | This week. |
| LOW | Good hygiene, such as pinning versions or adding headers. | When you can. |
| INFO | Worth knowing, such as API docs being public. | Decide for yourself. |

**Health score:** starts at 100 and drops by 25 per critical, 12 per high, 5 per medium and 2 per low finding. It is a quick indicator, not a guarantee of safety.

## 9. How to fix each kind of finding

| Rule | Fix |
|---|---|
| `aws-access-key`, `github-token`, `telegram-bot-token`, `stripe-live-key`, `slack-token`, `discord-token`, `google-api-key`, `openai-style-key` | **Revoke the key** in that provider's dashboard and create a new one. Put the new value in `.env` and read it with `os.environ["NAME"]` (Python) or `process.env.NAME` (Node). |
| `private-key` | Generate a new key pair, replace the old public key wherever it is trusted, delete the old one. |
| `db-url-password` | Change the database password, then read the URL from an env variable. |
| `hardcoded-secret` | Move the value to `.env`. If it's a harmless test value, add `# cipherbloom:ignore`. |
| `env-file-secret` | Normal for a local `.env`. Just make sure it's git-ignored and never shared or zipped. |
| `env-not-ignored` | Add `.env` to `.gitignore`. |
| `env-tracked` | `git rm --cached .env`, commit, then **rotate every key in it**. |
| `env-in-history` | Rotate every key that was in it. To purge history: `git filter-repo --path .env --invert-paths`, then force-push. |
| `env-example-missing` | Create `.env.example` with every variable name and a fake value. |
| `py-eval`, `py-exec`, `js-eval` | Don't run text as code. Use `json.loads` / `ast.literal_eval`, or a dictionary of allowed functions. |
| `py-shell-true`, `py-os-system`, `js-child-process-exec` | Pass commands as a list: `subprocess.run(["git", "status"])`. Never build commands from user input. |
| `py-sql-format` | Use placeholders: `cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))`. |
| `py-pickle-load` | Use JSON for any data that could come from outside. |
| `py-yaml-load` | Use `yaml.safe_load(...)`. |
| `py-debug-true` | `debug = os.environ.get("DEBUG") == "1"`, and keep it off in production. |
| `py-verify-false` | Remove `verify=False` and fix the certificate problem. |
| `py-cors-wildcard`, `js-cors-wildcard`, `cors-wildcard`, `cors-reflect-credentials` | List only your own domains, e.g. `allow_origins=["https://yourapp.com"]`. |
| `js-innerhtml` | Use `textContent`, or sanitize HTML first. |
| `py-syntax`, `json-syntax`, `js-syntax` | Open the file at the line shown. Also check the line above, where a missing bracket or quote often is. |
| `unpinned-dependency` | `pip freeze > requirements.txt`, or write `package==1.2.3`. |
| `wildcard-dependency`, `no-lockfile` | Use real version ranges (`^1.2.3`) and commit `package-lock.json`. |
| `known-vulnerability` | Upgrade to the fixed version shown. |
| `exposed-file`, `directory-listing` | Serve only a dedicated `public/` or `static/` folder, never the project root. Rotate anything that was exposed. |
| `missing-security-headers` | Express: `app.use(helmet())`. Flask: `flask-talisman`. FastAPI: a small middleware that sets the headers. |
| `version-disclosure` | Express: `app.disable("x-powered-by")`. Uvicorn: `--no-server-header`. |
| `debug-page`, `werkzeug-console` | Turn debug off and return plain error pages. |
| `weak-cookie` | Set `HttpOnly`, `SameSite=Lax` and `Secure` (when on HTTPS). |
| `api-docs-public` | Fine in development. In production: `FastAPI(docs_url=None, openapi_url=None)` or put it behind login. |

## 10. I leaked a key. What now?

Do it in this order:

1. **Revoke or rotate the key immediately** in the provider's dashboard. Deleting the file is not enough, because it may already have been copied.
2. **Check the provider's usage and billing page** for anything you didn't do.
3. **Move the new key into `.env`**, make sure `.env` is in `.gitignore`, and read it from the environment.
4. **Clean the git history** if it was ever committed (`git filter-repo`), then force-push.
5. **Run `cipherbloom scan .` again** until it's clean, and install the pre-commit hook so it doesn't happen again.

Quick links: [GitHub tokens](https://github.com/settings/tokens) · Telegram: message `@BotFather` and send `/revoke` · [AWS IAM](https://console.aws.amazon.com/iam/) · [Google Cloud credentials](https://console.cloud.google.com/apis/credentials) · [Stripe API keys](https://dashboard.stripe.com/apikeys) · [Discord developer portal](https://discord.com/developers/applications)

## 11. Stop leaks automatically (pre-commit hook)

```bash
cd your-project
cipherbloom hook install
```

Now every `git commit` checks the staged files for secrets first, and blocks the commit if it finds one. Remove it with `cipherbloom hook uninstall`. (CipherBloom won't overwrite an existing hook that isn't its own.)

## 12. Use it in CI / GitHub Actions

Add `.github/workflows/security.yml` to your project:

```yaml
name: Security
on: [push, pull_request]
jobs:
  guardian:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: dev-shubh-madara/project-protector@main
        with:
          path: .
          fail-on: high
```

The job fails if there is a HIGH or CRITICAL finding, and the HTML report is attached to the run as an artifact.

Other CI systems: `pip install git+https://github.com/dev-shubh-madara/project-protector` and run `cipherbloom scan . --fail-on high --no-color`.

## 13. Reports, exit codes and ignoring lines

- `--html report.html` writes the animated, self-contained HTML report (works offline).
- `--json report.json` writes machine-readable output for your own tools.
- **Exit codes:** `0` = finished, `1` = findings at/above `--fail-on`, `2` = bad input (wrong path, non-localhost live target...).
- **Ignore a line:** add `# cipherbloom:ignore` (or `// cipherbloom:ignore`) at the end of it.
- **Ignore a whole file:** put `# cipherbloom:ignore-file` in its first 5 lines (secret and risky-code checks skip it). Use this sparingly, for example for test fixtures.
- Folders such as `node_modules`, `.git`, `venv`, `dist` and `build`, plus binary files and lock files, are skipped automatically.

## 14. Privacy and safety

- Nothing is sent to any server. There is no AI, telemetry or account.
- `--audit` is the only option that uses the internet (it runs `pip-audit` / `npm audit`), and it's off by default.
- Scanning a repo link downloads it with `git`. Everything else is local.
- Code is read as text and **never executed**. Zips are checked for path-escape tricks and size before extracting.
- The dashboard listens on `127.0.0.1` only, checks the `Host` header, rejects other websites, and requires a per-launch token.
- Secret values are masked in every output.

## 15. Limitations

- It finds the **most common** mistakes, not every possible vulnerability. A clean result is not proof that a project is secure.
- Rules are pattern based, so there can be false positives (ignore them per line) and false negatives (please report them).
- Risky-code rules cover Python and JavaScript/TypeScript for now.
- The live check is intentionally gentle and localhost-only. It's not a full penetration test.

## 16. Troubleshooting

| Problem | Fix |
|---|---|
| `cipherbloom: command not found` | Use `python -m cipherbloom ...`, or add Python's Scripts/bin folder to PATH. |
| "Could not connect to http://127.0.0.1:8000" | Start your app first, and check the port. |
| "Refusing to test ..." | The live check only accepts localhost addresses. This is intentional. |
| Dashboard port busy | `cipherbloom ui --port 7879` |
| Dashboard says "wrong session token" | You restarted `cipherbloom ui`. Reload the page. |
| Repo link fails | It must be a public https GitHub/GitLab/Bitbucket link, and git must be installed. Otherwise download the zip and scan that. |
| JS syntax isn't checked | Install Node.js. |
| Too many "unpinned dependency" findings | Run `pip freeze > requirements.txt` once. |

Still stuck? [Open an issue](https://github.com/dev-shubh-madara/project-protector/issues) with the command you ran and the output (secrets are already masked).
