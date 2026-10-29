# Contributing to CipherBloom Guardian

Thanks for helping developers keep their secrets safe. Small, focused pull requests are the easiest to review.

## Ground rules

- **No new runtime dependencies.** The tool must keep working with only the Python standard library.
- **No AI calls or network calls by default.** Anything that needs the internet must be opt-in (like `--audit`).
- **Read code, never run it.** Scanners must treat project files as text.
- **Live checks stay harmless and localhost-only.** No attack payloads, brute force, flooding or writes.
- **Every finding needs a plain-language `why` and an actionable `fix`.**

## Setup

```bash
git clone https://github.com/dev-shubh-madara/project-protector
cd project-protector
python -m unittest discover -s tests -v
python -m cipherbloom scan .
python -m cipherbloom ui
```

## Add a new secret pattern (about 10 lines)

1. Open `cipherbloom/secrets_scan.py` and add a tuple to `PATTERNS`:

   ```python
   ("twilio-api-key", "Twilio API key",
    re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "critical",
    "Delete the key in the Twilio console and create a new one."),
   ```

2. Add a test in `tests/test_guardian.py`. Build the fake token from pieces (`"SK" + "0" * 32`) so the test file itself never contains a realistic secret.
3. Run the tests and open a pull request.

## Add a risky-code rule

Add an entry to `RULES` in `cipherbloom/risky.py` with the rule id, severity, title, file extensions, regex, `why` and `fix`, plus a test.

## Add a live probe

Add a probe to `PROBES` in `cipherbloom/live.py`. Probes must be plain GET requests with a validator that confirms the issue (to avoid false alarms). Add a test that runs against a tiny local `http.server`.

## Good first issues

Look for the `good first issue` label: new provider patterns, better fix text, docs translations and false-positive reports are all great starting points.

## Commit and PR checklist

- [ ] Tests pass: `python -m unittest discover -s tests`
- [ ] `python -m cipherbloom scan . --fail-on high` is clean
- [ ] New findings include `why` and `fix`
- [ ] README/GUIDE updated if behavior changed
