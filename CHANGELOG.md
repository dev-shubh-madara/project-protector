# Changelog

## 0.1.0 - 2026-10-29

First public release.

- Secret detection for AWS, GitHub, Telegram, Slack, Stripe, Discord, Google and AI-provider keys, private keys, DB URLs and high-entropy hard-coded secrets, with masked output
- `.env` hygiene: not ignored, tracked by git, present in git history, missing `.env.example`
- Risky-code rules for Python and JavaScript/TypeScript
- Python, JSON and JavaScript syntax checks with line numbers
- Dependency hygiene, plus optional `pip-audit` / `npm audit`
- Consent-gated, read-only, localhost-only live check
- Scan a folder, a `.zip` or a public repo link
- Glassmorphic localhost dashboard (`cipherbloom ui`) with token and Host-header protection
- Animated HTML and JSON reports
- Git pre-commit hook and GitHub Action
