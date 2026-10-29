# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems in CipherBloom Guardian itself.

Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository. Include the version, steps to reproduce and the impact. You should get a reply within 7 days.

## Scope

In scope: anything that lets CipherBloom Guardian execute scanned code, write outside its temp folder, leak unmasked secrets in its output, reach non-localhost targets in the live check, or let another website control the local dashboard.

Out of scope: missed detections or false positives. Please open a normal issue for those.

## Supported versions

Only the latest release receives fixes.
