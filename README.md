# security-workflows

Generated mirror. Do not edit here: the source lives in the private repo
`flow-84/cyber-security` (`.github/workflows/security-scan.yml`, `scripts/github/`)
and is published by `scripts/github/publish-workflows.sh`.

Reusable GitHub Actions workflow that scans a repository with

- Betterleaks (secrets, full git history)
- Trivy fs (dependency vulnerabilities, IaC and config misconfigurations)
- Trivy image (every Dockerfile is built and scanned)
- OSV-Scanner (advisories for all lockfiles)
- Opengrep (SAST with the pinned community rules)

The job fails on any secret and on HIGH or CRITICAL findings, and uploads all
results as SARIF to code scanning. Scanner binaries are pinned and verified
against SHA-256 sums in `scripts/github/tools.env`.

Use it with `scripts/github/caller.yml` as `.github/workflows/security-scan.yml`.
This repo scans itself with the same workflow (push, pull request, daily, manual).
Local run: `scripts/github/install-tools.sh <bin>` then `scripts/github/scan.sh <repo> <out>`.

Licenses: scripts MIT-compatible, scanners Apache-2.0 / MIT / LGPL-2.1. The
Opengrep community rules are under the Commons Clause and used here only to
scan our own repositories.
