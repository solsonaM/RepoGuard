# RepoGuard Decisions

Free-tier choices:
- GitHub Pages for the static frontend.
- Cloudflare Workers Free and KV for the API and short-lived cache.
- GitHub Actions for hosted scanning.
- JSON reports committed to this repository to avoid a paid database.
- Hosted daily scan cap: 8 submissions per day.
- Per-IP daily cap: 2 submissions per day.
- Scanner expanded-size cap: 100 MiB.
- Maximum file count: 5,000.
- Maximum single extracted file: 10 MiB.
- Maximum compressed fetch archive: 50 MiB.
- Maximum archive compression ratio: 100:1.
- Maximum nested archive depth: 3.

Dependencies:
- Python standard library for core analysis.
- pytest 8.4.2 for tests.
- Semgrep OSS for static analysis.
- Gitleaks for secret scanning.
- YARA for static signatures.
- OSV-Scanner for dependency vulnerability data.
- Wrangler for Cloudflare deployment.
- No LLM API is used inside RepoGuard.

Security:
- Never execute, install, import, or build target repository code in hosted mode.
- Fail closed on scanner errors.
- Reject encrypted/protected files and opaque executable binaries without matching source.
- Reject unsafe archives rather than partially approving them.
- Redact detected secrets in stored findings.
- Reject redirects and non-GitHub URLs at intake.
- Keep target content out of Worker secrets and GitHub token fields.
- UI uses textContent to avoid repository-content XSS.

Token scope:
The Worker token is separate from scan-container execution and is scoped only to the RepoGuard repository with the minimum Actions and Contents permissions necessary to dispatch scans and read/write reports.

Workflow branch:
The repository was empty and the final deployment request is to publish the working tree on main. The hosted workflow therefore checks out and stores reports on main. No force pushes or history rewrites are used.

Optional VirusTotal:
VirusTotal is hash-only and optional. If VT_API_KEY is absent, RepoGuard continues without it. Files are never uploaded by the helper.

Outdated reports:
A report records the scan-time commit SHA. The Worker compares it with current HEAD whenever a report is requested. A mismatch sets outdated=true.
