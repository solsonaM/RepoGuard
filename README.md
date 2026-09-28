# RepoGuard

RepoGuard is a zero-cost prototype that audits a public GitHub repository or AI-skill package before installation.

A submitted GitHub URL is resolved to an exact commit SHA. Repository bytes are fetched as data, analyzed without installing, importing, building, or executing target code, and assigned one final verdict: APPROVED or REJECTED.

No scanner can guarantee the absence of all threats.

Security model:
- Target repository content is treated as hostile input.
- Hosted scanning uses a network-disabled scanner container and provides it no API keys or platform secrets.
- URL intake only accepts HTTPS GitHub repository URLs with optional /tree/ref.
- Fetching rejects redirects, unsafe archive paths, symlinks, encrypted archive members, excessive compression ratios, excessive expanded size, excessive file count, and excessive single-file size.
- Every file gets one status: Analyzed - clean, Analyzed - flagged, or Rejected - unanalyzable (reason).
- Any flagged or unanalyzable file, scanner error, timeout, or exceeded limit causes REJECTED.
- Findings show path, line, snippet, rule, explanation, and scanner source.
- Reports are tied to the exact commit SHA and are marked outdated when the current target HEAD differs.
- Secrets are redacted before they are stored in reports.

Repository layout:
app/ Python intake, fetching, extraction, normalization, scanners, verdict
rules/ Semgrep, YARA, and Gitleaks rules
worker/ Cloudflare Worker API
web/ GitHub Pages static UI
.github/workflows/ hosted scan and Pages workflows
tests/ harmless security fixtures and automated tests
scripts/ local scan, behavior test, optional VirusTotal hash lookup
docs/ architecture, decisions, deployment, limits, testing
reports/ persisted JSON scan reports

Local run:
1. Install Docker, Docker Compose, Python 3.11+, and Git.
2. Create a virtual environment and run pip install -r requirements.txt.
3. Run pytest -q.
4. Run docker compose up --build.

Static local scan:
scripts/local_scan.sh https://github.com/owner/repo

Optional local-only behavior test:
scripts/local_behavior_test.sh /path/to/repository

Hosted deployment:
Create a free Cloudflare account, create KV, create a fine-grained repository-scoped GitHub token, store it as GITHUB_REPO_TOKEN in the Worker, set web/config.js to the Worker URL, and enable GitHub Pages using the included workflow. Exact steps are in docs/DEPLOY.md.

Free-tier design:
The prototype caps scans per day and per IP. It uses GitHub Actions, GitHub Pages, Cloudflare Workers/KV, open-source scanners, and standard-library Python. There are no paid APIs or required credit cards. Limits and decisions are recorded in docs/DECISIONS.md.

Testing:
pytest -q

Fixtures are harmless strings and generated binary/encrypted/archive samples only. No real malware is included.
