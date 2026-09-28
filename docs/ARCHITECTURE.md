# RepoGuard Architecture

Components:
1. GitHub Pages serves the static frontend.
2. Cloudflare Worker validates URLs, applies per-IP and daily caps, resolves the exact commit SHA, queries public GitHub reputation signals, and dispatches the scan workflow with a repo-scoped token stored only as a Worker secret.
3. GitHub Actions is the hosted scan orchestrator.
4. The fetcher uses GitHub API/codeload data only and verifies the expected commit SHA.
5. The scanner container has no network access during analysis.
6. Reports are JSON files committed to the RepoGuard repository and can also be cached in Cloudflare KV.
7. Local Docker mode adds an optional behavior test using a networkless, read-only container with tracing.

Trust boundaries:
- Untrusted boundary: every byte from the submitted repository.
- Worker boundary: accepts only a constrained GitHub URL and never executes target code.
- Workflow boundary: downloads target bytes as data; target code is never checked out as executable source.
- Scanner boundary: target files are mounted read-only into a network-disabled container and no secrets are provided.
- Report/UI boundary: repository-derived values are inserted with DOM textContent rather than HTML interpolation.

Two-verdict design:
APPROVED means 100% of files were analyzed, required scanners succeeded, and no findings met the configured threshold.
REJECTED means any flagged file, unanalyzable file, limit breach, scanner error/timeout, fetch failure, or failed local behavior test.

A scan never returns an unknown state.

Individual file states:
- Analyzed - clean
- Analyzed - flagged
- Rejected - unanalyzable (reason)

Hosted mode is static analysis only. It never executes target setup/install commands.

Local mode can optionally run declared install/setup commands inside the isolated, networkless behavior-test container. Sensitive-path reads, network connection attempts, denied writes, or a non-zero setup result cause rejection.

The Worker records the exact target commit SHA before dispatching Actions. The workflow confirms the fetched bytes resolve to that SHA. The report page compares the report SHA with current target HEAD and marks the report outdated when they differ.
