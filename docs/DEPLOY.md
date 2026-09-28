# RepoGuard Deployment Guide

1. Cloudflare
Create a free Cloudflare account. Open Workers and Pages. Create a KV namespace named REPOGUARD_KV. Copy its namespace ID and replace REPLACE_AFTER_CREATING_KV in worker/wrangler.toml.

2. GitHub token
Create a fine-grained personal access token for only solsonaM/RepoGuard. Give it only the repository permissions required to trigger the scan workflow and read/write report contents. Do not create a classic token and do not grant account-wide repository access.

3. Worker secret
From the worker directory, authenticate Wrangler and run:
wrangler secret put GITHUB_REPO_TOKEN
Paste the token when requested.
Then run:
wrangler deploy

4. Frontend
Edit web/config.js and replace the default local API URL with the deployed Worker URL.

5. GitHub Pages
Open the repository Settings, then Pages, and select GitHub Actions as the deployment source. The included pages workflow publishes the web directory.

6. Test
Open the Worker URL followed by /health. You should receive JSON with status ok. Then submit a public GitHub repository URL through the RepoGuard web page.

Never put GITHUB_REPO_TOKEN, VT_API_KEY, Cloudflare credentials, or another secret into frontend JavaScript or the scanned repository.
