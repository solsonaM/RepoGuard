#!/usr/bin/env bash
set -euo pipefail
URL=\${1:?usage: scripts/local_scan.sh https://github.com/owner/repo}
WORK="\${2:-local-work/manual}"
rm -rf "$WORK"
mkdir -p "$WORK" "$WORK/osv-cache"
docker build --pull -t repoguard-scanner:local .
python -m app.host_fetch --repo-url "$URL" --workspace "$WORK" | tee "$WORK/fetch.json"
SHA=$(python - <<PY
import json
print(json.load(open('$WORK/fetch.json'))['commit_sha'])
PY
)
mkdir -p "$WORK/report"
set +e
docker run --rm --network none \
  -v "$(pwd)/$WORK/repo:/input:ro" \
  -v "$(pwd)/$WORK/report:/output" \
  -v "$(pwd)/rules:/rules:ro" \
  repoguard-scanner:local \
  --root /input --repo-url "$URL" --commit-sha "$SHA" --output /output/report.json --rules /rules --mode local-static-analysis --threshold medium --with-external
STATUS=$?
set -e
cat "$WORK/report/report.json"
[ "$STATUS" -eq 0 ] || [ "$STATUS" -eq 2 ]
