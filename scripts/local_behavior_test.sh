#!/usr/bin/env bash
set -euo pipefail

REPO=\${1:?usage: scripts/local_behavior_test.sh /path/to/repo}
REPO=$(cd "$REPO" && pwd)
OUT=\${2:-local-work/behavior}
mkdir -p "$OUT"
rm -f "$OUT/trace.log" "$OUT/result.json"

cat > "$OUT/runner.sh" <<'INNER'
#!/usr/bin/env bash
set +e
cd /work/repo
status=0
if [ -f package.json ]; then
  python - <<'PY'
import json, subprocess
from pathlib import Path
d=json.loads(Path('package.json').read_text())
for name in ('preinstall','install','postinstall','prepare'):
    cmd=(d.get('scripts') or {}).get(name)
    if cmd: subprocess.run(['/bin/sh','-lc',cmd])
PY
  [ $? -eq 0 ] || status=1
fi
if [ -f setup.py ]; then
  python setup.py --name >/dev/null 2>&1 || status=1
fi
printf '%s\n' "$status" > /work/result.status
exit "$status"
INNER
chmod +x "$OUT/runner.sh"

docker build --pull -t repoguard-scanner:local . >/dev/null
docker run --rm --network none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit 64 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
  -v "$REPO:/work/repo:ro" \
  -v "$(cd "$OUT" && pwd):/work:rw" \
  --entrypoint /usr/bin/strace repoguard-scanner:local \
  -ff -e trace=file,network,process -o /work/trace.log /bin/bash /work/runner.sh || true
STATUS=$(cat "$OUT/result.status" 2>/dev/null || echo 1)
NETWORK=$(grep -E "connect\(" "$OUT"/trace.log* 2>/dev/null || true)
SENSITIVE=$(grep -E "(/root/|/home/[^/]+/\.ssh|/etc/ssh|\.env|wallet|AWS_ACCESS_KEY|GITHUB_TOKEN)" "$OUT"/trace.log* 2>/dev/null || true)
OUTSIDE=$(grep -E "(O_WRONLY|O_RDWR|creat\()" "$OUT"/trace.log* 2>/dev/null | grep -vE "/work/repo|/work/behavior|/tmp" || true)
if [ -n "$NETWORK" ] || [ -n "$SENSITIVE" ] || [ -n "$OUTSIDE" ] || [ "$STATUS" -ne 0 ]; then
  cat > "$OUT/result.json" <<JSON
{"passed":false,"reason":"A declared setup/install step failed or attempted a denied behavior. Review the container trace/output manually."}
JSON
else
  cat > "$OUT/result.json" <<JSON
{"passed":true,"reason":"Declared local setup/install steps completed in a network-less container with no host credentials mounted."}
JSON
fi
cat "$OUT/result.json"
[ "$STATUS" -eq 0 ]
