from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .intake import parse_repo_url
from .fetcher import fetch_repo, FetchError

p=argparse.ArgumentParser()
p.add_argument('--repo-url',required=True)
p.add_argument('--workspace',type=Path,required=True)
a=p.parse_args()
try:
    target=parse_repo_url(a.repo_url)
    r=fetch_repo(target,a.workspace)
    print(json.dumps({'repo_url':r.repo_url,'commit_sha':r.commit_sha,'root':str(r.root),'ref':r.metadata.get('ref')}))
except Exception as e:
    print(f'FETCH_FAILED: {e}',file=sys.stderr)
    raise SystemExit(2)
