from __future__ import annotations
import argparse, json
from datetime import datetime, timezone
from pathlib import Path


def build_failure_report(repo_url: str, commit_sha: str, output: Path, reason: str, scan_id: str) -> dict:
    report = {
        'product':'RepoGuard','schema_version':'1.0','scan_id':scan_id,'repo_url':repo_url,'commit_sha':commit_sha,
        'scanned_at':datetime.now(timezone.utc).isoformat(),'mode':'hosted-static-analysis','threshold':'medium','verdict':'REJECTED',
        'files_analyzed':0,'files_total':0,'all_files_analyzed':False,
        'checks':[{'check':'URL validation','status':'passed'},{'check':'Fetch/scanner orchestration','status':'error','detail':reason}],
        'file_results':[],
        'findings':[{'severity':'critical','file':'<scanner>','line':1,'snippet':reason[:500],'rule':'RG-ORCH-001','explanation':'The repository could not be fully fetched or scanned. The deny-by-default policy therefore rejects it.','source':'orchestrator'}],
        'rejection_reasons':[{'file':'<repository>','reason':reason}],
        'reputation':{'status':'not_available'},'sandbox':{'status':'not_run'},'outdated':False,
        'disclaimer':'No scanner can guarantee the absence of all threats. APPROVED means every file was analyzed and no threats were found by the listed checks.',
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--repo-url',required=True)
    p.add_argument('--commit-sha',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--reason',required=True)
    p.add_argument('--scan-id',required=True)
    a=p.parse_args()
    build_failure_report(a.repo_url,a.commit_sha,a.output,a.reason,a.scan_id)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
