from __future__ import annotations
import argparse, json, os, sys, tempfile
from pathlib import Path
from .intake import parse_repo_url, IntakeError
from .scanner import analyze_tree
from .verdict import build_report

def main() -> int:
    ap=argparse.ArgumentParser(description="RepoGuard scanner")
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--commit-sha", required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--rules", type=Path, default=Path("rules"))
    ap.add_argument("--mode", default="hosted-static-analysis")
    ap.add_argument("--threshold", choices=["low","medium","high","critical"], default="medium")
    ap.add_argument("--with-external", action="store_true")
    ap.add_argument("--reputation-json", default="{}")
    args=ap.parse_args()
    try:
        parse_repo_url(args.repo_url)
        with tempfile.TemporaryDirectory(prefix="repoguard-") as scratch:
            analysis=analyze_tree(args.root,args.rules,threshold=args.threshold,include_external=args.with_external,strict_scanners=True,scratch=Path(scratch))
        try: reputation=json.loads(args.reputation_json)
        except Exception: reputation={"status":"error","reason":"invalid reputation input"}
        report=build_report(args.repo_url,args.commit_sha,args.mode,analysis,reputation=reputation,threshold=args.threshold)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2),encoding="utf-8")
        print(json.dumps({"verdict":report["verdict"],"files":report["files_total"],"output":str(args.output)}))
        return 0 if report["verdict"]=="APPROVED" else 2
    except IntakeError as exc:
        print(f"INVALID_URL: {exc}",file=sys.stderr); return 3

if __name__=="__main__": raise SystemExit(main())
