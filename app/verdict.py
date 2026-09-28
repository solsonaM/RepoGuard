from __future__ import annotations
from datetime import datetime, timezone

def build_report(repo_url: str, commit_sha: str, mode: str, analysis: dict, reputation: dict | None=None, sandbox: dict | None=None, threshold: str="medium") -> dict:
    results=analysis["file_results"]
    rejected=[r for r in results if r["status"].startswith("Rejected")]
    flagged=[r for r in results if r["status"]=="Analyzed - flagged"]
    analyzed_count=sum(1 for r in results if r["status"].startswith("Analyzed"))
    n=analyzed_count
    total=len(results)
    scanner_errors=[c for c in analysis["checks"] if c.get("status")=="error"]
    analysis_errors=analysis.get("analysis_errors",[])
    if rejected or flagged or n != total or scanner_errors or analysis_errors:
        verdict="REJECTED"
    else:
        verdict="APPROVED"
    reasons=[]
    for r in rejected:
        reasons.append({"file":r["path"],"reason":r["reason"] or "unanalyzable"})
    for r in flagged:
        reasons.append({"file":r["path"],"reason":"one or more findings met the configured threshold"})
    for c in scanner_errors:
        reasons.append({"file":"<scanner>","reason":c.get("detail","scanner error")})
    for e in analysis_errors:
        reasons.append({"file":"<repository>","reason":e})
    if sandbox and sandbox.get("passed") is False:
        verdict="REJECTED"; reasons.append({"file":"<sandbox>","reason":sandbox.get("reason","behavior test failed")})
    return {
        "product":"RepoGuard",
        "schema_version":"1.0",
        "repo_url":repo_url,
        "commit_sha":commit_sha,
        "scanned_at":datetime.now(timezone.utc).isoformat(),
        "mode":mode,
        "threshold":threshold,
        "verdict":verdict,
        "files_analyzed":n,
        "files_total":total,
        "all_files_analyzed": n == total and not rejected,
        "checks":analysis["checks"],
        "file_results":results,
        "findings":analysis["findings"],
        "rejection_reasons":reasons,
        "reputation":reputation or {"status":"not_run"},
        "sandbox":sandbox or {"status":"not_run"},
        "outdated":False,
        "disclaimer":"No scanner can guarantee the absence of all threats. APPROVED means every file was analyzed and no threats were found by the listed checks.",
        "duration_seconds":analysis["duration_seconds"],
    }
