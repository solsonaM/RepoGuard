from __future__ import annotations
import json, urllib.parse, urllib.request

class ReputationError(RuntimeError): pass

def get_reputation(owner: str, repo: str, timeout: int=10) -> dict:
    base=f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"
    headers={"Accept":"application/vnd.github+json","User-Agent":"RepoGuard/1.0"}
    def get(url):
        req=urllib.request.Request(url,headers=headers)
        with urllib.request.urlopen(req,timeout=timeout) as r:
            if r.geturl()!=url: raise ReputationError("redirect in reputation request")
            return json.loads(r.read(2_000_000).decode())
    try:
        repo_obj=get(base)
        contrib=get(f"{base}/contributors?per_page=1&anon=true")
        commits=get(f"{base}/commits?per_page=30")
        dates=[]
        for c in commits:
            d=(c.get("commit") or {}).get("committer",{}).get("date")
            if d: dates.append(d)
        return {
            "status":"observed",
            "account_created_at":(repo_obj.get("owner") or {}).get("created_at"),
            "repo_created_at":repo_obj.get("created_at"),
            "stars":repo_obj.get("stargazers_count"),
            "forks":repo_obj.get("forks_count"),
            "contributors_observed_at_least":len(contrib),
            "recent_commit_count_sample":len(commits),
            "recent_commit_dates":dates,
            "watch_for_manual_review":["star-growth-spikes","recent-force-pushes/history-rewrites"],
        }
    except Exception as exc:
        return {"status":"error","reason":str(exc)}
