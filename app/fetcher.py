from __future__ import annotations
import json, os, shutil, tempfile, urllib.error, urllib.parse, urllib.request
from dataclasses import dataclass
from pathlib import Path
from .intake import RepoTarget
from .safe_extract import extract_archive, UnsafeArchiveError, MAX_EXPANDED, MAX_FILES, MAX_SINGLE, MAX_RATIO

MAX_COMPRESSED=50*1024*1024
FETCH_TIMEOUT=30

class FetchError(RuntimeError):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FetchError(f"redirect rejected: {newurl}")

@dataclass
class FetchResult:
    repo_url: str
    commit_sha: str
    root: Path
    metadata: dict

def _get_json(url: str, timeout: int=FETCH_TIMEOUT) -> dict:
    req=urllib.request.Request(url,headers={"Accept":"application/vnd.github+json","User-Agent":"RepoGuard/1.0"})
    opener=urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req,timeout=timeout) as r:
            if r.geturl()!=url: raise FetchError("redirect rejected")
            data=r.read(2*1024*1024+1)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"GitHub API HTTP {exc.code}") from exc
    if len(data)>2*1024*1024: raise FetchError("GitHub API response too large")
    try: return json.loads(data.decode("utf-8"))
    except Exception as exc: raise FetchError("GitHub API returned invalid JSON") from exc

def _resolve_sha(target: RepoTarget) -> tuple[str,dict]:
    base=f"https://api.github.com/repos/{urllib.parse.quote(target.owner)}/{urllib.parse.quote(target.repo)}"
    repo=_get_json(base)
    ref=target.ref or repo.get("default_branch")
    if not ref: raise FetchError("repository has no default branch")
    commit=_get_json(f"{base}/commits/{urllib.parse.quote(ref,safe='')}")
    sha=commit.get("sha")
    if not isinstance(sha,str) or not re.fullmatch(r"[0-9a-fA-F]{40}",sha):
        raise FetchError("GitHub did not return a full commit SHA")
    return sha,{"repo":repo,"ref":ref,"commit":commit}

import re

def _download_zip(owner: str, repo: str, sha: str, path: Path) -> int:
    url=f"https://codeload.github.com/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/zip/{sha}"
    req=urllib.request.Request(url,headers={"User-Agent":"RepoGuard/1.0"})
    opener=urllib.request.build_opener(NoRedirect)
    total=0
    try:
        with opener.open(req,timeout=FETCH_TIMEOUT) as r, path.open("wb") as out:
            if r.geturl()!=url: raise FetchError("unexpected download redirect")
            while True:
                chunk=r.read(1024*1024)
                if not chunk: break
                total += len(chunk)
                if total>MAX_COMPRESSED: raise FetchError(f"compressed archive exceeds {MAX_COMPRESSED} bytes")
                out.write(chunk)
    except urllib.error.HTTPError as exc: raise FetchError(f"codeload HTTP {exc.code}") from exc
    return total

def fetch_repo(target: RepoTarget, workspace: Path) -> FetchResult:
    workspace.mkdir(parents=True,exist_ok=True)
    sha, meta=_resolve_sha(target)
    archive=workspace/"repo.zip"; _download_zip(target.owner,target.repo,sha,archive)
    extracted=workspace/"extracted"
    try:
        extract_archive(archive,extracted,0)
    except Exception as exc:
        raise FetchError(str(exc)) from exc
    # GitHub zipballs contain a single top-level directory. Collapse it.
    dirs=[p for p in extracted.iterdir() if p.is_dir()]
    if len(dirs)==1:
        root=workspace/"repo"
        if root.exists(): shutil.rmtree(root)
        dirs[0].rename(root)
        shutil.rmtree(extracted,ignore_errors=True)
    else:
        root=extracted
    (workspace/"metadata.json").write_text(json.dumps({"repo_url":target.canonical_url,"commit_sha":sha,"ref":meta["ref"]},indent=2),encoding="utf-8")
    return FetchResult(target.canonical_url,sha,root,meta)
