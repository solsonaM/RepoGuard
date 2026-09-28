from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse
import ipaddress
import re

@dataclass(frozen=True)
class RepoTarget:
    owner: str
    repo: str
    ref: str | None
    canonical_url: str

class IntakeError(ValueError):
    pass

OWNER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
REF_RE = re.compile(r"^[A-Za-z0-9._/@-]{1,200}$")

def parse_repo_url(value: str) -> RepoTarget:
    if not isinstance(value, str) or not value.strip():
        raise IntakeError("URL is empty")
    raw = value.strip()
    if len(raw) > 500:
        raise IntakeError("URL is too long")
    parsed = urlparse(raw)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.port is not None:
        raise IntakeError("Only https://github.com/<owner>/<repo> URLs are accepted")
    if parsed.username or parsed.password:
        raise IntakeError("Userinfo in URL is not allowed")
    try:
        ipaddress.ip_address(parsed.hostname)
        raise IntakeError("IP addresses are not allowed")
    except ValueError:
        pass
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) not in (2, 4) or (len(parts) == 4 and parts[2] != "tree"):
        raise IntakeError("Use https://github.com/<owner>/<repo> or /tree/<ref>")
    owner, repo = parts[:2]
    repo = repo.removesuffix(".git")
    if not OWNER_RE.fullmatch(owner) or not REPO_RE.fullmatch(repo):
        raise IntakeError("Invalid owner or repository name")
    ref = parts[3] if len(parts) == 4 else None
    if ref is not None and not REF_RE.fullmatch(ref):
        raise IntakeError("Invalid branch/tag reference")
    if parsed.query or parsed.fragment:
        raise IntakeError("Query strings and fragments are not allowed")
    canonical = f"https://github.com/{owner}/{repo}" + (f"/tree/{ref}" if ref else "")
    return RepoTarget(owner, repo, ref, canonical)
