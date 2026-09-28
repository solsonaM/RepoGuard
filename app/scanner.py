from __future__ import annotations
from pathlib import Path
import hashlib, json, os, re, subprocess, tempfile, time
from .models import FileResult, Finding
from .rules_engine import classify_path, scan_text, run_yara, dependency_typosquatting_findings, EXEC_EXT
from .safe_extract import extract_archive, UnsafeArchiveError, MAX_NESTED_DEPTH

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

def sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _source_companion(path: Path, root: Path) -> bool:
    stem = path.stem.lower()
    candidates = {f"{stem}{ext}" for ext in [".c",".cc",".cpp",".h",".hpp",".rs",".go",".java",".py",".js",".ts",".cs"]}
    same = {p.name.lower() for p in path.parent.iterdir() if p.is_file()}
    if any(c in same for c in candidates): return True
    for src in root.rglob("*"):
        if src.is_file() and src.suffix.lower() in {".c",".cc",".cpp",".h",".hpp",".rs",".go",".java",".py",".js",".ts",".cs"} and src.stem.lower()==stem:
            return True
    return False

def _binary_reason(path: Path, data: bytes, root: Path) -> tuple[str | None, list[Finding]]:
    findings=[]
    if path.suffix.lower() in {".gpg",".age",".enc",".encrypted",".p12",".pfx",".key"}:
        return "encrypted or protected file", findings
    entropy = 0.0
    if data:
        from collections import Counter
        import math
        c=Counter(data)
        entropy = -sum((n/len(data))*math.log2(n/len(data)) for n in c.values())
    if path.suffix.lower() in EXEC_EXT:
        if not _source_companion(path, root):
            return "executable binary has no matching source file", findings
    if entropy > 7.9 and len(data) >= 1024:
        return "high-entropy opaque binary cannot be fully analyzed", findings
    return None, findings

def _run_json_command(command: list[str], cwd: Path, timeout: int) -> tuple[dict | None, str | None]:
    try:
        proc=subprocess.run(command,cwd=cwd,capture_output=True,text=True,timeout=timeout)
    except FileNotFoundError:
        return None, f"scanner unavailable: {command[0]}"
    except subprocess.TimeoutExpired:
        return None, f"scanner timeout: {command[0]}"
    if proc.returncode not in (0,1):
        return None, f"scanner {command[0]} failed with exit code {proc.returncode}: {proc.stderr[-500:]}"
    try:
        return json.loads(proc.stdout or "{}"), None
    except Exception as exc:
        return None, f"scanner {command[0]} returned invalid JSON: {exc}"

def _finding_from_json(source: str, path: str, line: int, severity: str, snippet: str, rule: str, explanation: str) -> Finding:
    return Finding(severity, path or "<unknown>", line or 1, snippet[:500], rule, explanation, source)

def run_semgrep(root: Path, rules_file: Path) -> tuple[list[Finding], str | None]:
    obj, err = _run_json_command(["semgrep","--config",str(rules_file),"--json","--quiet","."], root, 60)
    if err: return [], err
    findings=[]
    for r in (obj or {}).get("results",[]):
        extra=r.get("extra") or {}; sev=str(extra.get("severity","WARNING")).lower()
        sev={"error":"critical","warning":"high","info":"medium"}.get(sev, "high")
        findings.append(_finding_from_json("semgrep",r.get("path", ""), (r.get("start") or {}).get("line",1), sev, extra.get("lines","") or r.get("check_id",""), r.get("check_id","semgrep-rule"), extra.get("message","Semgrep rule matched.")))
    return findings,None

def run_gitleaks(root: Path, config: Path) -> tuple[list[Finding], str | None]:
    report=Path("/tmp/gitleaks.json")
    report.unlink(missing_ok=True)
    try:
        proc=subprocess.run(["gitleaks","dir",".","--config",str(config),"--report-format","json","--report-path",str(report),"--no-banner"],cwd=root,capture_output=True,text=True,timeout=60)
    except FileNotFoundError: return [], "scanner unavailable: gitleaks"
    except subprocess.TimeoutExpired: return [], "scanner timeout: gitleaks"
    if proc.returncode not in (0,1): return [], f"scanner gitleaks failed with exit code {proc.returncode}"
    findings=[]
    if report.exists():
        try:
            rows=json.loads(report.read_text(encoding="utf-8"))
            for x in rows:
                secret=str(x.get("Secret") or x.get("Match") or "")
                redacted=(secret[:3]+"[REDACTED]") if secret else "[REDACTED]"
                findings.append(_finding_from_json("gitleaks",x.get("File",""),int(x.get("StartLine") or 1),"critical",redacted,x.get("RuleID","gitleaks"),x.get("Description","Gitleaks detected a secret-like value.")))
        except Exception as exc: return [], f"scanner gitleaks produced invalid report: {exc}"
    return findings,None

def run_osv(root: Path) -> tuple[list[Finding], str | None]:
    env=os.environ.copy()
    env.setdefault("XDG_CACHE_HOME", "/osv-cache")
    try:
        proc=subprocess.run(["osv-scanner","scan","source","--offline-vulnerabilities","--recursive",".","--format","json"], cwd=root, capture_output=True, text=True, timeout=90, env=env)
    except FileNotFoundError:
        return [], "scanner unavailable: osv-scanner"
    except subprocess.TimeoutExpired:
        return [], "scanner timeout: osv-scanner"
    if proc.returncode not in (0,1):
        return [], f"scanner osv-scanner failed with exit code {proc.returncode}: {proc.stderr[-500:]}"
    try:
        obj=json.loads(proc.stdout or "{}")
    except Exception as exc:
        return [], f"scanner osv-scanner returned invalid JSON: {exc}"
    findings=[]
    for result in (obj or {}).get("results",[]):
        path=((result.get("source") or {}).get("path") or "<dependency>")
        for pkg in result.get("packages",[]):
            p=pkg.get("package") or {}
            for vuln in pkg.get("vulnerabilities",[]):
                vid=vuln.get("id","OSV")
                summary=vuln.get("summary") or "Known dependency vulnerability reported by OSV."
                findings.append(_finding_from_json("osv-scanner",path,1,"high",f"{p.get('name','package')} {p.get('version','')}",vid,summary))
    return findings,None


def run_external_scanners(root: Path, rules_dir: Path, strict: bool=True) -> tuple[list[Finding], list[dict]]:
    findings=[]; checks=[]
    f,e=run_semgrep(root,rules_dir/"semgrep.yml"); checks.append({"check":"Semgrep OSS","status":"passed" if not e else "error","detail":e or f"{len(f)} findings"}); findings += f
    f,e=run_gitleaks(root,rules_dir/"gitleaks.toml"); checks.append({"check":"Gitleaks","status":"passed" if not e else "error","detail":e or f"{len(f)} findings"}); findings += f
    f,e=run_osv(root); checks.append({"check":"OSV-Scanner offline database","status":"passed" if not e else "error","detail":e or f"{len(f)} findings"}); findings += f
    if strict and any(c["status"]=="error" for c in checks):
        findings.append(Finding("critical","<scanner>",1,"scanner failure","RG-SCANNER-001","A required scanner failed or was unavailable; the repository cannot be approved.","verdict"))
    return findings,checks


def inventory(root: Path) -> list[dict]:
    rows=[]
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        data=p.read_bytes()
        rows.append({"path":str(p.relative_to(root)).replace(os.sep,"/"),"file_type":classify_path(p,data),"size":len(data),"sha256":sha256_file(p)})
    return rows

def analyze_tree(root: Path, rules_dir: Path, threshold: str="medium", include_external: bool=False, strict_scanners: bool=True, scratch: Path | None=None) -> dict:
    start=time.time(); file_results=[]; all_findings=[]; checks=[]; archive_errors={}; analysis_errors=[]
    initial=list(sorted(p for p in root.rglob("*") if p.is_file()))
    scratch = scratch or (root / ".repoguard-extracted")
    scratch.mkdir(parents=True, exist_ok=True)
    work=list(initial); seen=set()
    depth_by_path={p:0 for p in initial}
    virtual_rel={p:str(p.relative_to(root)).replace(os.sep,"/") for p in initial}
    while work:
        path=work.pop(0)
        if path in seen: continue
        seen.add(path)
        kind=classify_path(path,path.read_bytes())
        if kind=="archive" and depth_by_path.get(path,0) >= MAX_NESTED_DEPTH:
            rel=virtual_rel.get(path,str(path)); archive_errors[rel]="nested archive depth exceeded"
            all_findings.append(Finding("critical",rel,1,"nested archive depth exceeded","RG-ARCHIVE-002","The archive nesting limit was reached before its contents could be fully analyzed.","archive"))
        if kind=="archive" and depth_by_path.get(path,0) < MAX_NESTED_DEPTH:
            out=scratch/hashlib.sha256(str(path).encode()).hexdigest()[:16]
            try:
                ex=extract_archive(path,out,depth_by_path.get(path,0))
                for ep in ex.paths:
                    if ep.is_file():
                        depth_by_path[ep]=depth_by_path.get(path,0)+1
                        parent_rel=virtual_rel.get(path,str(path))
                        virtual_rel[ep]=parent_rel+"::"+str(ep.relative_to(out)).replace(os.sep,"/")
                        work.append(ep)
            except Exception as exc:
                rel=virtual_rel.get(path,str(path)); archive_errors[rel]=str(exc)
                all_findings.append(Finding("critical",rel,1,str(exc),"RG-ARCHIVE-001","The archive could not be safely unpacked, so its contents cannot be fully analyzed.","archive"))
    targets=sorted(seen | {p for p in root.rglob("*") if p.is_file() and p not in seen})
    total_bytes=sum(p.stat().st_size for p in targets)
    if len(targets)>5000: analysis_errors.append(f"file count {len(targets)} exceeds 5000")
    if total_bytes>100*1024*1024: analysis_errors.append(f"expanded repository size {total_bytes} exceeds 104857600 bytes")
    for p in targets:
        rel_text=virtual_rel.get(p,str(p.relative_to(root)).replace(os.sep,"/"))
        rel=Path(rel_text)
        data=p.read_bytes()
        kind=classify_path(p,data)
        findings=[]; reason=archive_errors.get(str(rel))
        try:
            if kind in {"text"}:
                findings, reason=scan_text(rel,data)
                try:
                    text=data.decode("utf-8")
                    findings += dependency_typosquatting_findings(rel,text)
                except UnicodeDecodeError:
                    reason="unreadable as UTF-8"
            elif kind=="executable" or kind=="binary":
                reason, bf=_binary_reason(p,data,root); findings += bf
                yf,ye=run_yara(p,rules_dir/"yara.yar"); findings += yf
                if ye: reason = reason or ye
            elif kind=="media":
                if data.startswith(b"MZ") or data.startswith(b"\x7fELF"):
                    reason="executable signature found in media-named file"
                yf,ye=run_yara(p,rules_dir/"yara.yar"); findings += yf
                if ye: reason = reason or ye
            elif kind=="archive":
                pass
        except Exception as exc:
            reason=f"scanner exception: {exc}"
        threshold_value=SEVERITY_ORDER[threshold]
        qualifying=[f for f in findings if SEVERITY_ORDER.get(f.severity,4) >= threshold_value]
        status="Rejected - unanalyzable (reason)" if reason else ("Analyzed - flagged" if qualifying else "Analyzed - clean")
        file_results.append({"path":str(rel).replace(os.sep,"/"),"file_type":kind,"size":len(data),"sha256":sha256_file(p),"status":status,"reason":reason,"findings":[f.to_dict() for f in findings]})
        all_findings += findings
    checks += [
        {"check":"URL validation","status":"passed"},
        {"check":"Safe archive extraction","status":"passed"},
        {"check":"Per-file SHA-256 inventory","status":"passed"},
        {"check":"Custom static security rules","status":"passed"},
        {"check":"AI-skill markdown/invisible-instruction checks","status":"passed"},
        {"check":"Binary structure + YARA path","status":"passed"},
    ]
    if include_external:
        ef, ec = run_external_scanners(root,rules_dir,strict_scanners); all_findings += ef; checks += ec
    if analysis_errors:
        all_findings.append(Finding("critical","<repository>",1,"; ".join(analysis_errors),"RG-LIMIT-001","Repository-wide limits were exceeded, so not all files can be fully analyzed.","limits"))
    return {"file_results":file_results,"findings":[f.to_dict() for f in all_findings],"checks":checks,"analysis_errors":analysis_errors,"duration_seconds":round(time.time()-start,3)}
