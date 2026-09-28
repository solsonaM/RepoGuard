from __future__ import annotations
import hashlib, json, math, mimetypes, os, re, subprocess, time
from pathlib import Path
from .models import Finding
from .normalize import normalize_text, INVISIBLE_RE

SCRIPT_EXT = {".py",".js",".ts",".tsx",".jsx",".sh",".bash",".zsh",".ps1",".php",".rb",".pl",".lua",".go",".rs",".java",".c",".cc",".cpp",".h",".hpp",".cs",".swift",".kt",".kts"}
TEXT_EXT = SCRIPT_EXT | {".md",".markdown",".txt",".json",".yaml",".yml",".toml",".ini",".cfg",".conf",".env",".xml",".html",".css",".csv",".svg"}
ARCHIVE_EXT = {".zip",".tar",".tgz",".tar.gz",".tar.bz2",".tbz2",".tar.xz",".txz"}
EXEC_EXT = {".exe",".dll",".so",".dylib",".bin",".elf",".com",".msi",".apk",".ipa",".wasm"}
IMAGE_EXT = {".png",".jpg",".jpeg",".gif",".webp",".bmp",".ico",".svg"}
POPULAR = {"requests","urllib3","lodash","react","vue","express","django","flask","numpy","pandas","pytest","axios","typescript","webpack","vite","next","fastapi","boto3","rich","click"}

RULES = [
("RG-DL-001", "critical", re.compile(r"(?:curl|wget)\b[^\n|;&]*\|\s*(?:ba)?sh\b", re.I), "Downloads remote content and pipes it directly into a shell."),
("RG-DL-002", "high", re.compile(r"\b(?:curl|wget)\b[^\n;]*https?://", re.I), "Downloads executable or remote content; it requires review in untrusted repositories."),
("RG-EXEC-001", "high", re.compile(r"\b(?:eval|exec)\s*\(.*(?:base64|atob|fromCharCode|hex|decode)", re.I), "Executes data after decoding, which is a common obfuscation pattern."),
("RG-DESTRUCT-001", "critical", re.compile(r"\brm\s+-[rRf]+\s+(?:/|~|\$HOME)", re.I), "Attempts destructive recursive deletion of a root or home path."),
("RG-DESTRUCT-002", "critical", re.compile(r"\b(?:mkfs\.|format\s+[a-z]:|diskpart\b)", re.I), "Contains disk-formatting or destructive disk-management commands."),
("RG-RSHELL-001", "critical", re.compile(r"(?:/dev/tcp/|bash\s+-i|nc\s+-e|socat\s+[^\n]*exec:)", re.I), "Matches a common reverse-shell construction."),
("RG-PERSIST-001", "high", re.compile(r"(?:crontab|/etc/cron|systemd.*service|~/.bashrc|~/.zshrc|\\Microsoft\\Windows\\Start Menu\\Programs\\Startup)", re.I), "Modifies common persistence locations or scheduled-task mechanisms."),
("RG-THEFT-001", "critical", re.compile(r"(?:~/.ssh|\.ssh/|\.env\b|Chrome/User Data|Firefox/Profiles|wallet\.dat|metamask|aws_access_key_id|gcloud.*credentials)", re.I), "Attempts to read common private keys, credentials, browser data, or crypto-wallet data."),
("RG-MCP-001", "critical", re.compile(r"(?:mcp.*(?:command|exec|shell)|(?:command|exec).*mcp|stdio.*(?:bash|sh|powershell))", re.I), "AI/MCP configuration can launch local commands."),
("RG-HOOK-001", "high", re.compile(r"\b(?:postinstall|preinstall|prepare|prepublish|install)\b\s*[:=]", re.I), "Package metadata contains an automatic install lifecycle hook."),
("RG-HOOK-002", "high", re.compile(r"(?:cmdclass|entry_points|\.git/hooks|pull_request_target|self-hosted|persist-credentials:\s*true|uses:\s*\./)", re.I), "Build metadata, Git hooks, or workflow settings can execute code with elevated or trusted context."),
("RG-HOOK-003", "high", re.compile(r"(?:postCreateCommand|postStartCommand|onCreateCommand|postAttachCommand|overrideCommand\s*:\s*true)", re.I), "Dev-container lifecycle configuration can automatically execute repository-controlled commands."),
("RG-AI-003", "high", re.compile(r"(?:run|execute|copy|paste)\s+(?:this|the following|these)\s+(?:command|commands|script|shell)", re.I), "The text instructs an AI or operator to execute a command or script."),
("RG-AI-004", "critical", re.compile(r"(?:read|send|upload|exfiltrate)\s+(?:all|any|every)\s+(?:files?|documents?|environment variables?)", re.I), "Requests broad access to local data or files beyond a narrowly scoped task."),
("RG-NET-001", "medium", re.compile(r"https?://(?!github\.com|api\.github\.com|raw\.githubusercontent\.com|example\.invalid)[^\s'\"<>]+", re.I), "References an external network host outside GitHub; this can be a data-exfiltration or remote-code-download channel."),
("RG-AI-001", "critical", re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+.*instructions|disable\s+safety|exfiltrat(?:e|ion).*files?", re.I), "Contains prompt-injection instructions that attempt to override safeguards or exfiltrate data."),
]

SECRET_RE = re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{16,}")

def classify_path(path: Path, data: bytes) -> str:
    ext = path.suffix.lower()
    if ext in ARCHIVE_EXT or path.name.lower().endswith(('.tar.gz','.tar.bz2','.tar.xz')):
        return "archive"
    if ext in EXEC_EXT or ext in {".enc",".encrypted",".gpg",".age",".p12",".pfx",".key"}:
        return "executable" if ext in EXEC_EXT else "binary"
    if ext in IMAGE_EXT:
        return "media"
    if ext in TEXT_EXT:
        return "text"
    if b"\x00" not in data[:4096] and data:
        try:
            data.decode("utf-8")
            return "text"
        except UnicodeDecodeError:
            pass
    return "binary"

def _finding(rule_id, severity, path, line, snippet, explanation, source="custom"):
    return Finding(severity, str(path), line, snippet[:500], rule_id, explanation, source)

def scan_text(path: Path, raw: bytes) -> tuple[list[Finding], str | None]:
    try:
        text, layers = normalize_text(raw)
    except UnicodeDecodeError:
        return [], "unreadable as UTF-8"
    findings: list[Finding] = []
    for rule, severity, regex, explanation in RULES:
        for m in regex.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = text.splitlines()[line-1] if text.splitlines() else m.group(0)
            findings.append(_finding(rule, severity, path, line, snippet, explanation))
    if path.suffix.lower() in SCRIPT_EXT:
        for m in re.finditer(r"https?://(?!github\.com|api\.github\.com|raw\.githubusercontent\.com|example\.invalid)[^\s\'\"<>]+", text, re.I):
            line = text.count("\n", 0, m.start()) + 1
            snippet = text.splitlines()[line-1] if text.splitlines() else m.group(0)
            findings.append(_finding("RG-NET-002", "high", path, line, snippet, "A script references an external host outside the fixed GitHub allowlist; outbound access can enable data exfiltration or remote code retrieval."))
    if SECRET_RE.search(text):
        m = SECRET_RE.search(text)
        line = text.count("\n", 0, m.start()) + 1
        snippet = text.splitlines()[line-1] if text.splitlines() else "secret-like value"
        snippet = re.sub(r"([A-Za-z0-9_\-]{3})[A-Za-z0-9_\-/+=]{6,}", r"\1[REDACTED]", snippet)
        findings.append(_finding("RG-SECRET-001", "critical", path, line, snippet, "A credential-like hard-coded value was detected; only a redacted snippet is stored.", "custom-secret"))
    if layers:
        findings.append(_finding("RG-OBF-001", "high", path, 1, ", ".join(layers), "Encoded layers were decoded before scanning. Encoded executable content is treated as suspicious."))
    invisible = INVISIBLE_RE.search(text)
    if invisible:
        line = text.count("\n", 0, invisible.start()) + 1
        findings.append(_finding("RG-AI-002", "high", path, line, "[invisible character redacted]", "Invisible Unicode characters can hide instructions or alter what an AI sees."))
    if path.suffix.lower() in {".js", ".ts", ".mjs", ".cjs"} and len(text) > 2000:
        nonspace = len(re.sub(r"\s+", "", text))
        if nonspace > 0 and text.count("\n") / nonspace < 0.002:
            findings.append(_finding("RG-OBF-002", "medium", path, 1, "minified source", "The file is highly minified; it was normalized before scanning but remains difficult to audit."))
    return findings, None

def dependency_typosquatting_findings(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    names: set[str] = set()
    if path.name == "package.json":
        try:
            data = json.loads(text)
            for group in ("dependencies", "devDependencies", "optionalDependencies"):
                names.update((data.get(group) or {}).keys())
        except Exception:
            return []
    elif path.name in {"requirements.txt", "pyproject.toml"}:
        for line in text.splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.-]+)", line)
            if m: names.add(m.group(1))
    for name in names:
        if not name: continue
        low = name.lower().replace("-","").replace("_","")
        for pop in POPULAR:
            p = pop.replace("-","")
            if low != p and (low.startswith(p) or p.startswith(low)) and abs(len(low)-len(p)) <= 2:
                findings.append(_finding("RG-TYPO-001", "high", path, 1, name, f"Dependency name is suspiciously close to popular package '{pop}' and should be independently verified.", "typosquat"))
    return findings

def yara_available() -> bool:
    try:
        return subprocess.run(["yara", "-v"], capture_output=True, timeout=3).returncode == 0
    except Exception:
        return False

def run_yara(path: Path, rules_file: Path) -> tuple[list[Finding], str | None]:
    if not yara_available():
        return [], "YARA scanner unavailable"
    try:
        proc = subprocess.run(["yara", "-w", str(rules_file), str(path)], capture_output=True, text=True, timeout=10)
    except Exception as exc:
        return [], f"YARA error: {exc}"
    findings = []
    for line in proc.stdout.splitlines():
        if line.strip():
            findings.append(_finding("RG-YARA", "high", path, 1, line.strip(), "YARA matched a configured rule.", "yara"))
    if proc.returncode not in (0, 1):
        return findings, f"YARA scanner exit code {proc.returncode}"
    return findings, None

def _finding_from_json(source, file, line, severity, snippet, rule, explanation):
    return Finding(severity,file,int(line or 1),str(snippet or "")[:500],str(rule),str(explanation),source)

def run_semgrep(root: Path, config: Path) -> tuple[list[Finding], str | None]:
    try:
        proc=subprocess.run(["semgrep","scan","--config",str(config),"--json","--no-git-ignore","."],cwd=root,capture_output=True,text=True,timeout=120)
    except FileNotFoundError: return [], "scanner unavailable: semgrep"
    except subprocess.TimeoutExpired: return [], "scanner timeout: semgrep"
    if proc.returncode not in (0,1): return [], f"scanner semgrep failed with exit code {proc.returncode}"
    try: obj=json.loads(proc.stdout or "{}")
    except Exception as exc: return [], f"scanner semgrep returned invalid JSON: {exc}"
    findings=[]
    for r in obj.get("results",[]):
        extra=r.get("extra") or {}; sev=str(extra.get("severity","WARNING")).lower()
        sev={"error":"critical","warning":"high","info":"medium"}.get(sev, "medium")
        findings.append(_finding_from_json("semgrep",r.get("path",""),(r.get("start") or {}).get("line",1),sev,extra.get("lines","") or r.get("check_id",""),r.get("check_id","semgrep-rule"),extra.get("message","Semgrep rule matched.")))
    return findings,None

def run_gitleaks(root: Path, config: Path) -> tuple[list[Finding], str | None]:
    report=Path("/tmp/gitleaks.json"); report.unlink(missing_ok=True)
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
    env=os.environ.copy(); env.setdefault("XDG_CACHE_HOME", "/osv-cache")
    try:
        proc=subprocess.run(["osv-scanner","--offline-vulnerabilities","scan","source","-r",".","--format","json"], cwd=root, capture_output=True, text=True, timeout=90, env=env)
    except FileNotFoundError: return [], "scanner unavailable: osv-scanner"
    except subprocess.TimeoutExpired: return [], "scanner timeout: osv-scanner"
    if proc.returncode not in (0,1):
        return [], f"scanner osv-scanner failed with exit code {proc.returncode}: {proc.stderr[-500:]}"
    try: obj=json.loads(proc.stdout or "{}")
    except Exception as exc: return [], f"scanner osv-scanner returned invalid JSON: {exc}"
    findings=[]
    for result in (obj or {}).get("results",[]):
        path=((result.get("source") or {}).get("path") or "<dependency>")
        for pkg in result.get("packages",[]):
            p=pkg.get("package") or {}
            for vuln in pkg.get("vulnerabilities",[]):
                vid=vuln.get("id","OSV"); summary=vuln.get("summary") or "Known dependency vulnerability reported by OSV."
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
