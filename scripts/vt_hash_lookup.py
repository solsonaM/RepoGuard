#!/usr/bin/env python3
"""Optional VirusTotal hash-only lookup. Never uploads files."""
from __future__ import annotations
import json, os, sys, urllib.error, urllib.request, hashlib

API = "https://www.virustotal.com/api/v3/files/{}"

def sha256(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main(paths):
    key=os.environ.get("VT_API_KEY")
    if not key:
        print(json.dumps({"enabled":False,"reason":"VT_API_KEY is not set"}, indent=2)); return 0
    out=[]
    for raw in paths:
        p=os.path.abspath(raw); digest=sha256(p)
        req=urllib.request.Request(API.format(digest), headers={"x-apikey":key,"accept":"application/json"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                obj=json.load(r)
            attrs=((obj.get("data") or {}).get("attributes") or {})
            out.append({"path":raw,"sha256":digest,"found":True,"malicious":attrs.get("last_analysis_stats",{}).get("malicious",0),"suspicious":attrs.get("last_analysis_stats",{}).get("suspicious",0)})
        except urllib.error.HTTPError as exc:
            out.append({"path":raw,"sha256":digest,"found":False,"http_status":exc.code})
        except Exception as exc:
            out.append({"path":raw,"sha256":digest,"found":False,"error":str(exc)})
    print(json.dumps({"enabled":True,"results":out}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
