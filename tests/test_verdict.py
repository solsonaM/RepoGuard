from pathlib import Path
from app.scanner import analyze_tree
from app.verdict import build_report

def test_clean_fixture_is_approved():
    root=Path('tests/fixtures/clean')
    a=analyze_tree(root,Path('rules'),include_external=False)
    r=build_report('https://github.com/example/clean','a'*40,'hosted-static-analysis',a)
    assert r['verdict']=='APPROVED'
    assert r['files_analyzed']==r['files_total']
    assert r['files_analyzed']==3

def test_bad_files_are_rejected():
    root=Path('tests/fixtures/malicious_like')
    a=analyze_tree(root,Path('rules'),include_external=False)
    r=build_report('https://github.com/example/bad','b'*40,'hosted-static-analysis',a)
    assert r['verdict']=='REJECTED'
    paths={x['file'] for x in r['rejection_reasons']}
    assert 'encrypted.enc' in paths or 'blob.bin' in paths or 'fake.exe' in paths


def test_failure_report_is_rejected_and_explains_orchestration_error(tmp_path):
    import json, subprocess, sys
    out=tmp_path/'failure.json'
    subprocess.run([sys.executable,'-m','app.failure_report','--repo-url','https://github.com/example/repo','--commit-sha','c'*40,'--output',str(out),'--reason','fetch timeout','--scan-id','f'*36], check=True)
    data=json.loads(out.read_text())
    assert data['verdict']=='REJECTED'
    assert data['rejection_reasons'][0]['reason']=='fetch timeout'
    assert data['scan_id']=='f'*36
