from pathlib import Path
from app.rules_engine import RULES, scan_text

def test_each_static_rule_fires():
    path=Path('tests/fixtures/malicious_like/patterns.txt')
    findings,_=scan_text(path,path.read_bytes())
    rules={f.rule for f in findings}
    expected={r[0] for r in RULES if r[0] not in {'RG-NET-001'}}
    assert expected.issubset(rules)

def test_ai_skill_invisible_and_injection():
    p=Path('tests/fixtures/malicious_like/SKILL.md')
    findings,_=scan_text(p,p.read_bytes())
    rules={f.rule for f in findings}
    assert {'RG-AI-001','RG-AI-002','RG-AI-003'}.issubset(rules)
    assert all('[REDACTED]' not in f.snippet or 'Secret' not in f.rule for f in findings)

def test_secret_is_redacted():
    p=Path('tests/fixtures/malicious_like/secret.txt')
    p.write_text('API_KEY=SUPERSECRET1234567890ABCDEF\n')
    findings,_=scan_text(p,p.read_bytes())
    sec=[f for f in findings if f.rule=='RG-SECRET-001']
    assert sec and 'SUPERSECRET' not in sec[0].snippet and '[REDACTED]' in sec[0].snippet
