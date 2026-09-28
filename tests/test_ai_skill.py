from pathlib import Path
from app.rules_engine import scan_text

def test_skill_fixture_flags_injection_invisible_and_execution_instruction():
    p=Path('tests/fixtures/malicious_like/SKILL.md')
    findings,_=scan_text(p,p.read_bytes())
    rules={f.rule for f in findings}
    assert {'RG-AI-001','RG-AI-002','RG-AI-003'}.issubset(rules)

def test_skill_fixture_does_not_execute_text_during_scan():
    p=Path('tests/fixtures/malicious_like/SKILL.md')
    before=p.read_bytes()
    scan_text(p,before)
    assert p.read_bytes()==before
