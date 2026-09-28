import pytest
from app.intake import parse_repo_url, IntakeError

def test_valid_repo_and_ref():
    x=parse_repo_url('https://github.com/solsonaM/RepoGuard/tree/repoguard-prototype')
    assert x.owner=='solsonaM' and x.repo=='RepoGuard' and x.ref=='repoguard-prototype'

@pytest.mark.parametrize('url',[
    'http://github.com/a/b','https://evil.example/a/b','https://127.0.0.1/a/b',
    'https://github.com/a/b?x=1','https://github.com/a/b#x','https://github.com/a/b/tree/a/../../x',
    'https://github.com/a/b/blob/main/x',
])
def test_bad_urls(url):
    with pytest.raises(IntakeError): parse_repo_url(url)
