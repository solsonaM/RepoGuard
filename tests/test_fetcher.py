from pathlib import Path
from app.fetcher import NoRedirect

def test_redirect_handler_rejects():
    import pytest
    with pytest.raises(Exception): NoRedirect().redirect_request(None,None,302,'x',{},'https://evil.example')
