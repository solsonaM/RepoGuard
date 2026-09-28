from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import tempfile, os, pytest
from app.safe_extract import extract_archive, UnsafeArchiveError

def test_path_traversal_zip_refused(tmp_path):
    z=tmp_path/'evil.zip'
    with ZipFile(z,'w') as f: f.writestr('../escape.txt','x')
    with pytest.raises(UnsafeArchiveError): extract_archive(z,tmp_path/'out')

def test_compression_ratio_bomb_refused(tmp_path):
    z=tmp_path/'bomb.zip'
    with ZipFile(z,'w',compression=ZIP_DEFLATED) as f: f.writestr('zeros.bin',b'0'*(1024*1024))
    with pytest.raises(UnsafeArchiveError): extract_archive(z,tmp_path/'out')

def test_encrypted_zip_member_refused(tmp_path):
    import struct
    z=tmp_path/'enc.zip'
    with ZipFile(z,'w') as f: f.writestr('secret.txt','fixture')
    data=bytearray(z.read_bytes())
    pos=data.find(b"PK\x03\x04")
    assert pos >= 0
    struct.pack_into('<H', data, pos+6, 1)
    pos2=data.find(b"PK\x01\x02")
    assert pos2 >= 0
    struct.pack_into('<H', data, pos2+8, 1)
    z.write_bytes(data)
    with pytest.raises(UnsafeArchiveError): extract_archive(z,tmp_path/'out')
