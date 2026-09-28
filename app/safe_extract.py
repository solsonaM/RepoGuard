from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import io, os, stat, tarfile, zipfile

MAX_EXPANDED = 100 * 1024 * 1024
MAX_FILES = 5000
MAX_SINGLE = 10 * 1024 * 1024
MAX_RATIO = 100
MAX_NESTED_DEPTH = 3

class UnsafeArchiveError(ValueError):
    pass

@dataclass
class Extracted:
    paths: list[Path]
    rejected: list[tuple[str, str]]

def _safe_name(name: str) -> Path:
    if "\x00" in name or name.startswith("/") or name.startswith("\\"):
        raise UnsafeArchiveError("absolute or NUL path")
    p = Path(name)
    if p.is_absolute() or any(part == ".." for part in p.parts):
        raise UnsafeArchiveError("path traversal")
    return p

def _check_path(root: Path, rel: Path) -> Path:
    dest = (root / rel).resolve()
    root_resolved = root.resolve()
    if dest != root_resolved and root_resolved not in dest.parents:
        raise UnsafeArchiveError("path escapes extraction root")
    return dest

def extract_archive(path: Path, root: Path, depth: int = 0) -> Extracted:
    if depth > MAX_NESTED_DEPTH:
        raise UnsafeArchiveError("nested archive depth exceeded")
    root.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    rejected: list[tuple[str, str]] = []
    def ensure_limits(size: int, compressed: int = 1) -> None:
        if size > MAX_SINGLE:
            raise UnsafeArchiveError(f"single extracted file exceeds {MAX_SINGLE} bytes")
        current = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
        if current + size > MAX_EXPANDED:
            raise UnsafeArchiveError("expanded archive size limit exceeded")
        if compressed > 0 and size / compressed > MAX_RATIO:
            raise UnsafeArchiveError("compression ratio exceeds limit")
        if len(paths) >= MAX_FILES:
            raise UnsafeArchiveError("file count limit exceeded")

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            for info in infos:
                try:
                    rel = _safe_name(info.filename)
                    if info.is_dir():
                        _check_path(root, rel).mkdir(parents=True, exist_ok=True)
                        continue
                    if info.flag_bits & 0x1:
                        raise UnsafeArchiveError("password-protected/encrypted zip member")
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == stat.S_IFLNK:
                        raise UnsafeArchiveError("symlink in archive")
                    ensure_limits(info.file_size, max(info.compress_size, 1))
                    dest = _check_path(root, rel)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as src, dest.open("wb") as out:
                        remaining = info.file_size
                        while remaining:
                            chunk = src.read(min(1024 * 1024, remaining))
                            if not chunk:
                                break
                            out.write(chunk)
                            remaining -= len(chunk)
                        if remaining:
                            raise UnsafeArchiveError("archive member ended unexpectedly")
                    paths.append(dest)
                except Exception as exc:
                    rejected.append((info.filename, str(exc)))
                    raise
    elif tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                rel = _safe_name(member.name)
                if member.islnk() or member.issym():
                    raise UnsafeArchiveError(f"symlink/link in archive: {member.name}")
                if member.isdir():
                    _check_path(root, rel).mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise UnsafeArchiveError(f"unsupported tar member: {member.name}")
                ensure_limits(member.size, 1)
                dest = _check_path(root, rel)
                dest.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    raise UnsafeArchiveError(f"unable to extract {member.name}")
                remaining = member.size
                with src, dest.open("wb") as out:
                    while remaining:
                        chunk = src.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        out.write(chunk)
                        remaining -= len(chunk)
                    if remaining:
                        raise UnsafeArchiveError(f"truncated tar member {member.name}")
                paths.append(dest)
    else:
        raise UnsafeArchiveError("unsupported archive format")
    return Extracted(paths, rejected)
