from __future__ import annotations
import base64, binascii, html, re

INVISIBLE_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{32,})(?![0-9A-Fa-f])")

def decode_layers(text: str, max_layers: int = 3) -> tuple[str, list[str]]:
    current = text
    layers: list[str] = []
    for _ in range(max_layers):
        changed = False
        def b64(m):
            nonlocal changed
            raw = m.group(1)
            try:
                pad = "=" * ((4 - len(raw) % 4) % 4)
                out = base64.b64decode(raw + pad, validate=True)
                decoded = out.decode("utf-8")
                if sum(c.isprintable() or c in "\n\r\t" for c in decoded) / max(len(decoded),1) < .8:
                    return m.group(0)
                changed = True
                layers.append("base64")
                return decoded
            except Exception:
                return m.group(0)
        def hexd(m):
            nonlocal changed
            raw = m.group(1)
            try:
                out = binascii.unhexlify(raw)
                decoded = out.decode("utf-8")
                if sum(c.isprintable() or c in "\n\r\t" for c in decoded) / max(len(decoded),1) < .8:
                    return m.group(0)
                changed = True
                layers.append("hex")
                return decoded
            except Exception:
                return m.group(0)
        current2 = BASE64_RE.sub(b64, current)
        current2 = HEX_RE.sub(hexd, current2)
        if current2 == current and not changed:
            break
        current = current2
    return current, layers

def normalize_text(raw: bytes) -> tuple[str, list[str]]:
    text = raw.decode("utf-8", errors="strict")
    no_html = html.unescape(text)
    decoded, layers = decode_layers(no_html)
    normalized = re.sub(r"[ \t]+", " ", decoded)
    normalized = re.sub(r";(?=\S)", ";\n", normalized)
    return normalized, layers
