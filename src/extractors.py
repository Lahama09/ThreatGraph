"""Extract IOC candidates from evidence text.

An extracted string is only a *candidate*: syntactically valid, not necessarily malicious.
"""
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .normalize import (
    hash_type, normalize_domain, normalize_hash,
    normalize_ipv4, normalize_path, normalize_url,
)


@dataclass(frozen=True)
class Candidate:
    ioc_type: str   # md5, sha1, sha256, ipv4, domain, url, filepath
    original: str   # exact text as it appeared in the evidence
    canonical: str  # normalized value used for deduplication
    method: str     # e.g. "regex:url+refang", "derived:url-host"
    line_number: int | None = None


# Strings that look like domains but are almost always file names.
FILE_EXTENSIONS = frozenset("""
exe dll sys bat cmd ps1 vbs js json txt log csv xml html htm php py pyc jar zip
rar tar gz bin dat tmp ini cfg conf md pdf doc docx xls xlsx ppt pptx png jpg
jpeg gif bmp ico db sqlite pcap pcapng dmp lnk msi scr so img iso sh
""".split())

_TRAIL = ".,;:!?)]}'\""

_DEFANG = re.compile(
    r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[:\]|\[://\]|\[@\]|\[at\]"
    r"|hxxp(?=s?(?::|\[:\]|\[://\]))",
    re.IGNORECASE,
)
_REPLACEMENT = {
    "[.]": ".", "(.)": ".", "{.}": ".", "[dot]": ".", "(dot)": ".",
    "[:]": ":", "[://]": "://", "[@]": "@", "[at]": "@",
}

_URL_RE = re.compile(r"""\b(?:https?|ftp)://[^\s<>"'\\]+""", re.IGNORECASE)
_WIN_PATH_RE = re.compile(r"""(?<!\w)[A-Za-z]:[\\/](?:[^\\/:*?"<>|\s]+[\\/])*[^\\/:*?"<>|\s]+""")
_UNIX_PATH_RE = re.compile(r"(?<![\w/.:\\-])(?:/[A-Za-z0-9._~+@%-]+){2,}/?")
_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_HASH_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
)
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])"
)


def refang(text):
    """Undo common defanging. Returns (clean_text, starts, ends).

    starts[i] / ends[i] give the span in the ORIGINAL text that produced
    clean_text[i], so any match can be mapped back to its original form.
    """
    out, starts, ends = [], [], []
    pos = 0
    for m in _DEFANG.finditer(text):
        for i in range(pos, m.start()):
            out.append(text[i]); starts.append(i); ends.append(i + 1)
        key = m.group(0).lower()
        rep = "http" if key == "hxxp" else _REPLACEMENT[key]
        for ch in rep:
            out.append(ch); starts.append(m.start()); ends.append(m.end())
        pos = m.end()
    for i in range(pos, len(text)):
        out.append(text[i]); starts.append(i); ends.append(i + 1)
    return "".join(out), starts, ends


def _mask(text, s, e):
    return text[:s] + " " * (e - s) + text[e:]


def extract_from_line(line, line_number=None):
    text, starts, ends = refang(line)
    if not text:
        return []
    masked = text
    found = []  # (position, Candidate)

    def add(ioc_type, s, e, canonical, kind):
        orig = line[starts[s]:ends[e - 1]]
        method = f"regex:{kind}" + ("+refang" if orig != text[s:e] else "")
        found.append((s, Candidate(ioc_type, orig, canonical, method, line_number)))

    # 1. URLs (and the host of each URL)
    for m in _URL_RE.finditer(text):
        raw = m.group(0).rstrip(_TRAIL)
        s, e = m.start(), m.start() + len(raw)
        masked = _mask(masked, m.start(), m.end())
        canon = normalize_url(raw)
        if canon is None:
            continue
        add("url", s, e, canon, "url")
        host = urlsplit(canon).hostname
        host_type = "ipv4" if normalize_ipv4(host) else "domain"
        orig = line[starts[s]:ends[e - 1]]
        found.append((s, Candidate(host_type, orig, host, "derived:url-host", line_number)))

    # 2. File paths (Windows, then Unix)
    for rx, kind in ((_WIN_PATH_RE, "winpath"), (_UNIX_PATH_RE, "unixpath")):
        for m in list(rx.finditer(masked)):
            raw = m.group(0).rstrip(_TRAIL)
            s, e = m.start(), m.start() + len(raw)
            canon = normalize_path(raw) if raw else None
            if canon is None:
                continue
            add("filepath", s, e, canon, kind)
            masked = _mask(masked, m.start(), m.end())

    # 3. IPv4 addresses
    for m in _IP_RE.finditer(masked):
        canon = normalize_ipv4(m.group(0))
        if canon:
            add("ipv4", m.start(), m.end(), canon, "ipv4")

    # 4. Hashes
    for m in _HASH_RE.finditer(masked):
        raw = m.group(0)
        if raw.isdigit():
            continue
        canon = normalize_hash(raw)
        if canon:
            add(hash_type(canon), m.start(), m.end(), canon, "hash")

    # 5. Domains (what is left after URLs and paths were masked)
    for m in _DOMAIN_RE.finditer(masked):
        raw = m.group(0)
        if raw.rsplit(".", 1)[1].lower() in FILE_EXTENSIONS:
            continue
        canon = normalize_domain(raw)
        if canon:
            add("domain", m.start(), m.end(), canon, "domain")

    return [c for _, c in sorted(found, key=lambda x: x[0])]


def extract_from_text(text):
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        out.extend(extract_from_line(line, n))
    return out