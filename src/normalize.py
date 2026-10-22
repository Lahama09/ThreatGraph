"""Normalization helpers for IOC candidates.

Every function returns the canonical value, or None if the candidate is invalid.
The original text is never altered here; callers store it separately.
"""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[0-9a-f]+$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_WIN_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")


def hash_type(value):
    """Return 'md5', 'sha1' or 'sha256', or None."""
    v = value.strip().lower()
    if len(v) in HASH_LENGTHS and _HEX.match(v):
        return HASH_LENGTHS[len(v)]
    return None


def normalize_hash(value):
    v = value.strip().lower()
    return v if hash_type(v) else None


def normalize_ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ValueError:
        return None


def normalize_domain(value):
    v = value.strip().lower().rstrip(".")
    if not v or len(v) > 253:
        return None
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = v.split(".")
    if len(labels) < 2:
        return None
    if not all(_LABEL.match(label) for label in labels):
        return None
    if not _TLD.match(labels[-1]):
        return None
    return v


def _valid_host(host):
    return normalize_ipv4(host) or normalize_domain(host)


def normalize_url(value):
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
        return None
    host = _valid_host(parts.hostname)
    if host is None:
        return None
    before, sep, _ = parts.netloc.rpartition("@")
    userinfo = before + "@" if sep else ""
    netloc = userinfo + host + (f":{port}" if port is not None else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))


def path_kind(value):
    v = value.strip()
    if _WIN_PATH.match(v):
        return "windows"
    if v.startswith("/"):
        return "unix"
    return None


def normalize_path(value):
    """Canonical value doubles as the comparison key.

    Windows paths are case-insensitive, so they are lowercased and use backslashes.
    Unix paths keep their case. The original text is kept in the occurrence record.
    """
    v = value.strip()
    kind = path_kind(v)
    if kind == "windows":
        v = v.replace("/", "\\").lower()
        return v.rstrip("\\") if len(v) > 3 else v
    if kind == "unix":
        return v.rstrip("/") or "/"
    return None