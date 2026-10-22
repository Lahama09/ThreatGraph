import pytest

from src.normalize import (
    hash_type, normalize_hash, normalize_ipv4,
    normalize_domain, normalize_url, normalize_path,
)

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_hash_types():
    assert hash_type(MD5) == "md5"
    assert hash_type(SHA1) == "sha1"
    assert hash_type(SHA256) == "sha256"


def test_hash_uppercase_normalizes_to_lowercase():
    assert normalize_hash(SHA256.upper()) == SHA256


@pytest.mark.parametrize("bad", ["abc123", "g" * 32, MD5 + "0", ""])
def test_bad_hashes(bad):
    assert normalize_hash(bad) is None


def test_ipv4_valid_and_stripped():
    assert normalize_ipv4(" 198.51.100.24 ") == "198.51.100.24"


@pytest.mark.parametrize("bad", ["999.1.1.1", "1.2.3", "01.1.1.1", "a.b.c.d"])
def test_ipv4_invalid(bad):
    assert normalize_ipv4(bad) is None


def test_domain_case_and_trailing_dot():
    assert normalize_domain("EXAMPLE.org") == "example.org"
    assert normalize_domain("example.org.") == "example.org"


@pytest.mark.parametrize("bad", ["localhost", "1.2.3.4", "-bad.example.org",
                                 "exa_mple.org", "a..b.org", ""])
def test_domain_invalid(bad):
    assert normalize_domain(bad) is None


def test_url_lowercases_scheme_and_host_only():
    assert normalize_url("HTTPS://EXAMPLE.org/Path?Q=1") == "https://example.org/Path?Q=1"


def test_url_keeps_userinfo_and_port():
    assert normalize_url("http://user:pw@Example.org:8080/a") == "http://user:pw@example.org:8080/a"


def test_url_with_ip_host():
    assert normalize_url("http://198.51.100.24/x") == "http://198.51.100.24/x"


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "http://", "http://999.1.1.1/a"])
def test_url_invalid(bad):
    assert normalize_url(bad) is None


def test_windows_path_case_insensitive_key():
    assert normalize_path("C:/Lab/Sample.dat") == r"c:\lab\sample.dat"
    assert normalize_path(r"c:\LAB\sample.dat") == r"c:\lab\sample.dat"


def test_unix_path_keeps_case():
    assert normalize_path("/etc/Passwd/") == "/etc/Passwd"
    assert normalize_path("/") == "/"


def test_relative_path_rejected():
    assert normalize_path("relative/path") is None