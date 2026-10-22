from src.extractors import extract_from_text

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def pairs(text):
    return [(c.ioc_type, c.canonical) for c in extract_from_text(text)]


def test_url_and_derived_host():
    got = pairs("see http://Evil.example.org/a.php?x=1 now")
    assert ("url", "http://evil.example.org/a.php?x=1") in got
    assert got.count(("domain", "evil.example.org")) == 1
    assert not any(t == "domain" and v == "a.php" for t, v in got)


def test_defanged_url_and_ip_keep_original():
    cands = extract_from_text("hxxps://evil[.]example[.]org/p and 198[.]51[.]100[.]24")
    url = next(c for c in cands if c.ioc_type == "url")
    assert url.canonical == "https://evil.example.org/p"
    assert url.original == "hxxps://evil[.]example[.]org/p"
    assert url.method.endswith("+refang")
    ip = next(c for c in cands if c.ioc_type == "ipv4")
    assert ip.canonical == "198.51.100.24"
    assert ip.original == "198[.]51[.]100[.]24"


def test_defanged_email_domain():
    assert ("domain", "example.org") in pairs("analyst[@]example[.]org")


def test_hash_types_not_double_counted():
    assert pairs(f"hash {SHA256}") == [("sha256", SHA256)]
    assert pairs(f"md5 {MD5}") == [("md5", MD5)]


def test_uppercase_hash_normalized():
    assert pairs(SHA256.upper()) == [("sha256", SHA256)]


def test_hash_inside_longer_hex_rejected():
    assert pairs("a" * 50) == []


def test_all_digit_hash_rejected():
    assert pairs("1" * 32) == []


def test_invalid_ip_and_versions_rejected():
    assert pairs("999.1.1.1") == []
    assert pairs("version v1.2.3.4") == []
    assert pairs("1.2.3.4.5") == []


def test_file_name_lookalikes_not_domains():
    assert pairs("config.json setup.exe report.final.txt") == []


def test_domain_case_preserved_in_original():
    cands = extract_from_text("Contacted EXAMPLE.org today")
    assert [(c.canonical, c.original) for c in cands] == [("example.org", "EXAMPLE.org")]


def test_windows_path():
    cands = extract_from_text(r"dropped C:\Lab\Sample.dat then")
    assert [(c.ioc_type, c.canonical, c.original) for c in cands] == [
        ("filepath", r"c:\lab\sample.dat", r"C:\Lab\Sample.dat")
    ]


def test_unix_path():
    assert pairs("wrote /tmp/x/payload.bin") == [("filepath", "/tmp/x/payload.bin")]


def test_non_paths_ignored():
    assert pairs("and/or 10/22/2026 N/A") == []


def test_trailing_punctuation_stripped():
    got = pairs("Visit http://example.org/a, then 198.51.100.24.")
    assert ("url", "http://example.org/a") in got
    assert ("ipv4", "198.51.100.24") in got


def test_line_numbers():
    cands = extract_from_text("nothing here\nexample.org\n")
    assert [(c.canonical, c.line_number) for c in cands] == [("example.org", 2)]


def test_empty_text():
    assert extract_from_text("") == []