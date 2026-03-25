from pq_surface_audit.scanner import parse_target


def test_parse_target_url():
    t = parse_target("https://example.com:4443")
    assert t.hostname == "example.com"
    assert t.port == 4443
    assert t.scheme == "https"


def test_parse_target_host_port():
    t = parse_target("example.com:443")
    assert t.hostname == "example.com"
    assert t.port == 443
