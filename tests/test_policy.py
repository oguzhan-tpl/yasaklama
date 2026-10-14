import pytest
from dnslib import DNSRecord, QTYPE, RCODE

from controller import PolicyResolver, matches_blocked_domain, normalize_domain


def test_normalizes_case_and_trailing_dot():
    assert normalize_domain("  WWW.Example.COM. ") == "www.example.com"


def test_accepts_full_web_url_and_extracts_hostname():
    assert normalize_domain("https://www.example.com/a/path?q=1") == "www.example.com"


def test_accepts_url_without_scheme():
    assert normalize_domain("news.example.com/article") == "news.example.com"


def test_normalizes_international_domain_name():
    assert normalize_domain("bücher.de") == "xn--bcher-kva.de"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://example.com:bad/path",
        "*.example.com",
        "example..com",
        "-bad.example",
        "bad-.example",
        "127.0.0.1",
        "https://127.0.0.1/path",
    ],
)
def test_rejects_invalid_domain_input(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


def test_block_rule_matches_apex_and_subdomains():
    blocked = {"example.com"}
    assert matches_blocked_domain("example.com.", blocked)
    assert matches_blocked_domain("www.example.com.", blocked)
    assert matches_blocked_domain("classroom.www.example.com", blocked)


def test_block_rule_does_not_match_lookalike_domains():
    blocked = {"example.com"}
    assert not matches_blocked_domain("notexample.com.", blocked)
    assert not matches_blocked_domain("example.com.attacker.test.", blocked)
    assert not matches_blocked_domain("another.test.", blocked)


def test_query_domain_is_normalized_before_matching():
    assert matches_blocked_domain("WWW.BÜCHER.DE.", {"xn--bcher-kva.de"})


def test_dns_block_response_maps_a_query_to_portal_ip():
    resolver = PolicyResolver("127.0.0.1", block_ip="192.0.2.10")
    request = DNSRecord.question("social.example", "A")
    response = resolver._blocked_reply(request, "social.example")
    assert response.header.rcode == RCODE.NOERROR
    assert response.rr
    assert QTYPE[response.rr[0].rtype] == "A"
    assert str(response.rr[0].rdata) == "192.0.2.10"
    assert response.rr[0].ttl == 5


def test_dns_block_response_returns_no_aaaa_when_http_portal_is_enabled():
    resolver = PolicyResolver("127.0.0.1", block_ip="192.0.2.10")
    request = DNSRecord.question("social.example", "AAAA")
    response = resolver._blocked_reply(request, "social.example")
    assert response.header.rcode == RCODE.NOERROR
    assert response.rr == []


def test_dns_block_response_uses_nxdomain_without_portal_ip():
    resolver = PolicyResolver("127.0.0.1")
    request = DNSRecord.question("social.example", "A")
    response = resolver._blocked_reply(request, "social.example")
    assert response.header.rcode == RCODE.NXDOMAIN


def test_resolver_uses_block_policy_and_redirects_blocked_subdomain(monkeypatch):
    import controller
    from types import SimpleNamespace

    resolver = PolicyResolver("127.0.0.1", block_ip="192.0.2.10")
    monkeypatch.setattr(resolver, "_domains", lambda: {"example.com"})
    monkeypatch.setattr(controller, "record_block", lambda client_ip, domain: None)
    handler = SimpleNamespace(client_address=("192.0.2.33", 53000))
    response = resolver.resolve(DNSRecord.question("video.example.com", "A"), handler)

    assert response.header.rcode == RCODE.NOERROR
    assert str(response.rr[0].rdata) == "192.0.2.10"


def test_http_block_page_has_official_notice_and_safe_host_text():
    from starlette.requests import Request
    from controller import blocked_landing_page

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/blocked/path",
        "raw_path": b"/blocked/path",
        "query_string": b"",
        "headers": [(b"host", b"social.example")],
        "client": ("192.0.2.33", 50000),
        "server": ("192.0.2.10", 80),
    }
    response = blocked_landing_page("blocked/path", Request(scope))
    page = response.body.decode("utf-8")

    assert response.status_code == 403
    assert "Bu web sitesine erişim engellendi" in page
    assert "social.example" in page
    assert "Kurum ağı" in page
