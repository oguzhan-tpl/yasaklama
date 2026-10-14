import pytest

from controller import matches_blocked_domain, normalize_domain


def test_normalizes_case_and_trailing_dot():
    assert normalize_domain("  WWW.Example.COM. ") == "www.example.com"


def test_normalizes_international_domain_name():
    assert normalize_domain("bücher.de") == "xn--bcher-kva.de"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://example.com",
        "example.com/path",
        "*.example.com",
        "example..com",
        "-bad.example",
        "bad-.example",
        "127.0.0.1",
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
