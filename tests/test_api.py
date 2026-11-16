import json
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from custom_components.cloudflare_abuse_monitor import api

TOKEN = "test-api-token-0123456789"
HEADERS = api.get_headers(TOKEN)


def response(payload, status=200):
    r = MagicMock(status_code=status)
    r.json.return_value = payload
    r.text = json.dumps(payload)
    return r


def test_bearer_headers_only():
    assert HEADERS == {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def test_create_token_url_format():
    url = urlparse(api.CREATE_TOKEN_URL)
    assert (url.scheme, url.netloc, url.path) == ("https", "dash.cloudflare.com", "/")
    query = parse_qs(url.query)
    assert query["to"] == ["/:account/api-tokens"]
    assert query["name"] == ["Home Assistant Abuse Monitor"]
    keys = json.loads(query["permissionGroupKeys"][0])
    assert keys == [
        {"key": "c8fed203ed3043cba015a93ad1616f1f", "type": "read"},   # Zone Read
        {"key": "9c88f9c5bce24ce7af9a958ba9c504db", "type": "read"},   # Analytics Read
        {"key": "3030687196b94b638145a3953da2b699", "type": "edit"},   # Zone Settings
        {"key": "fb6778dc191143babbfaa57993f1d275", "type": "edit"},   # Zone WAF
        {"key": "2edbf20661fd4661b0fe10e9e12f485c", "type": "edit"},   # Account Filter Lists
    ]
    assert " " not in api.CREATE_TOKEN_URL and '"' not in api.CREATE_TOKEN_URL


def test_list_items_follow_every_page():
    pages = [
        response({
            "success": True,
            "result": [{"ip": f"198.51.100.{i}", "id": f"i{i}"} for i in range(25)],
            "result_info": {"cursors": {"after": "c1"}},
        }),
        response({"success": True, "result": [{"ip": "203.0.113.7", "id": "x"}], "result_info": {"cursors": {}}}),
    ]
    with patch.object(api.requests, "request", side_effect=pages) as req:
        items = api.get_list_items("acct", "list", HEADERS)
    assert len(items) == 26 and items["203.0.113.7"] == "x"
    assert req.call_args_list[1].kwargs["params"]["cursor"] == "c1"
    with patch.object(api.requests, "request", return_value=pages[1]):
        assert api.get_current_list_ips("acct", "list", HEADERS) == {"203.0.113.7"}


def test_remove_list_items_sends_ids():
    with patch.object(api.requests, "request", return_value=response({"success": True})) as req:
        api.remove_list_items("acct", "list", ["x"], HEADERS)
    assert req.call_args.args[0] == "DELETE"
    assert req.call_args.kwargs["json"] == {"items": [{"id": "x"}]}


def test_traffic_with_no_groups_yet_is_zero():
    payload = {"data": {"viewer": {"zones": [{"httpRequests1hGroups": []}]}}, "errors": None}
    with patch.object(api.requests, "request", return_value=response(payload)):
        summary = api.fetch_today_traffic_summary(HEADERS, "zone")
    assert summary["requests"] == 0


def test_graphql_error_raises():
    payload = {"data": None, "errors": [{"message": "unknown field"}]}
    with patch.object(api.requests, "request", return_value=response(payload)):
        with pytest.raises(api.CloudflareApiError, match="unknown field") as err:
            api.get_skip_ips("zone", "a", "b", HEADERS)
    assert not isinstance(err.value, api.CloudflareAuthError)


def test_graphql_not_authorized_is_an_auth_error():
    payload = {"data": None, "errors": [{"message": "not authorized for that account"}]}
    with patch.object(api.requests, "request", return_value=response(payload)):
        with pytest.raises(api.CloudflareAuthError):
            api.probe_analytics(HEADERS, "zone")


def test_rules_lists_keeps_only_ip_lists():
    payload = {"success": True, "result": [
        {"name": "block_ips", "id": "1", "kind": "ip"},
        {"name": "redirects", "id": "2", "kind": "redirect"},
    ]}
    with patch.object(api.requests, "request", return_value=response(payload)):
        assert api.fetch_rules_lists("acct", HEADERS) == {"block_ips": "1"}


@pytest.mark.parametrize("status", [401, 403])
def test_auth_status_raises_auth_error_without_the_token(status):
    payload = {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}
    with patch.object(api.requests, "request", return_value=response(payload, status)):
        with pytest.raises(api.CloudflareAuthError) as err:
            api.fetch_zones(HEADERS)
    assert TOKEN not in str(err.value)
    assert "Authentication error" in str(err.value)


def test_bad_token_400_is_an_auth_error():
    payload = {"success": False, "errors": [{"code": 6003, "message": "Invalid request headers"}]}
    with patch.object(api.requests, "request", return_value=response(payload, 400)):
        with pytest.raises(api.CloudflareAuthError):
            api.verify_user_token(HEADERS)


def test_server_error_is_not_an_auth_error():
    with patch.object(api.requests, "request", return_value=response({"success": False}, 502)):
        with pytest.raises(api.CloudflareApiError) as err:
            api.get_security_level("zone", HEADERS)
    assert not isinstance(err.value, api.CloudflareAuthError)


def test_missing_entrypoint_is_none():
    with patch.object(api.requests, "request", return_value=response({"success": False}, 404)):
        assert api.get_custom_entrypoint("zone", HEADERS) is None


def test_verify_returns_status():
    payload = {"success": True, "result": {"id": "t", "status": "active"}}
    with patch.object(api.requests, "request", return_value=response(payload)) as req:
        assert api.verify_user_token(HEADERS) == "active"
    assert req.call_args.args[1].endswith("/user/tokens/verify")
    assert req.call_args.kwargs["headers"]["Authorization"] == f"Bearer {TOKEN}"


def test_abuseipdb_429_is_rate_limited():
    with patch.object(api.requests, "get", return_value=response({}, status=429)):
        with pytest.raises(api.AbuseIPDBRateLimited):
            api.check_abuse_ip("203.0.113.1", "key")


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (200, {"data": {"abuseConfidenceScore": 0}}, "ok"),
        (401, {"errors": [{"detail": "Authentication failed"}]}, "invalid"),
        (429, {}, "rate_limited"),
    ],
)
def test_validate_abuseipdb_key(status, payload, expected):
    with patch.object(api.requests, "get", return_value=response(payload, status)) as get:
        assert api.validate_abuseipdb_key("key") == expected
    assert get.call_count == 1


# --- rule detection (block by exact expression, skip only when broad) --------------------

ALL_COUNTRIES = " ".join(f'"{a}{b}"' for a in "ABCDEFGHIJKLMNOP" for b in "ABCDEFGHIJKLMN")  # 224 codes


@pytest.mark.parametrize(
    ("expression", "counts"),
    [
        ("(ip.src in $block_ips)", True),
        ("ip.src  in  $BLOCK_IPS", True),
        ("((ip.src in $block_ips))", True),
        ("(ip.src in $block_ips_old)", False),
        ("(ip.src in $block_ips and http.host eq \"example.com\")", False),
        ("not (ip.src in $block_ips)", False),
    ],
)
def test_block_rule_needs_the_exact_expression(expression, counts):
    rule = {"action": "block", "expression": expression, "enabled": True}
    assert api.is_block_rule(rule, "block_ips") is counts


@pytest.mark.parametrize(
    ("rule", "counts"),
    [
        ({"ref": "cfam_skip_log", "action": "skip"}, True),
        ({"action": "skip", "expression": "not (ip.src in $block_ips)"}, True),
        ({"action": "skip", "expression": "true"}, True),
        ({"action": "skip", "expression": f"(ip.geoip.country in {{{ALL_COUNTRIES}}})",
          "action_parameters": {"ruleset": "current"}}, True),
        # Narrow skips: an uptime monitor, one country, one path.
        ({"action": "skip", "expression": "(ip.src eq 203.0.113.5)", "action_parameters": {"ruleset": "current"}}, False),
        ({"action": "skip", "expression": "(ip.geoip.country in {\"US\"})"}, False),
        ({"action": "skip", "expression": "(http.request.uri.path eq \"/health\")",
          "action_parameters": {"phases": ["http_ratelimit"]}}, False),
        # Broad, but disabled or not logged: no firewall events.
        ({"action": "skip", "expression": "true", "enabled": False}, False),
        ({"action": "skip", "expression": "true", "logging": {"enabled": False}}, False),
    ],
)
def test_skip_rule_must_be_broad(rule, counts):
    assert api.is_skip_rule(rule, "block_ips") is counts


def test_missing_rules_matching():
    assert [r["ref"] for r in api.missing_rules(None, "block_ips")] == ["cfam_block_ips", "cfam_skip_log"]
    narrow = {"rules": [
        {"action": "block", "expression": "(ip.src in $block_ips)", "enabled": True},
        {"action": "skip", "expression": "(ip.src eq 203.0.113.5)", "enabled": True},
    ]}
    assert [r["ref"] for r in api.missing_rules(narrow, "block_ips")] == ["cfam_skip_log"]


def test_block_goes_before_a_skip_of_the_rest_of_the_ruleset():
    ruleset = {"rules": [
        {"id": "r1", "action": "log", "expression": "true"},
        {"id": "r2", "action": "skip", "expression": "true", "enabled": False,
         "action_parameters": {"ruleset": "current"}},
        {"id": "r3", "action": "skip", "expression": "true", "action_parameters": {"phases": ["http_ratelimit"]}},
        {"id": "r4", "action": "skip", "expression": "true", "action_parameters": {"ruleset": "current"}},
    ]}
    assert api.block_rule_position(ruleset) == "r4"
    assert api.block_rule_position({"rules": [{"id": "r1", "action": "block"}]}) is None
    assert api.block_rule_position(None) is None


def test_add_custom_rule_position():
    with patch.object(api.requests, "request", return_value=response({"success": True})) as req:
        api.add_custom_rule("zone", "rs", api.block_rule("block_ips"), HEADERS, before="r4")
        assert req.call_args.kwargs["json"]["position"] == {"before": "r4"}
        api.add_custom_rule("zone", "rs", api.skip_rule("block_ips"), HEADERS)
        assert "position" not in req.call_args.kwargs["json"]


# --- GraphQL: only real authorization errors start a reauth ------------------------------

@pytest.mark.parametrize(
    ("error", "auth"),
    [
        ({"message": "not authorized for that account", "extensions": {"code": "authz"}}, True),
        ({"message": "something", "extensions": {"code": "authn"}}, True),
        ({"message": "zone 'x' does not have access to the path", "extensions": {"code": "authz-plan"}}, False),
        ({"message": "zone does not have access to the path"}, False),
        ({"message": "you lack permission to query data older than 1 day"}, False),
        ({"message": "not authorized for that account"}, True),
    ],
)
def test_graphql_auth_detection(error, auth):
    payload = {"data": None, "errors": [error]}
    with patch.object(api.requests, "request", return_value=response(payload)):
        with pytest.raises(api.CloudflareApiError) as err:
            api.probe_analytics(HEADERS, "zone")
    assert isinstance(err.value, api.CloudflareAuthError) is auth


# --- secrets never leave through a requests error ------------------------------------------

@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("Abc_123-xyz", True),
        ("0123456789abcdef", True),
        ("abc\ndef", False),
        ("abc def", False),
        ("abc\tdef", False),
        ("", False),
    ],
)
def test_valid_secret(value, ok):
    assert api.valid_secret(value) is ok


def test_invalid_header_never_carries_the_token():
    bad = api.get_headers("secret-part\nrest")
    leak = api.requests.exceptions.InvalidHeader(f"Invalid header value {bad['Authorization']!r}")
    with patch.object(api.requests, "request", side_effect=leak):
        with pytest.raises(api.CloudflareAuthError) as err:
            api.fetch_zones(bad)
    assert "secret-part" not in str(err.value)
    assert err.value.__cause__ is None and err.value.__suppress_context__


def test_invalid_header_never_carries_the_abuseipdb_key():
    leak = api.requests.exceptions.InvalidHeader("Invalid header value 'key-part\nrest'")
    with patch.object(api.requests, "get", side_effect=leak):
        with pytest.raises(api.AbuseIPDBError) as err:
            api.check_abuse_ip("203.0.113.1", "key-part\nrest")
    assert "key-part" not in str(err.value)
