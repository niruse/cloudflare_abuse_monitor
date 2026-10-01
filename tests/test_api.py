from unittest.mock import MagicMock, patch

import pytest

from custom_components.cloudflare_abuse_monitor import api


def response(payload, status=200):
    r = MagicMock(status_code=status)
    r.json.return_value = payload
    return r


def test_list_ips_follows_every_page():
    pages = [
        response({
            "result": [{"ip": f"198.51.100.{i}"} for i in range(25)],
            "result_info": {"cursors": {"after": "c1"}},
        }),
        response({"result": [{"ip": "203.0.113.7"}], "result_info": {"cursors": {}}}),
    ]
    with patch.object(api.requests, "get", side_effect=pages) as get:
        ips = api.get_current_list_ips("acct", "list", {})
    assert len(ips) == 26
    assert get.call_args_list[1].kwargs["params"]["cursor"] == "c1"


def test_traffic_with_no_groups_yet_is_zero():
    payload = {"data": {"viewer": {"zones": [{"httpRequests1hGroups": []}]}}, "errors": None}
    with patch.object(api.requests, "post", return_value=response(payload)):
        summary = api.fetch_today_traffic_summary("owner@example.com", "key", "zone")
    assert summary["requests"] == 0


def test_graphql_error_raises():
    payload = {"data": None, "errors": [{"message": "no access"}]}
    with patch.object(api.requests, "post", return_value=response(payload)):
        with pytest.raises(api.CloudflareApiError, match="no access"):
            api.get_skip_ips("zone", "a", "b", {})


def test_rules_lists_keeps_only_ip_lists():
    payload = {"result": [
        {"name": "block_ips", "id": "1", "kind": "ip"},
        {"name": "redirects", "id": "2", "kind": "redirect"},
    ]}
    with patch.object(api.requests, "get", return_value=response(payload)):
        assert api.fetch_rules_lists("acct", {}) == {"block_ips": "1"}


def test_bad_credentials_are_not_a_network_error():
    with patch.object(api.requests, "get", return_value=response({"success": False}, status=400)):
        assert api.fetch_zones("owner@example.com", "wrong")["success"] is False


def test_abuseipdb_429_is_rate_limited():
    with patch.object(api.requests, "get", return_value=response({}, status=429)):
        with pytest.raises(api.AbuseIPDBRateLimited):
            api.check_abuse_ip("203.0.113.1", "key")
