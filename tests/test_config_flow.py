"""Setup with a scoped token: probes, list and rule creation, reconfigure and reauth."""
import logging
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from homeassistant.config_entries import SOURCE_USER
from homeassistant.data_entry_flow import FlowResultType

from custom_components.cloudflare_abuse_monitor import api

from .conftest import ABUSE_KEY, ACCOUNT_ID, DOMAIN, LEGACY_DATA, LIST_ID, OLD_EMAIL, TOKEN, ZONE_ID

API = "custom_components.cloudflare_abuse_monitor.api"
SETUP = "custom_components.cloudflare_abuse_monitor.async_setup_entry"

USER_INPUT = {"api_token": TOKEN, "abuseipdb_token": ABUSE_KEY}
ZONE = {"id": ZONE_ID, "name": "example.com", "account": {"id": ACCOUNT_ID}}
OTHER_ZONE = {"id": "1" * 32, "name": "example.org", "account": {"id": ACCOUNT_ID}}
NEW_LIST = {"id": LIST_ID, "name": "block_ips", "kind": "ip"}
RULESET_ID = "abcdefabcdefabcdefabcdefabcdef12"
ALL_COUNTRIES = " ".join(f'"{a}{b}"' for a in "ABCDEFGHIJKLMNOP" for b in "ABCDEFGHIJKLMN")  # 224 codes


def auth_error(*_args, **_kwargs):
    raise api.CloudflareAuthError("HTTP 403: Authentication error", 403)


@pytest.fixture
def flow_api():
    """A fresh account: valid token, one zone, no lists, no custom rules, AbuseIPDB key OK."""
    with patch(SETUP, return_value=True), flow_api_mocks() as m:
        yield m


@contextmanager
def flow_api_mocks():
    """The setup-flow API calls, mocked; entry setup itself is left real."""
    names = [
        "verify_user_token", "verify_account_token", "fetch_zones", "probe_analytics",
        "get_security_level", "set_security_level", "fetch_ip_lists", "create_ip_list",
        "update_list_description", "get_custom_entrypoint", "create_custom_entrypoint",
        "add_custom_rule", "validate_abuseipdb_key",
        "fetch_zone_plan", "update_custom_rule", "delete_custom_rule",
    ]
    patches = {name: patch(f"{API}.{name}") for name in names}
    mocks = {name: p.start() for name, p in patches.items()}
    m = SimpleNamespace(**mocks)
    m.verify_user_token.return_value = "active"
    m.verify_account_token.return_value = "active"
    m.fetch_zones.return_value = [ZONE]
    m.probe_analytics.return_value = None
    m.get_security_level.return_value = "medium"
    m.fetch_ip_lists.return_value = []
    m.create_ip_list.return_value = NEW_LIST
    m.get_custom_entrypoint.return_value = None
    m.validate_abuseipdb_key.return_value = "ok"
    m.fetch_zone_plan.return_value = {"legacy_id": "free", "name": "Free Website"}
    try:
        yield m
    finally:
        for p in patches.values():
            p.stop()


async def start(hass, user_input=USER_INPUT):
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    return await hass.config_entries.flow.async_configure(result["flow_id"], user_input)


async def test_form_has_create_token_link(hass, flow_api):
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    placeholders = result["description_placeholders"]
    assert placeholders["token_url"] == api.CREATE_TOKEN_URL
    for _, _, name in api.TOKEN_PERMISSIONS:
        assert name in placeholders["permissions"]
    assert set(result["data_schema"].schema) == {"api_token", "abuseipdb_token"}


async def test_happy_path_creates_list_and_rules(hass, flow_api):
    result = await start(hass)

    assert result["type"] is FlowResultType.CREATE_ENTRY
    data = result["data"]
    assert data["api_token"] == TOKEN
    assert data["abuseipdb_token"] == ABUSE_KEY
    assert "email" not in data and "global_token" not in data
    assert data["zones"] == [{
        "zone_id": ZONE_ID, "zone_name": "example.com", "account_id": ACCOUNT_ID,
        "list_name": "block_ips", "list_id": LIST_ID, "uid_prefix": ZONE_ID,
    }]
    assert "zone_id" not in data and "uid_prefix" not in data
    assert data["mode"] == "Monitor" and data["abuse_confidence_score"] == 100.0
    assert data["recheck_days"] == 7 and data["scan_interval_minutes"] == 1
    assert result["result"].unique_id == ZONE_ID

    # Settings probe writes the level it just read.
    assert flow_api.set_security_level.call_args.args[2] == "medium"
    flow_api.create_ip_list.assert_called_once()
    assert flow_api.create_ip_list.call_args.args[1] == "block_ips"
    # No entrypoint yet: one PUT with both rules, block first.
    rules = flow_api.create_custom_entrypoint.call_args.args[1]
    assert [r["ref"] for r in rules] == ["cfam_block_ips", "cfam_skip_log"]
    assert rules[0]["expression"] == "(ip.src in $block_ips)" and rules[0]["action"] == "block"
    assert rules[1]["action"] == "skip" and rules[1]["expression"] == "not (ip.src in $block_ips)"
    flow_api.add_custom_rule.assert_not_called()
    flow_api.validate_abuseipdb_key.assert_called_once_with(ABUSE_KEY)

    # The same zone twice is refused.
    again = await start(hass)
    assert again["type"] is FlowResultType.ABORT
    assert again["reason"] == "already_configured"


async def test_existing_list_and_rules_are_reused_not_duplicated(hass, flow_api):
    flow_api.fetch_ip_lists.return_value = [
        {"id": "other", "name": "allow", "kind": "ip"},
        {"id": LIST_ID, "name": "block_ips", "kind": "ip", "description": "mine"},
    ]
    flow_api.get_custom_entrypoint.return_value = {
        "id": RULESET_ID,
        "rules": [
            {"action": "block", "expression": "(ip.src  in  $BLOCK_IPS)", "enabled": True},
            # The v1.5 README's "Skip by country" rule, every country listed.
            {"action": "skip", "expression": f"(ip.geoip.country in {{{ALL_COUNTRIES}}})", "enabled": True},
        ],
    }
    result = await start(hass)

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"]["zones"][0]["list_id"] == LIST_ID
    flow_api.create_ip_list.assert_not_called()
    # Edit is proven by writing the description back unchanged.
    flow_api.update_list_description.assert_called_once()
    assert flow_api.update_list_description.call_args.args[1:3] == (LIST_ID, "mine")
    flow_api.create_custom_entrypoint.assert_not_called()
    flow_api.add_custom_rule.assert_not_called()


async def test_only_the_missing_rule_is_added(hass, flow_api):
    flow_api.fetch_ip_lists.return_value = [NEW_LIST]
    flow_api.get_custom_entrypoint.return_value = {
        "id": RULESET_ID,
        "rules": [{"ref": "cfam_block_ips", "action": "block", "expression": "x", "enabled": True}],
    }
    result = await start(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    flow_api.create_custom_entrypoint.assert_not_called()  # a PUT would wipe the user's rules
    flow_api.add_custom_rule.assert_called_once()
    assert flow_api.add_custom_rule.call_args.args[1] == RULESET_ID
    assert flow_api.add_custom_rule.call_args.args[2]["ref"] == "cfam_skip_log"


async def test_narrow_existing_skip_still_gets_our_skip_rule(hass, flow_api):
    """A skip for one uptime-monitor IP would leave the sensors near-empty: add ours."""
    flow_api.fetch_ip_lists.return_value = [NEW_LIST]
    flow_api.get_custom_entrypoint.return_value = {
        "id": RULESET_ID,
        "rules": [
            {"id": "r-monitor", "action": "skip", "expression": "(ip.src eq 203.0.113.5)",
             "action_parameters": {"ruleset": "current"}, "enabled": True},
            {"id": "r-block", "action": "block", "expression": "(ip.src in $block_ips)", "enabled": True},
        ],
    }
    result = await start(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    flow_api.add_custom_rule.assert_called_once()
    args = flow_api.add_custom_rule.call_args.args
    assert args[2]["ref"] == "cfam_skip_log" and args[4] is None  # appended last


async def test_block_rule_goes_before_an_existing_broad_skip(hass, flow_api):
    """After a skip of the rest of the ruleset a new Block rule would never run."""
    flow_api.fetch_ip_lists.return_value = [NEW_LIST]
    flow_api.get_custom_entrypoint.return_value = {
        "id": RULESET_ID,
        "rules": [
            {"id": "r-log", "action": "log", "expression": "true", "enabled": True},
            {"id": "r-countries", "action": "skip", "expression": f"(ip.geoip.country in {{{ALL_COUNTRIES}}})",
             "action_parameters": {"ruleset": "current"}, "enabled": True},
        ],
    }
    result = await start(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    flow_api.create_custom_entrypoint.assert_not_called()
    flow_api.add_custom_rule.assert_called_once()  # the broad skip already logs visitors
    args = flow_api.add_custom_rule.call_args.args
    assert args[2]["ref"] == "cfam_block_ips"
    assert args[4] == "r-countries"


@pytest.mark.parametrize(
    ("user_input", "error"),
    [
        ({"api_token": "abc\ndef", "abuseipdb_token": ABUSE_KEY}, "invalid_token"),
        ({"api_token": TOKEN, "abuseipdb_token": "abc\tdef"}, "invalid_abuseipdb_key"),
    ],
)
async def test_pasted_control_characters_are_refused_before_any_request(hass, flow_api, user_input, error):
    result = await start(hass, user_input)
    assert result["errors"] == {"base": error}
    flow_api.verify_user_token.assert_not_called()
    flow_api.validate_abuseipdb_key.assert_not_called()


async def test_rules_present_with_read_only_waf_is_enough(hass, flow_api):
    flow_api.fetch_ip_lists.return_value = [NEW_LIST]
    flow_api.get_custom_entrypoint.return_value = {
        "id": RULESET_ID,
        "rules": [
            {"ref": "cfam_block_ips", "action": "block", "expression": "(ip.src in $block_ips)"},
            {"ref": "cfam_skip_log", "action": "skip", "expression": "not (ip.src in $block_ips)"},
        ],
    }
    flow_api.add_custom_rule.side_effect = auth_error
    flow_api.create_custom_entrypoint.side_effect = auth_error
    result = await start(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_several_zones_ask_which(hass, flow_api):
    flow_api.fetch_zones.return_value = [ZONE, OTHER_ZONE]
    result = await start(hass)
    assert result["step_id"] == "zones"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"zones": [OTHER_ZONE["id"]]})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert [zone["zone_name"] for zone in result["data"]["zones"]] == ["example.org"]


@pytest.mark.parametrize(
    ("mock_name", "permission", "writes_skipped"),
    [
        ("probe_analytics", "Zone > Analytics > Read", True),
        ("set_security_level", "Zone > Zone Settings > Edit", True),
        ("get_security_level", "Zone > Zone Settings > Edit", True),
        ("fetch_ip_lists", "Account > Account Filter Lists > Edit", True),
        ("get_custom_entrypoint", "Zone > Zone WAF > Edit", True),
        ("create_ip_list", "Account > Account Filter Lists > Edit", False),
        ("create_custom_entrypoint", "Zone > Zone WAF > Edit", False),
    ],
)
async def test_each_missing_permission_is_named(hass, flow_api, mock_name, permission, writes_skipped):
    getattr(flow_api, mock_name).side_effect = auth_error
    result = await start(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {"base": "missing_permissions"}
    assert permission in result["description_placeholders"]["missing"]
    if writes_skipped:
        flow_api.create_ip_list.assert_not_called()
        flow_api.create_custom_entrypoint.assert_not_called()


async def test_all_missing_permissions_in_one_error(hass, flow_api):
    for name in ("probe_analytics", "set_security_level", "fetch_ip_lists", "get_custom_entrypoint"):
        getattr(flow_api, name).side_effect = auth_error
    result = await start(hass)
    missing = result["description_placeholders"]["missing"]
    assert missing.count(">") == 8  # four "A > B > C" names


async def test_existing_list_without_edit_is_named(hass, flow_api):
    flow_api.fetch_ip_lists.return_value = [NEW_LIST]
    flow_api.update_list_description.side_effect = auth_error
    result = await start(hass)
    assert result["errors"] == {"base": "missing_permissions"}
    assert "Account Filter Lists" in result["description_placeholders"]["missing"]


async def test_invalid_token(hass, flow_api):
    flow_api.verify_user_token.side_effect = auth_error
    flow_api.fetch_zones.side_effect = auth_error
    result = await start(hass)
    assert result["errors"] == {"base": "invalid_token"}


async def test_inactive_token(hass, flow_api):
    flow_api.verify_user_token.return_value = "expired"
    result = await start(hass)
    assert result["errors"] == {"base": "token_inactive"}


async def test_token_without_zone_read(hass, flow_api):
    flow_api.fetch_zones.return_value = []
    result = await start(hass)
    assert result["errors"] == {"base": "no_zone"}


async def test_account_owned_token_is_verified_per_account(hass, flow_api):
    flow_api.verify_user_token.side_effect = auth_error
    result = await start(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    flow_api.verify_account_token.assert_called_once()
    assert flow_api.verify_account_token.call_args.args[0] == ACCOUNT_ID


async def test_bad_account_token(hass, flow_api):
    flow_api.verify_user_token.side_effect = auth_error
    flow_api.verify_account_token.side_effect = auth_error
    result = await start(hass)
    assert result["errors"] == {"base": "invalid_token"}


async def test_invalid_abuseipdb_key(hass, flow_api):
    flow_api.validate_abuseipdb_key.return_value = "invalid"
    result = await start(hass)
    assert result["errors"] == {"base": "invalid_abuseipdb_key"}
    flow_api.create_ip_list.assert_not_called()


async def test_abuseipdb_quota_used_up_is_accepted(hass, flow_api):
    flow_api.validate_abuseipdb_key.return_value = "rate_limited"
    result = await start(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_list_limit_offers_existing_lists(hass, flow_api):
    flow_api.fetch_ip_lists.return_value = [{"id": "aaaa", "name": "my_list", "kind": "ip"}]
    flow_api.create_ip_list.side_effect = api.CloudflareApiError("HTTP 400: limit reached", 400)
    result = await start(hass)
    assert result["step_id"] == "list_select"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"list_name": "my_list"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"]["zones"][0]["list_id"] == "aaaa"
    rules = flow_api.create_custom_entrypoint.call_args.args[1]
    assert rules[0]["expression"] == "(ip.src in $my_list)"


async def test_rule_limit(hass, flow_api):
    flow_api.create_custom_entrypoint.side_effect = api.CloudflareApiError("HTTP 400: exceeded", 400)
    result = await start(hass)
    assert result["errors"] == {"base": "rule_create_failed"}


async def test_connection_error_never_logs_the_token(hass, flow_api, caplog):
    caplog.set_level(logging.DEBUG)
    flow_api.fetch_zones.side_effect = api.CloudflareApiError("Zones: HTTP 502: no detail", 502)
    result = await start(hass)
    assert result["errors"] == {"base": "connection_error"}
    flow_api.fetch_zones.side_effect = None
    flow_api.create_custom_entrypoint.side_effect = api.CloudflareApiError("HTTP 400: bad", 400)
    await start(hass)
    assert "Could not" in caplog.text
    assert TOKEN not in caplog.text and ABUSE_KEY not in caplog.text


# --- reconfigure and reauth -------------------------------------------------------------

async def test_reconfigure_moves_a_global_key_entry_to_a_token(hass, flow_api, make_entry):
    entry = make_entry(data=LEGACY_DATA, minor_version=1)
    flow_api.fetch_ip_lists.return_value = [NEW_LIST]
    result = await entry.start_reconfigure_flow(hass)
    assert result["step_id"] == "reconfigure"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"api_token": TOKEN})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert entry.data["api_token"] == TOKEN
    assert "email" not in entry.data and "global_token" not in entry.data
    zone = entry.data["zones"][0]
    assert zone["uid_prefix"] == OLD_EMAIL and zone["legacy_storage"] is True
    assert zone["list_id"] == LIST_ID
    assert entry.data["abuseipdb_token"] == ABUSE_KEY
    flow_api.create_ip_list.assert_not_called()


async def test_reconfigure_wrong_zone(hass, flow_api, make_entry):
    entry = make_entry()
    flow_api.fetch_zones.return_value = [OTHER_ZONE]
    result = await entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"api_token": "other"})
    assert result["errors"] == {"base": "wrong_zone"}
    assert result["description_placeholders"]["zone"] == "example.com"


async def test_reauth_flow(hass, flow_api, make_entry):
    entry = make_entry()
    flow_api.fetch_ip_lists.return_value = [NEW_LIST]
    result = await entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"api_token": "new-token-xyz"})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data["api_token"] == "new-token-xyz"
    assert entry.data["zones"][0]["uid_prefix"] == OLD_EMAIL


async def test_reauth_with_missing_permission(hass, flow_api, make_entry):
    entry = make_entry()
    flow_api.probe_analytics.side_effect = auth_error
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"api_token": "t"})
    assert result["errors"] == {"base": "missing_permissions"}
    assert entry.data["api_token"] == TOKEN


# --- options ------------------------------------------------------------------------------

async def test_options_flow(hass, flow_api, make_entry):
    entry = make_entry()
    await hass.config_entries.async_setup(entry.entry_id)  # setup is patched: runs the migration only
    with patch(SETUP, return_value=True):
        result = await hass.config_entries.options.async_init(entry.entry_id)
        assert result["type"] is FlowResultType.FORM
        result = await hass.config_entries.options.async_configure(result["flow_id"], {"zones": [ZONE_ID]})
        assert result["type"] is FlowResultType.FORM and result["step_id"] == "zone_settings"
        assert result["description_placeholders"]["number"] == "1" and result["description_placeholders"]["total"] == "1"
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {
                "abuse_confidence_score": 75,
                "mode": "Active",
                "recheck_enabled": False,
                "recheck_days": 3,
                "under_attack_mode": True,
                "under_attack_request_threshold": 9000,
                "scan_interval_minutes": 10,
            },
        )
        await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    own = entry.options["zone_options"][ZONE_ID]
    assert own["mode"] == "Active" and own["recheck_enabled"] is False and own["scan_interval_minutes"] == 10
