from unittest.mock import patch

from homeassistant.data_entry_flow import FlowResultType

from .conftest import DOMAIN

FLOW = "custom_components.cloudflare_abuse_monitor.config_flow"
SETUP = "custom_components.cloudflare_abuse_monitor.async_setup_entry"

USER_INPUT = {
    "email": "owner@example.com",
    "global_token": "test-global-key",
    "abuseipdb_token": "test-abuseipdb-key",
    "abuse_confidence_score": 90,
    "recheck_days": 7,
    "scan_interval_minutes": 2,
}
ZONES = {"success": True, "result": [{"id": "zone1", "name": "example.com", "account": {"id": "acct1"}}]}


async def test_full_flow(hass):
    with (
        patch(f"{FLOW}.fetch_zones", return_value=ZONES),
        patch(f"{FLOW}.fetch_rules_lists", return_value={"block_ips": "list1"}),
        patch(SETUP, return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        assert result["type"] is FlowResultType.FORM
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
        assert result["step_id"] == "zone_select"
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {"zone_id": "zone1"})
        assert result["step_id"] == "list_select"
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {"list_name": "block_ips"})

        assert result["type"] is FlowResultType.CREATE_ENTRY
        assert result["data"]["list_id"] == "list1"
        assert result["data"]["mode"] == "Monitor"
        assert result["result"].unique_id == "zone1"

        # The same zone twice is refused.
        again = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        again = await hass.config_entries.flow.async_configure(again["flow_id"], USER_INPUT)
        again = await hass.config_entries.flow.async_configure(again["flow_id"], {"zone_id": "zone1"})
    assert again["type"] is FlowResultType.ABORT
    assert again["reason"] == "already_configured"


async def test_bad_key_is_auth_failed(hass):
    with patch(f"{FLOW}.fetch_zones", return_value={"success": False, "result": []}):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["errors"] == {"base": "auth_failed"}


async def test_network_error_is_connection_error(hass):
    with patch(f"{FLOW}.fetch_zones", side_effect=OSError("down")):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["errors"] == {"base": "connection_error"}


async def test_options_flow(hass, make_entry):
    entry = make_entry()
    with patch(SETUP, return_value=True):
        result = await hass.config_entries.options.async_init(entry.entry_id)
        assert result["type"] is FlowResultType.FORM
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {
                "abuse_confidence_score": 75,
                "mode": "Active",
                "recheck_days": 3,
                "under_attack_mode": True,
                "under_attack_request_threshold": 9000,
                "scan_interval_minutes": 10,
            },
        )
        await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.options["mode"] == "Active"
    assert entry.options["scan_interval_minutes"] == 10
