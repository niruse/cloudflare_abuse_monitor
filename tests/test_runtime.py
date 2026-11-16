"""Runtime: migration, reauth, the Under Attack switch, services, recheck off, diagnostics."""
import json
import logging

import pytest
import voluptuous as vol
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import entity_registry as er

from custom_components.cloudflare_abuse_monitor import api
from custom_components.cloudflare_abuse_monitor.diagnostics import async_get_config_entry_diagnostics

from .conftest import (
    ABUSE_KEY, ACCOUNT_ID, DOMAIN, ENTRY_DATA, LEGACY_DATA, LIST_ID, OLD_EMAIL, TOKEN, ZONE_ID, coord,
)
from .test_sensors import UNIQUE_IDS

SWITCH_UID = f"owner_example_com_{ZONE_ID}_under_attack_switch"


async def setup(hass, entry):
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def reauth_flows(hass):
    return [f for f in hass.config_entries.flow.async_progress() if f["context"]["source"] == SOURCE_REAUTH]


def switch_id(hass):
    return er.async_get(hass).async_get_entity_id("switch", DOMAIN, SWITCH_UID)


# --- migration and unique ids --------------------------------------------------------------

async def test_global_key_entry_migrates_and_asks_for_a_token(hass, config_dir, cf, make_entry):
    entry = make_entry(data=LEGACY_DATA, minor_version=1)
    await setup(hass, entry)
    assert entry.minor_version == 3
    assert entry.data["zones"][0]["uid_prefix"] == OLD_EMAIL
    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert len(reauth_flows(hass)) == 1
    cf.traffic.assert_not_called()


async def test_migrated_entry_keeps_every_unique_id(hass, config_dir, cf, make_entry):
    """Entities registered by v1.5 (ids built from the email) are the ones v1.6 updates."""
    registry = er.async_get(hass)
    entry = make_entry(data={**LEGACY_DATA, "api_token": TOKEN}, minor_version=1)
    old = {
        key: registry.async_get_or_create("sensor", DOMAIN, uid, config_entry=entry).entity_id
        for key, uid in UNIQUE_IDS.items()
    }
    await setup(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    for key, uid in UNIQUE_IDS.items():
        assert registry.async_get_entity_id("sensor", DOMAIN, uid) == old[key]
        assert hass.states.get(old[key]) is not None
    sensors = [e for e in er.async_entries_for_config_entry(registry, entry.entry_id) if e.domain == "sensor"]
    assert len(sensors) == 5  # no orphans, no duplicates
    await hass.config_entries.async_unload(entry.entry_id)


async def test_new_token_entry_uses_zone_id_prefix(hass, config_dir, cf, make_entry):
    data = {**ENTRY_DATA, "uid_prefix": ZONE_ID}
    entry = make_entry(data=data)
    await setup(hass, entry)
    registry = er.async_get(hass)
    assert registry.async_get_entity_id("sensor", DOMAIN, f"{ZONE_ID}_example.com_traffic_summary")
    assert registry.async_get_entity_id("switch", DOMAIN, f"{ZONE_ID}_{ZONE_ID}_under_attack_switch")
    # The old email is nowhere in entity names any more.
    for state in hass.states.async_all():
        assert "@" not in (state.attributes.get("friendly_name") or "")
    await hass.config_entries.async_unload(entry.entry_id)


# --- reauth -----------------------------------------------------------------------------

async def test_revoked_token_starts_reauth(hass, config_dir, cf, make_entry):
    entry = make_entry()
    await setup(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    cf.skip.side_effect = api.CloudflareAuthError("GraphQL: not authorized", 403)
    await coord(entry).async_refresh()
    await hass.async_block_till_done()
    assert len(reauth_flows(hass)) == 1
    await hass.config_entries.async_unload(entry.entry_id)


async def test_first_refresh_auth_error_starts_reauth(hass, config_dir, cf, make_entry):
    cf.traffic.side_effect = api.CloudflareAuthError("HTTP 401: Invalid API Token", 401)
    entry = make_entry()
    await setup(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert len(reauth_flows(hass)) == 1


async def test_server_error_does_not_start_reauth(hass, config_dir, cf, make_entry):
    cf.traffic.side_effect = api.CloudflareApiError("HTTP 502: no detail", 502)
    entry = make_entry()
    await setup(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    assert reauth_flows(hass) == []
    await hass.config_entries.async_unload(entry.entry_id)


async def test_token_never_logged(hass, config_dir, cf, make_entry, caplog):
    caplog.set_level(logging.DEBUG)
    cf.traffic.side_effect = api.CloudflareApiError("HTTP 502: no detail", 502)
    cf.abuse.side_effect = lambda ip, key: {"ip": ip, "error": "500: no detail"}
    entry = make_entry(mode="Active")
    await setup(hass, entry)
    await coord(entry).async_refresh()
    assert "failed" in caplog.text
    assert TOKEN not in caplog.text and ABUSE_KEY not in caplog.text
    await hass.config_entries.async_unload(entry.entry_id)


# --- Under Attack switch ------------------------------------------------------------------

async def test_switch_turns_on_and_restores_previous_level(hass, config_dir, cf, make_entry):
    entry = make_entry(mode="Active", under_attack_mode=False)
    await setup(hass, entry)
    entity_id = switch_id(hass)
    assert hass.states.get(entity_id).state == "off"

    await hass.services.async_call("switch", "turn_on", {"entity_id": entity_id}, blocking=True)
    assert cf.set_level.call_args.args[2] == "under_attack"
    cf.get_level.return_value = "under_attack"
    await coord(entry).async_refresh()
    await hass.async_block_till_done()
    assert hass.states.get(entity_id).state == "on"
    # Automation is off, but a level set with the switch is not undone by the next update.
    assert cf.set_level.call_count == 1

    await hass.services.async_call("switch", "turn_off", {"entity_id": entity_id}, blocking=True)
    assert cf.set_level.call_args.args[2] == "medium"
    await hass.config_entries.async_unload(entry.entry_id)


async def test_switch_off_without_saved_level_uses_high(hass, config_dir, cf, make_entry):
    cf.get_level.return_value = "under_attack"  # turned on in the Cloudflare dashboard
    entry = make_entry()
    await setup(hass, entry)
    entity_id = switch_id(hass)
    assert hass.states.get(entity_id).state == "on"
    await hass.services.async_call("switch", "turn_off", {"entity_id": entity_id}, blocking=True)
    assert cf.set_level.call_args.args[2] == "high"
    await hass.config_entries.async_unload(entry.entry_id)


# --- services ---------------------------------------------------------------------------

async def test_check_ip_service_returns_score(hass, config_dir, cf, make_entry):
    cf.abuse.side_effect = lambda ip, key: {"ip": ip, "abuse_confidence_score": 42}
    entry = make_entry()
    await setup(hass, entry)
    result = await hass.services.async_call(
        DOMAIN, "check_ip", {"ip": "2001:db8::5"}, blocking=True, return_response=True
    )
    assert result["abuse_confidence_score"] == 42
    cache = json.loads((config_dir / "cloudflare_checked_ips.json").read_text())
    assert cache["2001:db8::5"]["score"] == 42
    with pytest.raises(vol.Invalid):
        await hass.services.async_call(DOMAIN, "check_ip", {"ip": "not-an-ip"}, blocking=True, return_response=True)
    await hass.config_entries.async_unload(entry.entry_id)


async def test_block_and_unblock_services(hass, config_dir, cf, make_entry):
    cf.abuse.side_effect = lambda ip, key: {"ip": ip, "abuse_confidence_score": 100}
    entry = make_entry(mode="Monitor")
    await setup(hass, entry)

    await hass.services.async_call(DOMAIN, "block_ip", {"ip": "203.0.113.50"}, blocking=True)
    assert cf.add.call_args.args[:3] == (ACCOUNT_ID, LIST_ID, ["203.0.113.50"])

    await hass.services.async_call(DOMAIN, "unblock_ip", {"ip": "203.0.113.20"}, blocking=True)
    assert cf.remove.call_args.args[:3] == (ACCOUNT_ID, LIST_ID, ["item-20"])

    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "unblock_ip", {"ip": "203.0.113.99"}, blocking=True)

    # An unblocked high-risk IP is not added back by Active mode.
    cf.listed.return_value = set()
    cf.skip.return_value = ["203.0.113.20"]
    cf.add.reset_mock()
    hass.config_entries.async_update_entry(entry, options={"mode": "Active"})
    await hass.async_block_till_done()
    cf.add.assert_not_called()

    # Blocking it by hand clears that.
    await hass.services.async_call(DOMAIN, "block_ip", {"ip": "203.0.113.20"}, blocking=True)
    cf.add.reset_mock()
    await hass.services.async_call(DOMAIN, "refresh", {}, blocking=True)
    assert cf.add.call_args.args[2] == ["203.0.113.20"]
    await hass.config_entries.async_unload(entry.entry_id)


async def test_refresh_service(hass, config_dir, cf, make_entry):
    entry = make_entry()
    await setup(hass, entry)
    cf.skip.reset_mock()
    await hass.services.async_call(DOMAIN, "refresh", {"config_entry_id": entry.entry_id}, blocking=True)
    assert cf.skip.call_count == 1
    await hass.config_entries.async_unload(entry.entry_id)


# --- recheck off ------------------------------------------------------------------------

@pytest.mark.parametrize(("enabled", "lookups"), [(True, 1), (False, 0)])
async def test_recheck_can_be_turned_off(hass, config_dir, cf, make_entry, enabled, lookups):
    (config_dir / "cloudflare_checked_ips.json").write_text(
        json.dumps({"203.0.113.10": {"checked": "2000-01-01T00:00:00+00:00", "score": 5}})
    )
    entry = make_entry(recheck_enabled=enabled)
    await setup(hass, entry)
    assert cf.abuse.call_count == lookups
    await hass.config_entries.async_unload(entry.entry_id)


# --- diagnostics ------------------------------------------------------------------------

async def test_diagnostics_redact_everything(hass, config_dir, cf, make_entry):
    entry = make_entry(data={**ENTRY_DATA, "email": OLD_EMAIL, "global_token": "g-key"})
    await setup(hass, entry)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    text = json.dumps(diag)
    for secret in (TOKEN, ABUSE_KEY, OLD_EMAIL, "g-key", ZONE_ID, ACCOUNT_ID, LIST_ID, "example.com", "203.0.113"):
        assert secret not in text
    assert diag["sections"]["traffic"]["value"] == 1000
    await hass.config_entries.async_unload(entry.entry_id)


async def test_switch_is_unknown_when_its_section_failed(hass, config_dir, cf, make_entry):
    """The switch takes its state from is_on, never from a sensor value such as "error"."""
    cf.traffic.side_effect = api.CloudflareApiError("GraphQL: HTTP 502: no detail", 502)
    entry = make_entry()
    await setup(hass, entry)
    assert coord(entry).data["under_attack"]["value"] == "error"
    assert hass.states.get(switch_id(hass)).state == "unknown"
    await hass.config_entries.async_unload(entry.entry_id)


async def test_unblock_of_an_unlisted_ip_changes_nothing(hass, config_dir, cf, make_entry):
    cf.abuse.side_effect = lambda ip, key: {"ip": ip, "abuse_confidence_score": 100}
    entry = make_entry()
    await setup(hass, entry)
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "unblock_ip", {"ip": "203.0.113.10"}, blocking=True)
    cf.remove.assert_not_called()
    assert (await coord(entry)._async_state())["allowed_ips"] == []

    # So Active mode still blocks it when it turns out to be high risk.
    hass.config_entries.async_update_entry(entry, options={"mode": "Active"})
    await hass.async_block_till_done()
    assert cf.add.call_args.args[2] == ["203.0.113.10"]
    await hass.config_entries.async_unload(entry.entry_id)


async def test_diagnostics_redact_ids_inside_error_text(hass, config_dir, cf, make_entry):
    cf.listed.side_effect = OSError(
        "HTTPSConnectionPool(host='api.cloudflare.com', port=443): Max retries exceeded with url: "
        f"/client/v4/accounts/{ACCOUNT_ID}/rules/lists/{LIST_ID}/items?per_page=500"
    )
    cf.skip.side_effect = api.CloudflareApiError(
        f"zone {ZONE_ID} (example.com) for {OLD_EMAIL} from 203.0.113.9 / 2001:db8::9 / "
        "abcdef0123456789abcdef0123456789"
    )
    entry = make_entry()
    await setup(hass, entry)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    text = json.dumps(diag)
    for secret in (ZONE_ID, ACCOUNT_ID, LIST_ID, OLD_EMAIL, "example.com", "203.0.113.9", "2001:db8::9",
                   "abcdef0123456789abcdef0123456789"):
        assert secret not in text
    assert "Max retries exceeded" in diag["sections"]["list_ips"]["error"]
    await hass.config_entries.async_unload(entry.entry_id)
