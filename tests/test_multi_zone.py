"""v1.7: several zones per entry, the checkbox list, options add/remove, migration from v1.6, pacing.

Every value here is invented (example.com/.org/.net, 203.0.113.0/24, made-up ids).
"""
import asyncio
import json
from unittest.mock import patch

import pytest
from homeassistant.config_entries import SOURCE_USER, ConfigEntryState
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.storage import Store
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cloudflare_abuse_monitor import api
from custom_components.cloudflare_abuse_monitor.coordinator import ZonePacer
from custom_components.cloudflare_abuse_monitor.diagnostics import async_get_config_entry_diagnostics

from .conftest import SETTINGS, zone_settings
from .conftest import ABUSE_KEY, ACCOUNT_ID, DOMAIN, ENTRY_DATA, LIST_ID, OLD_EMAIL, TOKEN, ZONE_ID, coord
from .test_config_flow import SETUP, USER_INPUT, flow_api_mocks
from .test_sensors import UNIQUE_IDS

ACCOUNT_2 = "2" * 32
LIST_2 = "3" * 32
ZONE_A = {"id": ZONE_ID, "name": "example.com", "account": {"id": ACCOUNT_ID, "name": "Account One"}}
ZONE_B = {"id": "b" * 32, "name": "example.net", "account": {"id": ACCOUNT_ID, "name": "Account One"}}
ZONE_C = {"id": "c" * 32, "name": "example.org", "account": {"id": ACCOUNT_2, "name": "Account Two"}}
ZONE_D = {"id": "d" * 32, "name": "shop.example.com", "account": {"id": ACCOUNT_2, "name": "Account Two"}}


@pytest.fixture
def flow_api():
    """The setup-flow API mocks; the entry is created but not set up."""
    with patch(SETUP, return_value=True), flow_api_mocks() as m:
        yield m


def record(zone, list_id):
    return {
        "zone_id": zone["id"], "zone_name": zone["name"], "account_id": zone["account"]["id"],
        "list_name": "block_ips", "list_id": list_id, "uid_prefix": zone["id"],
    }


def v17_data(*records):
    base = {k: v for k, v in ENTRY_DATA.items() if k not in ("zone_id", "zone_name", "account_id",
                                                            "list_name", "list_id", "uid_prefix")}
    return {**base, "zones": list(records)}


def make_v17_entry(hass, *records, **options):
    entry = MockConfigEntry(
        domain=DOMAIN, data=v17_data(*records), options=options, title="Cloudflare: 2 zones",
        version=1, minor_version=3,
    )
    entry.add_to_hass(hass)
    return entry


def lists_per_account(account_id, headers):
    return []


def create_list(account_id, name, headers):
    return {"id": LIST_ID if account_id == ACCOUNT_ID else LIST_2, "name": name, "kind": "ip"}


async def start(hass):
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    return await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)


async def load(hass, entry):
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


# --- setup: checkbox list, two accounts, nothing duplicated -----------------------------------

async def test_setup_lists_every_zone_with_checkboxes_all_ticked(hass, flow_api):
    flow_api.fetch_zones.return_value = [ZONE_A, ZONE_B, ZONE_C]
    result = await start(hass)
    assert result["step_id"] == "zones"
    key = next(iter(result["data_schema"].schema))
    assert str(key) == "zones"
    assert sorted(key.default()) == sorted([ZONE_A["id"], ZONE_B["id"], ZONE_C["id"]])
    config = result["data_schema"].schema[key].config
    assert config["multiple"] is True and config["mode"] == "list"
    # Two accounts: each label names its account.
    labels = {o["value"]: o["label"] for o in config["options"]}
    assert labels[ZONE_C["id"]] == "example.org (Account Two)"

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"zones": []})
    assert result["errors"] == {"base": "no_zones"}


async def test_setup_two_accounts_one_list_each_rules_per_zone(hass, flow_api):
    flow_api.fetch_zones.return_value = [ZONE_A, ZONE_B, ZONE_C]
    flow_api.fetch_ip_lists.side_effect = lists_per_account
    flow_api.create_ip_list.side_effect = create_list
    result = await start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"zones": [ZONE_A["id"], ZONE_B["id"], ZONE_C["id"]]}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Cloudflare: 3 zones"
    zones = {z["zone_id"]: z for z in result["data"]["zones"]}
    assert zones[ZONE_A["id"]]["list_id"] == zones[ZONE_B["id"]]["list_id"] == LIST_ID
    assert zones[ZONE_C["id"]]["list_id"] == LIST_2 and zones[ZONE_C["id"]]["account_id"] == ACCOUNT_2
    assert all(z["uid_prefix"] == z["zone_id"] for z in zones.values())
    # One list per account, never one per zone; the second zone of an account does not even re-read lists.
    assert sorted(c.args[0] for c in flow_api.create_ip_list.call_args_list) == sorted([ACCOUNT_ID, ACCOUNT_2])
    assert sorted(c.args[0] for c in flow_api.fetch_ip_lists.call_args_list) == sorted([ACCOUNT_ID, ACCOUNT_2])
    # The Block and Skip rules on every zone, each zone once.
    rule_zones = [c.args[0] for c in flow_api.create_custom_entrypoint.call_args_list]
    assert sorted(rule_zones) == sorted(zones)
    # The probes ran per zone.
    assert sorted(c.args[1] for c in flow_api.probe_analytics.call_args_list) == sorted(zones)
    assert "zone_id" not in result["data"]


async def test_configured_zones_are_never_offered_again(hass, flow_api):
    flow_api.fetch_zones.return_value = [ZONE_A, ZONE_C]
    result = await start(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"zones": [ZONE_A["id"], ZONE_C["id"]]})
    assert result["type"] is FlowResultType.CREATE_ENTRY

    # Same token again: everything is taken.
    again = await start(hass)
    assert again["type"] is FlowResultType.ABORT and again["reason"] == "already_configured"

    # A new zone appears: only it is set up (no checkbox list for one zone).
    flow_api.fetch_zones.return_value = [ZONE_A, ZONE_C, ZONE_D]
    flow_api.create_custom_entrypoint.reset_mock()
    result = await start(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert [z["zone_id"] for z in result["data"]["zones"]] == [ZONE_D["id"]]
    assert [c.args[0] for c in flow_api.create_custom_entrypoint.call_args_list] == [ZONE_D["id"]]


async def test_account_token_is_verified_once_per_account(hass, flow_api):
    flow_api.verify_user_token.side_effect = api.CloudflareAuthError("HTTP 401", 401)
    flow_api.fetch_zones.return_value = [ZONE_A, ZONE_B, ZONE_C]
    result = await start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"zones": [ZONE_A["id"], ZONE_B["id"], ZONE_C["id"]]}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert sorted(c.args[0] for c in flow_api.verify_account_token.call_args_list) == sorted([ACCOUNT_ID, ACCOUNT_2])


async def test_a_zone_missing_a_permission_is_named(hass, flow_api):
    flow_api.fetch_zones.return_value = [ZONE_A, ZONE_C]
    flow_api.probe_analytics.side_effect = lambda headers, zone_id: (
        (_ for _ in ()).throw(api.CloudflareAuthError("HTTP 403", 403)) if zone_id == ZONE_C["id"] else None
    )
    result = await start(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"zones": [ZONE_A["id"], ZONE_C["id"]]})
    assert result["step_id"] == "zones"
    assert result["errors"] == {"base": "missing_permissions"}
    assert result["description_placeholders"]["zone"] == "example.org"
    # The retry after fixing the token re-uses what the first zone already has.
    flow_api.probe_analytics.side_effect = None
    flow_api.fetch_ip_lists.return_value = []
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"zones": [ZONE_A["id"], ZONE_C["id"]]})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert flow_api.create_ip_list.call_count == 2  # account one (first try) + account two, never twice


# --- per-zone devices, entities and services -----------------------------------------------------

async def test_each_zone_is_its_own_device_with_its_own_entities(hass, config_dir, cf):
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID), record(ZONE_C, LIST_2)))
    assert entry.state is ConfigEntryState.LOADED
    devices = dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
    assert sorted(d.name for d in devices) == ["Cloudflare example.com", "Cloudflare example.org"]
    entities = er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
    assert len(entities) == 30  # 5 sensors + 9 insight sensors + 1 switch per zone
    assert len({e.unique_id for e in entities}) == 28
    by_device = {}
    for e in entities:
        by_device.setdefault(e.device_id, []).append(e)
    assert sorted(len(v) for v in by_device.values()) == [14, 14]
    assert er.async_get(hass).async_get_entity_id("switch", DOMAIN, f"{ZONE_C['id']}_{ZONE_C['id']}_under_attack_switch")
    # Each zone polls its own zone id and its own account's list.
    assert sorted(c.args[1] for c in cf.traffic.call_args_list) == sorted([ZONE_A["id"], ZONE_C["id"]])
    assert sorted(c.args[:2] for c in cf.listed.call_args_list) == sorted([(ACCOUNT_ID, LIST_ID), (ACCOUNT_2, LIST_2)])
    await hass.config_entries.async_unload(entry.entry_id)


async def test_services_take_a_zone(hass, config_dir, cf):
    entry = await load(hass, make_v17_entry(
        hass, record(ZONE_A, LIST_ID), record(ZONE_B, LIST_ID), record(ZONE_C, LIST_2)
    ))
    # Different lists: block_ip must be told which zone.
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "block_ip", {"ip": "203.0.113.50"}, blocking=True)
    await hass.services.async_call(DOMAIN, "block_ip", {"ip": "203.0.113.50", "zone": "example.org"}, blocking=True)
    assert cf.add.call_args.args[:3] == (ACCOUNT_2, LIST_2, ["203.0.113.50"])

    # By device.
    device = next(
        d for d in dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id) if d.name.endswith("example.net")
    )
    await hass.services.async_call(DOMAIN, "block_ip", {"ip": "203.0.113.51", "device_id": device.id}, blocking=True)
    assert cf.add.call_args.args[:3] == (ACCOUNT_ID, LIST_ID, ["203.0.113.51"])

    # Unblocking from the shared list: no zone of that account may add it back.
    await hass.services.async_call(DOMAIN, "unblock_ip", {"ip": "203.0.113.20", "zone": "example.com"}, blocking=True)
    for zone in (ZONE_A, ZONE_B):
        assert (await coord(entry, zone["id"])._async_state())["allowed_ips"] == ["203.0.113.20"]
    assert (await coord(entry, ZONE_C["id"])._async_state())["allowed_ips"] == []

    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "refresh", {"zone": "example.invalid"}, blocking=True)
    cf.traffic.reset_mock()
    await hass.services.async_call(DOMAIN, "refresh", {"zone": "example.net"}, blocking=True)
    assert [c.args[1] for c in cf.traffic.call_args_list] == [ZONE_B["id"]]
    cf.traffic.reset_mock()
    await hass.services.async_call(DOMAIN, "refresh", {}, blocking=True)
    assert cf.traffic.call_count == 3
    await hass.config_entries.async_unload(entry.entry_id)


async def test_one_unreachable_zone_does_not_hold_back_the_others(hass, config_dir, cf):
    def traffic_for(headers, zone_id):
        if zone_id == ZONE_C["id"]:
            raise api.CloudflareApiError("HTTP 502", 502)
        from .conftest import traffic
        return traffic()

    cf.traffic.side_effect = traffic_for
    cf.skip.side_effect = lambda zone_id, *a: (
        (_ for _ in ()).throw(api.CloudflareApiError("HTTP 502", 502)) if zone_id == ZONE_C["id"] else ["203.0.113.10"]
    )
    cf.listed.side_effect = lambda account_id, *a: (
        (_ for _ in ()).throw(api.CloudflareApiError("HTTP 502", 502)) if account_id == ACCOUNT_2 else set()
    )
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID), record(ZONE_C, LIST_2)))
    assert entry.state is ConfigEntryState.LOADED
    assert coord(entry, ZONE_A["id"]).last_update_success
    assert not coord(entry, ZONE_C["id"]).last_update_success
    await hass.config_entries.async_unload(entry.entry_id)


async def test_diagnostics_redact_every_zone(hass, config_dir, cf):
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID), record(ZONE_C, LIST_2)))
    text = json.dumps(await async_get_config_entry_diagnostics(hass, entry))
    for secret in (TOKEN, ABUSE_KEY, ZONE_A["id"], ZONE_C["id"], ACCOUNT_ID, ACCOUNT_2, LIST_ID, LIST_2,
                   "example.com", "example.org", "203.0.113"):
        assert secret not in text
    await hass.config_entries.async_unload(entry.entry_id)


# --- options: add and remove zones ------------------------------------------------------------------

@pytest.fixture
def live_api(cf):
    """The setup-flow API mocks on top of the polling mocks, with the real entry setup."""
    with flow_api_mocks() as m:
        yield m

async def test_options_add_a_zone_of_a_known_account(hass, live_api, config_dir, cf):
    entry = make_v17_entry(hass, record(ZONE_A, LIST_ID))
    entry_title = "Cloudflare: example.com"
    hass.config_entries.async_update_entry(entry, title=entry_title)
    await load(hass, entry)
    live_api.fetch_zones.return_value = [ZONE_A, ZONE_B, ZONE_C]
    live_api.fetch_ip_lists.side_effect = lists_per_account
    live_api.create_ip_list.side_effect = create_list

    result = await hass.config_entries.options.async_init(entry.entry_id)
    key = next(k for k in result["data_schema"].schema if str(k) == "zones")
    assert key.default() == [ZONE_A["id"]]
    assert {o["value"] for o in result["data_schema"].schema[key].config["options"]} == {
        ZONE_A["id"], ZONE_B["id"], ZONE_C["id"]
    }
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"zones": [ZONE_A["id"], ZONE_B["id"], ZONE_C["id"]]})
    result = await zone_settings(hass, result, {"abuse_confidence_score": 90, "mode": "Active", "recheck_enabled": True, "recheck_days": 7, "under_attack_mode": False, "under_attack_request_threshold": 15000, "scan_interval_minutes": 5})
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    zones = {z["zone_id"]: z for z in entry.data["zones"]}
    assert zones[ZONE_B["id"]]["list_id"] == LIST_ID  # the account's existing list
    assert zones[ZONE_C["id"]]["list_id"] == LIST_2
    assert [c.args[0] for c in live_api.create_ip_list.call_args_list] == [ACCOUNT_2]
    assert [c.args[0] for c in live_api.fetch_ip_lists.call_args_list] == [ACCOUNT_2]
    assert sorted(c.args[0] for c in live_api.create_custom_entrypoint.call_args_list) == sorted(
        [ZONE_B["id"], ZONE_C["id"]]
    )
    assert {z: o["mode"] for z, o in entry.options["zone_options"].items()} == {
        ZONE_A["id"]: "Active", ZONE_B["id"]: "Active", ZONE_C["id"]: "Active"}
    assert "zones" not in entry.options and "mode" not in entry.options
    assert entry.title == "Cloudflare: 3 zones"
    assert entry.state is ConfigEntryState.LOADED
    assert len(entry.runtime_data.coordinators) == 3
    assert len(er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)) == 42
    await hass.config_entries.async_unload(entry.entry_id)


async def test_options_remove_a_zone_removes_its_device_only(hass, live_api, config_dir, cf):
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID), record(ZONE_C, LIST_2)))
    hass.config_entries.async_update_entry(entry, title="My websites")
    await hass.async_block_till_done()
    ent_reg, dev_reg = er.async_get(hass), dr.async_get(hass)
    kept = {e.entity_id for e in er.async_entries_for_config_entry(ent_reg, entry.entry_id)
            if ZONE_A["id"] in e.unique_id or "example.com" in e.unique_id}
    live_api.fetch_zones.return_value = [ZONE_A, ZONE_C]

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"zones": [ZONE_A["id"]]})
    result = await zone_settings(hass, result, {"abuse_confidence_score": 80, "mode": "Monitor", "recheck_enabled": True, "recheck_days": 7, "under_attack_mode": False, "under_attack_request_threshold": 15000, "scan_interval_minutes": 5})
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert [z["zone_id"] for z in entry.data["zones"]] == [ZONE_A["id"]]
    assert entry.title == "My websites"  # a title the user typed stays
    devices = dr.async_entries_for_config_entry(dev_reg, entry.entry_id)
    assert [d.name for d in devices] == ["Cloudflare example.com"]
    remaining = {e.entity_id for e in er.async_entries_for_config_entry(ent_reg, entry.entry_id)}
    assert remaining == kept and len(remaining) == 14
    # Nothing is written to Cloudflare for a removed zone: no probes, no rules, no list changes.
    live_api.set_security_level.assert_not_called()
    live_api.create_custom_entrypoint.assert_not_called()
    live_api.add_custom_rule.assert_not_called()
    cf.remove.assert_not_called()
    await hass.config_entries.async_unload(entry.entry_id)


async def test_options_still_work_when_cloudflare_is_unreachable(hass, live_api, config_dir, cf):
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID)))
    live_api.fetch_zones.side_effect = api.CloudflareApiError("HTTP 502", 502)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["errors"] == {"base": "zones_unavailable"}
    key = next(k for k in result["data_schema"].schema if str(k) == "zones")
    assert [o["value"] for o in result["data_schema"].schema[key].config["options"]] == [ZONE_A["id"]]
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"zones": [ZONE_A["id"]]})
    result = await zone_settings(hass, result, {"abuse_confidence_score": 80, "mode": "Monitor", "recheck_enabled": True, "recheck_days": 3, "under_attack_mode": False, "under_attack_request_threshold": 15000, "scan_interval_minutes": 5})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.options["zone_options"][ZONE_A["id"]]["recheck_days"] == 3
    await hass.async_block_till_done()
    await hass.config_entries.async_unload(entry.entry_id)


async def test_each_zone_has_its_own_settings(hass, live_api, config_dir, cf):
    """Nir, 11-17: the settings are per domain. The options ask each zone's in turn, and each zone uses its own."""
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID), record(ZONE_C, LIST_2)))
    live_api.fetch_zones.return_value = [ZONE_A, ZONE_C]
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert [str(k) for k in result["data_schema"].schema] == ["zones"]  # the zones alone first
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"zones": [ZONE_A["id"], ZONE_C["id"]]})
    assert result["step_id"] == "zone_settings"
    assert result["description_placeholders"]["zone"] == "example.com"
    assert (result["description_placeholders"]["number"], result["description_placeholders"]["total"]) == ("1", "2")
    result = await zone_settings(hass, result, per_zone={
        "example.com": {**SETTINGS, "mode": "Active", "scan_interval_minutes": 2},
        "example.org": {**SETTINGS, "abuse_confidence_score": 50, "under_attack_mode": True},
    })
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    coords = entry.runtime_data.coordinators
    a, c = coords[ZONE_A["id"]], coords[ZONE_C["id"]]
    assert (a.option("mode", None), c.option("mode", None)) == ("Active", "Monitor")
    assert (a.option("abuse_confidence_score", None), c.option("abuse_confidence_score", None)) == (80, 50)
    assert (a.option("under_attack_mode", None), c.option("under_attack_mode", None)) == (False, True)
    assert a.update_interval.total_seconds() == 120 and c.update_interval.total_seconds() == 300
    await hass.config_entries.async_unload(entry.entry_id)


async def test_settings_from_before_are_every_zones_until_changed(hass, live_api, config_dir, cf):
    """An entry from before v1.9 had one set of options for every zone: each zone reads it, and the form of each
    zone starts from it."""
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID), record(ZONE_C, LIST_2),
                                            mode="Active", abuse_confidence_score=60))
    coords = entry.runtime_data.coordinators
    assert {z: c.option("mode", None) for z, c in coords.items()} == {ZONE_A["id"]: "Active", ZONE_C["id"]: "Active"}
    live_api.fetch_zones.return_value = [ZONE_A, ZONE_C]
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"zones": [ZONE_A["id"], ZONE_C["id"]]})
    defaults = {str(k): k.default() for k in result["data_schema"].schema}
    assert defaults["mode"] == "Active" and defaults["abuse_confidence_score"] == 60
    hass.config_entries.options.async_abort(result["flow_id"])
    await hass.config_entries.async_unload(entry.entry_id)


# --- migration from v1.6 ----------------------------------------------------------------------------

async def test_v16_entry_migrates_keeping_ids_device_and_state(hass, config_dir, cf, make_entry):
    """The single-zone v1.6 entry: same entity ids, unique ids, device and Under Attack memory."""
    entry = make_entry()  # v1.6 data, minor version 2
    ent_reg, dev_reg = er.async_get(hass), dr.async_get(hass)
    device = dev_reg.async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={(DOMAIN, entry.entry_id)}, name="Cloudflare Abuse Monitor"
    )
    old = {
        key: ent_reg.async_get_or_create(
            "sensor", DOMAIN, uid, config_entry=entry, device_id=device.id, suggested_object_id=f"cf_{key}"
        ).entity_id
        for key, uid in UNIQUE_IDS.items()
    }
    switch_uid = f"owner_example_com_{ZONE_ID}_under_attack_switch"
    old_switch = ent_reg.async_get_or_create(
        "switch", DOMAIN, switch_uid, config_entry=entry, device_id=device.id, suggested_object_id="cf_ua"
    ).entity_id
    # v1.6 turned Under Attack Mode on with the switch and remembered the level it replaced.
    await Store(hass, 1, f"{DOMAIN}.{entry.entry_id}").async_save(
        {"enabled_by_us": True, "restore_level": "low", "manual": True, "allowed_ips": ["203.0.113.7"]}
    )
    cf.get_level.return_value = "under_attack"

    await load(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    assert entry.minor_version == 3
    assert entry.unique_id == ZONE_ID
    assert entry.data["zones"] == [{
        "zone_id": ZONE_ID, "zone_name": "example.com", "account_id": ACCOUNT_ID, "list_name": "block_ips",
        "list_id": LIST_ID, "uid_prefix": OLD_EMAIL, "legacy_storage": True,
    }]
    for key in ("zone_id", "zone_name", "account_id", "list_name", "list_id", "uid_prefix"):
        assert key not in entry.data
    assert entry.data["api_token"] == TOKEN and entry.data["abuseipdb_token"] == ABUSE_KEY

    for key, uid in UNIQUE_IDS.items():
        assert ent_reg.async_get_entity_id("sensor", DOMAIN, uid) == old[key]
        assert hass.states.get(old[key]) is not None
    assert ent_reg.async_get_entity_id("switch", DOMAIN, switch_uid) == old_switch
    assert len(er.async_entries_for_config_entry(ent_reg, entry.entry_id)) == 14  # no duplicates
    devices = dr.async_entries_for_config_entry(dev_reg, entry.entry_id)
    assert [d.id for d in devices] == [device.id]  # same device, new per-zone identifier
    assert devices[0].identifiers == {(DOMAIN, f"{entry.entry_id}_{ZONE_ID}")}
    assert all(e.device_id == device.id for e in er.async_entries_for_config_entry(ent_reg, entry.entry_id))

    # The stored state is still this zone's: unblocked IPs stay exempt, off restores "low".
    assert (await coord(entry)._async_state())["allowed_ips"] == ["203.0.113.7"]
    await hass.services.async_call("switch", "turn_off", {"entity_id": old_switch}, blocking=True)
    assert cf.set_level.call_args.args[2] == "low"

    # Reloading does not migrate again or move anything.
    await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert len(entry.data["zones"]) == 1
    assert len(er.async_entries_for_config_entry(ent_reg, entry.entry_id)) == 14
    await hass.config_entries.async_unload(entry.entry_id)


async def test_migrated_entry_can_add_a_second_zone(hass, live_api, config_dir, cf, make_entry):
    entry = await load(hass, make_entry())
    live_api.fetch_zones.return_value = [ZONE_A, ZONE_B]
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"zones": [ZONE_A["id"], ZONE_B["id"]]})
    result = await zone_settings(hass, result, {"abuse_confidence_score": 80, "mode": "Monitor", "recheck_enabled": True, "recheck_days": 7, "under_attack_mode": False, "under_attack_request_threshold": 15000, "scan_interval_minutes": 5})
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    zones = entry.data["zones"]
    assert zones[0]["uid_prefix"] == OLD_EMAIL and zones[0]["legacy_storage"] is True
    assert zones[1] == record(ZONE_B, LIST_ID)
    live_api.create_ip_list.assert_not_called()  # the account's list from v1.6 is shared
    registry = er.async_get(hass)
    for uid in UNIQUE_IDS.values():
        assert registry.async_get_entity_id("sensor", DOMAIN, uid)
    assert registry.async_get_entity_id("sensor", DOMAIN, f"{ZONE_B['id']}_example.net_traffic_summary")
    await hass.config_entries.async_unload(entry.entry_id)


# --- pacing ------------------------------------------------------------------------------------------

async def test_zones_take_turns_with_a_gap():
    pacer = ZonePacer(gap=1.0)
    running, overlaps, sleeps = [], [], []
    real_sleep = asyncio.sleep

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        await real_sleep(0)

    async def cycle(name):
        running.append(name)
        if len(running) > 1:
            overlaps.append(tuple(running))
        await real_sleep(0.01)
        running.remove(name)
        return name

    with patch("custom_components.cloudflare_abuse_monitor.coordinator.asyncio.sleep", fake_sleep):
        results = await asyncio.gather(*(pacer.run(z, lambda z=z: cycle(z)) for z in ("a", "b", "c")))
        assert results == ["a", "b", "c"]
        assert overlaps == []  # never two zones at once
        assert len(sleeps) == 2 and all(0.9 < s <= 1.0 for s in sleeps)  # a gap before b and before c

        sleeps.clear()
        await pacer.run("c", lambda: cycle("c"))  # the same zone again right away: no wait
        assert sleeps == []


async def test_entry_zones_share_one_pacer(hass, config_dir, cf):
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID), record(ZONE_C, LIST_2)))
    pacers = {id(c.pacer) for c in entry.runtime_data.coordinators.values()}
    assert len(pacers) == 1
    await hass.config_entries.async_unload(entry.entry_id)
