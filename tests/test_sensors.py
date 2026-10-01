import json

from homeassistant.helpers import entity_registry as er

from .conftest import DOMAIN, traffic

UNIQUE_IDS = {
    "traffic": "owner@example.com_example.com_traffic_summary",
    "skip": "owner@example.com_example.com_skip_ips",
    "list": "owner@example.com_example.com_list_ips",
    "high_risk": "owner@example.com_zone0000000000000000000000000001_high_risk_ips",
    "under_attack": "owner_example_com_zone0000000000000000000000000001_under_attack",
}


def state(hass, key):
    entity_id = er.async_get(hass).async_get_entity_id("sensor", DOMAIN, UNIQUE_IDS[key])
    assert entity_id, f"no entity for {key}"
    return hass.states.get(entity_id)


async def setup(hass, entry):
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry.runtime_data


async def test_all_sensors_from_one_cycle(hass, config_dir, cf, make_entry, caplog):
    entry = make_entry()
    coordinator = await setup(hass, entry)

    assert state(hass, "traffic").state == "1000"
    assert state(hass, "traffic").attributes["zone_id"] == "zone0000000000000000000000000001"
    assert state(hass, "skip").state == "2"
    assert state(hass, "list").state == "1"
    assert state(hass, "list").attributes["current_list_ips"] == ["203.0.113.20"]
    assert state(hass, "high_risk").state == "0"
    assert state(hass, "high_risk").attributes["ips_to_check"] == ["203.0.113.10"]
    assert state(hass, "under_attack").state == "off"
    assert state(hass, "under_attack").attributes["next_update_in_seconds"] == 300
    assert coordinator.update_interval.total_seconds() == 300
    # Each API is called once per cycle, not once per sensor.
    assert cf.skip.call_count == 1 and cf.listed.call_count == 1
    assert "took longer than the scheduled update interval" not in caplog.text
    assert "is taking over" not in caplog.text
    await hass.config_entries.async_unload(entry.entry_id)


async def test_failed_call_marks_only_its_sensor(hass, config_dir, cf, make_entry):
    cf.traffic.side_effect = RuntimeError("graphql down")
    entry = make_entry()
    await setup(hass, entry)

    # A numeric sensor must not be given the string "error" (HA rejects it).
    assert state(hass, "traffic").state == "unknown"
    assert state(hass, "traffic").attributes["error"] == "graphql down"
    assert state(hass, "under_attack").state == "error"
    assert state(hass, "skip").state == "2"
    assert state(hass, "high_risk").state == "0"
    await hass.config_entries.async_unload(entry.entry_id)


async def test_high_risk_cached_and_blocked_in_active_mode(hass, config_dir, cf, make_entry):
    cache_file = config_dir / "cloudflare_checked_ips.json"
    # Bare timestamp = an entry written by v1.4, still fresh, score unknown.
    cache_file.write_text(json.dumps({"203.0.113.30": "2999-01-01T00:00:00"}))
    cf.skip.return_value = ["203.0.113.10", "203.0.113.20", "203.0.113.30", "2001:db8::1"]
    scores = {"203.0.113.10": 95, "2001:db8::1": 10}
    cf.abuse.side_effect = lambda ip, key: {"ip": ip, "abuse_confidence_score": scores[ip]}

    entry = make_entry(mode="Active", abuse_confidence_score=80.0)
    coordinator = await setup(hass, entry)

    high = state(hass, "high_risk")
    assert high.state == "1"
    assert high.attributes["high_risk_ip_list"] == ["203.0.113.10"]
    assert sorted(high.attributes["ips_to_check"]) == ["2001:db8::1", "203.0.113.10"]
    cf.add.assert_called_once()
    assert cf.add.call_args.args[2] == ["203.0.113.10"]

    cache = json.loads(cache_file.read_text())
    assert cache["203.0.113.30"] == "2999-01-01T00:00:00"
    assert cache["203.0.113.10"]["score"] == 95

    # The add has not shown up in the list yet: the next cycle retries it from the cached
    # score, without a new AbuseIPDB lookup.
    cf.abuse.reset_mock()
    cf.add.reset_mock()
    await coordinator.async_refresh()
    cf.abuse.assert_not_called()
    assert cf.add.call_args.args[2] == ["203.0.113.10"]
    await hass.config_entries.async_unload(entry.entry_id)


async def test_monitor_mode_never_writes(hass, config_dir, cf, make_entry):
    cf.abuse.side_effect = lambda ip, key: {"ip": ip, "abuse_confidence_score": 100}
    entry = make_entry(mode="Monitor", under_attack_mode=True, under_attack_request_threshold=1)
    coordinator = await setup(hass, entry)
    cf.traffic.return_value = traffic(requests=5000)
    await coordinator.async_refresh()

    assert state(hass, "high_risk").state == "1"
    cf.add.assert_not_called()
    cf.set_level.assert_not_called()
    await hass.config_entries.async_unload(entry.entry_id)


async def test_failed_lookup_is_not_cached(hass, config_dir, cf, make_entry):
    cf.abuse.side_effect = lambda ip, key: {"ip": ip, "error": "500: oops"}
    entry = make_entry()
    coordinator = await setup(hass, entry)
    assert not (config_dir / "cloudflare_checked_ips.json").exists()

    cf.abuse.side_effect = lambda ip, key: {"ip": ip, "abuse_confidence_score": 5}
    cf.abuse.reset_mock()
    await coordinator.async_refresh()
    assert cf.abuse.call_count == 1
    assert "203.0.113.10" in json.loads((config_dir / "cloudflare_checked_ips.json").read_text())
    await hass.config_entries.async_unload(entry.entry_id)


async def test_rate_limit_stops_lookups(hass, config_dir, cf, make_entry):
    from custom_components.cloudflare_abuse_monitor.api import AbuseIPDBRateLimited

    cf.skip.return_value = ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    cf.listed.return_value = set()
    cf.abuse.side_effect = AbuseIPDBRateLimited("429")
    entry = make_entry()
    await setup(hass, entry)
    assert cf.abuse.call_count == 1
    assert state(hass, "high_risk").state == "0"
    await hass.config_entries.async_unload(entry.entry_id)


async def test_under_attack_disabled_does_not_touch_security_level(hass, config_dir, cf, make_entry):
    entry = make_entry(mode="Active", under_attack_mode=False)
    coordinator = await setup(hass, entry)
    await coordinator.async_refresh()
    cf.set_level.assert_not_called()
    assert state(hass, "under_attack").attributes["reason"] == "Under attack mode is disabled"
    await hass.config_entries.async_unload(entry.entry_id)


async def test_under_attack_triggers_on_spike_and_restores_when_switched_off(hass, config_dir, cf, make_entry):
    entry = make_entry(mode="Active", under_attack_mode=True, under_attack_request_threshold=100)
    coordinator = await setup(hass, entry)
    # The first cycle is only a baseline.
    cf.set_level.assert_not_called()
    assert state(hass, "under_attack").attributes["delta"] is None

    cf.traffic.return_value = traffic(requests=1050)
    await coordinator.async_refresh()
    cf.set_level.assert_not_called()  # +50 < 100

    cf.traffic.return_value = traffic(requests=1200)
    await coordinator.async_refresh()
    assert cf.set_level.call_args.args[2] == "under_attack"
    ua = state(hass, "under_attack")
    assert ua.state == "on"
    assert ua.attributes["delta"] == 150
    assert ua.attributes["enabled_by_integration"] is True

    # Switching the option off reloads the entry; the stored ownership restores the old level.
    cf.set_level.reset_mock()
    cf.get_level.return_value = "under_attack"
    hass.config_entries.async_update_entry(entry, options={**entry.options, "under_attack_mode": False})
    await hass.async_block_till_done()
    assert cf.set_level.call_args.args[2] == "medium"
    assert state(hass, "under_attack").state == "off"
    await hass.config_entries.async_unload(entry.entry_id)


async def test_new_day_is_not_a_spike(hass, config_dir, cf, make_entry):
    entry = make_entry(mode="Active", under_attack_mode=True, under_attack_request_threshold=100)
    coordinator = await setup(hass, entry)
    cf.traffic.return_value = traffic(requests=5000, start="2026-10-02T00:00:00Z")
    await coordinator.async_refresh()
    cf.set_level.assert_not_called()
    await hass.config_entries.async_unload(entry.entry_id)


async def test_manual_under_attack_is_left_alone(hass, config_dir, cf, make_entry):
    cf.get_level.return_value = "under_attack"
    entry = make_entry(mode="Active", under_attack_mode=False)
    coordinator = await setup(hass, entry)
    await coordinator.async_refresh()
    cf.set_level.assert_not_called()
    assert state(hass, "under_attack").state == "on"
    await hass.config_entries.async_unload(entry.entry_id)
