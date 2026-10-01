"""Fixtures: a config entry and the Cloudflare/AbuseIPDB calls mocked at the api module."""
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

DOMAIN = "cloudflare_abuse_monitor"
API = "custom_components.cloudflare_abuse_monitor.api"

ENTRY_DATA = {
    "email": "owner@example.com",
    "global_token": "test-global-key",
    "abuseipdb_token": "test-abuseipdb-key",
    "abuse_confidence_score": 80.0,
    "recheck_days": 7,
    "scan_interval_minutes": 5,
    "zone_id": "zone0000000000000000000000000001",
    "zone_name": "example.com",
    "account_id": "acct0000000000000000000000000001",
    "list_name": "block_ips",
    "list_id": "list0000000000000000000000000001",
    "mode": "Monitor",
}


def traffic(requests=1000, start="2026-10-01T00:00:00Z"):
    return {
        "from": start,
        "to": "2026-10-01T12:00:00Z",
        "pageviews": 15,
        "requests": requests,
        "bytes": 1,
        "cached_bytes": 0,
        "cached_requests": 0,
        "encrypted_bytes": 1,
        "encrypted_requests": requests,
    }


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture
def config_dir(hass, tmp_path):
    hass.config.config_dir = str(tmp_path)
    return tmp_path


@pytest.fixture
def cf():
    """Default world: 2 skip IPs, 1 already listed, nothing high risk, security level medium."""
    with (
        patch(f"{API}.fetch_today_traffic_summary", return_value=traffic()) as fetch_traffic,
        patch(f"{API}.get_skip_ips", return_value=["203.0.113.10", "203.0.113.20"]) as skip,
        patch(f"{API}.get_current_list_ips", return_value={"203.0.113.20"}) as listed,
        patch(
            f"{API}.check_abuse_ip",
            side_effect=lambda ip, key: {"ip": ip, "abuse_confidence_score": 0},
        ) as abuse,
        patch(f"{API}.add_ips_to_list") as add,
        patch(f"{API}.get_security_level", return_value="medium") as get_level,
        patch(f"{API}.set_security_level") as set_level,
    ):
        yield SimpleNamespace(
            traffic=fetch_traffic, skip=skip, listed=listed, abuse=abuse,
            add=add, get_level=get_level, set_level=set_level,
        )


@pytest.fixture
def make_entry(hass):
    def _make(**options):
        entry = MockConfigEntry(
            domain=DOMAIN, data=dict(ENTRY_DATA), options=options, title="Cloudflare: example.com"
        )
        entry.add_to_hass(hass)
        return entry
    return _make
