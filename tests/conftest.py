"""Fixtures: a config entry and the Cloudflare/AbuseIPDB calls mocked at the api module.

Every value here is invented (example.com, 203.0.113.0/24, 2001:db8::/32, made-up ids).
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

DOMAIN = "cloudflare_abuse_monitor"
API = "custom_components.cloudflare_abuse_monitor.api"

TOKEN = "test-api-token-0123456789"
ABUSE_KEY = "test-abuseipdb-key-0123456789"
ZONE_ID = "0123456789abcdef0123456789abcdef"
ACCOUNT_ID = "fedcba9876543210fedcba9876543210"
LIST_ID = "00112233445566778899aabbccddeeff"
OLD_EMAIL = "owner@example.com"

# An entry set up before v1.6 and moved to a token: unique ids still start with the old email.
ENTRY_DATA = {
    "api_token": TOKEN,
    "abuseipdb_token": ABUSE_KEY,
    "uid_prefix": OLD_EMAIL,
    "abuse_confidence_score": 80.0,
    "recheck_days": 7,
    "scan_interval_minutes": 5,
    "zone_id": ZONE_ID,
    "zone_name": "example.com",
    "account_id": ACCOUNT_ID,
    "list_name": "block_ips",
    "list_id": LIST_ID,
    "mode": "Monitor",
}

# What v1.5 stored: Global API Key + email, no token.
LEGACY_DATA = {
    **{k: v for k, v in ENTRY_DATA.items() if k not in ("api_token", "uid_prefix")},
    "email": OLD_EMAIL,
    "global_token": "test-global-key-0123456789",
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
        patch(f"{API}.get_list_items", return_value={"203.0.113.20": "item-20"}) as items,
        patch(
            f"{API}.check_abuse_ip",
            side_effect=lambda ip, key: {"ip": ip, "abuse_confidence_score": 0},
        ) as abuse,
        patch(f"{API}.add_ips_to_list") as add,
        patch(f"{API}.remove_list_items") as remove,
        patch(f"{API}.get_security_level", return_value="medium") as get_level,
        patch(f"{API}.set_security_level") as set_level,
    ):
        yield SimpleNamespace(
            traffic=fetch_traffic, skip=skip, listed=listed, items=items, abuse=abuse,
            add=add, remove=remove, get_level=get_level, set_level=set_level,
        )


@pytest.fixture
def make_entry(hass):
    def _make(data=None, minor_version=2, **options):
        entry = MockConfigEntry(
            domain=DOMAIN,
            data=dict(data or ENTRY_DATA),
            options=options,
            title="Cloudflare: example.com",
            unique_id=ZONE_ID,
            version=1,
            minor_version=minor_version,
        )
        entry.add_to_hass(hass)
        return entry
    return _make
