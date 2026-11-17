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


@pytest.fixture(autouse=True)
def no_zone_stagger():
    """Zones still take turns, without the real one-second gap (tested on its own)."""
    with patch("custom_components.cloudflare_abuse_monitor.coordinator.ZONE_STAGGER_SECONDS", 0):
        yield


def coord(entry, zone_id=None):
    """The coordinator of one zone (the only one when zone_id is left out)."""
    coordinators = entry.runtime_data.coordinators
    if zone_id is None:
        assert len(coordinators) == 1
        return next(iter(coordinators.values()))
    return coordinators[zone_id]


@pytest.fixture
def config_dir(hass, tmp_path):
    hass.config.config_dir = str(tmp_path)
    return tmp_path


def insights(visitors=42):
    """fetch_insights' answer for one zone (api.summarise_insights' shape)."""
    return {
        "date": "2026-10-01", "visitors": visitors, "visitors_7d": 300, "visitors_30d": 1200,
        "visitors_change_7d_pct": 12.5, "page_views": 120, "page_views_7d": 800, "page_views_30d": 3000,
        "page_views_change_7d_pct": -4.0, "requests": 1000, "requests_vs_usual_pct": 110, "bandwidth_mb": 12.3,
        "cached_mb": 4.1, "cache_ratio_pct": 33.3, "errors_4xx": 7, "errors_5xx": 2, "error_ratio_pct": 0.9,
        "statuses": {"200": 991, "404": 7, "502": 2}, "error_paths_24h": [{"path": "/x", "status": 404, "count": 7}],
        "countries": [{"name": "IL", "count": 900}, {"name": "US", "count": 100}], "threats": 3,
        "security_events_24h": 5, "security_events_capped": False,
        "security_by_action": [{"name": "block", "count": 4}, {"name": "skip", "count": 1}],
        "security_top_countries": [{"name": "CN", "count": 3}], "security_top_paths": [{"name": "/wp-login.php", "count": 4}],
        "daily": [{"date": "2026-10-01", "visitors": visitors, "page_views": 120, "requests": 1000, "threats": 3}],
    }


def settings():
    return {"ssl": "full", "min_tls_version": "1.0", "always_use_https": "on", "weak": ["min_tls_version"]}


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
        patch(f"{API}.fetch_insights", return_value=insights()) as fetch_insights,
        patch(f"{API}.fetch_zone_settings", return_value=settings()) as fetch_settings,
    ):
        yield SimpleNamespace(
            traffic=fetch_traffic, skip=skip, listed=listed, items=items, abuse=abuse,
            add=add, remove=remove, get_level=get_level, set_level=set_level,
            insights=fetch_insights, settings=fetch_settings,
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


SETTINGS = {
    "abuse_confidence_score": 80, "mode": "Monitor", "recheck_enabled": True, "recheck_days": 7,
    "under_attack_mode": False, "under_attack_request_threshold": 15000, "scan_interval_minutes": 5,
}


async def zone_settings(hass, result, settings=None, per_zone=None):
    """Answer the options flow's settings step of each zone in turn (v1.9: settings per zone), with ``settings``
    or, for a zone named in ``per_zone`` (zone name -> settings), its own."""
    while result.get("step_id") == "zone_settings":
        zone = result["description_placeholders"]["zone"]
        values = (per_zone or {}).get(zone, settings or SETTINGS)
        result = await hass.config_entries.options.async_configure(result["flow_id"], values)
    return result
