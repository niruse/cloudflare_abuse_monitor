"""v2.0 insights: visitors, page views, errors, cache, countries, security events and the zone's TLS settings."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from custom_components.cloudflare_abuse_monitor import api
from custom_components.cloudflare_abuse_monitor.coordinator import INSIGHTS_EVERY, insight_sections

from .conftest import coord, insights

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def day(date, visitors=10, page_views=20, requests=100, statuses=None, countries=None, cached=50, threats=0):
    return {
        "dimensions": {"date": date}, "uniq": {"uniques": visitors},
        "sum": {"requests": requests, "pageViews": page_views, "threats": threats, "bytes": 2_000_000,
                "cachedBytes": 1_000_000, "cachedRequests": cached,
                "countryMap": [{"clientCountryName": c, "requests": n, "threats": 0} for c, n in (countries or {}).items()],
                "responseStatusMap": [{"edgeResponseStatus": int(s), "requests": n} for s, n in (statuses or {}).items()]},
    }


def zone_answer():
    days = [day((NOW.date() - timedelta(days=n)).isoformat(), visitors=10 if n > 7 else 20) for n in range(15, 0, -1)]
    days.append(day(NOW.date().isoformat(), visitors=7, page_views=9, requests=60,
                    statuses={"200": 50, "404": 6, "503": 4}, countries={"IL": 40, "US": 15, "DE": 5}, cached=15))
    return {
        "days": days,
        "errors": [{"count": 6, "dimensions": {"clientRequestPath": "/old", "edgeResponseStatus": 404}}],
        "events": [{"action": "block", "clientCountryName": "CN", "clientRequestPath": "/wp-login.php"}] * 3
                  + [{"action": "managed_challenge", "clientCountryName": "RU", "clientRequestPath": "/"}],
        "blocked": [{"clientIP": "203.0.113.66", "clientCountryName": "CN", "clientRequestPath": "/wp-login.php"}] * 3
                   + [{"clientIP": "203.0.113.67", "clientCountryName": "RU", "clientRequestPath": "/xmlrpc.php"}],
    }


def test_summary_of_today_and_the_weeks_before():
    got = api.summarise_insights(zone_answer(), NOW)
    assert got["date"] == "2026-10-15"
    assert (got["visitors"], got["page_views"], got["requests"]) == (7, 9, 60)
    # the last 7 whole days (20 a day) against the 7 before (10 a day)
    assert got["visitors_7d"] == 140 and got["visitors_change_7d_pct"] == 100.0
    assert got["visitors_30d"] == 8 * 10 + 7 * 20
    # noon: half an ordinary day (100 requests) would be 50; 60 is 120 %
    assert got["requests_vs_usual_pct"] == 120
    assert (got["errors_4xx"], got["errors_5xx"], got["error_ratio_pct"]) == (6, 4, 16.7)
    assert got["cache_ratio_pct"] == 25.0 and got["bandwidth_mb"] == 2.0
    assert got["countries"][0] == {"name": "IL", "count": 40} and len(got["countries"]) == 3
    assert got["error_paths_24h"] == [{"path": "/old", "status": 404, "count": 6}]
    assert got["security_events_24h"] == 4 and not got["security_events_capped"]
    assert got["security_by_action"] == [{"name": "block", "count": 3}, {"name": "managed_challenge", "count": 1}]
    assert got["security_top_paths"][0] == {"name": "/wp-login.php", "count": 3}
    assert len(got["daily"]) == 16


def test_blocked_requests_are_counted_by_address_country_and_path():
    got = api.summarise_insights(zone_answer(), NOW)
    assert got["blocked_requests_24h"] == 4 and got["blocked_ips_24h"] == 2 and not got["blocked_capped"]
    assert got["blocked_top_ips"] == [{"name": "203.0.113.66", "count": 3}, {"name": "203.0.113.67", "count": 1}]
    assert got["blocked_top_countries"][0] == {"name": "CN", "count": 3}
    assert got["blocked_top_paths"][0] == {"name": "/wp-login.php", "count": 3}
    full = api.summarise_insights({"blocked": [{"clientIP": "203.0.113.66"}] * api.SECURITY_EVENTS_LIMIT}, NOW)
    assert full["blocked_requests_24h"] == api.SECURITY_EVENTS_LIMIT and full["blocked_capped"]


def test_blocked_requests_are_read_apart_from_the_logged_visitors():
    """The Skip rule logs every visitor, so the 1,000 events of the day are mostly "skip": the blocked
    requests have a query of their own, filtered on the server."""
    with patch.object(api, "_graphql_zone", return_value={}) as graphql:
        api.fetch_insights({}, "0123456789abcdef0123456789abcdef", NOW)
    query = " ".join(graphql.call_args.args[1].split())
    assert 'blocked: firewallEventsAdaptive(limit: 1000, filter: {datetime_geq: "2026-10-14T12:00:00Z", ' \
           'datetime_lt: "2026-10-15T12:00:00Z", action: "block"})' in query


def test_a_quiet_zone_is_zeros_not_errors():
    got = api.summarise_insights({"days": [], "errors": [], "events": []}, NOW)
    assert got["visitors"] == 0 and got["requests"] == 0
    assert got["cache_ratio_pct"] is None and got["error_ratio_pct"] is None
    assert got["visitors_change_7d_pct"] is None and got["requests_vs_usual_pct"] is None
    assert got["countries"] == [] and got["security_events_24h"] == 0


def test_weak_settings_are_named():
    assert api.summarise_settings({"ssl": "full", "min_tls_version": "1.2", "always_use_https": "on"})["weak"] == []
    weak = api.summarise_settings({"ssl": "flexible", "min_tls_version": "1.0", "always_use_https": "off"})["weak"]
    assert weak == ["ssl", "min_tls_version", "always_use_https"]


def test_sections_carry_value_and_attributes():
    sections = insight_sections(insights(), None)
    assert sections["visitors"]["value"] == 42 and sections["visitors"]["attrs"]["visitors_7d"] == 300
    assert sections["countries"]["value"] == "IL" and sections["countries"]["attrs"]["countries"][1]["name"] == "US"
    assert sections["errors"]["value"] == 2 and sections["errors"]["attrs"]["errors_4xx"] == 7
    failed = insight_sections(None, "Cloudflare said no")
    assert all(s["value"] is None and s["error"] == "Cloudflare said no" for s in failed.values())


async def test_insight_sensors_and_their_pace(hass, config_dir, cf, make_entry, freezer):
    entry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    states = {s.entity_id: s for s in hass.states.async_all("sensor")}

    def find(suffix):
        return next(s for eid, s in states.items() if eid.endswith(suffix))
    assert find("visitors_today").state == "42"
    assert find("visitors_today").attributes["visitors_change_7d_pct"] == 12.5
    assert find("top_country_today").state == "IL"
    assert find("ssl_mode").state == "full" and find("ssl_mode").attributes["weak"] == ["min_tls_version"]
    assert find("security_events_24h").attributes["security_top_paths"][0]["name"] == "/wp-login.php"
    assert find("blocked_requests_24h").state == "4"
    assert find("blocked_requests_24h").attributes["blocked_top_ips"][0] == {"name": "203.0.113.66", "count": 3}
    assert cf.insights.call_count == 1 and cf.settings.call_count == 1
    # the next cycles reuse them until INSIGHTS_EVERY has passed
    coordinator = coord(entry)
    await coordinator.async_refresh()
    assert cf.insights.call_count == 1
    freezer.tick(INSIGHTS_EVERY + timedelta(seconds=1))
    await coordinator.async_refresh()
    assert cf.insights.call_count == 2
    await hass.config_entries.async_unload(entry.entry_id)


async def test_a_refused_insight_marks_only_its_sensors(hass, config_dir, cf, make_entry):
    cf.insights.side_effect = api.CloudflareAuthError("not allowed")
    entry = make_entry()
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    states = {s.entity_id: s for s in hass.states.async_all("sensor")}
    visitors = next(s for eid, s in states.items() if eid.endswith("visitors_today"))
    assert visitors.state == "unknown" and visitors.attributes["error"] == "not allowed"
    traffic = next(s for eid, s in states.items() if eid.endswith("traffic_summary"))
    assert traffic.state == "1000"           # the rest of the cycle goes on; no new token is asked for
    assert not hass.config_entries.flow.async_progress()
    await hass.config_entries.async_unload(entry.entry_id)
