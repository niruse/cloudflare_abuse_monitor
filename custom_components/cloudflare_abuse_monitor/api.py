"""Blocking wrappers around the Cloudflare and AbuseIPDB APIs.

Every function here does network I/O with ``requests`` and must run in the executor.
Failures raise, so the caller can tell "the API said zero" apart from "the API failed".
"""
import logging
from datetime import datetime, timezone

import requests

_LOGGER = logging.getLogger(__name__)

CLOUDFLARE_API_URL = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_ZONES_URL = f"{CLOUDFLARE_API_URL}/zones"
CLOUDFLARE_GRAPHQL_URL = f"{CLOUDFLARE_API_URL}/graphql"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

# Without a timeout a stalled connection would hold an executor thread forever.
TIMEOUT = 30


class CloudflareApiError(Exception):
    """Cloudflare answered, but not with the data we asked for."""


class AbuseIPDBRateLimited(Exception):
    """AbuseIPDB refused the lookup because the daily quota is used up."""


def get_headers(email, api_key):
    return {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json",
    }


def iso_utc(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _graphql_zone(headers, query):
    response = requests.post(
        CLOUDFLARE_GRAPHQL_URL, headers=headers, json={"query": query}, timeout=TIMEOUT
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        raise CloudflareApiError(payload["errors"][0].get("message", str(payload["errors"])))
    zones = ((payload.get("data") or {}).get("viewer") or {}).get("zones") or []
    if not zones:
        raise CloudflareApiError("Cloudflare returned no analytics for this zone")
    return zones[0]


def fetch_zones(email, api_key):
    """Return {"success": bool, "result": [zones]}, following every page."""
    headers = get_headers(email, api_key)
    zones = []
    page = 1
    while True:
        response = requests.get(
            CLOUDFLARE_ZONES_URL,
            headers=headers,
            params={"page": page, "per_page": 50},
            timeout=TIMEOUT,
        )
        # Bad credentials come back as 400/403 with success=false, not as a network error.
        if response.status_code in (400, 401, 403):
            return {"success": False, "result": []}
        response.raise_for_status()
        payload = response.json()
        if not payload.get("success", False):
            return {"success": False, "result": []}
        zones.extend(payload.get("result", []))
        if page >= (payload.get("result_info") or {}).get("total_pages", 1):
            return {"success": True, "result": zones}
        page += 1


def fetch_today_traffic_summary(email, api_key, zone_id):
    headers = get_headers(email, api_key)

    now = datetime.now(timezone.utc)
    today_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

    datetime_geq = iso_utc(today_midnight)
    datetime_lt = iso_utc(now)

    # No dimensions requested, so Cloudflare returns one group summing the whole window.
    query = f"""
    {{
      viewer {{
        zones(filter: {{zoneTag: "{zone_id}"}}) {{
          httpRequests1hGroups(limit: 100, filter: {{datetime_geq: "{datetime_geq}", datetime_lt: "{datetime_lt}"}}) {{
            sum {{
              pageViews
              requests
              encryptedBytes
              encryptedRequests
              bytes
              cachedBytes
              cachedRequests
            }}
          }}
        }}
      }}
    }}
    """

    groups = _graphql_zone(headers, query).get("httpRequests1hGroups") or []
    # Right after midnight UTC there is no group yet: that is zero traffic, not an error.
    summary = groups[0]["sum"] if groups else {}

    return {
        "from": datetime_geq,
        "to": datetime_lt,
        "pageviews": summary.get("pageViews", 0),
        "requests": summary.get("requests", 0),
        "bytes": summary.get("bytes", 0),
        "cached_bytes": summary.get("cachedBytes", 0),
        "cached_requests": summary.get("cachedRequests", 0),
        "encrypted_bytes": summary.get("encryptedBytes", 0),
        "encrypted_requests": summary.get("encryptedRequests", 0),
    }


def get_skip_ips(zone_id, datetime_geq, datetime_lt, headers):
    # Filter on the server so the 1000-event limit is spent on "skip" events only.
    query = f"""
    {{
      viewer {{
        zones(filter: {{zoneTag: "{zone_id}"}}) {{
          firewallEventsAdaptive(
            limit: 1000,
            filter: {{
              datetime_geq: "{datetime_geq}",
              datetime_lt: "{datetime_lt}",
              action: "skip"
            }}
          ) {{
            clientIP
            action
          }}
        }}
      }}
    }}
    """

    events = _graphql_zone(headers, query).get("firewallEventsAdaptive") or []
    return sorted({event["clientIP"] for event in events if event.get("action") == "skip"})


def fetch_rules_lists(account_id, headers):
    """Return {list name: list id} for the account's IP lists."""
    url = f"{CLOUDFLARE_API_URL}/accounts/{account_id}/rules/lists"
    response = requests.get(url, headers=headers, timeout=TIMEOUT)
    response.raise_for_status()
    return {
        item["name"]: item["id"]
        for item in response.json().get("result", [])
        if item.get("kind", "ip") == "ip"
    }


def get_current_list_ips(account_id, list_id, headers):
    """Return every IP in the list (the endpoint is cursor-paginated, 25 items per page by default)."""
    url = f"{CLOUDFLARE_API_URL}/accounts/{account_id}/rules/lists/{list_id}/items"
    current_ips = set()
    cursor = None
    while True:
        params = {"per_page": 500}
        if cursor:
            params["cursor"] = cursor
        response = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        for item in payload.get("result", []):
            ip = item.get("ip")
            if ip:
                current_ips.add(ip)
        cursor = ((payload.get("result_info") or {}).get("cursors") or {}).get("after")
        if not cursor:
            return current_ips


def check_abuse_ip(ip: str, api_key: str):
    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
    }
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    response = requests.get(ABUSEIPDB_CHECK_URL, headers=headers, params=querystring, timeout=TIMEOUT)
    if response.status_code == 429:
        raise AbuseIPDBRateLimited(response.text)
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "ip": ip,
            "abuse_confidence_score": data["abuseConfidenceScore"],
            "countryCode": data.get("countryCode", "Unknown"),
            "usageType": data.get("usageType", "Unknown"),
            "domain": data.get("domain", "Unknown"),
            "totalReports": data.get("totalReports", 0),
            "lastReportedAt": data.get("lastReportedAt", "Never"),
        }
    return {"ip": ip, "error": f"{response.status_code}: {response.text}"}


def add_ips_to_list(account_id, list_id, new_ips, headers):
    url = f"{CLOUDFLARE_API_URL}/accounts/{account_id}/rules/lists/{list_id}/items"
    payload = [{"ip": ip} for ip in new_ips]

    response = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    if response.status_code != 200:
        raise CloudflareApiError(f"Failed to add IPs: {response.status_code} {response.text}")
    _LOGGER.info("Added %s to the Cloudflare list", ", ".join(new_ips))


def get_security_level(zone_id, headers):
    url = f"{CLOUDFLARE_API_URL}/zones/{zone_id}/settings/security_level"
    response = requests.get(url, headers=headers, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json().get("result", {}).get("value", "")


def set_security_level(zone_id, headers, level):
    url = f"{CLOUDFLARE_API_URL}/zones/{zone_id}/settings/security_level"
    response = requests.patch(url, headers=headers, json={"value": level}, timeout=TIMEOUT)
    if response.status_code != 200:
        raise CloudflareApiError(
            f"Failed to set security level to {level}: {response.status_code} {response.text}"
        )
    _LOGGER.info("Set Cloudflare security level to %s", level)
