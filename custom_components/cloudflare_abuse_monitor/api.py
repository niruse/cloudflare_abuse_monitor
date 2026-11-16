"""Blocking wrappers around the Cloudflare and AbuseIPDB APIs.

Every function here does network I/O with ``requests`` and must run in the executor.
Failures raise, so the caller can tell "the API said zero" apart from "the API failed".

Error text is built from the status code and Cloudflare's ``errors[].message`` only, never
from the request, so a token or key can never end up in a log line or an exception.
"""
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import requests

_LOGGER = logging.getLogger(__name__)

CLOUDFLARE_API_URL = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_ZONES_URL = f"{CLOUDFLARE_API_URL}/zones"
CLOUDFLARE_GRAPHQL_URL = f"{CLOUDFLARE_API_URL}/graphql"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

CUSTOM_PHASE = "http_request_firewall_custom"
BLOCK_RULE_REF = "cfam_block_ips"
SKIP_RULE_REF = "cfam_skip_log"

# Without a timeout a stalled connection would hold an executor thread forever.
TIMEOUT = 30

# Least-privilege token: (permissionGroupKey, type, display name shown in the dashboard).
TOKEN_PERMISSIONS = (
    ("zone", "read", "Zone > Zone > Read"),
    ("analytics", "read", "Zone > Analytics > Read"),
    ("zone_settings", "edit", "Zone > Zone Settings > Edit"),
    ("zone_waf", "edit", "Zone > Zone WAF > Edit"),
    ("account_filter_lists", "edit", "Account > Account Filter Lists > Edit"),
)
TOKEN_NAME = "Home Assistant Abuse Monitor"
# Cloudflare's permission group ids. The account-token link takes ids, so every row is pre-filled;
# the user-token link takes only short keys, and Cloudflare has no documented key for Zone WAF or
# Account Filter Lists (checked live 2026-11-16: the short-key link dropped Account Filter Lists).
PERMISSION_IDS = {
    "zone": "c8fed203ed3043cba015a93ad1616f1f",                  # Zone Read
    "analytics": "9c88f9c5bce24ce7af9a958ba9c504db",             # Analytics Read
    "zone_settings": "3030687196b94b638145a3953da2b699",         # Zone Settings Write
    "zone_waf": "fb6778dc191143babbfaa57993f1d275",              # Zone WAF Write
    "account_filter_lists": "2edbf20661fd4661b0fe10e9e12f485c",  # Account Filter Lists Write
}


def _create_token_url():
    keys = [{"key": PERMISSION_IDS[key], "type": kind} for key, kind, _ in TOKEN_PERMISSIONS]
    return (
        "https://dash.cloudflare.com/?to=/:account/api-tokens"
        f"&permissionGroupKeys={quote(json.dumps(keys, separators=(',', ':')), safe='')}"
        f"&name={quote(TOKEN_NAME, safe='')}"
    )


# Opens the dashboard's "create account API token" page (the account is picked there) with all
# five permissions pre-filled by id; the setup text asks the user to narrow Zone Resources to
# this zone. An account-owned token is checked with /accounts/{id}/tokens/verify.
CREATE_TOKEN_URL = _create_token_url()

# Only these characters can be sent in a header. Anything else (a pasted newline, a tab)
# would make requests raise InvalidHeader, whose message contains the whole header value.
_SECRET_RE = re.compile(r"[A-Za-z0-9._~+/=-]+")


def valid_secret(value):
    """True when value can be sent as a token or key without leaking through an error."""
    return bool(value) and _SECRET_RE.fullmatch(value) is not None

# Cloudflare error codes that mean "this token/credential is not accepted".
_AUTH_CODES = {1000, 1001, 6003, 6100, 6102, 6103, 6111, 9103, 9106, 9109, 10000}
# GraphQL answers HTTP 200 with errors[]. Only these mean the token: a plan or dataset limit
# ("does not have access to the path", a too-old time range) is not something a new token fixes.
_GRAPHQL_AUTH_CODES = {"authz", "authn", "unauthorized", "forbidden"}
_GRAPHQL_AUTH_TEXT = re.compile(r"not authori[sz]ed|authentication error", re.I)


class CloudflareApiError(Exception):
    """Cloudflare answered, but not with the data we asked for."""

    def __init__(self, message, status=None, codes=()):
        super().__init__(message)
        self.status = status
        self.codes = tuple(codes)


class CloudflareAuthError(CloudflareApiError):
    """The token is invalid, or lacks the permission this call needs (HTTP 401/403)."""


class CloudflareNotFound(CloudflareApiError):
    """HTTP 404."""


class AbuseIPDBRateLimited(Exception):
    """AbuseIPDB refused the lookup because the daily quota is used up."""


class AbuseIPDBError(Exception):
    """AbuseIPDB answered with an error that is not about the key."""


def get_headers(api_token):
    return {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}


def iso_utc(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _payload(response):
    try:
        payload = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _errors(payload):
    errors = payload.get("errors") or []
    return [e for e in errors if isinstance(e, dict)]


def _raise_for(response, payload, what):
    status = response.status_code
    errors = _errors(payload)
    codes = [e.get("code") for e in errors if isinstance(e.get("code"), int)]
    detail = "; ".join(str(e.get("message", "")) for e in errors if e.get("message")) or "no detail"
    message = f"{what}: HTTP {status}: {detail}"
    if status in (401, 403) or (status == 400 and set(codes) & _AUTH_CODES):
        raise CloudflareAuthError(message, status, codes)
    if status == 404:
        raise CloudflareNotFound(message, status, codes)
    raise CloudflareApiError(message, status, codes)


def _send(method, url, headers, what, **kwargs):
    try:
        return requests.request(method, url, headers=headers, timeout=TIMEOUT, **kwargs)
    except requests.exceptions.InvalidHeader:
        # The original message holds the header value (the token); never pass it on.
        raise CloudflareAuthError(f"{what}: the API token contains characters a header cannot carry") from None


def _call(method, url, headers, what, **kwargs):
    """Make one Cloudflare v4 call and return its JSON body, or raise a typed error."""
    response = _send(method, url, headers, what, **kwargs)
    payload = _payload(response)
    if response.status_code >= 300 or payload.get("success") is False:
        _raise_for(response, payload, what)
    return payload


def _graphql_auth_error(error):
    """Missing Analytics Read comes back as HTTP 200 with errors[]; tell it from a plan limit."""
    code = str((error.get("extensions") or {}).get("code") or "").lower()
    if code:
        return code in _GRAPHQL_AUTH_CODES
    return bool(_GRAPHQL_AUTH_TEXT.search(str(error.get("message", ""))))


def _graphql_zone(headers, query):
    response = _send("POST", CLOUDFLARE_GRAPHQL_URL, headers, "GraphQL", json={"query": query})
    payload = _payload(response)
    if response.status_code >= 300:
        _raise_for(response, payload, "GraphQL")
    errors = _errors(payload)
    if errors:
        first = errors[0]
        message = str(first.get("message", "GraphQL error"))
        if _graphql_auth_error(first):
            raise CloudflareAuthError(message)
        raise CloudflareApiError(message)
    zones = ((payload.get("data") or {}).get("viewer") or {}).get("zones") or []
    if not zones:
        raise CloudflareApiError("Cloudflare returned no analytics for this zone")
    return zones[0]


# --- token ---------------------------------------------------------------------------

def verify_user_token(headers):
    """Return the token status (active, disabled, expired). Raises CloudflareAuthError if unknown."""
    payload = _call("GET", f"{CLOUDFLARE_API_URL}/user/tokens/verify", headers, "Token verify")
    return (payload.get("result") or {}).get("status", "")


def verify_account_token(account_id, headers):
    """Same check for an account-owned token, which /user/tokens/verify does not know."""
    payload = _call(
        "GET", f"{CLOUDFLARE_API_URL}/accounts/{account_id}/tokens/verify", headers, "Token verify"
    )
    return (payload.get("result") or {}).get("status", "")


# --- zones and analytics ---------------------------------------------------------------

def fetch_zones(headers):
    """Return every zone the token can read, following every page."""
    zones = []
    page = 1
    while True:
        payload = _call(
            "GET", CLOUDFLARE_ZONES_URL, headers, "Zones", params={"page": page, "per_page": 50}
        )
        zones.extend(payload.get("result") or [])
        if page >= (payload.get("result_info") or {}).get("total_pages", 1):
            return zones
        page += 1


def fetch_today_traffic_summary(headers, zone_id):
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


def probe_analytics(headers, zone_id):
    """Read one row of each dataset the integration uses. Raises CloudflareAuthError without Analytics Read."""
    now = datetime.now(timezone.utc)
    geq, lt = iso_utc(now - timedelta(hours=1)), iso_utc(now)
    query = f"""
    {{
      viewer {{
        zones(filter: {{zoneTag: "{zone_id}"}}) {{
          httpRequests1hGroups(limit: 1, filter: {{datetime_geq: "{geq}", datetime_lt: "{lt}"}}) {{
            sum {{ requests }}
          }}
          firewallEventsAdaptive(limit: 1, filter: {{datetime_geq: "{geq}", datetime_lt: "{lt}"}}) {{
            action
          }}
        }}
      }}
    }}
    """
    _graphql_zone(headers, query)


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


# --- IP lists ----------------------------------------------------------------------------

def fetch_ip_lists(account_id, headers):
    """Return the account's lists of kind ip, as Cloudflare describes them."""
    payload = _call(
        "GET", f"{CLOUDFLARE_API_URL}/accounts/{account_id}/rules/lists", headers, "Lists"
    )
    return [item for item in payload.get("result") or [] if item.get("kind", "ip") == "ip"]


def fetch_rules_lists(account_id, headers):
    """Return {list name: list id} for the account's IP lists."""
    return {item["name"]: item["id"] for item in fetch_ip_lists(account_id, headers)}


def create_ip_list(account_id, name, headers):
    payload = _call(
        "POST",
        f"{CLOUDFLARE_API_URL}/accounts/{account_id}/rules/lists",
        headers,
        "Create list",
        json={
            "name": name,
            "kind": "ip",
            "description": "IPs blocked by Cloudflare Abuse Monitor (Home Assistant)",
        },
    )
    return payload.get("result") or {}


def update_list_description(account_id, list_id, description, headers):
    """Write the description back unchanged: proves Filter Lists Edit without changing anything."""
    _call(
        "PUT",
        f"{CLOUDFLARE_API_URL}/accounts/{account_id}/rules/lists/{list_id}",
        headers,
        "Update list",
        json={"description": description or ""},
    )


def get_list_items(account_id, list_id, headers):
    """Return {ip: item id} for every IP in the list (cursor-paginated, 25 per page by default)."""
    url = f"{CLOUDFLARE_API_URL}/accounts/{account_id}/rules/lists/{list_id}/items"
    items = {}
    cursor = None
    while True:
        params = {"per_page": 500}
        if cursor:
            params["cursor"] = cursor
        payload = _call("GET", url, headers, "List items", params=params)
        for item in payload.get("result") or []:
            ip = item.get("ip")
            if ip:
                items[ip] = item.get("id")
        cursor = ((payload.get("result_info") or {}).get("cursors") or {}).get("after")
        if not cursor:
            return items


def get_current_list_ips(account_id, list_id, headers):
    """Return every IP in the list."""
    return set(get_list_items(account_id, list_id, headers))


def add_ips_to_list(account_id, list_id, new_ips, headers):
    url = f"{CLOUDFLARE_API_URL}/accounts/{account_id}/rules/lists/{list_id}/items"
    _call("POST", url, headers, "Add IPs", json=[{"ip": ip} for ip in new_ips])
    _LOGGER.info("Added %s to the Cloudflare list", ", ".join(new_ips))


def remove_list_items(account_id, list_id, item_ids, headers):
    url = f"{CLOUDFLARE_API_URL}/accounts/{account_id}/rules/lists/{list_id}/items"
    _call("DELETE", url, headers, "Remove IPs", json={"items": [{"id": i} for i in item_ids]})


# --- security level ------------------------------------------------------------------

def get_security_level(zone_id, headers):
    url = f"{CLOUDFLARE_API_URL}/zones/{zone_id}/settings/security_level"
    return (_call("GET", url, headers, "Security level").get("result") or {}).get("value", "")


def set_security_level(zone_id, headers, level):
    url = f"{CLOUDFLARE_API_URL}/zones/{zone_id}/settings/security_level"
    _call("PATCH", url, headers, f"Set security level to {level}", json={"value": level})
    _LOGGER.info("Set Cloudflare security level to %s", level)


# --- WAF custom rules ----------------------------------------------------------------

def get_custom_entrypoint(zone_id, headers):
    """Return the zone's custom-rules entrypoint ruleset, or None when it does not exist yet."""
    url = f"{CLOUDFLARE_API_URL}/zones/{zone_id}/rulesets/phases/{CUSTOM_PHASE}/entrypoint"
    try:
        return _call("GET", url, headers, "Custom rules").get("result") or {}
    except CloudflareNotFound:
        return None


def create_custom_entrypoint(zone_id, rules, headers):
    """Only for a zone with no entrypoint: a PUT replaces every rule in an existing one."""
    url = f"{CLOUDFLARE_API_URL}/zones/{zone_id}/rulesets/phases/{CUSTOM_PHASE}/entrypoint"
    _call("PUT", url, headers, "Create custom rules", json={"rules": rules})


def add_custom_rule(zone_id, ruleset_id, rule, headers, before=None, position=None):
    """Add one rule to an existing ruleset, leaving the other rules alone.

    Appended at the end, placed right before the rule whose id is ``before``, or at
    ``position`` ({"after": id} or {"index": n}, as Cloudflare takes it).
    """
    url = f"{CLOUDFLARE_API_URL}/zones/{zone_id}/rulesets/{ruleset_id}/rules"
    body = dict(rule)
    if before:
        body["position"] = {"before": before}
    elif position:
        body["position"] = dict(position)
    _call("POST", url, headers, "Add custom rule", json=body)


def update_custom_rule(zone_id, ruleset_id, rule_id, rule, headers):
    """Change one rule in place (PATCH); every other rule of the ruleset stays as it is."""
    url = f"{CLOUDFLARE_API_URL}/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"
    _call("PATCH", url, headers, "Update custom rule", json=dict(rule))


def delete_custom_rule(zone_id, ruleset_id, rule_id, headers):
    url = f"{CLOUDFLARE_API_URL}/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"
    _call("DELETE", url, headers, "Delete custom rule")


# --- the plan's limit on custom rules ------------------------------------------------------

# Custom rules per zone by plan (Cloudflare documentation); an unknown plan is assumed Free.
PLAN_RULE_LIMITS = {"free": 5, "pro": 20, "business": 100, "enterprise": 1000}
FALLBACK_RULE_LIMIT = PLAN_RULE_LIMITS["free"]
_LIMIT_TEXT = re.compile(r"(\d+)\s+out\s+of\s+(\d+)", re.I)


def fetch_zone_plan(zone_id, headers):
    """Return the zone's plan as Cloudflare describes it ({"legacy_id": "free", "name": ...})."""
    payload = _call("GET", f"{CLOUDFLARE_ZONES_URL}/{zone_id}", headers, "Zone")
    return (payload.get("result") or {}).get("plan") or {}


def rule_limit_for_plan(plan):
    """Custom rules allowed by a zone plan, or None when the plan is not recognised."""
    if not isinstance(plan, dict):
        return None
    legacy = str(plan.get("legacy_id") or "").lower()
    if legacy in PLAN_RULE_LIMITS:
        return PLAN_RULE_LIMITS[legacy]
    name = str(plan.get("name") or "").lower()
    for key in ("enterprise", "business", "pro", "free"):
        if key in name.split():
            return PLAN_RULE_LIMITS[key]
    return None


def rule_limit_from_error(error):
    """The limit in "exceeded the maximum number of rules in the phase ...: 6 out of 5", or None."""
    match = _LIMIT_TEXT.search(str(error))
    return int(match.group(2)) if match else None


def block_rule(list_name):
    return {
        "ref": BLOCK_RULE_REF,
        "description": "Cloudflare Abuse Monitor: block listed IPs",
        "expression": f"(ip.src in ${list_name})",
        "action": "block",
        "enabled": True,
    }


def skip_rule(list_name):
    # Every visitor not already blocked produces a "skip" firewall event, which is the only
    # thing firewallEventsAdaptive(action: "skip") sees. Placed last it skips nothing real.
    return {
        "ref": SKIP_RULE_REF,
        "description": "Cloudflare Abuse Monitor: log visitors for checking",
        "expression": f"not (ip.src in ${list_name})",
        "action": "skip",
        "action_parameters": {"ruleset": "current"},
        "logging": {"enabled": True},
        "enabled": True,
    }


def normalize_expression(expression):
    """Lower case, single spaces, outer parentheses removed: "(ip.src  in $X)" -> "ip.src in $x"."""
    text = re.sub(r"\s+", " ", expression or "").strip().lower()
    while text.startswith("(") and text.endswith(")") and balanced(text[1:-1]):
        text = text[1:-1].strip()
    return text


_norm = normalize_expression


def balanced(text):
    depth = 0
    for char in text:
        depth += {"(": 1, ")": -1}.get(char, 0)
        if depth < 0:
            return False
    return depth == 0


def or_parts(expression):
    """Split an expression at its top-level ``or`` / ``||`` (outside brackets and strings)."""
    text = normalize_expression(expression)
    parts, depth, start, i, quoted = [], 0, 0, 0, False
    while i < len(text):
        char = text[i]
        if char == '"' and (i == 0 or text[i - 1] != "\\"):
            quoted = not quoted
        elif not quoted:
            if char in "({[":
                depth += 1
            elif char in ")}]":
                depth -= 1
            elif depth == 0:
                token = next((t for t in (" or ", " || ") if text.startswith(t, i)), None)
                if token:
                    parts.append(text[start:i])
                    i += len(token)
                    start = i
                    continue
        i += 1
    parts.append(text[start:])
    return [normalize_expression(part) for part in parts]


# The README up to v1.5 asked for a "Skip by country" rule listing every country.
_COUNTRY_SET = re.compile(r'^ip\.geoip\.country in \{((?:\s*"[a-z0-9]{2}")+)\s*\}$')
_ALL_COUNTRIES = 200


def _enabled(rule):
    return rule.get("enabled", True) is not False


def skips_rest_of_ruleset(rule):
    return rule.get("action") == "skip" and (rule.get("action_parameters") or {}).get("ruleset") == "current"


_skips_rest_of_ruleset = skips_rest_of_ruleset


def is_block_rule(rule, list_name):
    """Our Block rule: by ref, or "ip.src in $<list>" (any parentheses and spacing).

    Also a Block rule extended to make room, "(<original>) or (ip.src in $<list>)": the list
    test is one of the expression's top-level "or" parts.
    """
    if rule.get("ref") == BLOCK_RULE_REF:
        return True
    if not (_enabled(rule) and rule.get("action") == "block"):
        return False
    return f"ip.src in ${list_name.lower()}" in or_parts(rule.get("expression"))


def is_skip_rule(rule, list_name):
    """Our Skip rule, or a logged skip that matches (nearly) every visitor the same way.

    A narrow skip (one monitor IP, one path) does not count: firewallEventsAdaptive would then
    only see that traffic.
    """
    if rule.get("ref") == SKIP_RULE_REF:
        return True
    if not (_enabled(rule) and rule.get("action") == "skip"):
        return False
    if (rule.get("logging") or {}).get("enabled") is False:
        return False  # an unlogged skip produces no firewall events
    expression = _norm(rule.get("expression"))
    name = list_name.lower()
    if expression in ("true", f"not ip.src in ${name}", f"not (ip.src in ${name})"):
        return True
    match = _COUNTRY_SET.match(expression)
    return bool(match) and len(set(re.findall(r'"([a-z0-9]{2})"', match.group(1)))) >= _ALL_COUNTRIES


def missing_rules(ruleset, list_name):
    """Return the rules (block, then skip) that the ruleset does not have yet."""
    rules = (ruleset or {}).get("rules") or []
    wanted = []
    if not any(is_block_rule(rule, list_name) for rule in rules):
        wanted.append(block_rule(list_name))
    if not any(is_skip_rule(rule, list_name) for rule in rules):
        wanted.append(skip_rule(list_name))
    return wanted


def block_rule_position(ruleset):
    """Id of the first enabled rule that skips the rest of the ruleset, or None.

    A new Block rule goes before it: after such a skip it would never run for the requests
    the skip matches, and Active mode would list IPs that are never blocked.
    """
    for rule in (ruleset or {}).get("rules") or []:
        if _enabled(rule) and _skips_rest_of_ruleset(rule) and rule.get("id"):
            return rule["id"]
    return None


# --- AbuseIPDB ---------------------------------------------------------------------------

def check_abuse_ip(ip: str, api_key: str):
    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
    }
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    try:
        response = requests.get(ABUSEIPDB_CHECK_URL, headers=headers, params=querystring, timeout=TIMEOUT)
    except requests.exceptions.InvalidHeader:
        # The original message holds the key; never pass it on.
        raise AbuseIPDBError("AbuseIPDB: the API key contains characters a header cannot carry") from None
    if response.status_code == 429:
        raise AbuseIPDBRateLimited("AbuseIPDB daily quota reached")
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
    detail = "; ".join(
        str(e.get("detail", "")) for e in _errors(_payload(response)) if e.get("detail")
    )
    return {"ip": ip, "error": f"{response.status_code}: {detail or 'no detail'}", "status": response.status_code}


def validate_abuseipdb_key(api_key):
    """Return "ok", "rate_limited" or "invalid". One lookup, one unit of the daily quota."""
    try:
        result = check_abuse_ip("127.0.0.1", api_key)
    except AbuseIPDBRateLimited:
        return "rate_limited"  # the key is valid, the quota is used up
    if "error" not in result:
        return "ok"
    if result.get("status") in (401, 403, 422):
        return "invalid"
    raise AbuseIPDBError(f"AbuseIPDB: {result['error']}")
