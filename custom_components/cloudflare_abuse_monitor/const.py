DOMAIN = "cloudflare_abuse_monitor"

# AbuseIPDB lookup cache in the config dir, shared by every entry.
CHECKED_IPS_FILENAME = "cloudflare_checked_ips.json"

DEFAULT_SCAN_INTERVAL_MINUTES = 1
DEFAULT_ABUSE_CONFIDENCE_SCORE = 100.0
DEFAULT_RECHECK_DAYS = 7
DEFAULT_UNDER_ATTACK_THRESHOLD = 15000

MODE_ACTIVE = "Active"
MODE_MONITOR = "Monitor"

UNDER_ATTACK_LEVEL = "under_attack"

# Config entry data keys.
CONF_API_TOKEN = "api_token"
CONF_ABUSEIPDB_TOKEN = "abuseipdb_token"
CONF_UID_PREFIX = "uid_prefix"
CONF_RECHECK_ENABLED = "recheck_enabled"
# Left by v1.5 and earlier (Global API Key); removed once a token replaces them.
LEGACY_KEYS = ("email", "global_token")

DEFAULT_LIST_NAME = "block_ips"
FALLBACK_SECURITY_LEVEL = "high"

SERVICE_CHECK_IP = "check_ip"
SERVICE_BLOCK_IP = "block_ip"
SERVICE_UNBLOCK_IP = "unblock_ip"
SERVICE_REFRESH = "refresh"

# v1.7: one entry per token, any number of zones. Each zone is a dict in data[CONF_ZONES]
# (a list, so diagnostics can redact it): zone_id, zone_name, account_id, list_name, list_id,
# uid_prefix and, for the zone moved from a v1.6 entry, legacy_storage.
CONF_ZONES = "zones"
ZONE_KEYS = ("zone_id", "zone_name", "account_id", "list_name", "list_id")
CONF_LEGACY_STORAGE = "legacy_storage"

# Zones poll one after the other, this many seconds apart, so a token with many zones never
# sends a burst of requests (Cloudflare allows 1200 requests per 5 minutes per user).
ZONE_STAGGER_SECONDS = 1.0


def zone_records(data) -> list[dict]:
    """The zones of an entry's data, also for data not migrated yet (one zone at the top level)."""
    if data.get(CONF_ZONES):
        return [dict(zone) for zone in data[CONF_ZONES]]
    if not data.get("zone_id"):
        return []
    zone = {key: data.get(key) for key in ZONE_KEYS}
    zone[CONF_UID_PREFIX] = data.get(CONF_UID_PREFIX) or data.get("email") or data["zone_id"]
    zone[CONF_LEGACY_STORAGE] = True
    return [zone]
