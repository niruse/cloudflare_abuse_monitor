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
