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
