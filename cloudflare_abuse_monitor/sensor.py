from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from datetime import datetime, timedelta
from .api import fetch_today_traffic_summary, get_skip_ips, get_current_list_ips, check_abuse_ip, add_ips_to_list
import traceback
import logging
from pathlib import Path
import json

SCAN_INTERVAL = timedelta(hours=1)
SCAN_INTERVAL = timedelta(minutes=1)
CHECKED_IPS_FILE = Path("/config/cloudflare_checked_ips.json")
RECHECK_DAYS = 7

_LOGGER = logging.getLogger(__name__)

# Additional file logger
log_file_path = "/config/cloudflare_abuse_monitor.log"
file_handler = logging.FileHandler(log_file_path)
file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
file_handler.setLevel(logging.DEBUG)

custom_logger = logging.getLogger("cloudflare_abuse_monitor_file")
custom_logger.setLevel(logging.DEBUG)
custom_logger.addHandler(file_handler)
custom_logger.propagate = False

DOMAIN = "cloudflare_abuse_monitor"

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    async_add_entities([
        CloudflareAbuseMonitorSensor(entry),
        CloudflareTrafficSummarySensor(entry),
        CloudflareSkipIPsSensor(entry),
        CloudflareListIPsSensor(entry),
        CloudflareHighRiskIPsSensor(entry)
    ])

class CloudflareBaseSensor(SensorEntity):
    def __init__(self, entry: ConfigEntry, sensor_type: str, unit: str, initial_value):
        self._entry = entry
        data = entry.data
        email = data.get("email", "unknown_email")
        zone_name = data.get("zone_name", "unknown_zone")
        self._sensor_type = sensor_type
        self._attr_name = f"{email} {zone_name} {sensor_type}"
        self._attr_unique_id = f"{email}_{zone_name}_{sensor_type}".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = unit
        self._attr_native_value = initial_value
        self._attr_extra_state_attributes = {}
        self._attr_should_poll = True

class CloudflareAbuseMonitorSensor(CloudflareBaseSensor):
    def __init__(self, entry: ConfigEntry):
        super().__init__(entry, "Abuse Monitor", "events", "running")

    async def async_update(self):
        data = self._entry.data
        options = self._entry.options
        self._attr_extra_state_attributes = {
            "email": data.get("email"),
            "account_id": data.get("account_id"),
            "zone_id": data.get("zone_id"),
            "zone_name": data.get("zone_name"),
            "list_name": data.get("list_name"),
            "abuse_confidence_score": options.get("abuse_confidence_score", data.get("abuse_confidence_score", 100.0)),
        }

class CloudflareTrafficSummarySensor(CloudflareBaseSensor):
    def __init__(self, entry: ConfigEntry):
        super().__init__(entry, "Traffic Summary", "requests", None)

    async def async_update(self):
        data = self._entry.data
        email = data.get("email")
        api_key = data.get("global_token")
        zone_id = data.get("zone_id")
        try:
            summary = await self.hass.async_add_executor_job(fetch_today_traffic_summary, email, api_key, zone_id)
            self._attr_native_value = summary.get("requests", 0)
            self._attr_extra_state_attributes = summary
        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {"error": str(e)}

class CloudflareSkipIPsSensor(CloudflareBaseSensor):
    def __init__(self, entry: ConfigEntry):
        super().__init__(entry, "Skip IPs", "IPs", 0)

    async def async_update(self):
        data = self._entry.data
        email = data.get("email")
        api_key = data.get("global_token")
        zone_id = data.get("zone_id")
        headers = {
            "X-Auth-Email": email,
            "X-Auth-Key": api_key,
            "Content-Type": "application/json"
        }
        now = datetime.utcnow()
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        datetime_geq = midnight.strftime('%Y-%m-%dT%H:%M:%SZ')
        datetime_lt = now.strftime('%Y-%m-%dT%H:%M:%SZ')
        try:
            skip_ips = await self.hass.async_add_executor_job(get_skip_ips, zone_id, datetime_geq, datetime_lt, headers)
            self._attr_native_value = len(skip_ips)
            self._attr_extra_state_attributes = {"skip_ips": skip_ips}
        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {"error": str(e)}

class CloudflareListIPsSensor(CloudflareBaseSensor):
    def __init__(self, entry: ConfigEntry):
        super().__init__(entry, "List IPs", "IPs", 0)

    async def async_update(self):
        data = self._entry.data
        email = data.get("email")
        api_key = data.get("global_token")
        account_id = data.get("account_id")
        list_id = data.get("list_id")
        headers = {
            "X-Auth-Email": email,
            "X-Auth-Key": api_key,
            "Content-Type": "application/json"
        }
        try:
            current_ips = await self.hass.async_add_executor_job(get_current_list_ips, account_id, list_id, headers)
            self._attr_native_value = len(current_ips)
            self._attr_extra_state_attributes = {"current_list_ips": list(current_ips)}
        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {"error": str(e)}

class CloudflareHighRiskIPsSensor(SensorEntity):
    def __init__(self, entry: ConfigEntry):
        self._entry = entry
        data = entry.data
        self._email = data.get("email")
        self._zone_name = data.get("zone_name")
        self._zone_id = data.get("zone_id")
        self._attr_name = f"{self._email} {self._zone_name} High Risk IPs"
        self._attr_unique_id = f"{self._email}_{self._zone_id}_high_risk_ips".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "IPs"
        self._attr_native_value = 0
        self._attr_extra_state_attributes = {}
        self._attr_available = True
        self._attr_should_poll = True

    async def async_update(self):
        try:
            data = self._entry.data
            options = self._entry.options
            email = data.get("email")
            api_key = data.get("global_token")
            account_id = data.get("account_id")
            zone_id = data.get("zone_id")
            list_id = data.get("list_id")
            abuseipdb_api_key = data.get("abuseipdb_token")
            threshold = int(options.get("abuse_confidence_score", data.get("abuse_confidence_score", 100)))
            headers = {
                "X-Auth-Email": email,
                "X-Auth-Key": api_key,
                "Content-Type": "application/json"
            }
            now = datetime.utcnow()
            midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
            datetime_geq = midnight.strftime('%Y-%m-%dT%H:%M:%SZ')
            datetime_lt = now.strftime('%Y-%m-%dT%H:%M:%SZ')

            skip_ips = await self.hass.async_add_executor_job(get_skip_ips, zone_id, datetime_geq, datetime_lt, headers)
            current_ips = await self.hass.async_add_executor_job(get_current_list_ips, account_id, list_id, headers)
            ips_to_check = list(set(skip_ips) - set(current_ips))

            # Load or initialize cache file
            if CHECKED_IPS_FILE.exists():
                with open(CHECKED_IPS_FILE, "r") as f:
                    checked_cache = json.load(f)
            else:
                checked_cache = {}

            high_risk_ips = []
            updated_cache = checked_cache.copy()

            for ip in ips_to_check:
                last_checked = checked_cache.get(ip)
                should_check = True
                if last_checked:
                    try:
                        last_dt = datetime.fromisoformat(last_checked)
                        if (now - last_dt).days < RECHECK_DAYS:
                            should_check = False
                    except Exception:
                        pass

                if should_check:
                    try:
                        result = await self.hass.async_add_executor_job(check_abuse_ip, ip, abuseipdb_api_key)
                        updated_cache[ip] = now.isoformat()
                        if result.get("abuse_confidence_score", 0) >= threshold:
                            high_risk_ips.append(result)
                    except Exception as ip_error:
                        custom_logger.error("Error checking IP %s: %s", ip, ip_error)
                        custom_logger.debug(traceback.format_exc())

            # Save updated cache
            with open(CHECKED_IPS_FILE, "w") as f:
                json.dump(updated_cache, f, indent=2)

            # Add high risk IPs to Cloudflare list
            if high_risk_ips:
                for ip_info in high_risk_ips:
                    ip = ip_info["ip"]
                    try:
                        await self.hass.async_add_executor_job(
                            add_ips_to_list, account_id, list_id, [ip], headers
                        )
                        custom_logger.info(f"✅ Added high risk IP to list: {ip}")
                    except Exception as add_error:
                        custom_logger.error(f"❌ Failed to add IP {ip} to list: {add_error}")
                        custom_logger.debug(traceback.format_exc())

            self._attr_native_value = len(high_risk_ips)
            self._attr_extra_state_attributes = {
                "abuse_confidence_score_threshold": threshold,
                "high_risk_ip_list": [ip_info["ip"] for ip_info in high_risk_ips],
                "ips_to_check": ips_to_check
            }
            self._attr_available = True

        except Exception as e:
            custom_logger.error("Error updating CloudflareHighRiskIPsSensor: %s", e)
            custom_logger.debug(traceback.format_exc())
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {"error": str(e)}
            self._attr_available = False
