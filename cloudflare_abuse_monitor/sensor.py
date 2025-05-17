from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from datetime import datetime, timedelta
from .api import fetch_today_traffic_summary, get_skip_ips, get_current_list_ips, check_abuse_ip, add_ips_to_list
from pathlib import Path
import json

SCAN_INTERVAL = timedelta(minutes=1)
CHECKED_IPS_FILE = Path("/config/cloudflare_checked_ips.json")
RECHECK_DAYS = 7

DOMAIN = "cloudflare_abuse_monitor"

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    async_add_entities([
        CloudflareTrafficSummarySensor(entry),
        CloudflareSkipIPsSensor(entry),
        CloudflareListIPsSensor(entry),
        CloudflareHighRiskIPsSensor(entry)
    ])

class CloudflareBaseSensor(SensorEntity):
    def __init__(self, entry: ConfigEntry):
        self._entry = entry
        self._attr_should_poll = True

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Cloudflare Abuse Monitor",
            "manufacturer": "Nir Gliksman",
            "entry_type": "service",
        }

class CloudflareTrafficSummarySensor(CloudflareBaseSensor):
    def __init__(self, entry: ConfigEntry):
        super().__init__(entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} Traffic Summary"
        self._attr_unique_id = f"{data['email']}_{data['zone_name']}_traffic_summary".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "requests"
        self._attr_native_value = None
        self._attr_extra_state_attributes = {}

    async def async_update(self):
        data = self._entry.data
        try:
            summary = await self.hass.async_add_executor_job(
                fetch_today_traffic_summary, data["email"], data["global_token"], data["zone_id"]
            )
            self._attr_native_value = summary.get("requests", 0)
            self._attr_extra_state_attributes = summary
        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {"error": str(e)}

class CloudflareSkipIPsSensor(CloudflareBaseSensor):

    def __init__(self, entry: ConfigEntry):
        super().__init__(entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} Skip IPs"
        self._attr_unique_id = f"{data['email']}_{data['zone_name']}_skip_ips".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "IPs"
        self._attr_native_value = 0
        self._attr_extra_state_attributes = {}

    async def async_update(self):
        data = self._entry.data
        headers = {
            "X-Auth-Email": data["email"],
            "X-Auth-Key": data["global_token"],
            "Content-Type": "application/json"
        }
        now = datetime.utcnow()
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        try:
            skip_ips = await self.hass.async_add_executor_job(
                get_skip_ips,
                data["zone_id"],
                midnight.strftime('%Y-%m-%dT%H:%M:%SZ'),
                now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                headers
            )
            self._attr_native_value = len(skip_ips)
            self._attr_extra_state_attributes = {"skip_ips": skip_ips}
        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {"error": str(e)}

class CloudflareListIPsSensor(CloudflareBaseSensor):
    def __init__(self, entry: ConfigEntry):
        super().__init__(entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} List IPs"
        self._attr_unique_id = f"{data['email']}_{data['zone_name']}_list_ips".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "IPs"
        self._attr_native_value = 0
        self._attr_extra_state_attributes = {}

    async def async_update(self):
        data = self._entry.data
        headers = {
            "X-Auth-Email": data["email"],
            "X-Auth-Key": data["global_token"],
            "Content-Type": "application/json"
        }
        try:
            current_ips = await self.hass.async_add_executor_job(
                get_current_list_ips, data["account_id"], data["list_id"], headers
            )
            self._attr_native_value = len(current_ips)
            self._attr_extra_state_attributes = {"current_list_ips": list(current_ips)}
        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {"error": str(e)}

class CloudflareHighRiskIPsSensor(CloudflareBaseSensor):
    def __init__(self, entry: ConfigEntry):
        super().__init__(entry)
        data = entry.data
        self._email = data["email"]
        self._zone_name = data["zone_name"]
        self._zone_id = data["zone_id"]
        self._attr_name = f"{self._email} {self._zone_name} High Risk IPs"
        self._attr_unique_id = f"{self._email}_{self._zone_id}_high_risk_ips".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "IPs"
        self._attr_native_value = 0
        self._attr_extra_state_attributes = {}
        self._attr_available = True

    async def async_update(self):
        try:
            data = self._entry.data
            options = self._entry.options
            email = data["email"]
            api_key = data["global_token"]
            account_id = data["account_id"]
            zone_id = data["zone_id"]
            list_id = data["list_id"]
            abuseipdb_api_key = data["abuseipdb_token"]
            threshold = int(options.get("abuse_confidence_score", data.get("abuse_confidence_score", 100)))
            headers = {
                "X-Auth-Email": email,
                "X-Auth-Key": api_key,
                "Content-Type": "application/json"
            }

            now = datetime.utcnow()
            midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

            skip_ips = await self.hass.async_add_executor_job(
                get_skip_ips,
                zone_id,
                midnight.strftime('%Y-%m-%dT%H:%M:%SZ'),
                now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                headers
            )
            current_ips = await self.hass.async_add_executor_job(
                get_current_list_ips,
                account_id,
                list_id,
                headers
            )

            potential_ips = list(set(skip_ips) - set(current_ips))
            ips_to_check = []

            if CHECKED_IPS_FILE.exists():
                with open(CHECKED_IPS_FILE, "r") as f:
                    checked_cache = json.load(f)
            else:
                checked_cache = {}

            high_risk_ips = []
            updated_cache = checked_cache.copy()

            for ip in potential_ips:
                last_checked = checked_cache.get(ip)
                should_check = True
                if last_checked:
                    try:
                        last_dt = datetime.fromisoformat(last_checked)
                        if (now - last_dt).days < RECHECK_DAYS:
                            should_check = False
                            updated_cache[ip] = last_checked
                            continue
                    except Exception:
                        pass

                ips_to_check.append(ip)

                try:
                    result = await self.hass.async_add_executor_job(check_abuse_ip, ip, abuseipdb_api_key)
                    updated_cache[ip] = now.isoformat()
                    if result.get("abuse_confidence_score", 0) >= threshold:
                        high_risk_ips.append(result)
                except Exception:
                    pass

            with open(CHECKED_IPS_FILE, "w") as f:
                json.dump(updated_cache, f, indent=2)

            for ip_info in high_risk_ips:
                ip = ip_info["ip"]
                try:
                    await self.hass.async_add_executor_job(
                        add_ips_to_list,
                        account_id,
                        list_id,
                        [ip],
                        headers
                    )
                except Exception:
                    pass

            self._attr_native_value = len(high_risk_ips)
            self._attr_extra_state_attributes = {
                "abuse_confidence_score_threshold": threshold,
                "high_risk_ip_list": [ip["ip"] for ip in high_risk_ips],
                "ips_to_check": ips_to_check
            }

        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {"error": str(e)}
            self._attr_available = False
