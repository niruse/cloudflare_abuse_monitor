import asyncio
import random
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
import aiofiles
import os
from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .api import (
    fetch_today_traffic_summary,
    get_skip_ips,
    get_current_list_ips,
    check_abuse_ip,
    add_ips_to_list,
    set_under_attack_mode,
)
from .const import CONFIG_FILE 

DOMAIN = "cloudflare_abuse_monitor"
CHECKED_IPS_FILE = Path("/config/cloudflare_checked_ips.json")
_LOGGER = logging.getLogger(__name__)

log_file_path = "/config/cloudflare_abuse_monitor.log"
file_handler = logging.FileHandler(log_file_path)
file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
file_handler.setLevel(logging.DEBUG)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    async_add_entities([
        CloudflareTrafficSummarySensor(hass, entry),
        CloudflareSkipIPsSensor(hass, entry),
        CloudflareListIPsSensor(hass, entry),
        CloudflareHighRiskIPsSensor(hass, entry),
        CloudflareUnderAttackSensor(hass, entry),
    ])

class CloudflareBaseSensor(SensorEntity):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry):
        self.hass = hass
        self._entry = entry
        self._attr_should_poll = True
        self._next_update_in = 60 * 60
        self._attr_extra_state_attributes = {}
        self.config_file = CONFIG_FILE

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Cloudflare Abuse Monitor",
            "manufacturer": "Nir Gliksman",
            "entry_type": "service",
        }

    @property
    def extra_state_attributes(self):
        attrs = self._attr_extra_state_attributes.copy()
        if hasattr(self, '_next_update_in') and self._next_update_in is not None:
            attrs["next_update_in_seconds"] = self._next_update_in
        if hasattr(self, '_next_update_in_full_date') and self._next_update_in_full_date:
            attrs["next_update"] = self._next_update_in_full_date
        return attrs

    async def _get_sleep_interval(self):
        """Generate a sleep interval based on scan_interval_minutes from the config file."""
        if self.counter == 0:
            seconds_to_wait = random.randint(4, 7)
            self.counter = 1
        else:
            self.counter = 1
            try:
                if self.config_file.exists():
                    async with aiofiles.open(self.config_file, mode="r") as f:
                        content = await f.read()
                        config_data = json.loads(content)
                        minutes = int(config_data.get("scan_interval_minutes", 1))
                        seconds = max(1, minutes * 60)
                else:
                    seconds = 60
            except Exception as e:
                _LOGGER.warning(f"⚠️ Failed to read scan_interval_minutes from config: {e}")
                seconds = 60

            seconds_to_wait = seconds

        return seconds_to_wait
        
        
    async def _schedule_next_update(self):
        """Schedule the next sensor update after a random interval."""
        #print(f"Waiting for {self._next_update_in} seconds before next update...")
        await asyncio.sleep(self._next_update_in)  # Wait for the random interval
        #await self.async_update()  # Perform the update again


class CloudflareTrafficSummarySensor(CloudflareBaseSensor):
    def __init__(self, hass, entry):
        super().__init__(hass, entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} Traffic Summary"
        self._attr_unique_id = f"{data['email']}_{data['zone_name']}_traffic_summary".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "requests"
        self._attr_native_value = None
        self._next_update_in_full_date = None
        self._next_update_in = None
        self.counter = 0

    async def async_update(self):
        self._next_update_in = await self._get_sleep_interval() 
        next_run_full_format = datetime.now() + timedelta(seconds=self._next_update_in)
        self._next_update_in_full_date = next_run_full_format.strftime("%Y-%m-%d %H:%M:%S")           
        await self._schedule_next_update()
        self._next_update_in = await self._get_sleep_interval() 
        next_run_full_format = datetime.now() + timedelta(seconds=self._next_update_in)
        self._next_update_in_full_date = next_run_full_format.strftime("%Y-%m-%d %H:%M:%S")  

        try:
            data = self._entry.data
            summary = await self.hass.async_add_executor_job(
                fetch_today_traffic_summary, data["email"], data["global_token"], data["zone_id"]
            )
            self._attr_native_value = summary.get("requests", 0)

            # Merge summary fields directly into the attributes
            self._attr_extra_state_attributes = {
                **summary,
                "zone_id": data["zone_id"]
            }

            self._attr_extra_state_attributes.update({
                **summary,
                "zone_id": data["zone_id"]
            })

        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {
                "error": str(e),
                "zone_id": data.get("zone_id")
            }
class CloudflareSkipIPsSensor(CloudflareBaseSensor):
    def __init__(self, hass, entry):
        super().__init__(hass, entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} Skip IPs"
        self._attr_unique_id = f"{data['email']}_{data['zone_name']}_skip_ips".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "IPs"
        self._attr_native_value = 0
        self._next_update_in_full_date = None
        self._next_update_in = None
        self.counter = 0
        

    async def async_update(self):     
        self._next_update_in = await self._get_sleep_interval() 
        next_run_full_format = datetime.now() + timedelta(seconds=self._next_update_in)
        self._next_update_in_full_date = next_run_full_format.strftime("%Y-%m-%d %H:%M:%S")           
        await self._schedule_next_update()
        self._next_update_in = await self._get_sleep_interval() 
        next_run_full_format = datetime.now() + timedelta(seconds=self._next_update_in)
        self._next_update_in_full_date = next_run_full_format.strftime("%Y-%m-%d %H:%M:%S")  

        try:
            data = self._entry.data
            headers = {
                "X-Auth-Email": data["email"],
                "X-Auth-Key": data["global_token"],
                "Content-Type": "application/json"
            }
            now = datetime.utcnow()
            midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
            skip_ips = await self.hass.async_add_executor_job(
                get_skip_ips,
                data["zone_id"],
                midnight.strftime('%Y-%m-%dT%H:%M:%SZ'),
                now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                headers
            )
            self._attr_native_value = len(skip_ips)
            self._attr_extra_state_attributes["skip_ips"] = skip_ips
        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes["error"] = str(e)

class CloudflareListIPsSensor(CloudflareBaseSensor):
    def __init__(self, hass, entry):
        super().__init__(hass, entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} List IPs"
        self._attr_unique_id = f"{data['email']}_{data['zone_name']}_list_ips".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "IPs"
        self._attr_native_value = 0
        self._next_update_in_full_date = None
        self._next_update_in = None
        self.counter = 0

    async def async_update(self):      
        self._next_update_in = await self._get_sleep_interval() 
        next_run_full_format = datetime.now() + timedelta(seconds=self._next_update_in)
        self._next_update_in_full_date = next_run_full_format.strftime("%Y-%m-%d %H:%M:%S")           
        await self._schedule_next_update()
        self._next_update_in = await self._get_sleep_interval() 
        next_run_full_format = datetime.now() + timedelta(seconds=self._next_update_in)
        self._next_update_in_full_date = next_run_full_format.strftime("%Y-%m-%d %H:%M:%S")  

        try:
            data = self._entry.data
            headers = {
                "X-Auth-Email": data["email"],
                "X-Auth-Key": data["global_token"],
                "Content-Type": "application/json"
            }
            current_ips = await self.hass.async_add_executor_job(
                get_current_list_ips, data["account_id"], data["list_id"], headers
            )
            self._attr_native_value = len(current_ips)
            self._attr_extra_state_attributes["current_list_ips"] = list(current_ips)
        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes["error"] = str(e)

class CloudflareHighRiskIPsSensor(CloudflareBaseSensor):
    def __init__(self, hass, entry):
        super().__init__(hass, entry)
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
        self._next_update_in_full_date = None
        self._next_update_in = None
        self.counter = 0

    async def async_update(self):
        self._next_update_in = await self._get_sleep_interval() 
        next_run_full_format = datetime.now() + timedelta(seconds=self._next_update_in)
        self._next_update_in_full_date = next_run_full_format.strftime("%Y-%m-%d %H:%M:%S")           
        await self._schedule_next_update()
        self._next_update_in = await self._get_sleep_interval() 
        next_run_full_format = datetime.now() + timedelta(seconds=self._next_update_in)
        self._next_update_in_full_date = next_run_full_format.strftime("%Y-%m-%d %H:%M:%S")  

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
            recheck_days = int(options.get("recheck_days", data.get("recheck_days", 7)))
            mode = options.get("mode", data.get("mode", "Monitor"))

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
                        if (now - last_dt).days < recheck_days:
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

            if mode == "Active":
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
                "recheck_days": recheck_days,
                "mode": mode,
                "high_risk_ip_list": [ip["ip"] for ip in high_risk_ips],
                "ips_to_check": ips_to_check
            }

        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {"error": str(e)}
            self._attr_available = False

class CloudflareUnderAttackSensor(CloudflareBaseSensor):
    def __init__(self, hass, entry):
        super().__init__(hass, entry)
        self._attr_native_value = "off"
        self._attr_available = True
        self._attr_name = f"{entry.data['email']} {entry.data['zone_name']} Under Attack Mode"
        self._attr_unique_id = f"{entry.data['email']}_{entry.data['zone_id']}_under_attack".replace("@", "_").replace(".", "_").lower()
        self._next_update_in_full_date = None
        self._next_update_in = None
        self.counter = 0
        self.is_first_run = False

    async def _wait_for_sensor_state(self, entity_id: str, retries: int = 5, delay: int = 30):
        for attempt in range(retries):
            state = self.hass.states.get(entity_id)
            if state and state.state not in ("unknown", "unavailable", None):
                return state
            await asyncio.sleep(delay)
        return None

    async def async_update(self):
        self._next_update_in = await self._get_sleep_interval()
        self._next_update_in_full_date = (datetime.now() + timedelta(seconds=self._next_update_in)).strftime("%Y-%m-%d %H:%M:%S")
        await self._schedule_next_update()
        self._next_update_in = await self._get_sleep_interval()
        self._next_update_in_full_date = (datetime.now() + timedelta(seconds=self._next_update_in)).strftime("%Y-%m-%d %H:%M:%S")

        try:
            options = self._entry.options
            mode = options.get("mode", self._entry.data.get("mode", "Monitor"))
            if mode == "Monitor":
                self._attr_native_value = "off"
                self._attr_extra_state_attributes = {
                    "mode": "Monitor",
                    "reason": "Monitoring mode is active"
                }
                return

            enabled = options.get("under_attack_mode", False)
            threshold = options.get("under_attack_request_threshold", 15000)
            email = self._entry.data["email"]
            zone_name = self._entry.data["zone_name"]

            def sanitize_entity_id(email: str, zone: str, suffix: str):
                return f"{email}_{zone}_{suffix}".replace("@", "_").replace(".", "_").lower()

            traffic_entity_id = f"sensor.{sanitize_entity_id(email, zone_name, 'traffic_summary')}"
            state = await self._wait_for_sensor_state(traffic_entity_id)

            headers = {
                "X-Auth-Email": email,
                "X-Auth-Key": self._entry.data["global_token"],
                "Content-Type": "application/json"
            }

            if not enabled:
                self._attr_native_value = "off"
                self.is_first_run = True
                self._attr_extra_state_attributes = {
                    "enabled": enabled,
                    "reason": "Under attack mode is disabled",
                    "traffic_sensor": traffic_entity_id
                }
                await self.hass.async_add_executor_job(
                    set_under_attack_mode,
                    self._entry.data["zone_id"],
                    headers,
                    False
                )
                return

            if not state or state.state in ("unknown", "unavailable"):
                self.is_first_run = True
                self._attr_native_value = "unknown"
                self._attr_extra_state_attributes = {
                    "error": f"Sensor state is {state.state if state else 'missing'}",
                    "traffic_sensor": traffic_entity_id
                }
                self._attr_available = False
                return

            current_count = int(float(state.state))

            # Read or initialize config
            last_request_count = 0
            config_data = {}
                
            if CONFIG_FILE.exists():
                try:
                    async with aiofiles.open(CONFIG_FILE, mode="r") as f:
                        content = await f.read()
                        config_data = json.loads(content)
                    if "last_request_count" not in config_data:
                        self.is_first_run = True
                        config_data["last_request_count"] = current_count
                except Exception as e:
                    self.is_first_run = True
                    config_data["last_request_count"] = current_count
            else:
                self.is_first_run = True
                config_data["last_request_count"] = current_count

            last_request_count = config_data.get("last_request_count", current_count)
            if self.is_first_run:
                last_request_count = current_count
            delta = current_count - last_request_count
            real_mode_enabled = not self.is_first_run and delta >= threshold

            config_data["last_request_count"] = current_count
            async with aiofiles.open(CONFIG_FILE, mode="w") as f:
                await f.write(json.dumps(config_data, indent=2))
            if real_mode_enabled:
                await self.hass.async_add_executor_job(
                    set_under_attack_mode,
                    self._entry.data["zone_id"],
                    headers,
                    True
                )
            self.is_first_run = False
            self._attr_native_value = "on" if real_mode_enabled else "off"
            self._attr_extra_state_attributes = {
                "enabled": enabled,
                "threshold": threshold,
                "current_request_count": current_count,
                "last_request_count": last_request_count,
                "delta": delta,
                "under_attack_mode_active": real_mode_enabled,
                "traffic_sensor": traffic_entity_id
            }
            self._attr_available = True


        except Exception as e:
            self._attr_native_value = "error"
            self._attr_extra_state_attributes = {
                "error": str(e),
                "traffic_sensor": traffic_entity_id
            }
            self._attr_available = False

