import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from .const import DOMAIN,CONFIG_FILE
import json
from pathlib import Path
import logging
from .api import fetch_zones, fetch_rules_lists

_LOGGER = logging.getLogger(__name__)

class CloudflareAbuseMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cloudflare Abuse Monitor."""
    VERSION = 1

    def __init__(self):
        self.email = None
        self.api_key = None
        self.abuse_key = None
        self.abuse_score = None
        self.scan_interval = 1
        self.recheck_days = 7
        self.zones = []
        self.account_id = None
        self.zone_id = None
        self.zone_name = None
        self.rules_lists = {}
        self.config_file = CONFIG_FILE

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        schema = vol.Schema({
            vol.Required("email"): str,
            vol.Required("global_token"): str,
            vol.Required("abuseipdb_token"): str,
            vol.Required("abuse_confidence_score", default=100.0): vol.Coerce(float),
            vol.Required("recheck_days", default=7): vol.All(vol.Coerce(int), vol.Range(min=1)),
            vol.Required("scan_interval_minutes", default=1): vol.All(vol.Coerce(int), vol.Range(min=1)),
        })

        if user_input is not None:
            self.email = user_input["email"]
            self.api_key = user_input["global_token"]
            self.abuse_key = user_input["abuseipdb_token"]
            self.abuse_score = user_input["abuse_confidence_score"]
            self.recheck_days = user_input["recheck_days"]
            self.scan_interval = user_input["scan_interval_minutes"]

            try:
                response_data = await self.hass.async_add_executor_job(
                    fetch_zones, self.email, self.api_key
                )
                if not response_data.get("success", False):
                    return self.async_show_form(
                        step_id="user",
                        data_schema=schema,
                        errors={"base": "auth_failed"}
                    )

                self.zones = response_data.get("result", [])
                return await self.async_step_zone_select()

            except Exception:
                return self.async_show_form(
                    step_id="user",
                    data_schema=schema,
                    errors={"base": "connection_error"}
                )

        return self.async_show_form(step_id="user", data_schema=schema)

    async def async_step_zone_select(self, user_input=None):
        """Handle the zone selection step."""
        zone_options = {zone["id"]: zone["name"] for zone in self.zones}
        schema = vol.Schema({
            vol.Required("zone_id"): vol.In(zone_options),
        })

        if user_input is not None:

            try:
                config_data = {}
                if CONFIG_FILE.exists():
                    with CONFIG_FILE.open("r") as f:
                        config_data = json.load(f)

                config_data.update({
                    "scan_interval_minutes": self.scan_interval,
                })

                with CONFIG_FILE.open("w") as f:
                    json.dump(config_data, f, indent=2)

                _LOGGER.debug("✅ Zone configuration and scan_interval_minutes saved to file")

            except Exception as e:
                _LOGGER.warning(f"⚠️ Failed to save to {CONFIG_FILE}: {e}")

            self.zone_id = user_input["zone_id"]
            selected_zone = next(z for z in self.zones if z["id"] == self.zone_id)
            self.zone_name = selected_zone["name"]
            self.account_id = selected_zone["account"]["id"]

            headers = {
                "X-Auth-Email": self.email,
                "X-Auth-Key": self.api_key,
                "Content-Type": "application/json"
            }

            self.rules_lists = await self.hass.async_add_executor_job(
                fetch_rules_lists, self.account_id, headers
            )

            if not self.rules_lists:
                return self.async_abort(reason="no_rules_lists_found")

            return await self.async_step_list_select()

        return self.async_show_form(step_id="zone_select", data_schema=schema)

    async def async_step_list_select(self, user_input=None):
        """Handle the list selection step."""
        list_names = list(self.rules_lists.keys())
        schema = vol.Schema({
            vol.Required("list_name"): vol.In(list_names),
        })

        if user_input is not None:
            selected_list_name = user_input["list_name"]
            selected_list_id = self.rules_lists[selected_list_name]

            return self.async_create_entry(
                title=f"Cloudflare: {self.zone_name}",
                data={
                    "email": self.email,
                    "global_token": self.api_key,
                    "abuseipdb_token": self.abuse_key,
                    "abuse_confidence_score": self.abuse_score,
                    "recheck_days": self.recheck_days,
                    "scan_interval_minutes": self.scan_interval,
                    "zone_id": self.zone_id,
                    "zone_name": self.zone_name,
                    "account_id": self.account_id,
                    "list_name": selected_list_name,
                    "list_id": selected_list_id,
                    "mode": "Monitor",
                },
            )

        return self.async_show_form(step_id="list_select", data_schema=schema)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return CloudflareAbuseMonitorOptionsFlowHandler(config_entry)


class CloudflareAbuseMonitorOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle an options flow for Cloudflare Abuse Monitor."""

    def __init__(self, config_entry):
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        options = self.config_entry.options
        data = self.config_entry.data

        if user_input is not None:
            # 🔄 Save scan_interval_minutes to JSON config
            try:
                config_data = {}
                if CONFIG_FILE.exists():
                    with CONFIG_FILE.open("r") as f:
                        config_data = json.load(f)

                config_data["scan_interval_minutes"] = user_input["scan_interval_minutes"]

                with CONFIG_FILE.open("w") as f:
                    json.dump(config_data, f, indent=2)

                _LOGGER.debug(f"✅ scan_interval_minutes saved: {user_input['scan_interval_minutes']}")

            except Exception as e:
                _LOGGER.warning(f"⚠️ Failed to save scan_interval_minutes to {CONFIG_FILE}: {e}")

            return self.async_create_entry(title="", data=user_input)

        abuse_score = options.get("abuse_confidence_score", data.get("abuse_confidence_score", 100.0))
        mode = options.get("mode", data.get("mode", "Monitor"))
        recheck_days = options.get("recheck_days", data.get("recheck_days", 7))
        under_attack_mode = options.get("under_attack_mode", data.get("under_attack_mode", False))
        under_attack_request_threshold = options.get("under_attack_request_threshold", data.get("under_attack_request_threshold", 15000))
        scan_interval_minutes = options.get("scan_interval_minutes", data.get("scan_interval_minutes", 1))

        schema = vol.Schema({
            vol.Required("abuse_confidence_score", default=abuse_score): vol.Coerce(float),
            vol.Required("mode", default=mode): vol.In(["Active", "Monitor"]),
            vol.Required("recheck_days", default=recheck_days): vol.All(vol.Coerce(int), vol.Range(min=1)),
            vol.Required("under_attack_mode", default=under_attack_mode): bool,
            vol.Required("under_attack_request_threshold", default=under_attack_request_threshold): vol.All(vol.Coerce(int), vol.Range(min=1)),
            vol.Required("scan_interval_minutes", default=scan_interval_minutes): vol.All(vol.Coerce(int), vol.Range(min=1)),
        })

        return self.async_show_form(step_id="init", data_schema=schema)
