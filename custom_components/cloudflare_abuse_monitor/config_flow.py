import logging

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback

from .api import fetch_rules_lists, fetch_zones, get_headers
from .const import (
    DEFAULT_ABUSE_CONFIDENCE_SCORE,
    DEFAULT_RECHECK_DAYS,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DEFAULT_UNDER_ATTACK_THRESHOLD,
    DOMAIN,
    MODE_ACTIVE,
    MODE_MONITOR,
)

_LOGGER = logging.getLogger(__name__)

SCORE = vol.All(vol.Coerce(float), vol.Range(min=0, max=100))
POSITIVE_INT = vol.All(vol.Coerce(int), vol.Range(min=1))


class CloudflareAbuseMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cloudflare Abuse Monitor."""
    VERSION = 1

    def __init__(self):
        self.email = None
        self.api_key = None
        self.abuse_key = None
        self.abuse_score = None
        self.scan_interval = DEFAULT_SCAN_INTERVAL_MINUTES
        self.recheck_days = DEFAULT_RECHECK_DAYS
        self.zones = []
        self.account_id = None
        self.zone_id = None
        self.zone_name = None
        self.rules_lists = {}

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        schema = vol.Schema({
            vol.Required("email"): str,
            vol.Required("global_token"): str,
            vol.Required("abuseipdb_token"): str,
            vol.Required("abuse_confidence_score", default=DEFAULT_ABUSE_CONFIDENCE_SCORE): SCORE,
            vol.Required("recheck_days", default=DEFAULT_RECHECK_DAYS): POSITIVE_INT,
            vol.Required("scan_interval_minutes", default=DEFAULT_SCAN_INTERVAL_MINUTES): POSITIVE_INT,
        })

        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=schema)

        self.email = user_input["email"]
        self.api_key = user_input["global_token"]
        self.abuse_key = user_input["abuseipdb_token"]
        self.abuse_score = user_input["abuse_confidence_score"]
        self.recheck_days = user_input["recheck_days"]
        self.scan_interval = user_input["scan_interval_minutes"]

        try:
            response_data = await self.hass.async_add_executor_job(fetch_zones, self.email, self.api_key)
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Could not reach Cloudflare: %s", err)
            return self.async_show_form(step_id="user", data_schema=schema, errors={"base": "connection_error"})

        if not response_data.get("success", False):
            return self.async_show_form(step_id="user", data_schema=schema, errors={"base": "auth_failed"})

        self.zones = response_data.get("result", [])
        if not self.zones:
            return self.async_abort(reason="no_zones_found")
        return await self.async_step_zone_select()

    async def async_step_zone_select(self, user_input=None):
        """Handle the zone selection step."""
        zone_options = {zone["id"]: zone["name"] for zone in self.zones}
        schema = vol.Schema({
            vol.Required("zone_id"): vol.In(zone_options),
        })

        if user_input is None:
            return self.async_show_form(step_id="zone_select", data_schema=schema)

        self.zone_id = user_input["zone_id"]
        await self.async_set_unique_id(self.zone_id)
        self._abort_if_unique_id_configured()

        selected_zone = next(z for z in self.zones if z["id"] == self.zone_id)
        self.zone_name = selected_zone["name"]
        self.account_id = selected_zone["account"]["id"]

        try:
            self.rules_lists = await self.hass.async_add_executor_job(
                fetch_rules_lists, self.account_id, get_headers(self.email, self.api_key)
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Could not read the Cloudflare lists: %s", err)
            return self.async_show_form(step_id="zone_select", data_schema=schema, errors={"base": "connection_error"})

        if not self.rules_lists:
            return self.async_abort(reason="no_rules_lists_found")

        return await self.async_step_list_select()

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
                    "mode": MODE_MONITOR,
                },
            )

        return self.async_show_form(step_id="list_select", data_schema=schema)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return CloudflareAbuseMonitorOptionsFlowHandler()


class CloudflareAbuseMonitorOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle an options flow for Cloudflare Abuse Monitor."""

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options
        data = self.config_entry.data

        def current(key, default):
            return options.get(key, data.get(key, default))

        schema = vol.Schema({
            vol.Required("abuse_confidence_score", default=current("abuse_confidence_score", DEFAULT_ABUSE_CONFIDENCE_SCORE)): SCORE,
            vol.Required("mode", default=current("mode", MODE_MONITOR)): vol.In([MODE_ACTIVE, MODE_MONITOR]),
            vol.Required("recheck_days", default=current("recheck_days", DEFAULT_RECHECK_DAYS)): POSITIVE_INT,
            vol.Required("under_attack_mode", default=current("under_attack_mode", False)): bool,
            vol.Required("under_attack_request_threshold", default=current("under_attack_request_threshold", DEFAULT_UNDER_ATTACK_THRESHOLD)): POSITIVE_INT,
            vol.Required("scan_interval_minutes", default=current("scan_interval_minutes", DEFAULT_SCAN_INTERVAL_MINUTES)): POSITIVE_INT,
        })

        return self.async_show_form(step_id="init", data_schema=schema)
