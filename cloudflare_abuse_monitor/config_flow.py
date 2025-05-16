import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from .const import DOMAIN
from .api import fetch_zones, fetch_rules_lists

# Schema for the initial user input
STEP_USER_DATA_SCHEMA = vol.Schema({
    vol.Required("email"): str,
    vol.Required("global_token"): str,
    vol.Required("abuseipdb_token"): str,
    vol.Required("abuse_confidence_score", default=100.0): vol.Coerce(float),
})

class CloudflareAbuseMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cloudflare Abuse Monitor."""
    VERSION = 1

    def __init__(self):
        self.email = None
        self.api_key = None
        self.abuse_key = None
        self.abuse_score = None
        self.zones = []
        self.account_id = None
        self.zone_id = None
        self.zone_name = None
        self.rules_lists = {}

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        if user_input is not None:
            self.email = user_input["email"]
            self.api_key = user_input["global_token"]
            self.abuse_key = user_input["abuseipdb_token"]
            self.abuse_score = user_input["abuse_confidence_score"]

            try:
                response_data = await self.hass.async_add_executor_job(
                    fetch_zones, self.email, self.api_key
                )
                if not response_data.get("success", False):
                    return self.async_show_form(
                        step_id="user",
                        data_schema=STEP_USER_DATA_SCHEMA,
                        errors={"base": "auth_failed"}
                    )

                self.zones = response_data.get("result", [])
                return await self.async_step_zone_select()

            except Exception:
                return self.async_show_form(
                    step_id="user",
                    data_schema=STEP_USER_DATA_SCHEMA,
                    errors={"base": "connection_error"}
                )

        return self.async_show_form(step_id="user", data_schema=STEP_USER_DATA_SCHEMA)

    async def async_step_zone_select(self, user_input=None):
        """Handle the zone selection step."""
        zone_options = {zone["id"]: zone["name"] for zone in self.zones}
        zone_schema = vol.Schema({
            vol.Required("zone_id"): vol.In(zone_options),
        })

        if user_input is not None:
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

        return self.async_show_form(step_id="zone_select", data_schema=zone_schema)

    async def async_step_list_select(self, user_input=None):
        """Handle the list selection step."""
        list_names = list(self.rules_lists.keys())
        list_schema = vol.Schema({
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
                    "zone_id": self.zone_id,
                    "zone_name": self.zone_name,
                    "account_id": self.account_id,
                    "list_name": selected_list_name,
                    "list_id": selected_list_id,
                },
            )

        return self.async_show_form(step_id="list_select", data_schema=list_schema)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Return the options flow handler."""
        return CloudflareAbuseMonitorOptionsFlowHandler(config_entry)

class CloudflareAbuseMonitorOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle an options flow for Cloudflare Abuse Monitor."""

    def __init__(self, config_entry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            # Update the config entry with new options
            return self.async_create_entry(title="", data=user_input)

        # Use existing options or fallback to data
        abuse_score = self.config_entry.options.get(
            "abuse_confidence_score",
            self.config_entry.data.get("abuse_confidence_score", 100.0)
        )

        options_schema = vol.Schema({
            vol.Required("abuse_confidence_score", default=abuse_score): vol.Coerce(float),
        })

        return self.async_show_form(step_id="init", data_schema=options_schema)
