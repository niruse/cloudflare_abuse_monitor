"""Setup with one scoped Cloudflare API token, then everything else is automatic.

The token is checked, the zone and account are read from it, every permission the
integration needs is probed without changing anything, and the IP list and the two
firewall rules are created when they are missing (never twice).
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from . import api
from .const import (
    CONF_ABUSEIPDB_TOKEN,
    CONF_API_TOKEN,
    CONF_RECHECK_ENABLED,
    CONF_UID_PREFIX,
    DEFAULT_ABUSE_CONFIDENCE_SCORE,
    DEFAULT_LIST_NAME,
    DEFAULT_RECHECK_DAYS,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DEFAULT_UNDER_ATTACK_THRESHOLD,
    DOMAIN,
    LEGACY_KEYS,
    MODE_ACTIVE,
    MODE_MONITOR,
)

_LOGGER = logging.getLogger(__name__)

SCORE = vol.All(vol.Coerce(float), vol.Range(min=0, max=100))
POSITIVE_INT = vol.All(vol.Coerce(int), vol.Range(min=1))
SECRET = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))

PERMISSION = {key: name for key, _, name in api.TOKEN_PERMISSIONS}
PERMISSION_LIST = "\n".join(f"- {name}" for _, _, name in api.TOKEN_PERMISSIONS)


class SetupError(Exception):
    """Ends validation with one form error: {"base": key} plus placeholders."""

    def __init__(self, key: str, **placeholders: str) -> None:
        super().__init__(key)
        self.key = key
        self.placeholders = placeholders


def _placeholders(**extra: str) -> dict[str, str]:
    return {"token_url": api.CREATE_TOKEN_URL, "permissions": PERMISSION_LIST, "missing": "", **extra}


class CloudflareAbuseMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cloudflare Abuse Monitor."""

    VERSION = 1
    MINOR_VERSION = 2

    def __init__(self) -> None:
        self._token: str | None = None
        self._abuse_key: str | None = None
        self._token_checked_by_user_endpoint = True
        self._zones: list[dict] = []
        self._zone: dict | None = None
        self._lists: list[dict] = []

    # --- helpers ---------------------------------------------------------------------

    async def _job(self, func, *args):
        return await self.hass.async_add_executor_job(func, *args)

    async def _async_check_token(self, headers) -> None:
        """Steps 1-2: the token is valid and can read at least one zone."""
        user_endpoint_failed = False
        try:
            status = await self._job(api.verify_user_token, headers)
        except api.CloudflareAuthError:
            # Account-owned tokens are unknown to /user/tokens/verify; checked again per account.
            user_endpoint_failed = True
        else:
            if status != "active":
                raise SetupError("token_inactive")
        self._token_checked_by_user_endpoint = not user_endpoint_failed

        try:
            self._zones = await self._job(api.fetch_zones, headers)
        except api.CloudflareAuthError:
            raise SetupError("invalid_token" if user_endpoint_failed else "no_zone") from None
        if not self._zones:
            raise SetupError("invalid_token" if user_endpoint_failed else "no_zone")

    async def _async_check_account_token(self, headers, account_id: str) -> None:
        """Step 3: a token /user/tokens/verify did not know must be an account token."""
        if self._token_checked_by_user_endpoint:
            return
        try:
            status = await self._job(api.verify_account_token, account_id, headers)
        except api.CloudflareAuthError:
            raise SetupError("invalid_token") from None
        if status != "active":
            raise SetupError("token_inactive")

    async def _async_prepare_zone(
        self, headers, zone_id: str, account_id: str, list_name: str, list_id: str | None
    ) -> dict[str, str]:
        """Steps 4-7. Returns {"list_name", "list_id"}; raises SetupError on any problem."""
        missing: list[str] = []

        # 4. Analytics Read: one read-only row of each dataset.
        try:
            await self._job(api.probe_analytics, headers, zone_id)
        except api.CloudflareAuthError:
            missing.append(PERMISSION["analytics"])

        # 5. Zone Settings Edit: write the current security level back unchanged.
        try:
            level = await self._job(api.get_security_level, zone_id, headers)
            await self._job(api.set_security_level, zone_id, headers, level)
        except api.CloudflareAuthError:
            missing.append(PERMISSION["zone_settings"])

        # 6a. Filter Lists: read first, write later.
        try:
            self._lists = await self._job(api.fetch_ip_lists, account_id, headers)
        except api.CloudflareAuthError:
            self._lists = []
            missing.append(PERMISSION["account_filter_lists"])

        # 7a. WAF custom rules: read first. A 404 (no custom rules yet) comes back as None.
        try:
            ruleset = await self._job(api.get_custom_entrypoint, zone_id, headers)
        except api.CloudflareAuthError:
            ruleset = None
            missing.append(PERMISSION["zone_waf"])

        if missing:
            raise SetupError("missing_permissions", missing=", ".join(missing))

        # 6b. The list: the stored one, else one with the expected name, else a new one.
        existing = next((item for item in self._lists if item.get("id") == list_id), None) or next(
            (item for item in self._lists if item.get("name") == list_name), None
        )
        try:
            if existing:
                await self._job(
                    api.update_list_description, account_id, existing["id"], existing.get("description") or "", headers
                )
                chosen = {"list_name": existing["name"], "list_id": existing["id"]}
            else:
                try:
                    created = await self._job(api.create_ip_list, account_id, list_name, headers)
                except api.CloudflareAuthError:
                    raise
                except api.CloudflareApiError as err:
                    # Plan limit on lists: offer the lists that exist instead of failing silently.
                    _LOGGER.warning("Could not create the IP list: %s", err)
                    raise SetupError("list_create_failed") from None
                chosen = {"list_name": created.get("name", list_name), "list_id": created["id"]}
        except api.CloudflareAuthError:
            raise SetupError("missing_permissions", missing=PERMISSION["account_filter_lists"]) from None

        # 7b. The Block and Skip rules, only the ones that are missing.
        await self._async_ensure_rules(headers, zone_id, ruleset, chosen["list_name"])
        return chosen

    async def _async_ensure_rules(self, headers, zone_id: str, ruleset: dict | None, list_name: str) -> None:
        wanted = api.missing_rules(ruleset, list_name)
        if not wanted:
            return  # both rules exist: Zone WAF Read would have been enough
        try:
            if ruleset is None:
                await self._job(api.create_custom_entrypoint, zone_id, wanted, headers)
            else:
                for rule in wanted:
                    # Block goes before any rule that skips the rest of the custom rules,
                    # or it would never run; Skip goes last.
                    before = api.block_rule_position(ruleset) if rule["ref"] == api.BLOCK_RULE_REF else None
                    await self._job(api.add_custom_rule, zone_id, ruleset["id"], rule, headers, before)
        except api.CloudflareAuthError:
            raise SetupError("missing_permissions", missing=PERMISSION["zone_waf"]) from None
        except api.CloudflareApiError as err:
            _LOGGER.warning("Could not create the firewall rules: %s", err)
            raise SetupError("rule_create_failed") from None

    async def _async_check_abuseipdb(self, key: str) -> None:
        result = await self._job(api.validate_abuseipdb_key, key)
        if result == "invalid":
            raise SetupError("invalid_abuseipdb_key")
        if result == "rate_limited":
            _LOGGER.warning("AbuseIPDB key accepted, but today's lookup quota is already used up")

    async def _async_run(self, coro_factory, step_id: str, schema, **extra_placeholders):
        """Run validation; on a SetupError re-show step_id with the error."""
        try:
            return await coro_factory(), None
        except SetupError as err:
            return None, self.async_show_form(
                step_id=step_id,
                data_schema=schema,
                errors={"base": err.key},
                description_placeholders=_placeholders(**extra_placeholders, **err.placeholders),
            )
        except (api.CloudflareApiError, api.AbuseIPDBError, OSError) as err:
            # Never the token: these messages carry only status codes and Cloudflare's own text.
            _LOGGER.warning("Could not reach Cloudflare or AbuseIPDB: %s", err)
            return None, self.async_show_form(
                step_id=step_id,
                data_schema=schema,
                errors={"base": "connection_error"},
                description_placeholders=_placeholders(**extra_placeholders),
            )

    # --- user setup ------------------------------------------------------------------

    def _user_schema(self):
        return vol.Schema({
            vol.Required(CONF_API_TOKEN): SECRET,
            vol.Required(CONF_ABUSEIPDB_TOKEN): SECRET,
        })

    async def async_step_user(self, user_input=None):
        """Ask for the token and the AbuseIPDB key."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=self._user_schema(), description_placeholders=_placeholders()
            )

        self._token = user_input[CONF_API_TOKEN].strip()
        self._abuse_key = user_input[CONF_ABUSEIPDB_TOKEN].strip()
        # A pasted newline or tab inside would make requests echo the value in its error.
        bad = "invalid_token" if not api.valid_secret(self._token) else (
            "invalid_abuseipdb_key" if not api.valid_secret(self._abuse_key) else None
        )
        if bad:
            return self.async_show_form(
                step_id="user", data_schema=self._user_schema(), errors={"base": bad},
                description_placeholders=_placeholders(),
            )
        headers = api.get_headers(self._token)

        async def check():
            await self._async_check_token(headers)
            await self._async_check_abuseipdb(self._abuse_key)

        _, form = await self._async_run(check, "user", self._user_schema())
        if form:
            return form
        if len(self._zones) == 1:
            return await self._async_use_zone(self._zones[0])
        return await self.async_step_zone_select()

    async def async_step_zone_select(self, user_input=None):
        """More than one zone: ask which one."""
        options = {zone["id"]: zone["name"] for zone in self._zones}
        schema = vol.Schema({vol.Required("zone_id"): vol.In(options)})
        if user_input is None:
            return self.async_show_form(step_id="zone_select", data_schema=schema)
        zone = next(z for z in self._zones if z["id"] == user_input["zone_id"])
        return await self._async_use_zone(zone)

    async def _async_use_zone(self, zone: dict):
        self._zone = zone
        await self.async_set_unique_id(zone["id"])
        self._abort_if_unique_id_configured()
        return await self._async_finish_user()

    async def _async_finish_user(self):
        zone = self._zone
        headers = api.get_headers(self._token)
        account_id = zone["account"]["id"]

        async def prepare():
            await self._async_check_account_token(headers, account_id)
            return await self._async_prepare_zone(headers, zone["id"], account_id, DEFAULT_LIST_NAME, None)

        chosen, form = await self._async_run(prepare, "user", self._user_schema())
        if form:
            if form.get("errors") == {"base": "list_create_failed"} and self._lists:
                return await self.async_step_list_select()
            return form
        return self._create(chosen)

    async def async_step_list_select(self, user_input=None):
        """The list could not be created (plan limit): use one of the existing IP lists."""
        names = {item["name"]: item["id"] for item in self._lists}
        schema = vol.Schema({vol.Required("list_name"): vol.In(list(names))})
        if user_input is None:
            return self.async_show_form(step_id="list_select", data_schema=schema)

        zone = self._zone
        headers = api.get_headers(self._token)
        list_name = user_input["list_name"]

        async def prepare():
            return await self._async_prepare_zone(
                headers, zone["id"], zone["account"]["id"], list_name, names[list_name]
            )

        chosen, form = await self._async_run(prepare, "list_select", schema)
        if form:
            return form
        return self._create(chosen)

    def _create(self, chosen: dict[str, str]):
        zone = self._zone
        return self.async_create_entry(
            title=f"Cloudflare: {zone['name']}",
            data={
                CONF_API_TOKEN: self._token,
                CONF_ABUSEIPDB_TOKEN: self._abuse_key,
                CONF_UID_PREFIX: zone["id"],
                "zone_id": zone["id"],
                "zone_name": zone["name"],
                "account_id": zone["account"]["id"],
                "list_name": chosen["list_name"],
                "list_id": chosen["list_id"],
                "abuse_confidence_score": DEFAULT_ABUSE_CONFIDENCE_SCORE,
                "recheck_days": DEFAULT_RECHECK_DAYS,
                "scan_interval_minutes": DEFAULT_SCAN_INTERVAL_MINUTES,
                "mode": MODE_MONITOR,
            },
        )

    # --- new token for an existing entry (reconfigure and reauth) --------------------------

    def _token_schema(self):
        return vol.Schema({vol.Required(CONF_API_TOKEN): SECRET})

    async def _async_new_token(self, entry, user_input, step_id: str):
        placeholders = {"zone_name": entry.data.get("zone_name", "")}
        if user_input is None:
            return self.async_show_form(
                step_id=step_id, data_schema=self._token_schema(), description_placeholders=_placeholders(**placeholders)
            )

        token = user_input[CONF_API_TOKEN].strip()
        if not api.valid_secret(token):
            return self.async_show_form(
                step_id=step_id, data_schema=self._token_schema(), errors={"base": "invalid_token"},
                description_placeholders=_placeholders(**placeholders),
            )
        headers = api.get_headers(token)
        data = entry.data
        zone_id, account_id = data["zone_id"], data["account_id"]

        async def check():
            await self._async_check_token(headers)
            if not any(zone.get("id") == zone_id for zone in self._zones):
                raise SetupError("wrong_zone")
            await self._async_check_account_token(headers, account_id)
            return await self._async_prepare_zone(
                headers, zone_id, account_id, data.get("list_name") or DEFAULT_LIST_NAME, data.get("list_id")
            )

        chosen, form = await self._async_run(check, step_id, self._token_schema(), **placeholders)
        if form:
            return form

        new_data = {key: value for key, value in data.items() if key not in LEGACY_KEYS}
        new_data.update(chosen)
        new_data[CONF_API_TOKEN] = token
        # Entities keep the unique ids they were registered with (built from the old email).
        new_data.setdefault(CONF_UID_PREFIX, data.get("email") or zone_id)
        return self.async_update_reload_and_abort(entry, data=new_data)

    async def async_step_reconfigure(self, user_input=None):
        """Paste a new token; also moves a Global API Key entry to a token."""
        return await self._async_new_token(self._get_reconfigure_entry(), user_input, "reconfigure")

    async def async_step_reauth(self, entry_data: Mapping[str, Any]):
        """Cloudflare rejected the token (or the entry still uses a Global API Key)."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        return await self._async_new_token(self._get_reauth_entry(), user_input, "reauth_confirm")

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
            vol.Required(CONF_RECHECK_ENABLED, default=current(CONF_RECHECK_ENABLED, True)): bool,
            vol.Required("recheck_days", default=current("recheck_days", DEFAULT_RECHECK_DAYS)): POSITIVE_INT,
            vol.Required("under_attack_mode", default=current("under_attack_mode", False)): bool,
            vol.Required("under_attack_request_threshold", default=current("under_attack_request_threshold", DEFAULT_UNDER_ATTACK_THRESHOLD)): POSITIVE_INT,
            vol.Required("scan_interval_minutes", default=current("scan_interval_minutes", DEFAULT_SCAN_INTERVAL_MINUTES)): POSITIVE_INT,
        })

        return self.async_show_form(step_id="init", data_schema=schema)
