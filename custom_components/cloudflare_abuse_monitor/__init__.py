from __future__ import annotations

import ipaddress
import logging

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from . import api
from .const import (
    CONF_API_TOKEN,
    CONF_UID_PREFIX,
    DOMAIN,
    SERVICE_BLOCK_IP,
    SERVICE_CHECK_IP,
    SERVICE_REFRESH,
    SERVICE_UNBLOCK_IP,
)
from .coordinator import CloudflareAbuseMonitorCoordinator, owned_level_store

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.SWITCH]
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

ATTR_IP = "ip"
ATTR_CONFIG_ENTRY_ID = "config_entry_id"


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as err:
        raise vol.Invalid(f"not an IP address: {value}") from err


IP_SCHEMA = vol.Schema({vol.Required(ATTR_IP): _ip, vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string})
ENTRY_SCHEMA = vol.Schema({vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string})


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the services once, for every entry."""

    def coordinator_for(call: ServiceCall) -> CloudflareAbuseMonitorCoordinator:
        entry_id = call.data.get(ATTR_CONFIG_ENTRY_ID)
        loaded = [
            entry for entry in hass.config_entries.async_entries(DOMAIN)
            if entry.state is ConfigEntryState.LOADED and (entry_id is None or entry.entry_id == entry_id)
        ]
        if not loaded:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="entry_not_loaded"
            )
        if len(loaded) > 1:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="choose_entry"
            )
        return loaded[0].runtime_data

    async def guarded(coro):
        try:
            return await coro
        except ConfigEntryAuthFailed:
            raise
        except (api.CloudflareApiError, api.AbuseIPDBRateLimited, OSError) as err:
            raise HomeAssistantError(str(err)) from err

    async def check_ip(call: ServiceCall):
        result = await guarded(coordinator_for(call).async_check_ip(call.data[ATTR_IP]))
        if "error" in result:
            raise HomeAssistantError(f"AbuseIPDB: {result['error']}")
        return result

    async def block_ip(call: ServiceCall) -> None:
        await guarded(coordinator_for(call).async_block_ip(call.data[ATTR_IP]))

    async def unblock_ip(call: ServiceCall) -> None:
        if not await guarded(coordinator_for(call).async_unblock_ip(call.data[ATTR_IP])):
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="ip_not_listed",
                translation_placeholders={"ip": call.data[ATTR_IP]},
            )

    async def refresh(call: ServiceCall) -> None:
        await coordinator_for(call).async_refresh()

    hass.services.async_register(
        DOMAIN, SERVICE_CHECK_IP, check_ip, schema=IP_SCHEMA, supports_response=SupportsResponse.ONLY
    )
    hass.services.async_register(DOMAIN, SERVICE_BLOCK_IP, block_ip, schema=IP_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_UNBLOCK_IP, unblock_ip, schema=IP_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_REFRESH, refresh, schema=ENTRY_SCHEMA)
    return True


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """1.1 -> 1.2: keep the unique-id prefix (the old email) before the email can be dropped."""
    if entry.version > 1:
        return False
    if entry.minor_version < 2:
        data = dict(entry.data)
        # Entity unique ids were built from the email; keep that part so entities are not orphaned.
        data.setdefault(CONF_UID_PREFIX, data.get("email") or data["zone_id"])
        hass.config_entries.async_update_entry(entry, data=data, minor_version=2)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Cloudflare Abuse Monitor from a config entry."""
    if not entry.data.get(CONF_API_TOKEN):
        # Set up with a Global API Key (v1.5 and earlier): ask for a scoped token.
        raise ConfigEntryAuthFailed("This entry needs a Cloudflare API token")
    coordinator = CloudflareAbuseMonitorCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    # A new scan interval needs a new coordinator, so options changes reload the entry.
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload Cloudflare Abuse Monitor config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await owned_level_store(hass, entry.entry_id).async_remove()
