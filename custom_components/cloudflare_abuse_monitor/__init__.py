from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryNotReady,
    HomeAssistantError,
    ServiceValidationError,
)
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.typing import ConfigType

from . import api
from .const import (
    CONF_API_TOKEN,
    CONF_UID_PREFIX,
    CONF_ZONES,
    DOMAIN,
    SERVICE_BLOCK_IP,
    SERVICE_CHECK_IP,
    SERVICE_REFRESH,
    SERVICE_RESTORE_RULES,
    SERVICE_UNBLOCK_IP,
    ZONE_KEYS,
    zone_records,
)
from .coordinator import CloudflareAbuseMonitorCoordinator, ZonePacer, owned_level_store
from .entity import zone_device_identifier

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.SWITCH]
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

ATTR_IP = "ip"
ATTR_CONFIG_ENTRY_ID = "config_entry_id"
ATTR_ZONE = "zone"
ATTR_DEVICE_ID = "device_id"


@dataclass
class RuntimeData:
    """One coordinator per zone, keyed by zone id."""

    coordinators: dict[str, CloudflareAbuseMonitorCoordinator] = field(default_factory=dict)


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as err:
        raise vol.Invalid(f"not an IP address: {value}") from err


_TARGET = {
    vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
    vol.Optional(ATTR_ZONE): cv.string,
    vol.Optional(ATTR_DEVICE_ID): vol.Any(cv.string, [cv.string]),
}
IP_SCHEMA = vol.Schema({vol.Required(ATTR_IP): _ip, **_TARGET})
ENTRY_SCHEMA = vol.Schema(_TARGET)


def entry_zones(entry: ConfigEntry) -> list[dict]:
    return zone_records(entry.data)


def _zones_for(hass: HomeAssistant, call: ServiceCall) -> list[CloudflareAbuseMonitorCoordinator]:
    """Every loaded zone the call names (by entry, zone name or device); all of them if none."""
    entry_id = call.data.get(ATTR_CONFIG_ENTRY_ID)
    zone_name = (call.data.get(ATTR_ZONE) or "").strip().lower()
    device_ids = call.data.get(ATTR_DEVICE_ID) or []
    if isinstance(device_ids, str):
        device_ids = [device_ids]
    identifiers: set[tuple[str, str]] = set()
    if device_ids:
        registry = dr.async_get(hass)
        for device_id in device_ids:
            device = registry.async_get(device_id)
            if device is not None:
                identifiers |= device.identifiers

    found = []
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.state is not ConfigEntryState.LOADED or (entry_id and entry.entry_id != entry_id):
            continue
        for zone_id, coordinator in entry.runtime_data.coordinators.items():
            if zone_name and coordinator.zone["zone_name"].lower() != zone_name and zone_id != zone_name:
                continue
            if device_ids and zone_device_identifier(entry.entry_id, zone_id) not in identifiers:
                continue
            found.append(coordinator)
    if not found:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_not_loaded")
    return found


def _one_list(found: list[CloudflareAbuseMonitorCoordinator]) -> CloudflareAbuseMonitorCoordinator:
    """block_ip and unblock_ip act on one IP list: the zones named must all share it."""
    if len({coordinator.list_key for coordinator in found}) > 1:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="choose_zone")
    return found[0]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the services once, for every entry."""

    async def guarded(coro):
        try:
            return await coro
        except ConfigEntryAuthFailed:
            raise
        except (api.CloudflareApiError, api.AbuseIPDBRateLimited, OSError) as err:
            raise HomeAssistantError(str(err)) from err

    async def check_ip(call: ServiceCall):
        # AbuseIPDB does not depend on the zone: any zone of the named entry will do.
        result = await guarded(_zones_for(hass, call)[0].async_check_ip(call.data[ATTR_IP]))
        if "error" in result:
            raise HomeAssistantError(f"AbuseIPDB: {result['error']}")
        return result

    async def block_ip(call: ServiceCall) -> None:
        await guarded(_one_list(_zones_for(hass, call)).async_block_ip(call.data[ATTR_IP]))

    async def unblock_ip(call: ServiceCall) -> None:
        if not await guarded(_one_list(_zones_for(hass, call)).async_unblock_ip(call.data[ATTR_IP])):
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="ip_not_listed",
                translation_placeholders={"ip": call.data[ATTR_IP]},
            )

    async def refresh(call: ServiceCall) -> None:
        for coordinator in _zones_for(hass, call):
            await coordinator.async_refresh()

    async def restore_rules(call: ServiceCall):
        # Changes Cloudflare rules: the zone must be named, never "every zone" by default.
        if not (call.data.get(ATTR_ZONE) or call.data.get(ATTR_DEVICE_ID)):
            raise ServiceValidationError(translation_domain=DOMAIN, translation_key="restore_needs_zone")
        reports = {}
        for coordinator in _zones_for(hass, call):
            reports[coordinator.zone["zone_name"]] = await guarded(coordinator.async_restore_rules())
        return {"zones": reports}

    hass.services.async_register(
        DOMAIN, SERVICE_CHECK_IP, check_ip, schema=IP_SCHEMA, supports_response=SupportsResponse.ONLY
    )
    hass.services.async_register(DOMAIN, SERVICE_BLOCK_IP, block_ip, schema=IP_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_UNBLOCK_IP, unblock_ip, schema=IP_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_REFRESH, refresh, schema=ENTRY_SCHEMA)
    hass.services.async_register(
        DOMAIN, SERVICE_RESTORE_RULES, restore_rules, schema=ENTRY_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )
    return True


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """1.1 -> 1.2: keep the unique-id prefix (the old email) before the email can be dropped.

    1.2 -> 1.3 (v1.7): the one zone moves into data["zones"] with its unique-id prefix, list and
    storage file, and its device gets the per-zone identifier, so entity ids, unique ids, history
    and the Under Attack state all stay.
    """
    if entry.version > 1:
        return False
    if entry.minor_version < 2:
        data = dict(entry.data)
        # Entity unique ids were built from the email; keep that part so entities are not orphaned.
        data.setdefault(CONF_UID_PREFIX, data.get("email") or data["zone_id"])
        hass.config_entries.async_update_entry(entry, data=data, minor_version=2)
    if entry.minor_version < 3:
        data = dict(entry.data)
        if CONF_ZONES not in data:
            zone = zone_records(data)[0]
            for key in (*ZONE_KEYS, CONF_UID_PREFIX):
                data.pop(key, None)
            data[CONF_ZONES] = [zone]
            registry = dr.async_get(hass)
            # This entry's own devices only (identifiers are not unique across entries any more).
            for device in dr.async_entries_for_config_entry(registry, entry.entry_id):
                if (DOMAIN, entry.entry_id) in device.identifiers:
                    registry.async_update_device(
                        device.id, new_identifiers={zone_device_identifier(entry.entry_id, zone["zone_id"])}
                    )
        hass.config_entries.async_update_entry(entry, data=data, minor_version=3)
        _LOGGER.debug("Moved the zone of a v1.6 entry into the zone list")
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Cloudflare Abuse Monitor from a config entry: one coordinator per zone."""
    if not entry.data.get(CONF_API_TOKEN):
        # Set up with a Global API Key (v1.5 and earlier): ask for a scoped token.
        raise ConfigEntryAuthFailed("This entry needs a Cloudflare API token")
    zones = entry_zones(entry)
    _remove_stale_devices(hass, entry, zones)

    pacer = ZonePacer()
    runtime = RuntimeData()
    not_ready: list[Exception] = []
    for zone in zones:
        coordinator = CloudflareAbuseMonitorCoordinator(hass, entry, zone, pacer)
        try:
            await coordinator.async_config_entry_first_refresh()
        except ConfigEntryNotReady as err:
            # One unreachable zone must not hold back the others; it retries on its schedule.
            not_ready.append(err)
        runtime.coordinators[zone["zone_id"]] = coordinator
    if zones and len(not_ready) == len(zones):
        raise not_ready[0]
    for coordinator in runtime.coordinators.values():
        coordinator.peers = list(runtime.coordinators.values())
    entry.runtime_data = runtime
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    # A new scan interval or zone list needs new coordinators, so changes reload the entry.
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


def _remove_stale_devices(hass: HomeAssistant, entry: ConfigEntry, zones: list[dict]) -> None:
    """A zone unticked in the options: its device and entities go (its Cloudflare rules stay)."""
    wanted = {zone_device_identifier(entry.entry_id, zone["zone_id"]) for zone in zones}
    registry = dr.async_get(hass)
    for device in dr.async_entries_for_config_entry(registry, entry.entry_id):
        if not device.identifiers & wanted:
            registry.async_remove_device(device.id)


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload Cloudflare Abuse Monitor config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    for zone in entry_zones(entry):
        await owned_level_store(hass, entry.entry_id, zone).async_remove()
    await owned_level_store(hass, entry.entry_id).async_remove()
