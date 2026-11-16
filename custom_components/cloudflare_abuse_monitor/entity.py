"""Shared base for every entity: coordinator, unique-id prefix, device and data section.

Not a SensorEntity, so the switch gets its state from is_on rather than a sensor value.
"""
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_UID_PREFIX, DOMAIN
from .coordinator import CloudflareAbuseMonitorCoordinator


class CloudflareEntity(CoordinatorEntity[CloudflareAbuseMonitorCoordinator]):
    """Shows one section of the coordinator's data: {"value", "attrs", "error"}."""

    _section: str

    def __init__(self, coordinator: CloudflareAbuseMonitorCoordinator, entry: ConfigEntry):
        super().__init__(coordinator)
        self._entry = entry

    @property
    def _prefix(self) -> str:
        # The old email for entries made before v1.6, the zone id after: unique ids never change.
        data = self._entry.data
        return data.get(CONF_UID_PREFIX) or data.get("email") or data["zone_id"]

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Cloudflare Abuse Monitor",
            "manufacturer": "Cloudflare",
            "entry_type": "service",
        }

    @property
    def _payload(self) -> dict:
        return (self.coordinator.data or {}).get(self._section) or {}
