"""Shared base for every entity: zone coordinator, unique-id prefix, device and data section.

Not a SensorEntity, so the switch gets its state from is_on rather than a sensor value.
"""
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CloudflareAbuseMonitorCoordinator


def zone_device_identifier(entry_id: str, zone_id: str) -> tuple[str, str]:
    """One device per zone of an entry."""
    return DOMAIN, f"{entry_id}_{zone_id}"


class CloudflareEntity(CoordinatorEntity[CloudflareAbuseMonitorCoordinator]):
    """Shows one section of a zone coordinator's data: {"value", "attrs", "error"}."""

    _section: str

    def __init__(self, coordinator: CloudflareAbuseMonitorCoordinator, entry: ConfigEntry):
        super().__init__(coordinator)
        self._entry = entry
        self._zone = coordinator.zone

    @property
    def _prefix(self) -> str:
        # The old email for zones set up before v1.6, the zone id after: unique ids never change.
        zone = self._zone
        return zone.get("uid_prefix") or zone["zone_id"]

    @property
    def device_info(self):
        return {
            "identifiers": {zone_device_identifier(self._entry.entry_id, self._zone["zone_id"])},
            "name": f"Cloudflare {self._zone['zone_name']}",
            "manufacturer": "Cloudflare",
            "model": "Zone",
            "entry_type": "service",
        }

    @property
    def _payload(self) -> dict:
        return (self.coordinator.data or {}).get(self._section) or {}
