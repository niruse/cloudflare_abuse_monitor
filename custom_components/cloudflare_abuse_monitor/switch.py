"""Under Attack Mode switch: turn Cloudflare's Under Attack Mode on or off by hand."""
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .entity import CloudflareEntity

PARALLEL_UPDATES = 1


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    async_add_entities(
        CloudflareUnderAttackSwitch(coordinator, entry) for coordinator in entry.runtime_data.coordinators.values()
    )


class CloudflareUnderAttackSwitch(CloudflareEntity, SwitchEntity):
    """On while the zone's security level is under_attack. Off restores the level it replaced."""

    _section = "under_attack"
    _attr_icon = "mdi:shield-alert"

    def __init__(self, coordinator, entry):
        super().__init__(coordinator, entry)
        data = coordinator.zone
        self._attr_name = f"{data['zone_name']} Under Attack"
        self._attr_unique_id = (
            f"{self._prefix}_{data['zone_id']}_under_attack_switch".replace("@", "_").replace(".", "_").lower()
        )

    @property
    def is_on(self):
        value = self._payload.get("value")
        return None if value not in ("on", "off") else value == "on"

    @property
    def extra_state_attributes(self):
        attrs = self._payload.get("attrs") or {}
        return {key: attrs[key] for key in ("security_level", "enabled_by_integration") if key in attrs}

    async def async_turn_on(self, **kwargs) -> None:
        await self.coordinator.async_set_under_attack(True)

    async def async_turn_off(self, **kwargs) -> None:
        await self.coordinator.async_set_under_attack(False)
