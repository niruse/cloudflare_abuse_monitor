from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CloudflareAbuseMonitorCoordinator

# The coordinator does all the I/O; entities only read its data.
PARALLEL_UPDATES = 0


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    coordinator = entry.runtime_data
    async_add_entities([
        CloudflareTrafficSummarySensor(coordinator, entry),
        CloudflareSkipIPsSensor(coordinator, entry),
        CloudflareListIPsSensor(coordinator, entry),
        CloudflareHighRiskIPsSensor(coordinator, entry),
        CloudflareUnderAttackSensor(coordinator, entry),
    ])


class CloudflareBaseSensor(CoordinatorEntity[CloudflareAbuseMonitorCoordinator], SensorEntity):
    """Shows one section of the coordinator's data: {"value", "attrs", "error"}."""

    _section: str

    def __init__(self, coordinator: CloudflareAbuseMonitorCoordinator, entry: ConfigEntry):
        super().__init__(coordinator)
        self._entry = entry

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Cloudflare Abuse Monitor",
            "manufacturer": "Nir Gliksman",
            "entry_type": "service",
        }

    @property
    def _payload(self) -> dict:
        return (self.coordinator.data or {}).get(self._section) or {}

    @property
    def native_value(self):
        return self._payload.get("value")

    @property
    def extra_state_attributes(self):
        attrs = dict(self._payload.get("attrs") or {})
        if self._payload.get("error"):
            attrs["error"] = self._payload["error"]
        interval = self.coordinator.update_interval
        attrs["next_update_in_seconds"] = int(interval.total_seconds())
        updated_at = (self.coordinator.data or {}).get("updated_at")
        if updated_at:
            attrs["next_update"] = (updated_at + interval).strftime("%Y-%m-%d %H:%M:%S")
        return attrs


class CloudflareTrafficSummarySensor(CloudflareBaseSensor):
    _section = "traffic"

    def __init__(self, coordinator, entry):
        super().__init__(coordinator, entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} Traffic Summary"
        self._attr_unique_id = f"{data['email']}_{data['zone_name']}_traffic_summary".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "requests"


class CloudflareSkipIPsSensor(CloudflareBaseSensor):
    _section = "skip_ips"

    def __init__(self, coordinator, entry):
        super().__init__(coordinator, entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} Skip IPs"
        self._attr_unique_id = f"{data['email']}_{data['zone_name']}_skip_ips".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "IPs"


class CloudflareListIPsSensor(CloudflareBaseSensor):
    _section = "list_ips"

    def __init__(self, coordinator, entry):
        super().__init__(coordinator, entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} List IPs"
        self._attr_unique_id = f"{data['email']}_{data['zone_name']}_list_ips".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "IPs"


class CloudflareHighRiskIPsSensor(CloudflareBaseSensor):
    _section = "high_risk"

    def __init__(self, coordinator, entry):
        super().__init__(coordinator, entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} High Risk IPs"
        self._attr_unique_id = f"{data['email']}_{data['zone_id']}_high_risk_ips".replace(" ", "_").lower()
        self._attr_native_unit_of_measurement = "IPs"


class CloudflareUnderAttackSensor(CloudflareBaseSensor):
    _section = "under_attack"

    def __init__(self, coordinator, entry):
        super().__init__(coordinator, entry)
        data = entry.data
        self._attr_name = f"{data['email']} {data['zone_name']} Under Attack Mode"
        self._attr_unique_id = f"{data['email']}_{data['zone_id']}_under_attack".replace("@", "_").replace(".", "_").lower()
