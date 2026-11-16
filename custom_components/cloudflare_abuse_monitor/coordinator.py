"""One polling cycle per config entry: traffic, skip IPs, block list, AbuseIPDB and Under Attack Mode."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from . import api
from .const import (
    CHECKED_IPS_FILENAME,
    CONF_ABUSEIPDB_TOKEN,
    CONF_API_TOKEN,
    CONF_RECHECK_ENABLED,
    DEFAULT_ABUSE_CONFIDENCE_SCORE,
    DEFAULT_RECHECK_DAYS,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DEFAULT_UNDER_ATTACK_THRESHOLD,
    DOMAIN,
    FALLBACK_SECURITY_LEVEL,
    MODE_ACTIVE,
    MODE_MONITOR,
    UNDER_ATTACK_LEVEL,
)

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1

# Every entry reads and rewrites the same lookup cache file.
_CACHE_LOCK = asyncio.Lock()


def owned_level_store(hass: HomeAssistant, entry_id: str) -> Store:
    """Per entry: who turned Under Attack Mode on, the level to restore, and unblocked IPs."""
    return Store(hass, STORAGE_VERSION, f"{DOMAIN}.{entry_id}")


def _read_cache(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return {}
    try:
        data = json.loads(content) if content.strip() else {}
    except ValueError as err:
        _LOGGER.warning("Ignoring unreadable %s: %s", path, err)
        return {}
    return data if isinstance(data, dict) else {}


def _write_cache(path: str, cache: dict) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)
    os.replace(tmp, path)


def parse_cache_entry(value) -> tuple[datetime | None, float | None]:
    """Return (checked_at, score). Entries written before v1.5 are a bare timestamp with no score."""
    if isinstance(value, dict):
        checked, score = value.get("checked"), value.get("score")
    else:
        checked, score = value, None
    try:
        checked_at = datetime.fromisoformat(checked)
    except (TypeError, ValueError):
        return None, None
    if checked_at.tzinfo is None:  # older versions stored naive UTC
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    return checked_at, score


class CloudflareAbuseMonitorCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Fetches everything the sensors show in one pass, every scan_interval_minutes."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.entry = entry
        minutes = max(1, int(self.option("scan_interval_minutes", DEFAULT_SCAN_INTERVAL_MINUTES)))
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"Cloudflare {entry.data['zone_name']}",
            update_interval=timedelta(minutes=minutes),
        )
        self._cache_path = hass.config.path(CHECKED_IPS_FILENAME)
        self._store = owned_level_store(hass, entry.entry_id)
        self._state: dict[str, Any] | None = None
        # (window start, request count, time) from the previous cycle, for the Under Attack delta.
        self._last_count: tuple[str, int, datetime] | None = None

    def option(self, key: str, default):
        return self.entry.options.get(key, self.entry.data.get(key, default))

    async def _job(self, func, *args):
        return await self.hass.async_add_executor_job(func, *args)

    @property
    def headers(self) -> dict[str, str]:
        return api.get_headers(self.entry.data[CONF_API_TOKEN])

    async def _try(self, what: str, func, *args):
        """Run one step; a failure is reported on its own sensor instead of blanking all of them."""
        try:
            return await func(*args), None
        except api.CloudflareAuthError as err:
            # Token revoked or a permission removed: ask for a new token instead of retrying.
            raise ConfigEntryAuthFailed(str(err)) from err
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Cloudflare Abuse Monitor: %s failed: %s", what, err)
            return None, str(err) or type(err).__name__

    async def _async_update_data(self) -> dict[str, Any]:
        data = self.entry.data
        headers = self.headers
        now = dt_util.utcnow()
        window = (api.iso_utc(now.replace(hour=0, minute=0, second=0, microsecond=0)), api.iso_utc(now))

        traffic, traffic_err = await self._try(
            "traffic summary", self._job, api.fetch_today_traffic_summary, headers, data["zone_id"],
        )
        skip_ips, skip_err = await self._try(
            "skip IPs", self._job, api.get_skip_ips, data["zone_id"], *window, headers
        )
        list_ips, list_err = await self._try(
            "list IPs", self._job, api.get_current_list_ips, data["account_id"], data["list_id"], headers
        )
        if traffic_err and skip_err and list_err:
            raise UpdateFailed(traffic_err)

        if skip_err or list_err:
            high_risk, high_risk_err = None, skip_err or list_err
        else:
            high_risk, high_risk_err = await self._try(
                "AbuseIPDB check", self._async_high_risk, skip_ips, list_ips, headers, now
            )

        if traffic_err:
            under_attack, under_attack_err = None, traffic_err
        else:
            under_attack, under_attack_err = await self._try(
                "Under Attack Mode", self._async_under_attack, traffic, headers, now
            )

        return {
            "updated_at": dt_util.now(),
            "traffic": _section(
                traffic["requests"] if traffic is not None else None,
                {**traffic, "zone_id": data["zone_id"]} if traffic is not None else {"zone_id": data["zone_id"]},
                traffic_err,
            ),
            "skip_ips": _section(
                len(skip_ips) if skip_ips is not None else None,
                {"skip_ips": skip_ips} if skip_ips is not None else {},
                skip_err,
            ),
            "list_ips": _section(
                len(list_ips) if list_ips is not None else None,
                {"current_list_ips": sorted(list_ips)} if list_ips is not None else {},
                list_err,
            ),
            "high_risk": high_risk or _section(None, {}, high_risk_err),
            "under_attack": under_attack or _section("error", {}, under_attack_err),
        }

    async def _async_high_risk(self, skip_ips, list_ips, headers, now) -> dict[str, Any]:
        data = self.entry.data
        threshold = int(float(self.option("abuse_confidence_score", DEFAULT_ABUSE_CONFIDENCE_SCORE)))
        recheck_days = int(self.option("recheck_days", DEFAULT_RECHECK_DAYS))
        recheck_enabled = bool(self.option(CONF_RECHECK_ENABLED, True))
        mode = self.option("mode", MODE_MONITOR)
        state = await self._async_state()
        # IPs unblocked with the unblock_ip service are never added back automatically.
        candidates = sorted(set(skip_ips) - set(list_ips) - set(state["allowed_ips"]))

        ips_to_check: list[str] = []
        high_risk: list[str] = []
        async with _CACHE_LOCK:
            cache = await self._job(_read_cache, self._cache_path)
            changed = False
            stop_lookups = False
            for ip in candidates:
                checked_at, score = parse_cache_entry(cache.get(ip))
                due = checked_at is None or (recheck_enabled and (now - checked_at).days >= recheck_days)
                if due:
                    if stop_lookups:
                        continue
                    ips_to_check.append(ip)
                    try:
                        result = await self._job(api.check_abuse_ip, ip, data[CONF_ABUSEIPDB_TOKEN])
                    except api.AbuseIPDBRateLimited:
                        _LOGGER.warning("AbuseIPDB daily quota reached; the remaining IPs wait for a later cycle")
                        stop_lookups = True
                        continue
                    except Exception as err:  # noqa: BLE001
                        _LOGGER.warning("AbuseIPDB unreachable (%s); the remaining IPs wait for a later cycle", err)
                        stop_lookups = True
                        continue
                    if "error" in result:
                        # Not cached, so the IP is looked up again next cycle instead of in recheck_days.
                        _LOGGER.warning("AbuseIPDB lookup for %s failed: %s", ip, result["error"])
                        continue
                    score = result["abuse_confidence_score"]
                    cache[ip] = {"checked": now.isoformat(), "score": score}
                    changed = True
                if score is not None and score >= threshold:
                    high_risk.append(ip)
            if changed:
                await self._job(_write_cache, self._cache_path, cache)

        # A known high-risk IP stays a candidate until it is really in the list, so a failed
        # add, or a switch from Monitor to Active, is retried instead of waiting recheck_days.
        blocked: list[str] = []
        if mode == MODE_ACTIVE and high_risk:
            await self._job(api.add_ips_to_list, data["account_id"], data["list_id"], high_risk, headers)
            blocked = high_risk

        return _section(
            len(high_risk),
            {
                "abuse_confidence_score_threshold": threshold,
                "recheck_days": recheck_days,
                "recheck_enabled": recheck_enabled,
                "mode": mode,
                "high_risk_ip_list": high_risk,
                "ips_to_check": ips_to_check,
                "blocked_ips": blocked,
            },
        )

    async def _async_under_attack(self, traffic, headers, now) -> dict[str, Any]:
        zone_id = self.entry.data["zone_id"]
        mode = self.option("mode", MODE_MONITOR)
        enabled = bool(self.option("under_attack_mode", False))
        threshold = int(self.option("under_attack_request_threshold", DEFAULT_UNDER_ATTACK_THRESHOLD))
        automation_on = mode == MODE_ACTIVE and enabled

        # The request count is "since midnight UTC"; compare it with the previous cycle of the
        # same day only, so a restart, a missed cycle or midnight never reads as a spike.
        current = int(traffic["requests"])
        previous = self._last_count
        self._last_count = (traffic["from"], current, now)
        delta = None
        if previous and previous[0] == traffic["from"] and now - previous[2] <= 2 * self.update_interval:
            delta = current - previous[1]

        owned = await self._async_state()
        level = await self._job(api.get_security_level, zone_id, headers)

        if automation_on and delta is not None and delta >= threshold and level != UNDER_ATTACK_LEVEL:
            await self._job(api.set_security_level, zone_id, headers, UNDER_ATTACK_LEVEL)
            await self._async_save_state(enabled_by_us=True, restore_level=level, manual=False)
            level = UNDER_ATTACK_LEVEL
        elif not automation_on and owned["enabled_by_us"] and not owned["manual"]:
            # Switched off after it fired: undo our own change only, back to the level it replaced.
            # A level set with the switch is left alone; the switch turns it off.
            if level == UNDER_ATTACK_LEVEL:
                restore = owned["restore_level"] or FALLBACK_SECURITY_LEVEL
                await self._job(api.set_security_level, zone_id, headers, restore)
                level = restore
            await self._async_save_state(enabled_by_us=False, restore_level=None, manual=False)

        active = level == UNDER_ATTACK_LEVEL
        attrs = {
            "mode": mode,
            "enabled": enabled,
            "threshold": threshold,
            "current_request_count": current,
            "last_request_count": previous[1] if delta is not None else None,
            "delta": delta,
            "security_level": level,
            "under_attack_mode_active": active,
            "enabled_by_integration": owned["enabled_by_us"],
        }
        if mode != MODE_ACTIVE:
            attrs["reason"] = "Monitoring mode is active"
        elif not enabled:
            attrs["reason"] = "Under attack mode is disabled"
        return _section("on" if active else "off", attrs)

    async def _async_state(self) -> dict[str, Any]:
        if self._state is None:
            stored = await self._store.async_load() or {}
            self._state = {
                "enabled_by_us": bool(stored.get("enabled_by_us")),
                "restore_level": stored.get("restore_level"),
                "manual": bool(stored.get("manual")),
                "allowed_ips": list(stored.get("allowed_ips") or []),
            }
        return self._state

    async def _async_save_state(self, **changes) -> None:
        state = await self._async_state()
        state.update(changes)
        await self._store.async_save(state)

    # --- actions for the switch and the services ------------------------------------

    async def _call(self, func, *args):
        try:
            return await self._job(func, *args)
        except api.CloudflareAuthError as err:
            self.entry.async_start_reauth(self.hass)
            raise ConfigEntryAuthFailed(str(err)) from err

    async def async_set_under_attack(self, on: bool) -> None:
        """The Under Attack switch: on remembers the level it replaces, off restores it."""
        zone_id = self.entry.data["zone_id"]
        headers = self.headers
        state = await self._async_state()
        level = await self._call(api.get_security_level, zone_id, headers)
        if on:
            if level != UNDER_ATTACK_LEVEL:
                await self._call(api.set_security_level, zone_id, headers, UNDER_ATTACK_LEVEL)
                await self._async_save_state(enabled_by_us=True, restore_level=level, manual=True)
        else:
            if level == UNDER_ATTACK_LEVEL:
                restore = (state["restore_level"] if state["enabled_by_us"] else None) or FALLBACK_SECURITY_LEVEL
                await self._call(api.set_security_level, zone_id, headers, restore)
            await self._async_save_state(enabled_by_us=False, restore_level=None, manual=False)
        await self.async_request_refresh()

    async def async_check_ip(self, ip: str) -> dict[str, Any]:
        """Look one IP up now; a score is cached like the automatic lookups."""
        result = await self._job(api.check_abuse_ip, ip, self.entry.data[CONF_ABUSEIPDB_TOKEN])
        result.pop("status", None)
        if "error" not in result:
            async with _CACHE_LOCK:
                cache = await self._job(_read_cache, self._cache_path)
                cache[ip] = {"checked": dt_util.utcnow().isoformat(), "score": result["abuse_confidence_score"]}
                await self._job(_write_cache, self._cache_path, cache)
        return result

    async def async_block_ip(self, ip: str) -> None:
        data = self.entry.data
        await self._call(api.add_ips_to_list, data["account_id"], data["list_id"], [ip], self.headers)
        state = await self._async_state()
        if ip in state["allowed_ips"]:
            await self._async_save_state(allowed_ips=[a for a in state["allowed_ips"] if a != ip])
        await self.async_request_refresh()

    async def async_unblock_ip(self, ip: str) -> bool:
        """Remove ip from the list and never add it back automatically. False: it was not listed."""
        data = self.entry.data
        items = await self._call(api.get_list_items, data["account_id"], data["list_id"], self.headers)
        item_id = items.get(ip)
        if item_id is None:
            return False  # nothing changes: the IP is not exempted from Active mode either
        await self._call(api.remove_list_items, data["account_id"], data["list_id"], [item_id], self.headers)
        state = await self._async_state()
        if ip not in state["allowed_ips"]:
            await self._async_save_state(allowed_ips=[*state["allowed_ips"], ip])
        await self.async_request_refresh()
        return True


def _section(value, attrs: dict, error: str | None = None) -> dict[str, Any]:
    return {"value": value, "attrs": attrs, "error": error}
