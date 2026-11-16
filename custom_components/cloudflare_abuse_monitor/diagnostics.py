"""Diagnostics with every secret and identifier redacted."""
from __future__ import annotations

import re
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

TO_REDACT = {
    "api_token",
    "global_token",
    "abuseipdb_token",
    "email",
    "uid_prefix",
    "account_id",
    "zone_id",
    "zone_name",
    "list_id",
}


REDACTED = "**REDACTED**"
# Any Cloudflare id (32 hex), IPv4/IPv6 address or email that an error message may carry,
# e.g. a connection error quoting /accounts/<id>/rules/lists/<id>/items.
_PATTERNS = (
    re.compile(r"\b[0-9a-fA-F]{32}\b"),
    re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b|\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:?)*"),
)


def redact_text(text: str | None, entry: ConfigEntry) -> str | None:
    """Remove the entry's identifiers and anything id-, IP- or email-shaped from an error string."""
    if not text:
        return text
    for key in TO_REDACT:
        value = entry.data.get(key)
        if isinstance(value, str) and len(value) >= 4:
            text = text.replace(value, REDACTED)
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ConfigEntry) -> dict[str, Any]:
    coordinator = getattr(entry, "runtime_data", None)
    sections = {}
    if coordinator is not None and coordinator.data:
        # Values and errors only: the attributes hold visitor IP addresses.
        sections = {
            name: {"value": section.get("value"), "error": redact_text(section.get("error"), entry)}
            for name, section in coordinator.data.items()
            if isinstance(section, dict)
        }
    return {
        "entry": {
            "title": REDACTED,
            "version": entry.version,
            "minor_version": entry.minor_version,
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": async_redact_data(dict(entry.options), TO_REDACT),
        },
        "sections": sections,
    }
