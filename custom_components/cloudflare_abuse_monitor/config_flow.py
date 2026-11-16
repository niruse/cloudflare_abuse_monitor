"""Setup with one scoped Cloudflare API token, then everything else is automatic.

The token is checked and every zone it can read is listed with a checkbox. For each ticked
zone every permission the integration needs is probed without changing anything, and the
IP list (one per Cloudflare account, shared by its zones) and the two firewall rules are
created when they are missing (never twice). A zone at its custom-rule limit gets a plan that
makes room (room.py), shown in rules_confirm and applied only once approved. The options add
and remove zones the same way.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from . import api, room
from .const import (
    CONF_ABUSEIPDB_TOKEN,
    CONF_API_TOKEN,
    CONF_RECHECK_ENABLED,
    CONF_UID_PREFIX,
    CONF_ZONES,
    DEFAULT_ABUSE_CONFIDENCE_SCORE,
    DEFAULT_LIST_NAME,
    DEFAULT_RECHECK_DAYS,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DEFAULT_UNDER_ATTACK_THRESHOLD,
    DOMAIN,
    LEGACY_KEYS,
    MODE_ACTIVE,
    MODE_MONITOR,
    ZONE_KEYS,
    zone_records,
)
from .coordinator import owned_level_store, rules_store

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


class NeedsApproval(Exception):
    """The zone has no room for the rules; the plan that makes room waits for the user."""

    def __init__(self, plan: room.RoomPlan, list_name: str) -> None:
        super().__init__("approval required")
        self.plan = plan
        self.list_name = list_name


def _placeholders(**extra: str) -> dict[str, str]:
    return {
        "token_url": api.CREATE_TOKEN_URL,
        "permissions": PERMISSION_LIST,
        "missing": "",
        "zone": "",
        "count": "",
        "limit": "",
        "needed": "",
        "short": "",
        "rules": "",
        **extra,
    }


def _zone_selector(zones: list[dict]) -> SelectSelector:
    """A checkbox per zone, like the camera list of other integrations."""
    accounts = {(zone.get("account") or {}).get("id") for zone in zones}
    options = []
    for zone in sorted(zones, key=lambda z: z["name"]):
        label = zone["name"]
        account_name = (zone.get("account") or {}).get("name")
        if len(accounts) > 1 and account_name:
            label = f"{label} ({account_name})"
        options.append(SelectOptionDict(value=zone["id"], label=label))
    return SelectSelector(SelectSelectorConfig(options=options, multiple=True, mode=SelectSelectorMode.LIST))


def _zone_from_record(record: dict) -> dict:
    """A stored zone in the shape Cloudflare's /zones returns."""
    return {"id": record["zone_id"], "name": record["zone_name"], "account": {"id": record["account_id"]}}


def _new_record(zone: dict, chosen: dict[str, str]) -> dict:
    return {
        "zone_id": zone["id"],
        "zone_name": zone["name"],
        "account_id": zone["account"]["id"],
        "list_name": chosen["list_name"],
        "list_id": chosen["list_id"],
        CONF_UID_PREFIX: zone["id"],
    }


def _title(records: list[dict]) -> str:
    if len(records) == 1:
        return f"Cloudflare: {records[0]['zone_name']}"
    return f"Cloudflare: {len(records)} zones"


def _zones_in_other_entries(flow, own_entry_id: str | None) -> set[str]:
    taken = set()
    for entry in flow.hass.config_entries.async_entries(DOMAIN):
        if entry.entry_id == own_entry_id:
            continue
        taken |= {zone["zone_id"] for zone in zone_records(entry.data)}
    return taken


class ZoneSetupMixin:
    """The automatic per-zone setup, shared by the config flow and the options flow.

    Ticked zones go into a queue; each is prepared in turn (permission probes, the account's
    IP list, the rules). An error re-shows the form it came from; a list Cloudflare would not
    create detours through list_select and then the queue goes on.
    """

    def _init_zone_setup(self) -> None:
        self._token: str | None = None
        self._token_checked_by_user_endpoint = True
        self._verified_accounts: set[str] = set()
        self._zones: list[dict] = []
        self._lists: list[dict] = []
        # account id -> {"list_name", "list_id"}: the list its zones block with.
        self._account_lists: dict[str, dict[str, str]] = {}
        # zone id -> (list name, list id) to look for before creating a new list.
        self._wanted_lists: dict[str, tuple[str, str | None]] = {}
        self._queue: list[dict] = []
        self._prepared: dict[str, dict[str, str]] = {}
        self._zone: dict | None = None
        self._error_step: tuple[str, Any] | None = None
        # Making room for the rules: zone id -> Cloudflare plan, limit learned from a 400,
        # signature of the plan the user approved; the plan waiting for approval.
        self._zone_plans: dict[str, dict | None] = {}
        self._rule_limits: dict[str, int] = {}
        self._approved: dict[str, tuple] = {}
        self._pending: tuple[dict, room.RoomPlan, str] | None = None

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
        if self._token_checked_by_user_endpoint or account_id in self._verified_accounts:
            return
        try:
            status = await self._job(api.verify_account_token, account_id, headers)
        except api.CloudflareAuthError:
            raise SetupError("invalid_token") from None
        if status != "active":
            raise SetupError("token_inactive")
        self._verified_accounts.add(account_id)

    async def _async_prepare_zone(
        self, headers, zone_id: str, account_id: str, list_name: str, list_id: str | None
    ) -> dict[str, str]:
        """Steps 4-7. Returns {"list_name", "list_id"}; raises SetupError on any problem.

        The list is per account: once one zone of an account has it, the next zones of that
        account use it as is (no second list, no second list probe).
        """
        known = self._account_lists.get(account_id)
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
        if known is None:
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
        if known is not None:
            chosen = dict(known)
        else:
            existing = next((item for item in self._lists if item.get("id") == list_id), None) or next(
                (item for item in self._lists if item.get("name") == list_name), None
            )
            try:
                if existing:
                    await self._job(
                        api.update_list_description, account_id, existing["id"],
                        existing.get("description") or "", headers,
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
                    # Listed now, so a retry after a later error finds it instead of making another.
                    self._lists = [*self._lists, {"id": chosen["list_id"], "name": chosen["list_name"]}]
            except api.CloudflareAuthError:
                raise SetupError("missing_permissions", missing=PERMISSION["account_filter_lists"]) from None
            self._account_lists[account_id] = chosen

        # 7b. The Block and Skip rules, only the ones that are missing.
        await self._async_ensure_rules(headers, zone_id, ruleset, chosen["list_name"])
        return chosen

    async def _async_ensure_rules(self, headers, zone_id: str, ruleset: dict | None, list_name: str) -> None:
        """Add the missing rules; when the zone is at its rule limit, make room first.

        Making room changes user rules, so it needs the user's approval (NeedsApproval shows the
        plan; the queue runs again once it is approved). A limit Cloudflare reports in a 400
        ("6 out of 5") is learned, and the plan is worked out once more with it.
        """
        for attempt in range(2):
            if not api.missing_rules(ruleset, list_name):
                return  # both rules exist: Zone WAF Read would have been enough
            limit = await self._async_rule_limit(headers, zone_id, ruleset, list_name)
            plan = room.build_plan(ruleset, list_name, limit)
            if not plan.possible:
                _LOGGER.warning(
                    "Zone %s: %s of %s custom rules used; %s more rule(s) cannot be made room for",
                    zone_id, plan.count, plan.limit, plan.short,
                )
                raise SetupError(
                    "no_room", count=str(plan.count), limit=str(plan.limit),
                    needed=str(len(plan.wanted)), short=str(plan.short), rules=room.describe_rules(plan),
                )
            if plan.changes and self._approved.get(zone_id) != plan.signature():
                raise NeedsApproval(plan, list_name)
            try:
                await self._async_apply_plan(headers, zone_id, ruleset, plan, list_name)
                return
            except api.CloudflareAuthError:
                raise SetupError("missing_permissions", missing=PERMISSION["zone_waf"]) from None
            except api.CloudflareApiError as err:
                learned = api.rule_limit_from_error(err)
                if attempt or learned is None:
                    _LOGGER.warning("Could not create the firewall rules: %s", err)
                    raise SetupError("rule_create_failed") from None
                _LOGGER.info("Zone %s allows %s custom rules; working out the rules again", zone_id, learned)
                self._rule_limits[zone_id] = learned
                try:
                    ruleset = await self._job(api.get_custom_entrypoint, zone_id, headers)
                except api.CloudflareAuthError:
                    raise SetupError("missing_permissions", missing=PERMISSION["zone_waf"]) from None

    async def _async_rule_limit(self, headers, zone_id: str, ruleset: dict | None, list_name: str) -> int:
        """Custom rules the zone's plan allows: learned from a 400, else from the plan, else 5."""
        rules = (ruleset or {}).get("rules") or []
        if zone_id in self._rule_limits:
            return max(self._rule_limits[zone_id], len(rules))
        if len(rules) + len(api.missing_rules(ruleset, list_name)) <= api.FALLBACK_RULE_LIMIT:
            return api.FALLBACK_RULE_LIMIT  # fits on every plan: no need to ask
        if zone_id not in self._zone_plans:
            try:
                self._zone_plans[zone_id] = await self._job(api.fetch_zone_plan, zone_id, headers)
            except api.CloudflareApiError as err:
                _LOGGER.debug("Could not read the plan of zone %s: %s", zone_id, err)
                self._zone_plans[zone_id] = None
        limit = api.rule_limit_for_plan(self._zone_plans[zone_id]) or api.FALLBACK_RULE_LIMIT
        # A zone never has more rules than its plan allows: an unknown plan is at least that.
        return max(limit, len(rules))

    async def _async_apply_plan(self, headers, zone_id: str, ruleset: dict | None,
                                plan: room.RoomPlan, list_name: str) -> None:
        if ruleset is None:
            # Only for a zone with no entrypoint: a PUT replaces every rule in an existing one.
            await self._job(api.create_custom_entrypoint, zone_id, plan.add, headers)
            return
        if plan.changes:
            # The originals are saved before anything is changed, so restore_rules can undo it.
            store = rules_store(self.hass, zone_id)
            stored = await store.async_load() or {}
            changes = list(stored.get("changes") or [])
            changes += [change for change in room.store_changes(plan, list_name) if change not in changes]
            await store.async_save({"ruleset_id": ruleset["id"], "changes": changes})
            await self._job(room.apply_changes, zone_id, ruleset["id"], plan, headers)
        after = room.rules_after(plan)
        for rule in plan.add:
            # Block goes before any rule that skips the rest of the custom rules,
            # or it would never run; Skip goes last.
            before = room.block_position(after) if rule["ref"] == api.BLOCK_RULE_REF else None
            await self._job(api.add_custom_rule, zone_id, ruleset["id"], rule, headers, before)

    async def _async_run(self, coro_factory, step_id: str, schema, **extra_placeholders):
        """Run validation; on a SetupError re-show step_id with the error."""
        try:
            return await coro_factory(), None
        except NeedsApproval as pending:
            self._pending = (self._zone, pending.plan, pending.list_name)
            return None, await self.async_step_rules_confirm()
        except SetupError as err:
            return None, self.async_show_form(
                step_id=step_id,
                data_schema=schema,
                errors={"base": err.key},
                description_placeholders=_placeholders(**{**extra_placeholders, **err.placeholders}),
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

    # --- the queue of ticked zones ---------------------------------------------------------

    def _start_queue(self, zones: list[dict], step_id: str, schema) -> None:
        self._queue = list(zones)
        self._prepared = {}
        self._error_step = (step_id, schema)

    async def _async_process_queue(self, first_step: tuple[str, Any] | None = None):
        headers = api.get_headers(self._token)
        step = first_step or self._error_step
        while self._queue:
            zone = self._queue[0]
            self._zone = zone
            if zone.get("plan") is not None:
                self._zone_plans.setdefault(zone["id"], zone["plan"])  # /zones already said
            account_id = zone["account"]["id"]
            list_name, list_id = self._wanted_lists.get(zone["id"], (DEFAULT_LIST_NAME, None))

            async def prepare(zone=zone, account_id=account_id, list_name=list_name, list_id=list_id):
                await self._async_check_account_token(headers, account_id)
                return await self._async_prepare_zone(headers, zone["id"], account_id, list_name, list_id)

            chosen, form = await self._async_run(prepare, step[0], step[1], zone=zone["name"])
            if form:
                if form.get("errors") == {"base": "list_create_failed"} and self._lists:
                    self._zone = zone
                    return await self.async_step_list_select()
                return form
            self._queue.pop(0)
            self._prepared[zone["id"]] = chosen
            step = self._error_step
        return await self._async_zones_ready()

    async def async_step_list_select(self, user_input=None):
        """The list could not be created (plan limit): use one of the existing IP lists."""
        names = {item["name"]: item["id"] for item in self._lists}
        schema = vol.Schema({vol.Required("list_name"): vol.In(list(names))})
        placeholders = {"zone": self._zone["name"]}
        if user_input is None:
            return self.async_show_form(
                step_id="list_select", data_schema=schema, description_placeholders=placeholders
            )
        name = user_input["list_name"]
        self._wanted_lists[self._zone["id"]] = (name, names[name])
        return await self._async_process_queue(("list_select", schema))

    async def async_step_rules_confirm(self, user_input=None):
        """The zone is at its rule limit: show exactly what would change, apply only when approved."""
        zone, plan, list_name = self._pending
        schema = vol.Schema({vol.Required("approve", default=False): bool})
        placeholders = {
            "zone": zone["name"],
            "count": str(plan.count),
            "limit": str(plan.limit),
            "needed": str(len(plan.wanted)),
            "changes": room.describe_changes(plan, list_name),
        }
        if user_input is None or not user_input.get("approve"):
            return self.async_show_form(
                step_id="rules_confirm", data_schema=schema, description_placeholders=placeholders,
                errors=None if user_input is None else {"base": "approval_required"},
            )
        # The rules are read again before anything is written; if they changed meanwhile, the
        # new plan has another signature and is shown again instead of being applied.
        self._approved[zone["id"]] = plan.signature()
        self._pending = None
        return await self._async_process_queue()

    async def _async_zones_ready(self):
        raise NotImplementedError


class CloudflareAbuseMonitorConfigFlow(ZoneSetupMixin, config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cloudflare Abuse Monitor."""

    VERSION = 1
    MINOR_VERSION = 3

    def __init__(self) -> None:
        self._init_zone_setup()
        self._abuse_key: str | None = None
        self._available: list[dict] = []
        self._reauth_entry = None

    async def _async_check_abuseipdb(self, key: str) -> None:
        result = await self._job(api.validate_abuseipdb_key, key)
        if result == "invalid":
            raise SetupError("invalid_abuseipdb_key")
        if result == "rate_limited":
            _LOGGER.warning("AbuseIPDB key accepted, but today's lookup quota is already used up")

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

        # A zone another entry already monitors is not offered again.
        taken = _zones_in_other_entries(self, None)
        self._available = [zone for zone in self._zones if zone["id"] not in taken]
        if not self._available:
            return self.async_abort(reason="already_configured")
        if len(self._available) == 1:
            self._start_queue(self._available, "user", self._user_schema())
            return await self._async_process_queue()
        return await self.async_step_zones()

    def _zones_schema(self, selected: list[str] | None = None):
        default = selected if selected is not None else [zone["id"] for zone in self._available]
        return vol.Schema({vol.Required(CONF_ZONES, default=default): _zone_selector(self._available)})

    async def async_step_zones(self, user_input=None):
        """More than one zone: a checkbox per zone, all ticked to start with."""
        placeholders = _placeholders(count=str(len(self._available)))
        if user_input is None:
            return self.async_show_form(
                step_id="zones", data_schema=self._zones_schema(), description_placeholders=placeholders
            )
        selected = list(user_input.get(CONF_ZONES) or [])
        schema = self._zones_schema(selected)
        if not selected:
            return self.async_show_form(
                step_id="zones", data_schema=schema, errors={"base": "no_zones"},
                description_placeholders=placeholders,
            )
        self._start_queue([zone for zone in self._available if zone["id"] in selected], "zones", schema)
        return await self._async_process_queue()

    async def _async_zones_ready(self):
        if self._reauth_entry is not None:
            return self._async_finish_new_token()
        records = [_new_record(zone, self._prepared[zone["id"]]) for zone in self._available
                   if zone["id"] in self._prepared]
        if len(records) == 1:
            # Like v1.6: an entry with one zone is found by that zone's id.
            await self.async_set_unique_id(records[0]["zone_id"])
            self._abort_if_unique_id_configured()
        return self.async_create_entry(
            title=_title(records),
            data={
                CONF_API_TOKEN: self._token,
                CONF_ABUSEIPDB_TOKEN: self._abuse_key,
                CONF_ZONES: records,
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
        records = zone_records(entry.data)
        placeholders = {"zone_name": ", ".join(record["zone_name"] for record in records)}
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

        async def check():
            await self._async_check_token(headers)
            visible = {zone.get("id") for zone in self._zones}
            for record in records:
                if record["zone_id"] not in visible:
                    raise SetupError("wrong_zone", zone=record["zone_name"])

        _, form = await self._async_run(check, step_id, self._token_schema(), **placeholders)
        if form:
            return form

        self._token = token
        self._reauth_entry = entry
        # Every zone keeps the list it has.
        self._wanted_lists = {record["zone_id"]: (record.get("list_name") or DEFAULT_LIST_NAME,
                                                  record.get("list_id")) for record in records}
        self._start_queue([_zone_from_record(record) for record in records], step_id, self._token_schema())
        return await self._async_process_queue()

    def _async_finish_new_token(self):
        entry = self._reauth_entry
        records = []
        for record in zone_records(entry.data):
            # Unique-id prefix and storage stay; only the list can change.
            records.append({**record, **self._prepared[record["zone_id"]]})
        # An entry not migrated yet (a v1.5 Global API Key entry) also gets the v1.7 shape here.
        new_data = {
            key: value for key, value in entry.data.items()
            if key not in LEGACY_KEYS and key not in ZONE_KEYS and key != CONF_UID_PREFIX
        }
        new_data[CONF_ZONES] = records
        new_data[CONF_API_TOKEN] = self._token
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


class CloudflareAbuseMonitorOptionsFlowHandler(ZoneSetupMixin, config_entries.OptionsFlow):
    """The zone checkboxes plus the options; they apply to every zone of the entry."""

    def __init__(self) -> None:
        self._init_zone_setup()
        self._choices: list[dict] | None = None
        self._options: dict[str, Any] = {}
        self._selected: list[str] = []
        self._lookup_error: str | None = None

    async def _async_zone_choices(self) -> list[dict]:
        """The zones the token sees now (minus other entries' zones) plus the configured ones."""
        if self._choices is not None:
            return self._choices
        entry = self.config_entry
        self._token = entry.data.get(CONF_API_TOKEN)
        configured = [_zone_from_record(record) for record in entry.data.get(CONF_ZONES) or []]
        live: list[dict] = []
        if self._token:
            try:
                await self._async_check_token(api.get_headers(self._token))
                live = self._zones
            except SetupError as err:
                self._lookup_error = "zones_unavailable"
                _LOGGER.warning("Could not list the token's zones: %s", err.key)
            except (api.CloudflareApiError, OSError) as err:
                self._lookup_error = "zones_unavailable"
                _LOGGER.warning("Could not list the token's zones: %s", err)
        taken = _zones_in_other_entries(self, entry.entry_id)
        by_id = {zone["id"]: zone for zone in configured}
        for zone in live:
            if zone["id"] not in taken:
                by_id[zone["id"]] = zone  # the live copy has the account name for the label
        self._choices = list(by_id.values())
        return self._choices

    def _schema(self, values: dict) -> vol.Schema:
        def current(key, default):
            return values.get(key, default)

        return vol.Schema({
            vol.Required(CONF_ZONES, default=current(CONF_ZONES, [])): _zone_selector(self._choices or []),
            vol.Required("abuse_confidence_score", default=current("abuse_confidence_score", DEFAULT_ABUSE_CONFIDENCE_SCORE)): SCORE,
            vol.Required("mode", default=current("mode", MODE_MONITOR)): vol.In([MODE_ACTIVE, MODE_MONITOR]),
            vol.Required(CONF_RECHECK_ENABLED, default=current(CONF_RECHECK_ENABLED, True)): bool,
            vol.Required("recheck_days", default=current("recheck_days", DEFAULT_RECHECK_DAYS)): POSITIVE_INT,
            vol.Required("under_attack_mode", default=current("under_attack_mode", False)): bool,
            vol.Required("under_attack_request_threshold", default=current("under_attack_request_threshold", DEFAULT_UNDER_ATTACK_THRESHOLD)): POSITIVE_INT,
            vol.Required("scan_interval_minutes", default=current("scan_interval_minutes", DEFAULT_SCAN_INTERVAL_MINUTES)): POSITIVE_INT,
        })

    async def async_step_init(self, user_input=None):
        """Manage the zones and the options."""
        entry = self.config_entry
        await self._async_zone_choices()
        records = list(entry.data.get(CONF_ZONES) or [])
        configured_ids = [record["zone_id"] for record in records]

        if user_input is None:
            values = {**entry.data, **entry.options, CONF_ZONES: configured_ids}
            errors = {"base": self._lookup_error} if self._lookup_error else None
            return self.async_show_form(
                step_id="init", data_schema=self._schema(values), errors=errors,
                description_placeholders=_placeholders(),
            )

        selected = list(user_input.get(CONF_ZONES) or [])
        schema = self._schema(user_input)
        if not selected:
            return self.async_show_form(
                step_id="init", data_schema=schema, errors={"base": "no_zones"},
                description_placeholders=_placeholders(),
            )
        self._selected = selected
        self._options = {key: value for key, value in user_input.items() if key != CONF_ZONES}

        # Zones that stay keep their list; a new zone of a known account uses that account's list.
        for record in records:
            if record["zone_id"] in selected:
                self._account_lists.setdefault(record["account_id"], {
                    "list_name": record["list_name"], "list_id": record["list_id"],
                })
        added = [zone for zone in self._choices if zone["id"] in selected and zone["id"] not in configured_ids]
        self._start_queue(added, "init", schema)
        return await self._async_process_queue()

    async def _async_zones_ready(self):
        entry = self.config_entry
        records = list(entry.data.get(CONF_ZONES) or [])
        kept = [record for record in records if record["zone_id"] in self._selected]
        added = [_new_record(zone, self._prepared[zone["id"]]) for zone in self._choices
                 if zone["id"] in self._prepared]
        for record in records:
            if record["zone_id"] not in self._selected:
                # Its device and entities go on reload; its rules and list stay in Cloudflare.
                await owned_level_store(self.hass, entry.entry_id, record).async_remove()
        new_records = kept + added
        # A title the user typed stays; the automatic one follows the zones.
        title = _title(new_records) if records and entry.title == _title(records) else entry.title
        self.hass.config_entries.async_update_entry(
            entry,
            title=title,
            data={**entry.data, CONF_ZONES: new_records},
            options=self._options,
        )
        return self.async_create_entry(title="", data=self._options)
