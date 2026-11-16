"""v1.8: making room for the Block and Skip rules in a zone at its custom-rule limit.

Every value here is invented (example.com/.net, 203.0.113.0/24, made-up ids and rules).
"""
import copy
from unittest.mock import patch

import pytest
from homeassistant.config_entries import SOURCE_RECONFIGURE, SOURCE_USER
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import ServiceValidationError

from custom_components.cloudflare_abuse_monitor import api, room
from custom_components.cloudflare_abuse_monitor.coordinator import rules_store

from .conftest import DOMAIN, LIST_ID, ZONE_ID
from .test_api import HEADERS, response
from .test_config_flow import NEW_LIST, RULESET_ID, SETUP, USER_INPUT, ZONE, flow_api_mocks
from .test_multi_zone import ZONE_A, ZONE_B, load, make_v17_entry, record

STORE_KEY = f"{DOMAIN}.rules.{ZONE_ID}"
LIMIT_ERROR = (
    "Add custom rule: HTTP 400: exceeded the maximum number of rules in the phase "
    "http_request_firewall_custom: 6 out of 5"
)


def rule(rule_id, action, expression, description, **extra):
    return {"id": rule_id, "action": action, "expression": expression, "description": description,
            "enabled": True, "version": "1", "last_updated": "2026-11-16T00:00:00Z", **extra}


SKIP_CURRENT = {"ruleset": "current"}

# Five rules (the Free plan maximum), one of them a plain Block rule.
FULL_ZONE = [
    rule("r1", "block", '(http.user_agent contains "BadBot")', "Block bad bots"),
    rule("r2", "managed_challenge", '(http.request.uri.path contains "/admin")', "Challenge admin"),
    rule("r3", "managed_challenge", '(http.request.uri.path contains "/login")', "Challenge login"),
    rule("r4", "js_challenge", '(http.request.uri.path contains "/api")', "Check API clients"),
    rule("r5", "skip", "(ip.src eq 203.0.113.5)", "Uptime monitor",
         action_parameters=SKIP_CURRENT, logging={"enabled": False}),
]


class FakeRules:
    """One zone's custom-rules entrypoint as Cloudflare keeps it, with the plan limit enforced."""

    def __init__(self, rules, limit=5):
        self.rules = copy.deepcopy(rules)
        self.limit = limit
        self.writes = []
        self._next = 0

    def ruleset(self):
        if self.rules is None:
            return None
        return {"id": RULESET_ID, "rules": copy.deepcopy(self.rules)}

    def get(self, zone_id, headers):
        return self.ruleset()

    def create(self, zone_id, rules, headers):
        self.writes.append(("create", None))
        self.rules = [self._new(r) for r in rules]

    def _new(self, body):
        self._next += 1
        new = {k: copy.deepcopy(v) for k, v in body.items() if k != "position"}
        new.setdefault("enabled", True)
        new["id"] = f"new{self._next}"
        return new

    def add(self, zone_id, ruleset_id, body, headers, before=None, position=None):
        assert ruleset_id == RULESET_ID
        if len(self.rules) >= self.limit:
            raise api.CloudflareApiError(
                "Add custom rule: HTTP 400: exceeded the maximum number of rules in the phase "
                f"http_request_firewall_custom: {len(self.rules) + 1} out of {self.limit}", 400
            )
        new = self._new(body)
        ids = [r["id"] for r in self.rules]
        if before:
            index = ids.index(before)
        elif position and "after" in position:
            index = ids.index(position["after"]) + 1
        elif position and "index" in position:
            index = position["index"] - 1
        else:
            index = len(self.rules)
        self.rules.insert(index, new)
        self.writes.append(("add", new["id"]))

    def update(self, zone_id, ruleset_id, rule_id, body, headers):
        index = [r["id"] for r in self.rules].index(rule_id)
        self.rules[index] = {**copy.deepcopy(body), "id": rule_id}
        self.writes.append(("update", rule_id))

    def delete(self, zone_id, ruleset_id, rule_id, headers):
        self.rules = [r for r in self.rules if r["id"] != rule_id]
        self.writes.append(("delete", rule_id))


def wire(mocks, fake):
    mocks.get_custom_entrypoint.side_effect = fake.get
    mocks.create_custom_entrypoint.side_effect = fake.create
    mocks.add_custom_rule.side_effect = fake.add
    mocks.update_custom_rule.side_effect = fake.update
    mocks.delete_custom_rule.side_effect = fake.delete


@pytest.fixture
def flow_api():
    with patch(SETUP, return_value=True), flow_api_mocks() as m:
        m.fetch_ip_lists.return_value = [NEW_LIST]
        yield m


async def start(hass):
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    return await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)


def view(rules):
    """What matters about the rules, without ids and Cloudflare's own fields."""
    return [(r.get("description"), r["action"], r["expression"], r.get("enabled", True)) for r in rules]


# --- the limit --------------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("plan", "limit"),
    [
        ({"legacy_id": "free", "name": "Free Website"}, 5),
        ({"legacy_id": "pro", "name": "Pro Website"}, 20),
        ({"legacy_id": "business"}, 100),
        ({"legacy_id": "enterprise"}, 1000),
        ({"name": "Pro Website"}, 20),
        ({"name": "Something new"}, None),
        ({}, None),
        (None, None),
    ],
)
def test_limit_from_the_zone_plan(plan, limit):
    assert api.rule_limit_for_plan(plan) == limit


def test_limit_from_the_400_text():
    assert api.rule_limit_from_error(api.CloudflareApiError(LIMIT_ERROR, 400)) == 5
    assert api.rule_limit_from_error("... 21 out of 20") == 20
    assert api.rule_limit_from_error(api.CloudflareApiError("HTTP 400: bad expression", 400)) is None


def test_fetch_zone_plan_and_rule_writes_use_single_rule_endpoints():
    plan = {"id": "p", "legacy_id": "free", "name": "Free Website"}
    with patch.object(api.requests, "request", return_value=response({"success": True, "result": {"plan": plan}})) as req:
        assert api.fetch_zone_plan("zone", HEADERS) == plan
        assert req.call_args.args[:2] == ("GET", f"{api.CLOUDFLARE_ZONES_URL}/zone")
        api.update_custom_rule("zone", "rs", "r1", {"expression": "true"}, HEADERS)
        assert req.call_args.args[:2] == ("PATCH", f"{api.CLOUDFLARE_API_URL}/zones/zone/rulesets/rs/rules/r1")
        api.delete_custom_rule("zone", "rs", "r1", HEADERS)
        assert req.call_args.args[:2] == ("DELETE", f"{api.CLOUDFLARE_API_URL}/zones/zone/rulesets/rs/rules/r1")
        api.add_custom_rule("zone", "rs", {"expression": "true"}, HEADERS, position={"after": "r1"})
        assert req.call_args.args[:2] == ("POST", f"{api.CLOUDFLARE_API_URL}/zones/zone/rulesets/rs/rules")
        assert req.call_args.kwargs["json"]["position"] == {"after": "r1"}
        assert not any("entrypoint" in c.args[1] and c.args[0] == "PUT" for c in req.call_args_list)


def test_extended_block_rule_is_recognised():
    extended = rule("r1", "block", '(http.user_agent contains "BadBot") or (ip.src in $block_ips)', "x")
    assert api.is_block_rule(extended, "block_ips")
    assert api.is_block_rule({**extended, "expression": "ip.src in $block_ips || (true)"}, "block_ips")
    # The list inside an "and", or inside a string, is not a Block rule for the list.
    assert not api.is_block_rule({**extended, "expression": "(ip.src in $block_ips and http.host eq \"a\")"}, "block_ips")
    assert not api.is_block_rule({**extended, "expression": '(http.host eq "a or ip.src in $block_ips")'}, "block_ips")
    assert not api.is_block_rule({**extended, "enabled": False}, "block_ips")
    assert not api.is_block_rule({**extended, "action": "log"}, "block_ips")


# --- the plan ----------------------------------------------------------------------------------

def plan_for(rules, limit=5, list_name="block_ips"):
    return room.build_plan({"id": RULESET_ID, "rules": rules}, list_name, limit)


def test_room_enough_needs_no_changes():
    plan = plan_for(FULL_ZONE[:3])
    assert not plan.changes and plan.possible
    assert [r["ref"] for r in plan.add] == ["cfam_block_ips", "cfam_skip_log"]


def test_full_zone_with_a_block_rule_uses_reuse_and_one_merge():
    plan = plan_for(FULL_ZONE)
    assert plan.possible and plan.short == 0
    assert plan.extend["rule"]["id"] == "r1"
    assert plan.extend["expression"] == '(http.user_agent contains "BadBot") or (ip.src in $block_ips)'
    assert [(m["first"]["id"], m["second"]["id"]) for m in plan.merges] == [("r2", "r3")]
    merge = plan.merges[0]
    assert merge["expression"] == '(http.request.uri.path contains "/admin") or (http.request.uri.path contains "/login")'
    assert merge["description"] == "Challenge admin + Challenge login"
    assert [r["ref"] for r in plan.add] == ["cfam_skip_log"]
    text = room.describe_changes(plan, "block_ips")
    assert "The rule 'Block bad bots' will become:" in text
    assert "The rules 'Challenge admin' and 'Challenge login' will be merged into one rule" in text
    assert "will be added" in text


def test_only_as_many_changes_as_needed():
    # Four rules: one slot free, two rules needed -> reuse alone is enough.
    plan = plan_for(FULL_ZONE[:4])
    assert plan.extend is not None and plan.merges == []
    # Block rule exists already: only Skip is needed -> one merge, no reuse.
    with_block = [*FULL_ZONE[1:4], rule("rb", "block", "(ip.src in $block_ips)", "Mine"), FULL_ZONE[4]]
    plan = plan_for(with_block)
    assert plan.extend is None and len(plan.merges) == 1


def test_reuse_never_touches_disabled_parameterised_or_unreachable_block_rules():
    rules = [
        rule("s1", "skip", "true", "Skip all", action_parameters=SKIP_CURRENT, logging={"enabled": False}),
        rule("b1", "block", "(http.host eq \"a.example.com\")", "After the skip"),
        {**rule("b2", "block", "(http.host eq \"b.example.com\")", "Disabled"), "enabled": False},
        rule("b3", "block", "(http.host eq \"c.example.com\")", "Custom page",
             action_parameters={"response": {"status_code": 403, "content": "no", "content_type": "text/plain"}}),
        rule("l1", "log", "true", "Log"),
    ]
    plan = plan_for([rules[2], rules[3], rules[0], rules[1], rules[4]])
    assert plan.extend is None  # disabled, custom response, or after a skip of the rest
    assert plan.merges == []
    assert not plan.possible and plan.short == 2


def test_merge_needs_adjacent_rules_with_the_same_action_and_settings():
    challenge = "managed_challenge"
    rules = [
        rule("a", challenge, "(http.host eq \"a.example.com\")", "A"),
        {**rule("x", challenge, "(http.host eq \"x.example.com\")", "X"), "enabled": False},
        rule("b", challenge, "(http.host eq \"b.example.com\")", "B"),
        rule("c", "skip", "(ip.src eq 203.0.113.1)", "C", action_parameters={"phases": ["http_ratelimit"]}),
        rule("d", "skip", "(ip.src eq 203.0.113.2)", "D", action_parameters={"phases": ["http_request_sbfm"]}),
    ]
    plan = plan_for(rules)
    # a and b have a (disabled) rule between them; c and d have different action parameters.
    assert plan.merges == [] and plan.short == 2

    rules[3]["action_parameters"] = {"phases": ["http_request_sbfm"]}
    rules[3]["logging"] = {"enabled": False}
    plan = plan_for(rules)
    assert plan.merges == [] and plan.short == 2  # logging differs
    rules[4]["logging"] = {"enabled": False}
    plan = plan_for(rules)
    assert [(m["first"]["id"], m["second"]["id"]) for m in plan.merges] == [("c", "d")]
    assert plan.short == 1  # one more slot still missing


def test_merge_respects_the_expression_length_limit():
    long_a = '(http.request.uri.path contains "' + "a" * 2100 + '")'
    long_b = '(http.request.uri.path contains "' + "b" * 2100 + '")'
    rules = [
        rule("p", "block", long_a, "Long A", action_parameters={"response": {"status_code": 403}}),
        rule("q", "block", long_b, "Long B", action_parameters={"response": {"status_code": 403}}),
        rule("s", "managed_challenge", "(http.host eq \"s.example.com\")", "S"),
        rule("t", "managed_challenge", "(http.host eq \"t.example.com\")", "T"),
        rule("u", "log", "true", "U"),
    ]
    plan = plan_for(rules, list_name="block_ips")
    assert len(room.joined(long_a, long_b)) > room.MAX_EXPRESSION_LENGTH
    assert [(m["first"]["id"], m["second"]["id"]) for m in plan.merges] == [("s", "t")]
    assert plan.short == 1

    # Reuse is skipped too when the extended expression would be too long.
    huge = rule("h", "block", '(http.user_agent contains "' + "z" * 4080 + '")', "Huge")
    plan = plan_for([huge, *rules[2:4]], limit=3)
    assert plan.extend is None


def test_our_own_rules_are_never_merged():
    rules = [
        {**api.skip_rule("block_ips"), "id": "o1"},
        {**rule("k", "skip", "not (ip.src in $block_ips)", "Copy"), "action_parameters": SKIP_CURRENT,
         "logging": {"enabled": True}},
    ]
    plan = plan_for(rules, limit=2)
    assert plan.merges == []


# --- the setup flow ---------------------------------------------------------------------------

async def test_live_case_five_rules_confirmation_first_then_applied(hass, flow_api, hass_storage):
    fake = FakeRules(FULL_ZONE)
    wire(flow_api, fake)
    result = await start(hass)

    assert result["type"] is FlowResultType.FORM and result["step_id"] == "rules_confirm"
    placeholders = result["description_placeholders"]
    assert (placeholders["zone"], placeholders["count"], placeholders["limit"], placeholders["needed"]) == (
        "example.com", "5", "5", "2"
    )
    assert "'Block bad bots' will become" in placeholders["changes"]
    assert set(result["data_schema"].schema) == {"approve"}
    # Nothing written to the rules before approval, and no originals stored.
    assert fake.writes == [] and STORE_KEY not in hass_storage
    flow_api.fetch_zone_plan.assert_called_once()

    # Not ticked: refused, still nothing written.
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"approve": False})
    assert result["step_id"] == "rules_confirm" and result["errors"] == {"base": "approval_required"}
    assert fake.writes == []

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"approve": True})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert fake.writes == [("update", "r1"), ("update", "r2"), ("delete", "r3"), ("add", "new1")]
    assert view(fake.rules) == [
        ("Block bad bots", "block", '(http.user_agent contains "BadBot") or (ip.src in $block_ips)', True),
        ("Challenge admin + Challenge login", "managed_challenge",
         '(http.request.uri.path contains "/admin") or (http.request.uri.path contains "/login")', True),
        ("Check API clients", "js_challenge", '(http.request.uri.path contains "/api")', True),
        ("Uptime monitor", "skip", "(ip.src eq 203.0.113.5)", True),
        ("Cloudflare Abuse Monitor: log visitors for checking", "skip", "not (ip.src in $block_ips)", True),
    ]
    # The skip of the rest keeps its own settings; the merged rule keeps the first rule's id.
    assert fake.rules[3]["logging"] == {"enabled": False} and fake.rules[1]["id"] == "r2"
    flow_api.create_custom_entrypoint.assert_not_called()  # never a PUT over existing rules

    # The originals were stored first, with every field and position.
    stored = hass_storage[STORE_KEY]["data"]
    assert stored["ruleset_id"] == RULESET_ID
    extend, merge = stored["changes"]
    assert extend["type"] == "extend" and extend["original"]["id"] == "r1" and extend["original"]["position"] == 1
    assert extend["original"]["rule"]["expression"] == '(http.user_agent contains "BadBot")'
    assert "version" not in extend["original"]["rule"]
    assert merge["type"] == "merge" and [o["id"] for o in merge["originals"]] == ["r2", "r3"]
    assert [o["position"] for o in merge["originals"]] == [2, 3]

    # Idempotent: a second run (new token for the entry) finds both rules and changes nothing.
    entry = result["result"]
    fake.writes.clear()
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"api_token": "test-api-token-new0"})
    assert result["type"] is FlowResultType.ABORT and result["reason"] == "reconfigure_successful"
    assert fake.writes == []
    assert len(hass_storage[STORE_KEY]["data"]["changes"]) == 2


async def test_no_room_reports_what_is_missing_and_changes_nothing(hass, flow_api, hass_storage):
    rules = [
        rule("a", "managed_challenge", "(http.host eq \"a.example.com\")", "Challenge A"),
        rule("b", "js_challenge", "(http.host eq \"b.example.com\")", "Check B"),
        {**rule("c", "block", "(http.host eq \"c.example.com\")", "Old block"), "enabled": False},
        rule("d", "log", "true", "Log all"),
        rule("e", "skip", "(ip.src eq 203.0.113.9)", "", action_parameters=SKIP_CURRENT),
    ]
    fake = FakeRules(rules)
    wire(flow_api, fake)
    result = await start(hass)
    assert result["errors"] == {"base": "no_room"}
    placeholders = result["description_placeholders"]
    assert (placeholders["count"], placeholders["limit"], placeholders["needed"], placeholders["short"]) == (
        "5", "5", "2", "2"
    )
    assert "- Challenge A (managed_challenge)" in placeholders["rules"]
    assert "- Old block (block, disabled)" in placeholders["rules"]
    assert "- Rule 5 (no description) (skip)" in placeholders["rules"]
    assert fake.writes == [] and STORE_KEY not in hass_storage


async def test_limit_from_the_plan_in_the_zone_list_needs_no_extra_call(hass, flow_api):
    flow_api.fetch_zones.return_value = [{**ZONE, "plan": {"legacy_id": "pro", "name": "Pro Website"}}]
    fake = FakeRules(FULL_ZONE, limit=20)
    wire(flow_api, fake)
    result = await start(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY  # 20 allowed: no plan, no confirmation
    flow_api.fetch_zone_plan.assert_not_called()
    assert [w[0] for w in fake.writes] == ["add", "add"]
    flow_api.update_custom_rule.assert_not_called()


async def test_small_zone_never_asks_for_the_plan(hass, flow_api):
    fake = FakeRules(FULL_ZONE[:3])
    wire(flow_api, fake)
    result = await start(hass)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    flow_api.fetch_zone_plan.assert_not_called()
    # Block before the first skip of the rest (none here: appended), Skip last.
    assert [r.get("ref") for r in fake.rules][-2:] == ["cfam_block_ips", "cfam_skip_log"]


async def test_limit_learned_from_the_400_leads_to_the_confirmation(hass, flow_api):
    """The plan says Pro, Cloudflare says 5: the 400 is read, and the plan is shown."""
    flow_api.fetch_zone_plan.return_value = {"legacy_id": "pro"}
    fake = FakeRules(FULL_ZONE, limit=5)
    wire(flow_api, fake)
    result = await start(hass)
    assert result["step_id"] == "rules_confirm"
    assert result["description_placeholders"]["limit"] == "5"
    assert fake.writes == []
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"approve": True})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert len(fake.rules) == 5
    assert any(api.is_block_rule(r, "block_ips") for r in fake.rules)
    assert any(r.get("ref") == "cfam_skip_log" for r in fake.rules)


async def test_rules_changed_before_approval_are_shown_again(hass, flow_api, hass_storage):
    fake = FakeRules(FULL_ZONE)
    wire(flow_api, fake)
    result = await start(hass)
    assert result["step_id"] == "rules_confirm"
    # Meanwhile someone edits the Block rule in the dashboard: the approved plan is outdated.
    fake.rules[0]["expression"] = '(http.user_agent contains "OtherBot")'
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"approve": True})
    assert result["step_id"] == "rules_confirm"
    assert "OtherBot" in result["description_placeholders"]["changes"]
    assert fake.writes == [] and STORE_KEY not in hass_storage


# --- the options flow ---------------------------------------------------------------------------

@pytest.fixture
def live_api(cf):
    with flow_api_mocks() as m:
        yield m


async def test_options_add_a_full_zone_with_confirmation(hass, live_api, config_dir, cf, hass_storage):
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID)))
    live_api.fetch_zones.return_value = [ZONE_A, ZONE_B]
    fakes = {ZONE_B["id"]: FakeRules(FULL_ZONE)}
    fake = fakes[ZONE_B["id"]]
    live_api.get_custom_entrypoint.side_effect = lambda zone_id, headers: fakes[zone_id].get(zone_id, headers)
    live_api.add_custom_rule.side_effect = fake.add
    live_api.update_custom_rule.side_effect = fake.update
    live_api.delete_custom_rule.side_effect = fake.delete

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(result["flow_id"], {
        "zones": [ZONE_A["id"], ZONE_B["id"]], "abuse_confidence_score": 80, "mode": "Monitor",
        "recheck_enabled": True, "recheck_days": 7, "under_attack_mode": False,
        "under_attack_request_threshold": 15000, "scan_interval_minutes": 5,
    })
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "rules_confirm"
    assert result["description_placeholders"]["zone"] == "example.net"
    assert fake.writes == []
    assert [z["zone_id"] for z in entry.data["zones"]] == [ZONE_A["id"]]  # not saved yet

    result = await hass.config_entries.options.async_configure(result["flow_id"], {"approve": False})
    assert result["errors"] == {"base": "approval_required"} and fake.writes == []

    result = await hass.config_entries.options.async_configure(result["flow_id"], {"approve": True})
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert [z["zone_id"] for z in entry.data["zones"]] == [ZONE_A["id"], ZONE_B["id"]]
    assert fake.writes == [("update", "r1"), ("update", "r2"), ("delete", "r3"), ("add", "new1")]
    assert f"{DOMAIN}.rules.{ZONE_B['id']}" in hass_storage
    await hass.config_entries.async_unload(entry.entry_id)


# --- restore_rules --------------------------------------------------------------------------------

async def _changed_zone(hass, fake):
    """Make room the way the flow does: originals stored, changes made, the Skip rule added."""
    plan = room.build_plan(fake.ruleset(), "block_ips", 5)
    await rules_store(hass, ZONE_ID).async_save(
        {"ruleset_id": RULESET_ID, "changes": room.store_changes(plan, "block_ips")}
    )
    with patch.object(api, "update_custom_rule", side_effect=fake.update), \
            patch.object(api, "delete_custom_rule", side_effect=fake.delete):
        room.apply_changes(ZONE_ID, RULESET_ID, plan, HEADERS)
    for new in plan.add:
        fake.add(ZONE_ID, RULESET_ID, new, HEADERS)


@pytest.fixture
def restore_api(cf):
    with patch(f"{api.__name__}.get_custom_entrypoint") as get, \
            patch(f"{api.__name__}.update_custom_rule") as update, \
            patch(f"{api.__name__}.delete_custom_rule") as delete, \
            patch(f"{api.__name__}.add_custom_rule") as add:
        yield get, update, delete, add


async def test_restore_rules_puts_the_zone_back(hass, config_dir, cf, restore_api, hass_storage):
    fake = FakeRules(FULL_ZONE)
    await _changed_zone(hass, fake)
    assert len(fake.rules) == 5 and view(fake.rules) != view(FULL_ZONE)
    get, update, delete, add = restore_api
    get.side_effect, update.side_effect, delete.side_effect, add.side_effect = (
        fake.get, fake.update, fake.delete, fake.add
    )
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID)))

    # The zone must be named.
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "restore_rules", {}, blocking=True)

    fake.writes.clear()
    response = await hass.services.async_call(
        DOMAIN, "restore_rules", {"zone": "example.com"}, blocking=True, return_response=True
    )
    report = response["zones"]["example.com"]
    assert report["removed"] == ["Cloudflare Abuse Monitor: log visitors for checking"]
    assert sorted(report["restored"]) == sorted(["'Block bad bots'", "'Challenge admin' and 'Challenge login'"])
    assert report["skipped"] == []
    # Our rule goes first (frees the slot), then the merge is split and the Block rule restored.
    assert fake.writes[0][0] == "delete"
    assert view(fake.rules) == view(FULL_ZONE)
    assert fake.rules[0]["id"] == "r1" and fake.rules[1]["id"] == "r2"
    assert fake.rules[4]["logging"] == {"enabled": False}
    assert STORE_KEY not in hass_storage

    # Nothing left to restore: a second call changes no rule.
    fake.writes.clear()
    await hass.services.async_call(DOMAIN, "restore_rules", {"zone": "example.com"}, blocking=True)
    assert fake.writes == []
    await hass.config_entries.async_unload(entry.entry_id)


async def test_restore_leaves_a_rule_edited_afterwards(hass, config_dir, cf, restore_api, hass_storage):
    fake = FakeRules(FULL_ZONE)
    await _changed_zone(hass, fake)
    fake.rules[0]["expression"] = "(http.host eq \"edited.example.com\")"  # edited by the owner
    get, update, delete, add = restore_api
    get.side_effect, update.side_effect, delete.side_effect, add.side_effect = (
        fake.get, fake.update, fake.delete, fake.add
    )
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID)))
    response = await hass.services.async_call(
        DOMAIN, "restore_rules", {"zone": "example.com"}, blocking=True, return_response=True
    )
    report = response["zones"]["example.com"]
    assert report["skipped"] == ["'Block bad bots'"]
    assert report["restored"] == ["'Challenge admin' and 'Challenge login'"]
    assert fake.rules[0]["expression"] == "(http.host eq \"edited.example.com\")"
    # The skipped change stays stored, so nothing is lost.
    assert [c["type"] for c in hass_storage[STORE_KEY]["data"]["changes"]] == ["extend"]
    await hass.config_entries.async_unload(entry.entry_id)


async def test_zone_removal_does_not_restore(hass, live_api, config_dir, cf, hass_storage):
    fake = FakeRules(FULL_ZONE)
    await _changed_zone(hass, fake)
    entry = await load(hass, make_v17_entry(hass, record(ZONE_A, LIST_ID), record(ZONE_B, LIST_ID)))
    live_api.fetch_zones.return_value = [ZONE_A, ZONE_B]
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(result["flow_id"], {
        "zones": [ZONE_B["id"]], "abuse_confidence_score": 80, "mode": "Monitor",
        "recheck_enabled": True, "recheck_days": 7, "under_attack_mode": False,
        "under_attack_request_threshold": 15000, "scan_interval_minutes": 5,
    })
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    live_api.update_custom_rule.assert_not_called()
    live_api.delete_custom_rule.assert_not_called()
    assert STORE_KEY in hass_storage  # the originals stay for a later restore
    await hass.config_entries.async_unload(entry.entry_id)
