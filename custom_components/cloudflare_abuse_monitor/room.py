"""Making room for the Block and Skip rules in a zone whose custom rules are at the plan limit.

Everything here is plain data, except apply_plan and restore_rules, which call Cloudflare and
must run in the executor. A plan only ever does two things, and only as many as needed:

- reuse: an enabled Block rule of the user also blocks the IP list, ``(<original>) or (ip.src in
  $<list>)``, so the integration needs no Block rule of its own;
- merge: two adjacent rules with the same action and the same settings become one rule
  ``(<A>) or (<B>)`` at the position of the first, which behaves the same way.

No user rule is ever deleted except the second rule of a merge, whose expression lives on in the
merged rule. Every rule a plan changes is saved first (see coordinator.rules_store), so
restore_rules can put the zone back exactly as it was.
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field

from . import api

_LOGGER = logging.getLogger(__name__)

# Cloudflare's limit on the length of a rule expression.
MAX_EXPRESSION_LENGTH = 4096
# Rule fields Cloudflare sets itself; everything else is written back unchanged.
READ_ONLY_FIELDS = ("id", "version", "last_updated", "categories")
# Rules with these fields do more than match and act; they are never changed.
SPECIAL_FIELDS = ("ratelimit", "exposed_credential_check")
OUR_REFS = (api.BLOCK_RULE_REF, api.SKIP_RULE_REF)


@dataclass
class RoomPlan:
    """What has to change in one zone so the missing rules fit."""

    limit: int
    count: int
    wanted: list[dict]                   # every rule the integration still needs
    add: list[dict]                      # the rules that will be added after the changes
    extend: dict | None = None           # {"rule": original, "expression": new}
    merges: list[dict] = field(default_factory=list)  # {"first", "second", "expression", "description"}
    short: int = 0                       # slots still missing after every strategy (0: the plan works)
    rules: list[dict] = field(default_factory=list)   # the zone's rules, for the report

    @property
    def changes(self) -> bool:
        return self.extend is not None or bool(self.merges)

    @property
    def possible(self) -> bool:
        return self.short <= 0

    def signature(self) -> tuple:
        """The same plan computed twice has the same signature (used for the approval)."""
        return (
            (self.extend["rule"].get("id"), self.extend["expression"]) if self.extend else None,
            tuple((m["first"].get("id"), m["second"].get("id"), m["expression"]) for m in self.merges),
            tuple(rule["ref"] for rule in self.add),
        )


# --- expressions --------------------------------------------------------------------------------

def bare(expression: str) -> str:
    """The expression as written, without spaces or parentheses around the whole of it."""
    text = (expression or "").strip()
    while text.startswith("(") and text.endswith(")") and api.balanced(text[1:-1]):
        text = text[1:-1].strip()
    return text


def joined(first: str, second: str) -> str:
    """``(<first>) or (<second>)``: each side keeps its meaning whatever operators it uses."""
    return f"({bare(first)}) or ({bare(second)})"


def list_expression(list_name: str) -> str:
    return f"ip.src in ${list_name}"


# --- rules ----------------------------------------------------------------------------------------

def label(rule: dict, position: int) -> str:
    """How a rule is named in the dialog: its description, else its position."""
    description = (rule.get("description") or "").strip()
    return description or f"Rule {position} (no description)"


def writable(rule: dict) -> dict:
    """The rule as it can be sent back to Cloudflare."""
    return {key: copy.deepcopy(value) for key, value in rule.items() if key not in READ_ONLY_FIELDS}


def snapshot(rule: dict, position: int) -> dict:
    """Everything needed to put a rule back: id, position and every writable field."""
    return {"id": rule.get("id"), "position": position, "rule": writable(rule)}


def _same(value_a, value_b) -> bool:
    return (value_a or {}) == (value_b or {})


def _touchable(rule: dict) -> bool:
    """A rule a plan may change: enabled, a user rule, nothing special about it."""
    return (
        rule.get("enabled", True) is True
        and bool(rule.get("id"))
        and rule.get("ref") not in OUR_REFS
        and rule.get("action") not in (None, "execute")
        and not any(key in rule for key in SPECIAL_FIELDS)
    )


def _mergeable(first: dict, second: dict) -> bool:
    return (
        _touchable(first)
        and _touchable(second)
        and first.get("action") == second.get("action")
        and _same(first.get("action_parameters"), second.get("action_parameters"))
        and _same(first.get("logging"), second.get("logging"))
    )


def _first_skip_index(rules: list[dict]) -> int:
    """Index of the first enabled rule that skips the rest of the custom rules (len if none)."""
    for index, rule in enumerate(rules):
        if rule.get("enabled", True) is not False and api.skips_rest_of_ruleset(rule):
            return index
    return len(rules)


def merged_description(first: dict, second: dict, first_pos: int, second_pos: int) -> str:
    return f"{label(first, first_pos)} + {label(second, second_pos)}"


def build_plan(ruleset: dict | None, list_name: str, limit: int) -> RoomPlan:
    """Work out how the missing rules fit into the zone's custom rules."""
    rules = list((ruleset or {}).get("rules") or [])
    wanted = api.missing_rules(ruleset, list_name)
    plan = RoomPlan(limit=limit, count=len(rules), wanted=wanted, add=list(wanted), rules=rules)
    if ruleset is None:
        return plan  # a new entrypoint holds both rules on any plan
    short = len(wanted) - (limit - len(rules))
    if short <= 0:
        return plan

    used: set[int] = set()
    # a. Reuse an enabled Block rule of the user, if it runs before any skip of the rest.
    if any(rule["ref"] == api.BLOCK_RULE_REF for rule in wanted):
        stop = _first_skip_index(rules)
        for index, rule in enumerate(rules[:stop]):
            if not (_touchable(rule) and rule.get("action") == "block" and not rule.get("action_parameters")):
                continue
            expression = joined(rule.get("expression"), list_expression(list_name))
            if len(expression) > MAX_EXPRESSION_LENGTH:
                continue
            plan.extend = {"rule": rule, "position": index + 1, "expression": expression}
            plan.add = [r for r in plan.add if r["ref"] != api.BLOCK_RULE_REF]
            used.add(index)
            short -= 1
            break

    # b. Merge adjacent rules with the same action and settings, one pair at a time.
    index = 0
    while short > 0 and index + 1 < len(rules):
        first, second = rules[index], rules[index + 1]
        if index in used or index + 1 in used or not _mergeable(first, second):
            index += 1
            continue
        expression = joined(first.get("expression"), second.get("expression"))
        if len(expression) > MAX_EXPRESSION_LENGTH:
            index += 1
            continue
        plan.merges.append({
            "first": first, "second": second,
            "first_position": index + 1, "second_position": index + 2,
            "expression": expression,
            "description": merged_description(first, second, index + 1, index + 2),
        })
        used.update((index, index + 1))
        short -= 1
        index += 2

    # c. Whatever is still missing must be freed by the user.
    plan.short = max(short, 0)
    return plan


def rules_after(plan: RoomPlan) -> list[dict]:
    """The zone's rules as they will be once the plan's changes (not the additions) are made."""
    removed = {merge["second"].get("id") for merge in plan.merges}
    changed = {merge["first"].get("id"): merge for merge in plan.merges}
    result = []
    for rule in plan.rules:
        if rule.get("id") in removed:
            continue
        if rule.get("id") in changed:
            rule = {**rule, "expression": changed[rule["id"]]["expression"]}
        result.append(rule)
    return result


def block_position(rules: list[dict]) -> str | None:
    return api.block_rule_position({"rules": rules})


# --- what the dialog shows ------------------------------------------------------------------

def describe_changes(plan: RoomPlan, list_name: str) -> str:
    lines = []
    if plan.extend:
        rule = plan.extend["rule"]
        lines.append(
            f"- The rule '{label(rule, plan.extend['position'])}' will become: `{plan.extend['expression']}`. "
            f"It then also blocks the IP addresses in the list `{list_name}`, so the integration "
            "does not add a Block rule of its own."
        )
    for merge in plan.merges:
        lines.append(
            f"- The rules '{label(merge['first'], merge['first_position'])}' and "
            f"'{label(merge['second'], merge['second_position'])}' will be merged into one rule "
            f"'{merge['description']}' with the expression `{merge['expression']}`. Both rules are "
            "adjacent and have the same action and settings, so the merged rule behaves in the same way."
        )
    for rule in plan.add:
        lines.append(f"- The rule '{rule['description']}' will be added.")
    return "\n".join(lines)


def describe_rules(plan: RoomPlan) -> str:
    return "\n".join(
        f"- {label(rule, index + 1)} ({rule.get('action', 'unknown action')}"
        f"{', disabled' if rule.get('enabled', True) is False else ''})"
        for index, rule in enumerate(plan.rules)
    )


# --- applying and restoring (blocking: run in the executor) ------------------------------------

def store_changes(plan: RoomPlan, list_name: str) -> list[dict]:
    """What the zone's store keeps for each change, before anything is written."""
    changes = []
    if plan.extend:
        changes.append({
            "type": "extend",
            "list_name": list_name,
            "original": snapshot(plan.extend["rule"], plan.extend["position"]),
            "written": plan.extend["expression"],
        })
    for merge in plan.merges:
        changes.append({
            "type": "merge",
            "originals": [
                snapshot(merge["first"], merge["first_position"]),
                snapshot(merge["second"], merge["second_position"]),
            ],
            "written": merge["expression"],
            "written_description": merge["description"],
        })
    return changes


def apply_changes(zone_id: str, ruleset_id: str, plan: RoomPlan, headers) -> None:
    """Make the plan's changes: PATCH single rules and DELETE the second rule of a merge."""
    if plan.extend:
        rule = plan.extend["rule"]
        body = {**writable(rule), "expression": plan.extend["expression"]}
        api.update_custom_rule(zone_id, ruleset_id, rule["id"], body, headers)
    for merge in plan.merges:
        first, second = merge["first"], merge["second"]
        body = {**writable(first), "expression": merge["expression"], "description": merge["description"]}
        # The merged rule first, then the second one goes: no moment without either.
        api.update_custom_rule(zone_id, ruleset_id, first["id"], body, headers)
        api.delete_custom_rule(zone_id, ruleset_id, second["id"], headers)


def _by_id(ruleset: dict | None) -> dict[str, dict]:
    return {rule.get("id"): rule for rule in (ruleset or {}).get("rules") or [] if rule.get("id")}


def _expression(rule: dict | None) -> str:
    return api.normalize_expression((rule or {}).get("expression"))


def _put_back(zone_id, ruleset_id, original: dict, headers, after: str | None = None) -> None:
    """Add a deleted rule again at its old place."""
    position = {"after": after} if after else {"index": max(1, int(original.get("position") or 1))}
    api.add_custom_rule(zone_id, ruleset_id, original["rule"], headers, position=position)


def restore_rules(zone_id: str, stored: dict, headers) -> dict:
    """Undo every stored change and remove the integration's own rules.

    A rule that was edited again after the integration changed it is left alone and reported,
    and its change stays in the store. Returns {"restored", "removed", "skipped", "remaining"}.
    """
    report = {"restored": [], "removed": [], "skipped": [], "remaining": []}
    ruleset = api.get_custom_entrypoint(zone_id, headers)
    if ruleset is None:
        report["skipped"] = [_change_label(change) for change in stored.get("changes") or []]
        report["remaining"] = list(stored.get("changes") or [])
        return report
    ruleset_id = ruleset["id"]

    # 1. The integration's own rules go first: that frees the slots a re-split needs.
    for rule in ruleset.get("rules") or []:
        if rule.get("ref") in OUR_REFS and rule.get("id"):
            api.delete_custom_rule(zone_id, ruleset_id, rule["id"], headers)
            report["removed"].append(rule.get("description") or rule["ref"])

    current = _by_id(ruleset)
    for change in reversed(stored.get("changes") or []):
        if change["type"] == "extend":
            original = change["original"]
            rule = current.get(original["id"])
            if rule is not None and _expression(rule) == _expression(original["rule"]):
                continue  # never applied, or already back
            if rule is None or _expression(rule) != api.normalize_expression(change["written"]):
                report["skipped"].append(_change_label(change))
                report["remaining"].append(change)
                continue
            api.update_custom_rule(zone_id, ruleset_id, original["id"], original["rule"], headers)
            report["restored"].append(_change_label(change))
        else:
            first, second = change["originals"]
            rule = current.get(first["id"])
            if rule is not None and _expression(rule) == _expression(first["rule"]):
                # The merge was never written: put the second rule back only if it is gone.
                if second["id"] not in current:
                    _put_back(zone_id, ruleset_id, second, headers, after=first["id"])
                    report["restored"].append(_change_label(change))
                continue
            if rule is None or _expression(rule) != api.normalize_expression(change["written"]):
                report["skipped"].append(_change_label(change))
                report["remaining"].append(change)
                continue
            api.update_custom_rule(zone_id, ruleset_id, first["id"], first["rule"], headers)
            if second["id"] not in current:
                _put_back(zone_id, ruleset_id, second, headers, after=first["id"])
            report["restored"].append(_change_label(change))
    report["remaining"].reverse()
    return report


def _change_label(change: dict) -> str:
    if change["type"] == "extend":
        original = change["original"]
        return f"'{label(original['rule'], original['position'])}'"
    first, second = change["originals"]
    return f"'{label(first['rule'], first['position'])}' and '{label(second['rule'], second['position'])}'"
