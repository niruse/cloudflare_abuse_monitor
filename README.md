# Cloudflare Abuse Monitor

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz)

A Home Assistant custom integration that watches the visitors of a **Cloudflare** zone, looks each new IP address up on **AbuseIPDB**, and can block the dangerous ones in Cloudflare's firewall. It can also turn on Cloudflare's **Under Attack Mode** when traffic spikes, or by hand with a switch.

Install it through [HACS](https://hacs.xyz) as a custom repository, or copy it by hand.

If you find it useful, you can [buy me a coffee](https://coff.ee/niruse).

---

## What it does

Every update (every minute by default) the integration:

1. Reads today's traffic for the zone (requests, page views, bytes) from Cloudflare's GraphQL analytics.
2. Reads the IP addresses that hit the **Skip rule** today. These are your visitors (see [the firewall rules](#the-firewall-rules-it-creates) for why a Skip rule is needed).
3. Reads the IPs already in your Cloudflare IP list (`block_ips`).
4. Looks every visitor that is not in the list yet up on AbuseIPDB, once, and again after a number of days if rechecking is on. Scores are cached, so an IP costs one AbuseIPDB lookup, not one per update.
5. Marks IPs whose score reaches your threshold as **high risk**. In **Active** mode it adds them to the IP list, and Cloudflare's Block rule blocks them. In **Monitor** mode it only reports them.
6. In **Active** mode, with Under Attack automation on, turns on Under Attack Mode when the number of requests between two updates reaches your threshold.

Everything happens with one scoped Cloudflare API token that can touch only your zone and its IP lists.

---

## Requirements

- **A Cloudflare zone**: a domain on a [Cloudflare](https://dash.cloudflare.com/) account. The Free plan is enough (it allows 5 custom rules and 1 IP list; the integration needs 2 rules and 1 list).
- **An AbuseIPDB API key**: sign up at [AbuseIPDB](https://www.abuseipdb.com/) and create a key under **Account > API**. The free plan allows 1,000 lookups a day.
- Home Assistant 2025.12 or newer.

---

## Installation

### HACS

1. Open **HACS**, then the three-dots menu > **Custom repositories**.
2. Add `https://github.com/niruse/cloudflare_abuse_monitor` with the type **Integration**.
3. Install **Cloudflare Abuse Monitor** and restart Home Assistant.

### Manual

1. Copy the `custom_components/cloudflare_abuse_monitor` folder into `/config/custom_components/`.
2. Restart Home Assistant.

---

## Setup

1. Go to **Settings > Devices & services > + Add integration** and search for **Cloudflare Abuse Monitor**.
2. Click **Create a Cloudflare API token** in the form. It opens Cloudflare's "create token" page with the token name and permissions pre-filled.
3. **Check that all five permission rows below are there.** Cloudflare documents the keys for the first three rows; if a row is missing when the page opens, add it with **+ Add more**.

   | Permission | Why the integration needs it |
   |---|---|
   | Zone > Zone > Read | Finds your zone and the account it belongs to. |
   | Zone > Analytics > Read | The traffic summary, and the visitors seen by the Skip rule (GraphQL `httpRequests1hGroups` and `firewallEventsAdaptive`). |
   | Zone > Zone Settings > Edit | Reads and changes the zone's security level, which is how Under Attack Mode is turned on and off. |
   | Zone > Zone WAF > Edit | Reads your custom firewall rules, and creates the Block and Skip rules during setup if they are missing. **Read** is enough if you create both rules yourself. |
   | Account > Account Filter Lists > Edit | Reads the IP list, adds and removes IPs, and creates the `block_ips` list during setup. |

   Nothing else is needed: no DNS, no account settings, no billing, no other zones.

4. **Narrow the token (required).** The link starts with *all accounts* and *all zones*, because Cloudflare's link format needs a value there. Under **Account Resources** choose your account. Under **Zone Resources** choose **Specific zone** and your zone. The token can then touch nothing else.
5. Create the token, copy it, and paste it into the form together with your AbuseIPDB API key.

That is all. The integration then does the rest by itself:

- checks the token with Cloudflare (`/user/tokens/verify`, or the account endpoint for an account-owned token) and refuses a disabled or expired one;
- finds the zones the token can read: one is picked automatically, otherwise you choose;
- reads the account from the zone;
- checks the AbuseIPDB key with a single lookup (if today's quota is already used up, the key is accepted with a warning in the log);
- tests every permission without changing anything: one analytics row, the security level written back unchanged, the IP lists read, the custom rules read. Every missing permission is named in the form, all at once, and nothing is created until all of them pass;
- uses the IP list `block_ips` if it exists (it proves the Edit permission by writing the list's description back unchanged), or creates it. If your plan's list limit is reached, you can choose one of your existing IP lists instead;
- creates the Block and Skip rules if they are missing. Existing rules are never replaced or duplicated;
- starts in **Monitor** mode with these defaults, which you can change under **Configure**: score threshold 100, rechecking on after 7 days, an update every minute, Under Attack automation off.

The token and the AbuseIPDB key are stored only in Home Assistant. They are never written to the log, and diagnostics downloads redact them together with the zone, account and list identifiers.

### The firewall rules it creates

In Cloudflare: your zone > **Security > Security rules > Custom rules**.

**Block listed IPs**
```
(ip.src in $block_ips)
Action: Block
```

**Log visitors for checking** (a Skip rule)
```
not (ip.src in $block_ips)
Action: Skip (all remaining custom rules), Log matching requests: on
```

Why a Skip rule? Cloudflare's firewall events only record a request when a rule acted on it, and the integration reads the visitors that hit a Skip action. This rule matches everyone who is not already blocked, and because it is the last custom rule it skips nothing that would otherwise run.

How existing rules are handled:

- A Block rule counts as present when its expression is exactly `ip.src in $block_ips` (spacing, case and outer parentheses do not matter). A rule for another list, or with extra conditions, does not count.
- A Skip rule counts as present when it is logged and matches (almost) every visitor: the rule above, `true`, or the "Skip by country" rule with every country listed that older versions of this README asked for. A narrow skip, for example for your uptime monitor's IP, does not count, because the sensors would then see only that traffic. The integration adds its own Skip rule at the end.
- A new Block rule is placed **before** the first rule that skips the remaining custom rules. Placed after it, it would never run for the requests that skip matches, and Active mode would list IPs that are never blocked.
- When there are no custom rules at all, both rules are created in one step. Otherwise each missing rule is added on its own; your other rules are never touched.

**Prefer to create the rules yourself?** Create both rules as shown before setup. When both exist, the token needs only **Zone > Zone WAF > Read**: the integration writes rules only during setup, never afterwards.

### A new token later (reconfigure and reauthentication)

- **Settings > Devices & services > Cloudflare Abuse Monitor > three dots > Reconfigure** asks for a new token. It must be able to read the zone this entry monitors, and it goes through the same permission checks.
- If Cloudflare rejects the token while the integration runs (HTTP 401/403, or an authorization error from analytics), Home Assistant shows a **Reauthenticate** notice. Paste a new token there. Server errors (5xx) and plan limits do not start reauthentication; they show as an `error` attribute on the sensor that failed.

### Upgrading from v1.5 (Global API Key)

v1.6 no longer accepts the email + Global API Key. After the update, a setup that uses them shows a **Reauthenticate** notice. Create a token as described above and paste it. The email and the Global API Key are then deleted from Home Assistant. Entity IDs and unique IDs stay the same, so dashboards and automations keep working. Entity display names no longer contain the email.

---

## Options

**Settings > Devices & services > Cloudflare Abuse Monitor > Configure.** Saving reloads the integration; no restart is needed.

| Option | Default | What it does |
|---|---|---|
| `abuse_confidence_score` | `100` | AbuseIPDB score (0-100) from which an IP counts as high risk. |
| `mode` | `Monitor` | `Monitor` only reports high-risk IPs. `Active` also adds them to the IP list, and enables Under Attack automation. |
| `recheck_enabled` | on | Look IPs up again after `recheck_days`. Off: every IP is looked up only once. |
| `recheck_days` | `7` | Days before an IP is looked up again (when rechecking is on). |
| `under_attack_mode` | off | Turn Under Attack Mode on automatically on a traffic spike. Works only in `Active` mode. |
| `under_attack_request_threshold` | `15000` | Requests between two updates that count as a spike. |
| `scan_interval_minutes` | `1` | How often the integration updates, in minutes. |

Setup itself asks only for the token and the AbuseIPDB key. Reconfigure and reauthentication ask only for a new token.

---

## Monitor and Active mode

| | Monitor | Active |
|---|---|---|
| Traffic, visitors and list are read | yes | yes |
| Visitors are looked up on AbuseIPDB | yes | yes |
| High-risk IPs are added to the IP list (and blocked by the Block rule) | no | yes |
| Under Attack Mode is turned on automatically on a spike (if `under_attack_mode` is on) | no | yes |
| The Under Attack switch and the services work | yes | yes |

A high-risk IP stays a candidate until it really is in the list, so switching from Monitor to Active blocks the IPs already found. An IP removed with the `unblock_ip` service is never added back automatically.

### Under Attack Mode

- **Automatic** (Active mode and `under_attack_mode` on): when the requests counted since the previous update reach `under_attack_request_threshold`, the zone's security level is set to `under_attack`. The integration remembers the level it replaced. The count resets at midnight UTC, and a restart or a missed update never reads as a spike.
- It stays on until you turn `under_attack_mode` off or switch to Monitor. The integration then restores the level it replaced. It never changes a level it did not set itself.
- **The Under Attack switch** turns it on and off by hand, in either mode. On remembers the level it replaces; off restores it, or sets `high` if Under Attack Mode was turned on somewhere else (for example in the Cloudflare dashboard). A level set with the switch is not undone by the automatic logic.

### Rechecking

Each IP is looked up once and its score is stored in `/config/cloudflare_checked_ips.json` (shared by all configured zones). With rechecking on, an IP seen again after `recheck_days` is looked up again; with it off, never. A failed lookup is not stored, so it is retried on the next update. When AbuseIPDB's daily quota is used up, the remaining IPs wait for a later update.

---

## Entities

All entities belong to one device per zone, **Cloudflare Abuse Monitor**. For a zone `example.com` the entity IDs look like this (an entry upgraded from v1.5 keeps its old IDs):

| Entity | State | Main attributes |
|---|---|---|
| `sensor.example_com_traffic_summary` | requests today (UTC) | `pageviews`, `requests`, `bytes`, `cached_bytes`, `cached_requests`, `encrypted_bytes`, `encrypted_requests`, `from`, `to` |
| `sensor.example_com_skip_ips` | visitors seen by the Skip rule today | `skip_ips` |
| `sensor.example_com_list_ips` | IPs in the block list | `current_list_ips` |
| `sensor.example_com_high_risk_ips` | high-risk IPs found this update | `high_risk_ip_list`, `ips_to_check`, `blocked_ips`, `abuse_confidence_score_threshold`, `recheck_enabled`, `recheck_days`, `mode` |
| `sensor.example_com_under_attack_mode` | `on` / `off` (`error` if it could not be read) | `security_level`, `current_request_count`, `last_request_count`, `delta`, `threshold`, `enabled`, `enabled_by_integration`, `mode`, `reason` |
| `switch.example_com_under_attack` | `on` while the security level is `under_attack` | `security_level`, `enabled_by_integration` |

Every sensor also has `next_update_in_seconds` and `next_update` (local time), and an `error` attribute when its part of the update failed. One failing part never blanks the other sensors.

---

## Services

| Service | What it does |
|---|---|
| `cloudflare_abuse_monitor.check_ip` | Looks one IP up on AbuseIPDB now and returns the result (call it with *response*). The score is cached like the automatic lookups. |
| `cloudflare_abuse_monitor.block_ip` | Adds an IP to the block list. |
| `cloudflare_abuse_monitor.unblock_ip` | Removes an IP from the block list. It is then never added back automatically, even in Active mode, until you block it again with `block_ip`. An IP that is not in the list gives an error and changes nothing. |
| `cloudflare_abuse_monitor.refresh` | Updates every entity now. |

`ip` accepts IPv4 and IPv6. Each service takes an optional `config_entry_id`, needed only when more than one zone is configured.

```yaml
action: cloudflare_abuse_monitor.check_ip
data:
  ip: 203.0.113.10
response_variable: result
```

```yaml
action: cloudflare_abuse_monitor.unblock_ip
data:
  ip: 2001:db8::10
```

---

## Example dashboard

This example uses [`button-card`](https://github.com/custom-cards/button-card). Replace the entity IDs with yours.

```yaml
type: vertical-stack
title: Cloudflare Abuse Monitor
cards:
  - type: horizontal-stack
    cards:
      - type: custom:button-card
        entity: sensor.example_com_traffic_summary
        name: Requests today
        icon: mdi:chart-box-outline
        show_state: true
      - type: custom:button-card
        entity: sensor.example_com_skip_ips
        name: Visitors
        icon: mdi:account-multiple-outline
        show_state: true
  - type: horizontal-stack
    cards:
      - type: custom:button-card
        entity: sensor.example_com_list_ips
        name: Blocked IPs
        icon: mdi:format-list-bulleted
        show_state: true
      - type: custom:button-card
        entity: sensor.example_com_high_risk_ips
        name: High risk (checked / found)
        icon: mdi:alert-outline
        show_state: true
        state_display: |
          [[[
            const a = entity.attributes;
            return `${(a.ips_to_check || []).length} / ${(a.high_risk_ip_list || []).length}`;
          ]]]
  - type: custom:button-card
    entity: switch.example_com_under_attack
    name: Under Attack Mode
    icon: mdi:shield-alert
    show_state: true
    tap_action:
      action: toggle
      confirmation:
        text: Change Cloudflare's Under Attack Mode?
    styles:
      card:
        - background-color: |
            [[[
              if (entity.state === "on") return "rgba(255, 0, 0, 0.2)";
              if (entity.state === "off") return "rgba(0, 128, 0, 0.2)";
              return "rgba(128, 128, 128, 0.2)";
            ]]]
```

---

## Troubleshooting

| Message in the setup form | What to do |
|---|---|
| *The token is missing: …* | Edit the token in Cloudflare (**My Profile > API Tokens > Edit**) and add each permission named, then submit again. Analytics Read, Zone Settings Edit, Zone WAF Edit and Account Filter Lists Edit are the usual ones, because the link may not pre-fill the last two. |
| *Cloudflare does not accept this API token* | The token was not pasted whole (no spaces or line breaks), was deleted, or is an account token for another account. |
| *This API token is disabled or expired* | Re-enable it, or create a new one. |
| *The token cannot read any zone* | Add **Zone > Zone > Read** and choose your zone under **Zone Resources**. |
| *The token cannot read the zone this entry monitors* | (Reconfigure, reauthentication) Choose this entry's zone under **Zone Resources**. |
| *Cloudflare would not create the IP list* | Create a list of type IP under **Manage Account > Configurations > Lists**, or delete an unused list, then try again. |
| *Cloudflare would not add the firewall rules* | The plan's custom-rule limit is reached (5 on Free). Free a slot, or create the two rules by hand as shown above. |
| *AbuseIPDB rejected this API key* | Copy the key again from AbuseIPDB **Account > API**. |
| *Could not reach Cloudflare or AbuseIPDB* | A network problem or an outage; try again. The log has the status code. |

After setup:

- **A sensor shows `unknown` with an `error` attribute**: that part of the update failed (an outage, a plan limit). The other sensors keep working, and the next update tries again.
- **A Reauthenticate notice**: Cloudflare rejected the token. It was deleted, expired, or lost a permission. Paste a new one.
- **Skip IPs stays at 0**: check that the Skip rule exists, is enabled, is the last custom rule, and has **Log matching requests** on.
- **High-risk IPs are listed but not blocked**: check that the Block rule is enabled and comes before any rule that skips the remaining custom rules.
- **Diagnostics**: the integration's three-dots menu > **Download diagnostics** gives a file without the token, keys, zone, account, list identifiers or visitor IPs, safe to attach to an issue.

---

## Disclaimer

You are responsible for how you use this integration. Blocking IP addresses can block real visitors; start in Monitor mode and check the high-risk list before switching to Active. The author is not responsible for misuse or unintended blocking.

## Contributing

Bug fixes, features and suggestions are welcome: submit a pull request or [open an issue](https://github.com/niruse/cloudflare_abuse_monitor/issues).
