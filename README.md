# **Cloudflare Abuse Monitor**

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz)

**Home Assistant: Cloudflare Threat Intelligence Integration**

This is a **custom integration** for Home Assistant and is available via [HACS](https://hacs.xyz) by adding this repository as a custom source.

---

Welcome to **Cloudflare Abuse Monitor**!  
This custom Home Assistant integration allows you to monitor and manage abusive IPs on your **Cloudflare** zone. It integrates:

- 🔄 Real-time traffic analysis
- 🛡️ IP reputation lookups via AbuseIPDB
- 🔁 Automated updates to your Cloudflare firewall IP lists
- 🧠 Dynamic recheck logic – every 7 days, can be changed via configuration.
- 🚨 Under Attack Mode control – based on request thresholds
- ⏱️ Smart scheduling – runs every custom number of minutes set via scan_interval_minutes


> *Keep your network protected and your automations smart.*

---

## 🔍 Features

- ✅ **Automatic Blocking**: Block malicious IPs by updating your Cloudflare firewall list.
- 🔄 **Recheck IPs**: Optionally recheck IPs after X days (configurable).
- ⚙️ **Custom Modes**: Choose between `Monitor` or `Active` mode for automatic blocking.
- 🧠 **Smart Skipping**: Avoid rechecking IPs already handled.
- 🚨 Cloudflare Under Attack Mode support
  
## Sensors
- 📊 **Traffic Summary**: Track HTTP requests via Cloudflare GraphQL API.
- 🚫 **Skipped IPs**: Track IPs skipped due to existing rules  
- 📋 **Listed IPs**: Track IPs currently in your block list  
- ❌ **High-Risk IP Detection**: IPs with high AbuseIPDB scores are flagged and handled.
- 🛡️ Under Attack Mode: Indicates whether Cloudflare's Under Attack Mode is currently enabled (on) or disabled (off) for your zone.

Each sensor updates at a configurable interval (*default: every minute*) and integrates seamlessly with your **Home Assistant dashboard**.

---

## 🆕 What's New in v1.2

### 🛡️ Under Attack Mode Sensor (NEW!)
- Monitor and **toggle Cloudflare's "Under Attack Mode"** directly from Home Assistant.
- Useful for automating emergency protections when malicious traffic is detected.
- Includes visual state feedback and custom styling for clear alert levels.
- last_request_count tracking in global file – Remembers the previous request count to compare with the current value and detect traffic spikes
### ⏱️ Smart Scheduling & Next Update Info
- Sensors now expose:
  - `next_update_in`: Countdown (in seconds) until the next update.
  - `next_run_full_format`: Human-readable time of next scheduled run.
- Update intervals can now be **controlled from GUI or config file**:

 
  `/config/cloudflare_abuse_monitor_configuration.json`

Example:
```json
{
  "scan_interval_minutes": 1,
  "last_request_count": 695
}
```

---

## 🖼️ Screenshots

### 📊 Dashboard Overview  



### 📋 Sensor Details
Listed IPs



High-Risk IPs

<!-- High-Risk IPs -->


Skipped IPs

<!-- Skipped IPs -->


Traffic Summary

<!-- Traffic Summary -->


Under Attack Mode

<!-- Under Attack Mode -->


---

## ✅ Requirements

### AbuseIPDB API Token
- Sign up at [AbuseIPDB](https://www.abuseipdb.com/)
- Generate an API key from your dashboard

### Cloudflare Setup
- Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/)
- Add your domain (Zone)

---

## 📋 Create a Cloudflare IP List
- Go to **Your Accounts > Configurations > Lists**
- Create a list named: `block_ips`. You can set any name.

---

## 🔒 Configure Cloudflare Rules
Select your domain (zone) > In the left sidebar, go to Security > Security Rules

**Rule 1: Block IPs in List** > 
**Note:** If you used a different list name, remember to update it in the rule below.
```
(ip.src in $block_ips)
Action: Block
```

**Rule 2: Skip by Country**
```
(ip.geoip.country in {"AD" "AE" "AF" "AG" "AI" "AL" "AM" "AO" "AQ" "AR" "AS" "AT" "AU" "AW" "AX" "AZ" "BA" "BB" "BD" "BE" "BF" "BG" "BH" "BI" "BJ" "BL" "BM" "BN" "BO" "BQ" "BR" "BS" "BT" "BV" "BW" "BY" "BZ" "CA" "CC" "CD" "CF" "CG" "CH" "CI" "CK" "CL" "CM" "CN" "CO" "CR" "CU" "CV" "CW" "CX" "CY" "CZ" "DE" "DJ" "DK" "DM" "DO" "DZ" "EC" "EE" "EG" "EH" "ER" "ES" "ET" "FI" "FJ" "FM" "FO" "FR" "GA" "GB" "GD" "GE" "GF" "GG" "GH" "GI" "GL" "GM" "GN" "GP" "GQ" "GR" "GT" "GU" "GW" "GY" "HK" "HM" "HN" "HR" "HT" "HU" "ID" "IE" "IL" "IM" "IN" "IO" "IQ" "IR" "IS" "IT" "JE" "JM" "JO" "JP" "KE" "KG" "KH" "KI" "KM" "KN" "KP" "KR" "KW" "KY" "KZ" "LA" "LB" "LC" "LI" "LK" "LR" "LS" "LT" "LU" "LV" "LY" "MA" "MC" "MD" "ME" "MF" "MG" "MH" "MK" "ML" "MM" "MN" "MO" "MP" "MQ" "MR" "MS" "MT" "MU" "MV" "MW" "MX" "MY" "MZ" "NA" "NC" "NE" "NF" "NG" "NI" "NL" "NO" "NP" "NR" "NU" "NZ" "OM" "PA" "PE" "PF" "PG" "PH" "PK" "PL" "PM" "PN" "PR" "PS" "PT" "PW" "PY" "QA" "RE" "RO" "RS" "RU" "RW" "SA" "SB" "SC" "SD" "SE" "SG" "SH" "SI" "SJ" "SK" "SL" "SM" "SN" "SO" "SR" "SS" "ST" "SV" "SX" "SY" "SZ" "TC" "TD" "TF" "TG" "TH" "TJ" "TK" "TL" "TM" "TN" "TO" "TR" "TT" "TV" "TZ" "UA" "UG" "UM" "US" "UY" "UZ" "VA" "VC" "VE" "VG" "VI" "VN" "VU" "WF" "WS" "YE" "YT" "ZA" "ZM" "ZW"})
Action: Skip
```




---

## 🛠️ Installation

## 📦 Installation via HACS

1. Go to **HACS **
2. Click the **three dots menu > Custom repositories**
3. Add this repository URL: https://github.com/niruse/cloudflare_abuse_monitor/tree/main



### Manual Installation
- Download the `cloudflare_abuse_monitor` folder  
- Place inside `/config/custom_components/`  
- Restart Home Assistant

---

## ⚙️ Configuration

- Go to **Settings > Devices & Services**  
- Click **+ Add Integration**, search for `Cloudflare Abuse Monitor`  
- Fill in:
  - Cloudflare Email
  - Global API Key - Cloudflare Global Token
  1. Log in to the Cloudflare dashboard and go to User Profile in the right corner > API Tokens left side.
  2. In the API Keys section, scroll down, click View button of Global API Key.
  

  - AbuseIPDB API Key
  - AbuseIPDB score threshold under abuse_confidence_score
  - Recheck Days → recheck_days (how many days to wait before rechecking the stored IPs)
  - Zone ID
  - List ID
  - Mode is automatically set to "Monitor" by default, but you can change it after completing the configuration

  

  Page for zone id
  
  

  Page for list id
 
  



## 🧩 Configuration Options

You can now **dynamically adjust** key settings directly from the Home Assistant UI.

### ⚙️ Available Options:

| Option                          | Description                                                                 |
|---------------------------------|-----------------------------------------------------------------------------|
| `abuse_confidence_score`        | Minimum AbuseIPDB score to treat an IP as "high risk". Default: `100`      |
| `mode`                          | `Monitor`: Logs only, or `Active`: Automatically blocks high-risk IPs.     |
| `recheck_days`                  | Days to wait before rechecking previously flagged IPs.                     |
| `under_attack_mode`             | Enable or disable Cloudflare Under Attack Mode based on request threshold. |
| `under_attack_request_threshold`| The number of requests per minute is evaluated based on scan_interval_minutes to determine whether to trigger Under Attack Mode.              |
| `scan_interval_minutes`         | How often (in minutes) each sensor should run.                             |

> These options can be changed anytime without restarting Home Assistant.
> These options are accessible under **Configure** in the integration settings:





---

## 💡 Example Behavior

If `under_attack_mode` is enabled and `under_attack_request_threshold = 3000`:
- Under Attack Mode is triggered if the number of requests during the scan_interval_minutes period exceeds the defined threshold.

---

## 📊 Cloudflare Abuse Monitor Dashboard

This example **Lovelace dashboard** uses [`button-card`](https://github.com/custom-cards/button-card) to show your sensors.
> ℹ️ **Make sure to update the entity names to match your actual sensor IDs:**

- `sensor.cloudflare_traffic_summary` → Replace with your traffic summary sensor  
- `sensor.cloudflare_skipped_ips` → Replace with your skipped IPs sensor  
- `sensor.cloudflare_listed_ips` → Replace with your listed IPs sensor  
- `sensor.cloudflare_high_risk_ips` → Replace with your high-risk IPs sensor
- `sensor.under_attack_mode` → Replace with your under_attack_mode sensor

```yaml
type: vertical-stack
title: Cloudflare Abuse Monitor
cards:
  - type: horizontal-stack
    cards:
      - type: custom:button-card
        name: Traffic Summary
        icon: mdi:chart-box-outline
        show_state: true
        show_icon: true
        show_name: true
        entity: sensor.cloudflare_traffic_summary
        tap_action:
          action: more-info
        state_display: >
          [[[ return "Total requests to Cloudflare zone"; ]]]

      - type: custom:button-card
        name: Skipped IPs
        icon: mdi:minus-circle-outline
        show_state: true
        entity: sensor.cloudflare_skipped_ips
        tap_action:
          action: more-info

  - type: horizontal-stack
    cards:
      - type: custom:button-card
        name: Listed IPs
        icon: mdi:format-list-bulleted
        show_state: true
        entity: sensor.cloudflare_listed_ips
        tap_action:
          action: more-info

      - type: custom:button-card
        name: High-Risk IPs
        icon: mdi:alert-outline
        show_state: true
        entity: sensor.cloudflare_high_risk_ips
        state_display: >
          [[[ 
            return `${states['sensor.cloudflare_high_risk_ips'].attributes.ips_to_check?.length || 0} / ${states['sensor.cloudflare_high_risk_ips'].attributes.ips_to_block?.length || 0}`; 
          ]]]
        tap_action:
          action: more-info
  - type: custom:button-card
    name: Under Attack Mode
    icon: mdi:shield-alert
    show_state: true
    show_icon: true
    show_name: true
    entity: sensor.under_attack_mode
    tap_action:
      action: more-info
    state_display: |
      [[[
        if (entity.state === "on") return "ACTIVE";
        if (entity.state === "off") return "OFF";
        if (entity.state === "unknown") return "Unknown";
        if (entity.state === "error") return "Error";
        return entity.state;
      ]]]
    styles:
      card:
        - background-color: |
            [[[
              if (entity.state === "on") return "rgba(255, 0, 0, 0.2)";
              if (entity.state === "off") return "rgba(0, 128, 0, 0.2)";
              return "rgba(128, 128, 128, 0.2)";
            ]]]
        - border: 1px solid rgba(255, 255, 255, 0.1)
        - border-radius: 12px
        - padding: 12px
      name:
        - font-weight: bold
      state:
        - font-size: 14px
        - font-weight: 500
```

---

## 🧰 Services



---

## 🧠 Notes

- Checked IPs are stored in `cloudflare_checked_ips.json`
- You can change the update interval of all the sensors by modifying the SCAN_INTERVAL value inside sensor.py.

---

## Disclaimer

⚠️ It's your responsibility to use this integration safely and responsibly. The developer is not responsible for misuse or unintended blocking.

---

## 🤝 Contributing

We welcome:
- 🔧 Bug fixes
- 🌟 Features
- 🧠 Suggestions

Submit a PR or [open an issue](https://github.com/niruse/cloudflare_abuse_monitor/issues)

---

**Protect your Cloudflare zone with real-time threat monitoring — directly in Home Assistant!**

## ☕ Support

If you found this project helpful, you can [buy me a coffee](https://coff.ee/niruse)!

