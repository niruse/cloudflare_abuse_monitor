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
- 🧠 Dynamic recheck logic – every 7 days
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
<img width="324" alt="image" src="https://github.com/user-attachments/assets/78c40095-c8eb-48ea-9493-bea520f763e7" />
 
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
<img width="394" alt="image" src="https://github.com/user-attachments/assets/f3750974-2d2a-4f1e-b80e-14262a579327" />


### 📋 Sensor Details
Listed IPs

<img src="https://github.com/user-attachments/assets/fe482670-3283-453a-a6f3-c78f1bfbb6d9" alt="Listed IPs" width="500"/>

High-Risk IPs

<!-- High-Risk IPs -->
<img src="https://github.com/user-attachments/assets/02046585-8b77-4f6c-a838-b56cb8d9e32f" alt="High-Risk IPs" width="500"/>

Skipped IPs

<!-- Skipped IPs -->
<img src="https://github.com/user-attachments/assets/327cd9e9-87d7-439c-891c-8b4ba46058a3" alt="Skipped IPs" width="500"/>

Traffic Summary

<!-- Traffic Summary -->
<img src="https://github.com/user-attachments/assets/09a5f8bf-5687-4d5f-b49d-149d216c38b5" alt="Traffic Summary" width="500"/>

Under Attack Mode

<!-- Under Attack Mode -->
<img width="456" alt="image" src="https://github.com/user-attachments/assets/2dcdd02c-d464-42bb-8df3-235ebc15681c" />

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
<img width="1297" alt="image" src="https://github.com/user-attachments/assets/a708d8d4-c3d3-4ff3-916d-2661160a65ca" />
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

<img width="526" alt="image" src="https://github.com/user-attachments/assets/e4024f62-8196-41d8-8218-8d8a045cfa93" />


---

## 🛠️ Installation

## 📦 Installation via HACS

1. Go to **HACS **
2. Click the **three dots menu > Custom repositories**
3. Add this repository URL: https://github.com/niruse/cloudflare_abuse_monitor/tree/main
<img width="297" alt="image" src="https://github.com/user-attachments/assets/5b518d98-9435-4c44-b797-46711b0b1321" />


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
  <img width="1349" alt="image" src="https://github.com/user-attachments/assets/857be387-c684-4cae-9382-be6613d061b9" />

  - AbuseIPDB API Key
  - AbuseIPDB score threshold under abuse_confidence_score
  - Recheck Days → recheck_days (how many days to wait before rechecking the stored IPs)
  - Zone ID
  - List ID
  - Mode is automatically set to "Monitor" by default, but you can change it after completing the configuration

  <img width="326" alt="image" src="https://github.com/user-attachments/assets/d329c52f-1f15-4597-86f3-a4cad405815d" />

  Page for zone id
  
  <img width="312" alt="image" src="https://github.com/user-attachments/assets/e60b2ed2-bc68-4ab6-a641-e8a3206cfa4a" />

  Page for list id
 
  <img width="322" alt="image" src="https://github.com/user-attachments/assets/db660023-d3b5-4a2e-bbcb-f7292951dd85" />



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

![Options](https://github.com/user-attachments/assets/96fd9879-40ae-4619-8fb5-a208c0509306)

<img width="325" alt="image" src="https://github.com/user-attachments/assets/599018c9-935b-4073-8c45-924f8f085405" />

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

![Services](https://github.com/user-attachments/assets/2f9f85e2-8b7c-4e83-beb6-928c93456e73)

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
