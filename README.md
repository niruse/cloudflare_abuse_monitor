# **Cloudflare Abuse Monitor**

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz)

**Home Assistant: Cloudflare Threat Intelligence Integration**

This is a **custom integration** for Home Assistant and is available via [HACS](https://hacs.xyz) by adding this repository as a custom source.

---

Welcome to **Cloudflare Abuse Monitor**!  
This custom Home Assistant integration allows you to monitor and manage abusive IPs on your **Cloudflare** zone. It integrates:

- 🔄 Real-time traffic analysis  
- 🛡️ IP reputation lookups via **AbuseIPDB**  
- 🔁 Automated updates to your **Cloudflare** firewall IP lists

> *Keep your network protected and your automations smart.*

---

## 🔍 Features

- 📊 **Traffic Summary**: Track HTTP requests via Cloudflare GraphQL API.
- 🚫 **Skipped IPs**: Track IPs skipped due to existing rules  
- 📋 **Listed IPs**: Track IPs currently in your block list  
- ❌ **High-Risk IP Detection**: IPs with high AbuseIPDB scores are flagged and handled.
- ✅ **Automatic Blocking**: Block malicious IPs by updating your Cloudflare firewall list.
- 🔄 **Recheck IPs**: Optionally recheck IPs after X days (configurable).
- ⚙️ **Custom Modes**: Choose between `Monitor` or `Active` mode for automatic blocking.
- 🧠 **Smart Skipping**: Avoid rechecking IPs already handled.

Each sensor updates at a configurable interval (*default: every minute*) and integrates seamlessly with your **Home Assistant dashboard**.

---

## 🖼️ Screenshots

### 📊 Dashboard Overview  
![Dashboard Overview](https://github.com/user-attachments/assets/cd87eae1-0c3d-4725-bcaf-7db4dd7dca93)

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
- Go to **Rules > IP Lists**
- Create a list named: `block_ips`. You can set any name.

---

## 🔒 Configure Cloudflare Rules

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

1. Go to **HACS > Integrations > + Explore & Download Repositories**
2. Click the **three dots menu > Custom repositories**
3. Add this repository URL: 

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
  - Global API Key
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

| Option                    | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| **AbuseIPDB Score Threshold** | Minimum score to consider an IP as high risk (default: 100).                  |
| **Mode** (Active / Monitor)   | - **Active**: Automatically adds high-risk IPs to your Cloudflare list. <br> - **Monitor**: Just detects and logs IPs. |
| **Recheck Interval (Days)**   | Controls how often previously seen IPs are re-checked (default: 7 days).     |

> These options are accessible under **Configure** in the integration settings:

![Options](https://github.com/user-attachments/assets/8434f4c2-0fa1-4b88-bedb-d861ccf2fc3a)

<img width="338" alt="image" src="https://github.com/user-attachments/assets/e7eb5d3a-6435-4ce6-a169-56ae869b079f" />



---

## 📊 Cloudflare Abuse Monitor Dashboard

This example **Lovelace dashboard** uses [`button-card`](https://github.com/custom-cards/button-card) to show your sensors.
> ℹ️ **Make sure to update the entity names to match your actual sensor IDs:**

- `sensor.cloudflare_traffic_summary` → Replace with your traffic summary sensor  
- `sensor.cloudflare_skipped_ips` → Replace with your skipped IPs sensor  
- `sensor.cloudflare_listed_ips` → Replace with your listed IPs sensor  
- `sensor.cloudflare_high_risk_ips` → Replace with your high-risk IPs sensor

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
```

---

## 🧰 Services

![Services](https://github.com/user-attachments/assets/ee35b310-5b82-417e-b6f0-6fedd202f5a6)

---

## 🧠 Notes

- Checked IPs are stored in `cloudflare_checked_ips.json`
- You can change the update interval of all the sensors by modifying the SCAN_INTERVAL value inside sensor.py.

---

## 🤝 Contributing

We welcome:
- 🔧 Bug fixes
- 🌟 Features
- 🧠 Suggestions

Submit a PR or [open an issue](https://github.com/niruse/cloudflare_abuse_monitor/issues)

---

**Protect your Cloudflare zone with real-time threat monitoring — directly in Home Assistant!**
