import requests
from datetime import datetime, timedelta
import logging
import json


_LOGGER = logging.getLogger(__name__)

CLOUDFLARE_ZONES_URL = "https://api.cloudflare.com/client/v4/zones"
CLOUDFLARE_GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"

def get_headers(email, api_key):
    return {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }

def fetch_zones(email, api_key):
    headers = get_headers(email, api_key)
    response = requests.get(CLOUDFLARE_ZONES_URL, headers=headers)
    response.raise_for_status()
    return response.json()

def fetch_today_traffic_summary(email, api_key, zone_id):
    headers = get_headers(email, api_key)

    now = datetime.utcnow()
    today_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

    datetime_geq = today_midnight.strftime('%Y-%m-%dT%H:%M:%SZ')
    datetime_lt = now.strftime('%Y-%m-%dT%H:%M:%SZ')

    query = f"""
    {{
      viewer {{
        zones(filter: {{zoneTag: "{zone_id}"}}) {{
          httpRequests1hGroups(limit: 100, filter: {{datetime_geq: "{datetime_geq}", datetime_lt: "{datetime_lt}"}}) {{
            sum {{
              pageViews
              requests
              encryptedBytes
              encryptedRequests
              bytes
              cachedBytes
              cachedRequests
            }}
          }}
        }}
      }}
    }}
    """

    response = requests.post(
        CLOUDFLARE_GRAPHQL_URL,
        headers=headers,
        json={'query': query}
    )
    response.raise_for_status()
    data = response.json()

    summary = data["data"]["viewer"]["zones"][0]["httpRequests1hGroups"][0]["sum"]

    return {
        "from": datetime_geq,
        "to": datetime_lt,
        "pageviews": summary.get("pageViews", 0),
        "requests": summary.get("requests", 0),
        "bytes": summary.get("bytes", 0),
        "cached_bytes": summary.get("cachedBytes", 0),
        "cached_requests": summary.get("cachedRequests", 0),
        "encrypted_bytes": summary.get("encryptedBytes", 0),
        "encrypted_requests": summary.get("encryptedRequests", 0),
    }



def get_skip_ips(zone_id, datetime_geq, datetime_lt, headers):
    query = f"""
    {{
      viewer {{
        zones(filter: {{zoneTag: "{zone_id}"}}) {{
          firewallEventsAdaptive(
            limit: 1000,
            filter: {{
              datetime_geq: "{datetime_geq}",
              datetime_lt: "{datetime_lt}"
            }}
          ) {{
            clientIP
            action
            clientCountryName
            datetime
            userAgent
          }}
        }}
      }}
    }}
    """

    response = requests.post(
        'https://api.cloudflare.com/client/v4/graphql',
        headers=headers,
        json={'query': query}
    )

    if response.status_code != 200:
        print(f"Failed to fetch data: {response.status_code} - {response.text}")
        return []

    try:
        result = response.json()
        events = result.get("data", {}).get("viewer", {}).get("zones", [])[0].get("firewallEventsAdaptive", [])
        skip_ips = {event["clientIP"] for event in events if event.get("action") == "skip"}
        return list(skip_ips)
    except Exception as e:
        print(f"Error parsing result: {e}")
        return []




def fetch_rules_lists(account_id, headers):
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return {item["name"]: item["id"] for item in data.get("result", [])}
    else:
        return {}



def get_current_list_ips(account_id, list_id, headers):
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists/{list_id}/items"
    response = requests.get(url, headers=headers)

    current_ips = set()
    if response.status_code == 200:
        data = response.json()
        for item in data.get("result", []):
            ip = item.get("ip")
            if ip:
                current_ips.add(ip)
    else:
        print(f"❌ API Error while fetching list items: {response.status_code}\n{response.text}")

    return current_ips


def check_abuse_ip(ip: str, api_key: str):
  url = "https://api.abuseipdb.com/api/v2/check"
  querystring = {
      'ipAddress': ip,
      'maxAgeInDays': '90'
  }
  headers = {
      'Key': api_key,
      'Accept': 'application/json'
  }

  response = requests.get(url, headers=headers, params=querystring)
  if response.status_code == 200:
      data = response.json()
      return {
          "ip": ip,
          "abuse_confidence_score": data['data']['abuseConfidenceScore'],
          "countryCode": data['data'].get('countryCode', 'Unknown'),
          "usageType": data['data'].get('usageType', 'Unknown'),
          "domain": data['data'].get('domain', 'Unknown'),
          "totalReports": data['data'].get('totalReports', 0),
          "lastReportedAt": data['data'].get('lastReportedAt', 'Never')
      }
  else:
      return {"ip": ip, "error": response.text}



def add_ips_to_list(account_id, list_id, new_ips, headers):
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists/{list_id}/items"
    payload = [{"ip": ip} for ip in new_ips]

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        _LOGGER.info("✅ Successfully added new IPs to the list.")
        _LOGGER.debug(response.json())
    else:
        _LOGGER.error("❌ Failed to add IPs: %s\n%s", response.status_code, response.text)



def set_under_attack_mode(zone_id, headers, enable=True):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level"
    mode = "under_attack" if enable else "high"

    payload = {"value": mode}
    response = requests.patch(url, headers=headers, json=payload)

    if response.status_code == 200:
        _LOGGER.info("✅ Set Cloudflare 'Under Attack' mode to: %s", mode)
        return mode
    else:
        _LOGGER.error("❌ Failed to update security level: %s - %s", response.status_code, response.text)
        return "error"


def get_cloudflare_security_level(zone_id, headers):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("result", {}).get("value", "")
    else:
        _LOGGER.error(f"Failed to fetch Cloudflare security level: {response.status_code}")
        return ""