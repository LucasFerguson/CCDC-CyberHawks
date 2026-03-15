#!/usr/bin/env python3
"""
pa_get_active_config_xml.py

Retrieves the active Palo Alto configuration using:
type=config&action=show

Saves the XML response locally.
"""

import sys
import requests
import urllib3
from xml.etree import ElementTree as ET

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Firewall connection details
FIREWALL_IP = "172.20.242.150"
USERNAME = "admin"
PASSWORD = "Changeme123"

# Output file
OUTPUT_FILE = "palo_active_config_response.xml"


def get_api_key(firewall_ip: str, username: str, password: str) -> str:
    url = f"https://{firewall_ip}/api/"
    data = {
        "type": "keygen",
        "user": username,
        "password": password,
    }

    response = requests.post(url, data=data, verify=False, timeout=30)
    response.raise_for_status()

    root = ET.fromstring(response.text)
    if root.attrib.get("status") != "success":
        raise RuntimeError(f"Keygen failed:\n{response.text}")

    key_elem = root.find(".//key")
    if key_elem is None or not key_elem.text:
        raise RuntimeError(f"API key not found in response:\n{response.text}")

    return key_elem.text.strip()


def get_active_config(firewall_ip: str, api_key: str) -> str:
    url = f"https://{firewall_ip}/api/"
    params = {
        "type": "config",
        "action": "show",
    }
    headers = {
        "X-PAN-KEY": api_key,
    }

    response = requests.get(url, params=params, headers=headers, verify=False, timeout=60)
    response.raise_for_status()

    # Validate that it looks like a successful PAN-OS XML API response
    root = ET.fromstring(response.text)
    if root.attrib.get("status") != "success":
        raise RuntimeError(f"Config retrieval failed:\n{response.text}")

    return response.text


def main():
    try:
        print(f"[+] Getting API key from {FIREWALL_IP}...")
        api_key = get_api_key(FIREWALL_IP, USERNAME, PASSWORD)

        print("[+] Retrieving active configuration...")
        xml_text = get_active_config(FIREWALL_IP, api_key)

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(xml_text)

        print(f"[+] Done. Saved to: {OUTPUT_FILE}")
    except requests.RequestException as e:
        print(f"[!] HTTP error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()