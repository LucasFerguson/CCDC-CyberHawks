#!/usr/bin/env python3
"""
pa_export_config_file.py

Exports a Palo Alto firewall configuration file via the PAN-OS XML API
and saves it locally as XML.

Tested against PAN-OS XML API patterns documented for 11.0.
"""

import os
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
OUTPUT_FILE = "palo_running_export.xml"


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


def export_configuration_file(firewall_ip: str, api_key: str, output_file: str) -> None:
    url = f"https://{firewall_ip}/api/"
    params = {
        "type": "export",
        "category": "configuration",
    }
    headers = {
        "X-PAN-KEY": api_key,
    }

    response = requests.get(url, params=params, headers=headers, verify=False, timeout=60)
    response.raise_for_status()

    # If the firewall returns XML error instead of file data, catch that
    content_type = response.headers.get("Content-Type", "").lower()
    if "xml" in content_type or response.text.lstrip().startswith("<response"):
        try:
            root = ET.fromstring(response.text)
            if root.tag == "response" and root.attrib.get("status") != "success":
                raise RuntimeError(f"Export failed:\n{response.text}")
        except ET.ParseError:
            pass

    with open(output_file, "wb") as f:
        f.write(response.content)


def main():
    try:
        print(f"[+] Getting API key from {FIREWALL_IP}...")
        api_key = get_api_key(FIREWALL_IP, USERNAME, PASSWORD)

        print("[+] Exporting configuration file...")
        export_configuration_file(FIREWALL_IP, api_key, OUTPUT_FILE)

        print(f"[+] Done. Saved to: {OUTPUT_FILE}")
    except requests.RequestException as e:
        print(f"[!] HTTP error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()