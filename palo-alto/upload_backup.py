# upload_backup.py
import sys
import requests

UPLOAD_URL = "https://172.20.242.25:8443/upload"
API_TOKEN = "supersecrettoken"
FILE_PATH = "palo_running_export.xml"

headers = {
    "Authorization": f"Bearer {API_TOKEN}"
}

with open(FILE_PATH, "rb") as f:
    files = {
        "file": (FILE_PATH, f, "application/xml")
    }
    r = requests.post(UPLOAD_URL, headers=headers, files=files, verify=False, timeout=60)

print(r.status_code)
print(r.text)

if not r.ok:
    sys.exit(1)