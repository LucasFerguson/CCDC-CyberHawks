import os
import subprocess
from difflib import unified_diff
import json

def cmd(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode() # .split("\n")
        return output
    except subprocess.CalledProcessError as e:
        return ""

# Read device JSON file
with open('device.json', 'r') as file:
    device = json.load(file)

assert "arch" in device and (device['arch'] == "deb" or device['arch'] == 'rhel'), "device.json file doesn't have the arch attribute specified, or it has an improper value (not deb or rhel)!"

# Get base truth service folder
BASEFOLDER = f"psychocity-{device['arch']}"

# Check for presence of services from base folder
base_services = []
with os.scandir(BASEFOLDER) as files:
    for file in files:
        if file.is_file():
            base_services.append(file.name)

print("Diffing...")
diffs_found = False

# Get present service confs and compare
for service in base_services:
    confpath = cmd(f"systemctl show -P FragmentPath {service}").strip()
    if confpath: # service is present
        base_path = BASEFOLDER + "/" + service
        with open(base_path, 'r') as file:
            basecontent = [line for line in file.read().splitlines() if not line.startswith("#")]
        with open(confpath, 'r') as file:
            realcontent = [line for line in file.read().splitlines() if not line.startswith("#")]

        # Compare
        if basecontent != realcontent: # service files not the same!
            print(f"\nSystem's service {service} configuration file is different than the one stored!")
            print("\n".join(list(unified_diff(basecontent, realcontent, fromfile=base_path, tofile=confpath))))
            diffs_found = True

if not diffs_found:
    print("No service configuration diffs found!")