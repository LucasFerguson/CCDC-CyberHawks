import subprocess
import os

def cmd(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode() # .split("\n")
        return output
    except subprocess.CalledProcessError as e:
        return ""

HASHDIR = "/var/lib/dpkg/info"

hashfiles = cmd(f'ls {HASHDIR} | grep "\.md5sums$"').splitlines()

for hashfile in hashfiles:
    path = f'{HASHDIR}/{hashfile}'
    hashstats = os.stat(path)
    hashstat = max(hashstats.st_mtime, hashstats.st_ctime)
    with open(path, 'r') as file:
        hashedfiles = [" ".join(line.strip().split(" ")[2:]) for line in file.read().splitlines()]
    for hashedfile in hashedfiles:
        filepath = f"/{hashedfile}"
        if os.path.exists(filepath):
            stats = os.stat(filepath)
            stat = max(stats.st_mtime, stats.st_ctime)
            if hashstat - 10 > stat:
                print(hashstat-stat)

# cat network-manager.md5sums | cut -d' ' -f3- | while read -r line; do sudo stat -c "%W %Y %Z %n" "/$line"; done