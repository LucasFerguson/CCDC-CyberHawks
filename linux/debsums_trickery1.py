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


# Get Package Install Date

# Get .md5sums date

# Get .postinst access date

# Get file itself date


# for hashfile in hashfiles:
#     path = f'{HASHDIR}/{hashfile}'
#     hashstats = os.stat(path)
#     hashstat = max(hashstats.st_mtime, hashstats.st_ctime)
#     list_stats = os.stat(path[:-1*len(".md5sums")] + ".list")
#     list_stat = max(list_stats.st_ctime, list_stats.st_mtime)
#     if hashstat > list_stat:
#         print("shoot", str(hashstat - list_stat))
    # # maxstat = 0
    # with open(path, 'r') as file:
    #     hashedfiles = [" ".join(line.strip().split(" ")[2:]) for line in file.read().splitlines()]
    # for hashedfile in hashedfiles:
    #     filepath = f"/{hashedfile}"
    #     if os.path.exists(filepath):
    #         stats = os.stat(filepath)
    #         # stat = max(stats.st_mtime, stats.st_ctime)
    #         stat = stats.st_atime
    #         # if stat > maxstat:
    #         #     maxstat = stat
    # if maxstat != 0 and hashstat - 4 > maxstat:
    #     print(hashstat-maxstat)
# cat network-manager.md5sums | cut -d' ' -f3- | while read -r line; do sudo stat -c "%W %Y %Z %n" "/$line"; done