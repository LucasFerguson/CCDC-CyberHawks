import hashlib
import json
import os
from pathlib import Path

def hashfile(filepath):
    with open(filepath, 'rb') as file:
        cntnt = file.read()
    return hashlib.sha256(cntnt).hexdigest()

with open('device.json', 'r') as file:
    device = json.load(file)

assert "preserve_files" in device and "hashfile" in device, "Needed attributes not present in device.json!"

HASHFILE = device['hashfile']
FILES = device['preserve_files']
HASHES = []

print("Hashing files...")
for file in FILES:
    # fullpath = os.path.abspath(file)
    filepath = Path(file)
    if filepath.is_file():
        HASHES.append(file + " " + hashfile(file))
    elif filepath.is_dir():
        for curr_dir, _, curr_dir_files in os.walk(filepath):
            dirpath = Path(curr_dir)
            for f in curr_dir_files:
                fpath = dirpath / f
                if fpath.is_file(): # make sure the file exists and isn't a broken symlink
                    HASHES.append(str(fpath) + " " + hashfile(fpath))

with open(HASHFILE, 'w') as file:
    file.write("\n".join(HASHES))

print("Hashing completed! Saved to", HASHFILE)