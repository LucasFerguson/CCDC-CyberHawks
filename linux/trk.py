from pathlib import Path
import bisect

with open('trk', 'r') as file:
    dpkg_files = file.read().split("\n")

with open('elfs', 'r') as file:
    elfs = file.read().split("\n")
    elfs.sort()

fixed = []

for i in range(len(dpkg_files)):
    d = dpkg_files[i]
    path = Path(d)
    if path.exists():
        fixed.append(str(path.resolve(strict=False)))

fixed.sort()

not_tracked = []

for elf in elfs:
    if (bidx:=bisect.bisect_left(fixed, elf)) == -1 or bidx >= len(fixed) or fixed[bidx] != elf:
        not_tracked.append(elf)

with open('non_trk', 'w') as file:
    file.write("\n".join(not_tracked))