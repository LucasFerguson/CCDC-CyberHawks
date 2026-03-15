#!/usr/bin/env python3
import gzip, os, re, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

INFO = Path("/var/lib/dpkg/info")

def stat_ts(p):
    try:
        st = p.stat()
        ts = [st.st_mtime, st.st_ctime]
        if b := getattr(st, "st_birthtime", None): ts.append(b)
        return max(ts)
    except: return None

def log_times():
    times = {}
    rx = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?:install|upgrade|configure|trigproc) ([^: \n]+)")
    for p in [Path("/var/log/dpkg.log"), *sorted(Path("/var/log").glob("dpkg.log.*"))]:
        if not p.exists(): continue
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt", errors="replace") as f:
            for line in f:
                m = rx.match(line)
                if not m: continue
                pkg = m.group(2).split(":")[0]
                ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                if pkg not in times or ts < times[pkg]: times[pkg] = ts
    return times

def fmt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown"

pkgs = subprocess.run(["dpkg-query","-W","-f=${Package}\n"], capture_output=True, text=True).stdout.splitlines()
ltimes = log_times()

print(f"{'PACKAGE':<40} {'INSTALL':19} {'MD5SUMS':19} {'MAX_LISTED_FILE':19} FLAG")
print("-"*105)

for pkg in pkgs:
    md5 = INFO / f"{pkg}.md5sums"
    lst = INFO / f"{pkg}.list"

    install_ts = ltimes.get(pkg) or stat_ts(lst)
    md5_ts = stat_ts(md5)

    file_ts = None
    try:
        for line in md5.read_text(errors="replace").splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                t = stat_ts(Path("/") / parts[1])
                if t and (file_ts is None or t > file_ts): file_ts = t
    except: pass

    flag = ""
    if install_ts and md5_ts and md5_ts > install_ts + 60:
        flag = "SUSPICIOUS: md5sums newer than install"

    print(f"{pkg:<40} {fmt(install_ts):19} {fmt(md5_ts):19} {fmt(file_ts):19} {flag}")