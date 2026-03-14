#!/usr/bin/env python3
"""
dpkg_audit.py

For every installed dpkg package, collects ALL timestamps from every relevant
source and compares them to detect anomalies — specifically .md5sums files
(or installed files) whose timestamps post-date the known install event.

Timestamp sources per package
──────────────────────────────
  LOG   – earliest matching entry in /var/log/dpkg.log* (most authoritative)
  MD5   – btime/mtime/ctime of /var/lib/dpkg/info/<pkg>.md5sums
  LIST  – btime/mtime/ctime of /var/lib/dpkg/info/<pkg>.list
  FILES – btime/mtime/ctime of every file path listed inside <pkg>.md5sums
          (per-file detail available with --verbose)

Suspicion logic
───────────────
  A package is flagged SUSPICIOUS when the .md5sums file has a timestamp
  that post-dates the install reference time by more than GRACE_SECONDS.

  Reference time (most trustworthy first):
    1. dpkg log entry  → use that directly
    2. No log entry    → use min(LIST btime/mtime/ctime) as a proxy

  Additional flags:
    CTIME>MTIME  – ctime is newer than mtime on .md5sums (inode changed
                   without content change – possible attribute tampering)
    BTIME>MTIME  – birth time is newer than mtime (clock skew or copy-on-
                   write snapshot artefact, worth noting)
    FILE_NEWER   – an installed file is newer than install ref + grace
                   (possible in-place replacement of a package file)

Output modes
────────────
  Default  : show all packages with a one-line summary + SUSPICIOUS flag
  --suspicious-only : only print flagged packages
  --verbose / -v    : also print per-file detail for flagged packages
  --grace N         : set grace period in seconds (default 60)
  --tsv             : machine-readable TSV instead of aligned table
"""

import gzip
import os
import re
import subprocess
import sys
from argparse import ArgumentParser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DPKG_INFO_DIR = Path("/var/lib/dpkg/info")
DPKG_LOG_PATHS = [
    Path("/var/log/dpkg.log"),
    *sorted(Path("/var/log").glob("dpkg.log.*")),
]
DEFAULT_GRACE = 60  # seconds


# ── data structures ──────────────────────────────────────────────────────────

@dataclass
class FileStat:
    path: Path
    btime: Optional[float]   # birth time (may be None)
    mtime: float
    ctime: float

    @property
    def max_ts(self) -> float:
        candidates = [self.mtime, self.ctime]
        if self.btime is not None:
            candidates.append(self.btime)
        return max(candidates)

    @property
    def min_ts(self) -> float:
        candidates = [self.mtime, self.ctime]
        if self.btime is not None:
            candidates.append(self.btime)
        return min(candidates)


@dataclass
class PackageAudit:
    name: str
    log_ts: Optional[float]            # from dpkg.log
    md5sums: Optional[FileStat]        # stat of .md5sums
    list_file: Optional[FileStat]      # stat of .list
    installed_files: list[FileStat] = field(default_factory=list)

    # computed
    flags: list[str] = field(default_factory=list)
    ref_ts: Optional[float] = None     # install reference timestamp used
    ref_source: str = "unknown"

    def compute(self, grace: float) -> None:
        # ── choose reference time ──────────────────────────────────────────
        if self.log_ts is not None:
            self.ref_ts = self.log_ts
            self.ref_source = "dpkg-log"
        elif self.list_file is not None:
            self.ref_ts = self.list_file.min_ts
            self.ref_source = "list-stat"
        else:
            self.ref_ts = None
            self.ref_source = "unknown"

        if self.ref_ts is None:
            return

        threshold = self.ref_ts + grace

        # ── md5sums anomalies ──────────────────────────────────────────────
        if self.md5sums:
            ms = self.md5sums
            if ms.max_ts > threshold:
                delta = ms.max_ts - self.ref_ts
                self.flags.append(
                    f"MD5SUMS_NEWER_THAN_INSTALL(+{_fmt_delta(delta)})"
                )
            if ms.ctime > ms.mtime + grace:
                self.flags.append(
                    f"MD5SUMS_CTIME>MTIME(+{_fmt_delta(ms.ctime - ms.mtime)})"
                )
            if ms.btime is not None and ms.btime > ms.mtime + grace:
                self.flags.append(
                    f"MD5SUMS_BTIME>MTIME(+{_fmt_delta(ms.btime - ms.mtime)})"
                )

        # ── installed file anomalies ───────────────────────────────────────
        newer_files = [
            f for f in self.installed_files if f.max_ts > threshold
        ]
        if newer_files:
            worst = max(newer_files, key=lambda f: f.max_ts)
            self.flags.append(
                f"FILE_NEWER_THAN_INSTALL({len(newer_files)} files"
                f", worst +{_fmt_delta(worst.max_ts - self.ref_ts)})"
            )

    @property
    def is_suspicious(self) -> bool:
        return bool(self.flags)

    @property
    def install_ts(self) -> Optional[float]:
        return self.ref_ts

    @property
    def md5sums_max_ts(self) -> Optional[float]:
        return self.md5sums.max_ts if self.md5sums else None


# ── helpers ──────────────────────────────────────────────────────────────────

def _fmt_delta(seconds: float) -> str:
    seconds = abs(seconds)
    if seconds < 120:
        return f"{seconds:.0f}s"
    if seconds < 7200:
        return f"{seconds/60:.1f}m"
    if seconds < 86400 * 2:
        return f"{seconds/3600:.1f}h"
    return f"{seconds/86400:.1f}d"


def ts_str(ts: Optional[float]) -> str:
    if ts is None:
        return "─" * 19
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def stat_file(path: Path) -> Optional[FileStat]:
    try:
        st = path.stat()
    except OSError:
        return None
    btime = getattr(st, "st_birthtime", None)
    return FileStat(path=path, btime=btime, mtime=st.st_mtime, ctime=st.st_ctime)


def parse_md5sums(path: Path) -> list[Path]:
    paths: list[Path] = []
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(None, 1)
                if len(parts) == 2:
                    paths.append(Path("/") / parts[1])
    except OSError:
        pass
    return paths


def build_log_times() -> dict[str, float]:
    """earliest install/upgrade timestamp per package from dpkg logs."""
    rx = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
        r" (?:install|upgrade|trigproc|configure)"
        r" ([^: \n]+)"
    )
    times: dict[str, float] = {}
    for log in DPKG_LOG_PATHS:
        if not log.exists():
            continue
        try:
            opener = gzip.open if log.suffix == ".gz" else open
            with opener(log, "rt", errors="replace") as fh:
                for line in fh:
                    m = rx.match(line)
                    if not m:
                        continue
                    pkg = m.group(2).split(":")[0]
                    try:
                        ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S") \
                                     .replace(tzinfo=timezone.utc).timestamp()
                    except ValueError:
                        continue
                    if pkg not in times or ts < times[pkg]:
                        times[pkg] = ts
        except OSError as e:
            print(f"[warn] {log}: {e}", file=sys.stderr)
    return times


def get_packages() -> list[str]:
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\n"],
            capture_output=True, text=True, check=True,
        )
        return [p for p in r.stdout.splitlines() if p]
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[error] dpkg-query: {e}", file=sys.stderr)
        sys.exit(1)


# ── reporting ─────────────────────────────────────────────────────────────────

def print_table(audits: list[PackageAudit], tsv: bool) -> None:
    if tsv:
        cols = ["PACKAGE", "REF_SOURCE", "INSTALL_TS_UTC",
                "MD5SUMS_MAX_TS_UTC", "MD5SUMS_MTIME_UTC",
                "MD5SUMS_CTIME_UTC", "MD5SUMS_BTIME_UTC",
                "SUSPICIOUS", "FLAGS"]
        print("\t".join(cols))
        for a in audits:
            ms = a.md5sums
            row = [
                a.name,
                a.ref_source,
                ts_str(a.install_ts),
                ts_str(a.md5sums_max_ts),
                ts_str(ms.mtime if ms else None),
                ts_str(ms.ctime if ms else None),
                ts_str(ms.btime if ms else None),
                "YES" if a.is_suspicious else "no",
                "; ".join(a.flags),
            ]
            print("\t".join(row))
    else:
        P, I, M = 36, 20, 20
        hdr = (f"{'PACKAGE':<{P}}  {'REF SOURCE':<11}"
               f"  {'INSTALL (UTC)':<{I}}  {'MD5SUMS MAX (UTC)':<{M}}"
               f"  STATUS")
        sep = "─" * len(hdr)
        print(hdr)
        print(sep)
        for a in audits:
            status = ("⚠  SUSPICIOUS  " + ", ".join(a.flags)
                      if a.is_suspicious else "ok")
            print(
                f"{a.name:<{P}}  {a.ref_source:<11}"
                f"  {ts_str(a.install_ts):<{I}}  {ts_str(a.md5sums_max_ts):<{M}}"
                f"  {status}"
            )
        print(sep)


def print_verbose_detail(a: PackageAudit) -> None:
    """Print detailed timestamp breakdown for one flagged package."""
    print(f"\n{'═'*70}")
    print(f"  PACKAGE : {a.name}")
    print(f"  FLAGS   : {', '.join(a.flags) if a.flags else 'none'}")
    print(f"  INSTALL REF ({a.ref_source}): {ts_str(a.install_ts)}")

    def _row(label: str, fs: Optional[FileStat]) -> None:
        if fs is None:
            print(f"  {label:<12}: (not found)")
            return
        b = ts_str(fs.btime) if fs.btime is not None else "n/a (no btime)"
        print(f"  {label:<12}: mtime={ts_str(fs.mtime)}  "
              f"ctime={ts_str(fs.ctime)}  btime={b}")

    _row(".md5sums", a.md5sums)
    _row(".list", a.list_file)

    if a.installed_files:
        if a.ref_ts is not None:
            newer = [f for f in a.installed_files if f.mtime > a.ref_ts + 60]
        else:
            newer = []
        print(f"  installed files: {len(a.installed_files)} total, "
              f"{len(newer)} with mtime > install_ref+60s")
        for f in sorted(newer, key=lambda x: x.mtime, reverse=True)[:20]:
            print(f"    {ts_str(f.mtime)}  {f.path}")
        if len(newer) > 20:
            print(f"    … and {len(newer)-20} more")
    print(f"{'═'*70}")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = ArgumentParser(description=__doc__)
    ap.add_argument("--suspicious-only", action="store_true",
                    help="Only print packages with anomalies")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Print per-file detail for suspicious packages")
    ap.add_argument("--grace", type=float, default=DEFAULT_GRACE,
                    metavar="N",
                    help=f"Grace period in seconds (default {DEFAULT_GRACE})")
    ap.add_argument("--tsv", action="store_true",
                    help="Machine-readable TSV output")
    args = ap.parse_args()

    eprint = lambda *a, **k: print(*a, file=sys.stderr, **k)

    eprint("Collecting installed packages …")
    packages = get_packages()
    eprint(f"  {len(packages)} packages found.")

    eprint("Parsing dpkg logs …")
    log_times = build_log_times()
    eprint(f"  {len(log_times)} log entries indexed.")

    eprint("Stating files …")
    audits: list[PackageAudit] = []

    for pkg in packages:
        md5_path  = DPKG_INFO_DIR / f"{pkg}.md5sums"
        list_path = DPKG_INFO_DIR / f"{pkg}.list"

        md5_stat  = stat_file(md5_path)
        list_stat = stat_file(list_path)

        inst_files: list[FileStat] = []
        if md5_stat is not None:
            for fp in parse_md5sums(md5_path):
                fs = stat_file(fp)
                if fs:
                    inst_files.append(fs)

        audit = PackageAudit(
            name=pkg,
            log_ts=log_times.get(pkg),
            md5sums=md5_stat,
            list_file=list_stat,
            installed_files=inst_files,
        )
        audit.compute(grace=args.grace)
        audits.append(audit)

    # sort: suspicious first, then by install time
    audits.sort(key=lambda a: (
        not a.is_suspicious,
        a.install_ts is None,
        a.install_ts or 0,
    ))

    suspicious = [a for a in audits if a.is_suspicious]
    eprint(f"  Done. {len(suspicious)}/{len(audits)} packages flagged suspicious.")

    if not args.tsv:
        print(f"\n{'━'*70}")
        print(f"  dpkg package audit  |  grace period: {args.grace}s"
              f"  |  {len(suspicious)} suspicious / {len(audits)} total")
        print(f"{'━'*70}\n")

    display = suspicious if args.suspicious_only else audits
    print_table(display, tsv=args.tsv)

    if args.verbose and not args.tsv:
        if suspicious:
            print(f"\n{'━'*70}")
            print(f"  DETAIL FOR SUSPICIOUS PACKAGES ({len(suspicious)})")
            for a in suspicious:
                print_verbose_detail(a)
        else:
            print("\n  No suspicious packages found.")

    if not args.tsv:
        if not suspicious:
            print("\n  ✓ No anomalies detected.")
        else:
            print(f"\n  ⚠  {len(suspicious)} package(s) flagged. "
                  "Re-run with --verbose for per-file detail.")
            print("  Flags explained:")
            print("    MD5SUMS_NEWER_THAN_INSTALL – .md5sums timestamp post-dates install ref")
            print("    MD5SUMS_CTIME>MTIME        – inode metadata changed after content write")
            print("                                 (ownership/perms/xattr tweak?)")
            print("    MD5SUMS_BTIME>MTIME        – file was born after its mtime")
            print("                                 (copied with preserved mtime, or CoW snap)")
            print("    FILE_NEWER_THAN_INSTALL    – an installed file post-dates the package")
            print("                                 (possible in-place replacement)")


if __name__ == "__main__":
    main()