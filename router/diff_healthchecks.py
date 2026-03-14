#!/usr/bin/env python3
from __future__ import annotations

import difflib
import filecmp
from pathlib import Path
from typing import List

BASE_DIR = Path("./healthcheck")
REPORT_NAME = "diff-report.txt"
MAX_DIFF_LINES = 40


def read_text_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except Exception as exc:
        return [f"[ERROR READING FILE: {exc}]\n"]


def get_snapshot_dirs(base_dir: Path) -> List[Path]:
    if not base_dir.exists():
        return []
    dirs = [p for p in base_dir.iterdir() if p.is_dir() and p.name != "latest"]
    return sorted(dirs, key=lambda p: p.name)


def compare_two_snapshots(old: Path, new: Path) -> str:
    output: List[str] = []
    output.append("=" * 80)
    output.append(f"Comparing {old.name}  ->  {new.name}")
    output.append("=" * 80)

    old_files = {p.name: p for p in old.iterdir() if p.is_file()}
    new_files = {p.name: p for p in new.iterdir() if p.is_file()}

    all_names = sorted(set(old_files) | set(new_files))

    added = [name for name in all_names if name not in old_files]
    removed = [name for name in all_names if name not in new_files]
    common = [name for name in all_names if name in old_files and name in new_files]

    changed: List[str] = []
    unchanged: List[str] = []

    for name in common:
        same = filecmp.cmp(old_files[name], new_files[name], shallow=False)
        if same:
            unchanged.append(name)
        else:
            changed.append(name)

    output.append("")
    output.append("Summary:")
    output.append(f"  Added files: {len(added)}")
    output.append(f"  Removed files: {len(removed)}")
    output.append(f"  Changed files: {len(changed)}")
    output.append(f"  Unchanged files: {len(unchanged)}")

    if added:
        output.append("")
        output.append("Added:")
        output.extend([f"  + {name}" for name in added])

    if removed:
        output.append("")
        output.append("Removed:")
        output.extend([f"  - {name}" for name in removed])

    if changed:
        output.append("")
        output.append("Changed:")
        output.extend([f"  * {name}" for name in changed])

        for name in changed:
            output.append("")
            output.append("-" * 80)
            output.append(f"Diff preview for {name}")
            output.append("-" * 80)

            old_lines = read_text_lines(old_files[name])
            new_lines = read_text_lines(new_files[name])

            diff_lines = list(
                difflib.unified_diff(
                    old_lines,
                    new_lines,
                    fromfile=f"{old.name}/{name}",
                    tofile=f"{new.name}/{name}",
                    lineterm=""
                )
            )

            if not diff_lines:
                output.append("  [Binary or no textual diff preview available]")
                continue

            preview = diff_lines[:MAX_DIFF_LINES]
            output.extend(preview)

            if len(diff_lines) > MAX_DIFF_LINES:
                output.append(f"\n  ... diff truncated, showing first {MAX_DIFF_LINES} lines ...")

    output.append("")
    return "\n".join(output)


def main() -> None:
    snapshots = get_snapshot_dirs(BASE_DIR)

    if len(snapshots) < 2:
        print("Need at least two health check snapshots in ./healthcheck")
        return

    full_report: List[str] = []
    print(f"Found {len(snapshots)} snapshots.\n")

    for i in range(len(snapshots) - 1):
        old = snapshots[i]
        new = snapshots[i + 1]
        section = compare_two_snapshots(old, new)
        print(section)
        print()
        full_report.append(section)

    report_path = BASE_DIR / REPORT_NAME
    report_path.write_text("\n\n".join(full_report), encoding="utf-8")
    print(f"Wrote full diff report to: {report_path}")


if __name__ == "__main__":
    main()