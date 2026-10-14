"""Combines run_codec_bench.py end-to-end results taken at several --threads values.

usage: threads_summary.py <out summary.md> <label=dir>... where each dir holds one results.json
and its label is the thread count the run used.
"""

import json
import sys
from pathlib import Path

MEBIBYTE = 1 << 20


def main():
    out = Path(sys.argv[1])
    runs = {}
    environment = None
    for item in sys.argv[2:]:
        label, directory = item.split("=", 1)
        data = json.loads((Path(directory) / "results.json").read_text())
        environment = environment or data["environment"]
        runs[label] = {(row["target"], row["preset"]): row for row in data["presets"]}

    labels = list(runs)
    keys = list(runs[labels[0]])
    lines = [
        "# Parallel create, thread scaling",
        "",
        f"- machine: {environment['cpu_model']} ({environment['logical_cpus']} logical CPUs)",
        f"- governor: {environment['governor']}, SMT active: {environment['smt_active']}",
        f"- corpus: {environment['corpus_sha256']}, commit {environment['git_commit']}",
        f"- {environment['e2e_runs']} runs per cell; create seconds are medians",
        "- archive MiB is the exact size from each run; it must not change with the thread count",
        "",
        "| target | preset | input MiB | threads | archive MiB | archive bytes | create s | create MB/s "
        "| speedup | create RSS KiB |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key in keys:
        base = runs[labels[0]][key]["create_seconds"]["median"]
        for label in labels:
            row = runs[label][key]
            seconds = row["create_seconds"]["median"]
            lines.append(
                f"| {key[0]} | {key[1]} | {row['input_bytes'] / MEBIBYTE:.1f} | {label} "
                f"| {row['archive_bytes'] / MEBIBYTE:.2f} | {row['archive_bytes']} "
                f"| {seconds:.3f} | {row['input_bytes'] / 1e6 / seconds:.1f} "
                f"| {base / seconds:.2f}x | {row['create_peak_rss_kb']} |"
            )
    out.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
