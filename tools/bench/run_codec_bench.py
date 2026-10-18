"""Runs the codec and end-to-end benchmarks and records the environment (whitepaper 5.4.2).

Each codec runs in its own process so peak memory is reported per codec. Results go to
<out>/results.json and a readable <out>/summary.md.
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_CODECS = ["raw", "zstd:1", "zstd:3", "zstd:9", "zstd:19", "deflate:1", "deflate:6", "deflate:9"]
PRESETS = ["fast", "balanced", "small", "restore-fast", "portable"]


def read_first_line(path):
    try:
        return Path(path).read_text().splitlines()[0].strip()
    except (OSError, IndexError):
        return None


def cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    if sys.platform == "darwin":
        result = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True)
        return result.stdout.strip() or None
    return platform.processor() or None


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def git_commit(directory):
    result = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"], capture_output=True, text=True)
    return result.stdout.strip() or None


def environment(arguments, corpus_manifest):
    return {
        "date_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_model": cpu_model(),
        "logical_cpus": os.cpu_count(),
        "governor": read_first_line("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "smt_active": read_first_line("/sys/devices/system/cpu/smt/active"),
        "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
        "pinned_cpu": arguments.cpu,
        "python": sys.version.split()[0],
        "bench_sha256": sha256_of(arguments.bench),
        "bale_sha256": sha256_of(arguments.bale) if arguments.bale else None,
        "git_commit": git_commit(Path(__file__).resolve().parent),
        "corpus_sha256": corpus_manifest.get("sha256"),
        "corpus_version": corpus_manifest.get("version"),
        "chunk_size": arguments.chunk_size,
        "runs": arguments.runs,
    }


def pinned(command, cpu):
    if cpu is None:
        return command
    if shutil.which("taskset") is None:
        sys.exit("--cpu needs taskset (Linux)")
    return ["taskset", "-c", str(cpu), *command]


def run_measured(command):
    start = time.perf_counter()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if hasattr(os, "wait4"):
        stdout = process.stdout.read()
        stderr = process.stderr.read()
        _, status, usage = os.wait4(process.pid, 0)
        elapsed = time.perf_counter() - start
        process.returncode = os.waitstatus_to_exitcode(status)
        peak = usage.ru_maxrss // 1024 if sys.platform == "darwin" else usage.ru_maxrss
    else:
        stdout, stderr = process.communicate()
        elapsed = time.perf_counter() - start
        peak = None
    if process.returncode != 0:
        sys.exit(f"{' '.join(map(str, command))} failed:\n{stderr.decode(errors='replace')}")
    return stdout.decode(), elapsed, peak


def codec_results(arguments):
    rows = []
    for codec in arguments.codec or DEFAULT_CODECS:
        command = [
            str(arguments.bench),
            str(arguments.corpus),
            "--chunk-size",
            str(arguments.chunk_size),
            "--runs",
            str(arguments.runs),
            "--codec",
            codec,
        ]
        stdout, _, peak = run_measured(pinned(command, arguments.cpu))
        for line in stdout.splitlines():
            record = json.loads(line)
            if "group" in record:
                record["peak_rss_kb"] = peak
                rows.append(record)
        print(f"codec {codec} done", file=sys.stderr)
    return rows


def spread(samples):
    return {
        "median": statistics.median(samples),
        "min": min(samples),
        "max": max(samples),
    }


def end_to_end_results(arguments):
    rows = []
    input_bytes = sum(item.stat().st_size for item in arguments.corpus.rglob("*") if item.is_file())
    with tempfile.TemporaryDirectory(prefix="bale-bench-") as directory:
        work = Path(directory)
        for preset in PRESETS:
            create_times = []
            extract_times = []
            create_peak = 0
            extract_peak = 0
            archive_bytes = 0
            for run in range(arguments.runs):
                archive = work / f"{preset}-{run}.bale"
                output = work / f"{preset}-{run}.out"
                create = [str(arguments.bale), "create", str(archive), str(arguments.corpus), "--preset", preset]
                _, seconds, peak = run_measured(pinned(create, arguments.cpu))
                create_times.append(seconds)
                create_peak = max(create_peak, peak or 0)
                archive_bytes = archive.stat().st_size

                extract = [str(arguments.bale), "extract", str(archive), "-o", str(output)]
                _, seconds, peak = run_measured(pinned(extract, arguments.cpu))
                extract_times.append(seconds)
                extract_peak = max(extract_peak, peak or 0)

                archive.unlink()
                shutil.rmtree(output)

            rows.append(
                {
                    "preset": preset,
                    "input_bytes": input_bytes,
                    "archive_bytes": archive_bytes,
                    "create_seconds": spread(create_times),
                    "extract_seconds": spread(extract_times),
                    "create_peak_rss_kb": create_peak or None,
                    "extract_peak_rss_kb": extract_peak or None,
                }
            )
            print(f"preset {preset} done", file=sys.stderr)
    return rows


def summary(env, codecs, presets):
    lines = [
        "# BALE codec benchmark",
        "",
        f"- date: {env['date_utc']}",
        f"- machine: {env['cpu_model']} ({env['logical_cpus']} logical CPUs, {env['platform']})",
        f"- governor: {env['governor']}, SMT active: {env['smt_active']}, pinned CPU: {env['pinned_cpu']}",
        f"- load average at start: {env['load_average']}",
        f"- corpus: {env['corpus_sha256']}",
        f"- commit: {env['git_commit']}, chunk size {env['chunk_size']}, {env['runs']} runs",
        "",
        "Codec rows compare identical fixed chunks with deduplication disabled. Stored bytes include",
        "BALE record overhead and per-chunk raw fallback.",
        "",
    ]
    for group in sorted({row["group"] for row in codecs}):
        lines += [
            f"## {group}",
            "",
            "| codec | ratio | raw fallback | encode MB/s median [min-max] | decode MB/s median [min-max] | peak RSS KiB |",
            "|---|---:|---:|---|---|---:|",
        ]
        for row in (row for row in codecs if row["group"] == group):
            encode = row["encode_mb_s"]
            decode = row["decode_mb_s"]
            ratio = row["stored_bytes"] / row["input_bytes"] if row["input_bytes"] else 0
            lines.append(
                f"| {row['codec']} | {ratio:.4f} | {row['raw_fallback_chunks']}/{row['chunks']} "
                f"| {encode['median']:.1f} [{encode['min']:.1f}-{encode['max']:.1f}] "
                f"| {decode['median']:.1f} [{decode['min']:.1f}-{decode['max']:.1f}] "
                f"| {row['peak_rss_kb']} |"
            )
        lines.append("")

    if presets:
        lines += [
            "## End to end, deduplication enabled",
            "",
            "| preset | ratio | create s median [min-max] | extract s median [min-max] | create RSS KiB |",
            "|---|---:|---|---|---:|",
        ]
        for row in presets:
            create = row["create_seconds"]
            extract = row["extract_seconds"]
            ratio = row["archive_bytes"] / row["input_bytes"] if row["input_bytes"] else 0
            lines.append(
                f"| {row['preset']} | {ratio:.4f} "
                f"| {create['median']:.3f} [{create['min']:.3f}-{create['max']:.3f}] "
                f"| {extract['median']:.3f} [{extract['min']:.3f}-{extract['max']:.3f}] "
                f"| {row['create_peak_rss_kb']} |"
            )
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bench", type=Path, required=True, help="path to bale_bench_codecs")
    parser.add_argument("--bale", type=Path, help="path to bale; enables the end-to-end runs")
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--chunk-size", type=int, default=1 << 20)
    parser.add_argument("--cpu", type=int, help="pin every run to this CPU with taskset")
    parser.add_argument("--codec", action="append", help="codec spec, repeatable (default: a standard set)")
    arguments = parser.parse_args()

    corpus_file = arguments.corpus / "corpus.json"
    corpus_manifest = json.loads(corpus_file.read_text()) if corpus_file.exists() else {}
    if not corpus_manifest:
        print("warning: no corpus.json; results will not name a corpus hash", file=sys.stderr)

    env = environment(arguments, corpus_manifest)
    codecs = codec_results(arguments)
    presets = end_to_end_results(arguments) if arguments.bale else []

    arguments.out.mkdir(parents=True, exist_ok=True)
    results = {"environment": env, "codecs": codecs, "presets": presets}
    (arguments.out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    (arguments.out / "summary.md").write_text(summary(env, codecs, presets))
    print(arguments.out / "summary.md")


if __name__ == "__main__":
    main()
