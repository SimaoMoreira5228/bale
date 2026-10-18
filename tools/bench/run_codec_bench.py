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

MEBIBYTE = 1 << 20
DEFAULT_CODECS = ["raw", "lz4:0", "lz4:9", "zstd:1", "zstd:3", "zstd:9", "zstd:19", "deflate:1", "deflate:6", "deflate:9"]
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
        "e2e_runs": arguments.e2e_runs,
        "create_args": arguments.create_args,
        "work_dir": str(arguments.work_dir),
    }


def pinned(command, cpu):
    if cpu is None:
        return command
    if shutil.which("taskset") is None:
        sys.exit("--cpu needs taskset (Linux)")
    return ["taskset", "-c", str(cpu), *command]


def time_command():
    if not Path("/usr/bin/time").exists():
        return None
    if sys.platform == "darwin":
        return ["/usr/bin/time", "-l"]
    if sys.platform.startswith("linux"):
        return ["/usr/bin/time", "-f", "bale-peak-rss-kb %M"]
    return None


def peak_from_time(stderr):
    for line in stderr.splitlines():
        words = line.split()
        if line.startswith("bale-peak-rss-kb ") and len(words) == 2:
            return int(words[1])
        if line.endswith("maximum resident set size") and words:
            return int(words[0]) // 1024
    return None


# NOTE: a child forked from Python reports Python's memory in ru_maxrss until it execs, so peak
# memory comes from /usr/bin/time, which forks the measured program from a small process.
def run_measured(command, track_memory=True):
    wrapper = time_command() if track_memory else None
    start = time.perf_counter()
    result = subprocess.run([*(wrapper or []), *command], capture_output=True)
    elapsed = time.perf_counter() - start

    stderr = result.stderr.decode(errors="replace")
    if result.returncode != 0:
        sys.exit(f"{' '.join(map(str, command))} failed:\n{stderr}")
    peak = peak_from_time(stderr) if wrapper else None
    return result.stdout.decode(), elapsed, peak


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
        stdout, _, _ = run_measured(pinned(command, arguments.cpu), track_memory=False)
        records = [json.loads(line) for line in stdout.splitlines()]
        peak = next((record["peak_rss_kb"] for record in records if "peak_rss_kb" in record), None)
        for record in records:
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


def directory_bytes(path):
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file() and not item.is_symlink())


def end_to_end_targets(corpus):
    groups = sorted(
        (item for item in corpus.iterdir() if item.is_dir() and not item.is_symlink()),
        key=lambda item: (directory_bytes(item), item.name),
    )
    targets = [(group.name, group) for group in groups]
    if len(groups) > 1:
        targets.append(("all", corpus))
    return targets


def profile_arguments(profile):
    if profile in PRESETS:
        return ["--preset", profile]
    codec, _, level = profile.partition(":")
    return ["--codec", codec, *(["--level", level] if level else [])]


def parse_profile(text):
    if text in PRESETS or text == "raw":
        return text
    codec, _, level = text.partition(":")
    if codec in ("zstd", "lz4") and level.lstrip("-").isdigit():
        return text
    raise argparse.ArgumentTypeError(f"{text} is neither a preset nor a codec:level spec")


def end_to_end_run(arguments, work, preset, source, run):
    name = preset.replace(":", "-")
    archive = work / f"{name}-{run}.bale"
    output = work / f"{name}-{run}.out"
    create = [str(arguments.bale), "create", str(archive), str(source), *profile_arguments(preset)]
    create += arguments.create_args
    _, create_seconds, create_peak = run_measured(pinned(create, arguments.cpu))
    archive_bytes = archive.stat().st_size

    extract = [str(arguments.bale), "extract", str(archive), "-o", str(output)]
    _, extract_seconds, extract_peak = run_measured(pinned(extract, arguments.cpu))

    archive.unlink()
    shutil.rmtree(output)
    return archive_bytes, create_seconds, create_peak, extract_seconds, extract_peak


def end_to_end_results(arguments):
    rows = []
    arguments.work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bale-bench-", dir=arguments.work_dir) as directory:
        work = Path(directory)
        for target, source in end_to_end_targets(arguments.corpus):
            input_bytes = directory_bytes(source)
            for preset in arguments.presets or PRESETS:
                create_times = []
                extract_times = []
                create_peak = 0
                extract_peak = 0
                archive_bytes = 0
                for run in range(arguments.e2e_runs):
                    measured = end_to_end_run(arguments, work, preset, source, run)
                    archive_bytes = measured[0]
                    create_times.append(measured[1])
                    create_peak = max(create_peak, measured[2] or 0)
                    extract_times.append(measured[3])
                    extract_peak = max(extract_peak, measured[4] or 0)

                rows.append(
                    {
                        "target": target,
                        "preset": preset,
                        "input_bytes": input_bytes,
                        "archive_bytes": archive_bytes,
                        "create_seconds": spread(create_times),
                        "extract_seconds": spread(extract_times),
                        "create_peak_rss_kb": create_peak or None,
                        "extract_peak_rss_kb": extract_peak or None,
                    }
                )
                print(f"{target} {preset} done", file=sys.stderr)
    return rows


def summary(env, codecs, presets):
    lines = [
        "# BALE codec benchmark",
        "",
        f"- date: {env['date_utc']}",
        f"- machine: {env['cpu_model']} ({env['logical_cpus']} logical CPUs, {env['platform']})",
        f"- governor: {env['governor']}, SMT active: {env['smt_active']}, pinned CPU: {env['pinned_cpu']}",
        f"- load average at start: {env['load_average']}",
        f"- bale create arguments: {' '.join(env.get('create_args') or []) or '(none)'}",
        f"- corpus: {env['corpus_sha256']}",
        f"- commit: {env['git_commit']}, chunk size {env['chunk_size']}, {env['runs']} runs",
        "",
        "Codec rows compare identical fixed chunks with deduplication disabled. Stored bytes include",
        "BALE record overhead and per-chunk raw fallback.",
        "",
    ]
    group_bytes = {row["group"]: row["input_bytes"] for row in codecs}
    for group in sorted(group_bytes, key=lambda name: (group_bytes[name], name)):
        lines += [
            f"## {group}",
            "",
            "| codec | stored MiB | ratio | raw fallback | encode MB/s median [min-max] "
            "| decode MB/s median [min-max] | peak RSS KiB |",
            "|---|---:|---:|---:|---|---|---:|",
        ]
        for row in (row for row in codecs if row["group"] == group):
            encode = row["encode_mb_s"]
            decode = row["decode_mb_s"]
            ratio = row["stored_bytes"] / row["input_bytes"] if row["input_bytes"] else 0
            lines.append(
                f"| {row['codec']} | {row['stored_bytes'] / MEBIBYTE:.1f} | {ratio:.4f} "
                f"| {row['raw_fallback_chunks']}/{row['chunks']} "
                f"| {encode['median']:.1f} [{encode['min']:.1f}-{encode['max']:.1f}] "
                f"| {decode['median']:.1f} [{decode['min']:.1f}-{decode['max']:.1f}] "
                f"| {row['peak_rss_kb']} |"
            )
        lines.append("")

    if presets:
        lines += [
            "## End to end, deduplication enabled",
            "",
            "Throughput is input bytes over the median time, which includes reading the input and",
            "writing the output.",
            "",
            "| target | input MiB | preset | archive MiB | ratio | create MB/s "
            "| create s median [min-max] | extract MB/s | extract s median [min-max] "
            "| create RSS KiB | extract RSS KiB |",
            "|---|---:|---|---:|---:|---:|---|---:|---|---:|---:|",
        ]
        for row in presets:
            create = row["create_seconds"]
            extract = row["extract_seconds"]
            megabytes = row["input_bytes"] / 1e6
            ratio = row["archive_bytes"] / row["input_bytes"] if row["input_bytes"] else 0
            lines.append(
                f"| {row['target']} | {row['input_bytes'] / MEBIBYTE:.1f} | {row['preset']} "
                f"| {row['archive_bytes'] / MEBIBYTE:.1f} | {ratio:.4f} "
                f"| {megabytes / create['median']:.1f} "
                f"| {create['median']:.3f} [{create['min']:.3f}-{create['max']:.3f}] "
                f"| {megabytes / extract['median']:.1f} "
                f"| {extract['median']:.3f} [{extract['min']:.3f}-{extract['max']:.3f}] "
                f"| {row['create_peak_rss_kb']} | {row['extract_peak_rss_kb']} |"
            )
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--summarize",
        type=Path,
        metavar="RESULTS_JSON",
        help="rewrite summary.md next to an existing results.json and exit",
    )
    parser.add_argument("--bench", type=Path, help="path to bale_bench_codecs")
    parser.add_argument("--bale", type=Path, help="path to bale; enables the end-to-end runs")
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--chunk-size", type=int, default=1 << 20)
    parser.add_argument("--cpu", help="pin every run to this CPU or CPU list (taskset -c syntax)")
    parser.add_argument("--codec", action="append", help="codec spec, repeatable (default: a standard set)")
    parser.add_argument(
        "--preset",
        dest="presets",
        action="append",
        type=parse_profile,
        help="preset or codec:level (raw, zstd:L, lz4:L) for end-to-end runs, repeatable (default: all presets)",
    )
    parser.add_argument(
        "--create-arg",
        dest="create_args",
        action="append",
        default=[],
        help="extra argument for bale create, repeatable (for example --create-arg=--threads --create-arg=4)",
    )
    parser.add_argument("--e2e-runs", type=int, default=3, help="repetitions of each end-to-end run")
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="where end-to-end archives and extractions go (default: next to --out); avoid tmpfs for large inputs",
    )
    arguments = parser.parse_args()

    if arguments.summarize:
        saved = json.loads(arguments.summarize.read_text())
        text = summary(saved["environment"], saved["codecs"], saved["presets"])
        (arguments.summarize.parent / "summary.md").write_text(text)
        return

    for name in ("bench", "corpus", "out"):
        if getattr(arguments, name) is None:
            parser.error(f"--{name} is required")

    if arguments.work_dir is None:
        arguments.work_dir = arguments.out.parent / "bench-work"

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
