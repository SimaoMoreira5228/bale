# brotli vs zstd at high levels: a real size win, still not worth it for `small`

- machine: Intel Xeon E5-2690 v3, performance governor; run-a-threads is the default
  8-worker build, run-b-pinned1 is pinned to CPU 3 with `--threads 1`
- corpus 58ea0cf48e6e3d15a64e441004ac225762999074646425e84ff9c84bc1ef7ec0, built with
  `make_corpus.py --add bale-src=src` (synthetic groups plus this repo's source);
  every synthetic group is byte-identical to the lzma2 round's corpus, only bale-src
  grew (128 to 156 files) with the brotli work itself
- fixed 1 MiB chunks; codec rows use deduplication off, end-to-end rows deduplication on;
  raw `results.json` files sit next to the per-run `summary.md` files

## What the numbers say

Codec rows (identical chunks, dedup off, run A medians):

```text
group         zstd:19 ratio  enc/dec MB/s   brotli:6 ratio  enc/dec MB/s   brotli:11 ratio  enc/dec MB/s
text          0.2570         2.3 / 616      0.2962          22 / 362       0.2559          0.5 / 355
bale-src      0.2413         2.4 / 473      0.2385          31 / 255       0.2194          0.7 / 212
structured    0.5061         3.9 / 470      0.4695          23 / 221       0.4688          0.5 / 155
small-files   0.3581         22.8 / 235     0.3373          25 / 113       0.3491          0.8 / 65
repeated      0.8150         tie at the top level; brotli:6 keeps one extra chunk (0.8295)
```

End to end with dedup on (`all` target, 20.3 MiB):

```text
preset    archive MiB  create s A / B   extract s A / B   create RSS KiB A / B
small     14.5         0.71 / 4.39      0.122 / 0.133     179296 / 27400
brotli:6  14.4         0.14 / 0.64      0.165 / 0.179     122956 / 22644
brotli:11 14.3         6.17 / 35.55     0.175 / 0.194     265852 / 40556
```

Single 32 MiB file (single-file extraction latency):

```text
preset    archive MiB  create s A / B   extract s A / B   create RSS KiB A / B
small     18.8         1.47 / 8.52      0.058 / 0.058     179880 / 25952
brotli:6  19.4         0.20 / 1.20      0.134 / 0.135     115648 / 19556
brotli:11 18.7         7.40 / 57.28     0.130 / 0.139     323468 / 43240
```

## Verdict: presets stay as they are

Brotli clears the half of the whitepaper 5.4.1 claim that lzma2 failed: it compresses
more. Quality 11 beats zstd:19 by 9% on source, 7% on structured records, ties prose
to under half a percent, and matches it on shifted repeats; quality 6 takes small
files by 6% and is the only level that encodes faster than zstd:19 (up to 13x per
chunk on the large groups; parity on small files).
lzma2 still wins structured outright (0.4413 vs 0.4688), and brotli:11 regresses
against brotli:6 on small files (0.3491 vs 0.3373): quality 11's per-chunk framing
costs more than it saves on ~600-byte files.

Neither level earns a preset. Quality 11 saves 0.2 of 14.5 MiB on mixed data while
mixed-data create gets 8-9x slower in both runs, single-file extract 2.2-2.4x slower and create
RSS climbs (1.5x at 8 workers, 1.5x pinned). The lzma2 round rejected the same 0.2
MiB saving for far smaller costs, so `small` stays zstd:19 by the same bar. Quality
6 is cheaper to create but is not maximum compression: it loses prose by 15% and the
single 32 MiB file by 3% against zstd:19 while extracting 1.4-2.3x slower, so no
other preset earns a change either. The null hypothesis holds on the candidacy
workload itself: on prose brotli:11 only ties zstd:19 and brotli:6 loses badly, so
zstd covers text-heavy without a new codec. Brotli remains an explicit
`--codec brotli --level 0-11` choice; the portable profile is untouched.

## Commands

```sh
python3 tools/bench/make_corpus.py build/bench-corpus --add bale-src=src
python3 tools/bench/run_codec_bench.py --bench build/release/bench/bale_bench_codecs \
    --bale build/release/src/cli/bale --corpus build/bench-corpus \
    --out bench/results/2026-10-19-xeon-e5-2690v3-brotli/run-a-threads \
    --runs 5 --e2e-runs 3 --single-mib 32 \
    --codec raw --codec lz4:0 --codec lz4:9 --codec zstd:3 --codec zstd:9 \
    --codec zstd:19 --codec lzma2:6 --codec lzma2:9 \
    --codec brotli:1 --codec brotli:6 --codec brotli:11 \
    --preset fast --preset balanced --preset small --preset restore-fast \
    --preset portable --preset brotli:1 --preset brotli:6 --preset brotli:11
python3 tools/bench/run_codec_bench.py --bench build/release/bench/bale_bench_codecs \
    --bale build/release/src/cli/bale --corpus build/bench-corpus \
    --out bench/results/2026-10-19-xeon-e5-2690v3-brotli/run-b-pinned1 \
    --cpu 3 --runs 5 --e2e-runs 3 --single-mib 32 \
    --create-arg=--threads --create-arg=1 \
    [same --codec and --preset list as run-a-threads]
```

Release binaries came from `cmake -S . -B build/release -G Ninja
-DCMAKE_BUILD_TYPE=Release -DBALE_BUILD_BENCHMARKS=ON -DBALE_WERROR=ON`.
Corpus hash 58ea0c... (see `build/bench-corpus/corpus.json` for the file list;
`bench/results/2026-10-19-xeon-e5-2690v3-lzma2` used corpus 3bc638c2... whose
synthetic groups are byte-identical — only its bale-src group predates this work).
