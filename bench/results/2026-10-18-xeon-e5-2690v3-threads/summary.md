# Parallel create: thread scaling

- date: 2026-10-18, Release build (`-DCMAKE_BUILD_TYPE=Release -DBALE_BUILD_BENCHMARKS=ON`)
- machine: Intel Xeon E5-2690 v3 (12 cores, 24 logical CPUs), performance governor, SMT on
- every run pinned with `taskset -c 1-9` (nine distinct physical cores: the writer thread plus up
  to eight workers), the same CPU set for every thread count
- work directory on local disk (page cache, not tmpfs); 2 end-to-end runs per cell, medians shown
- load average while timing: 2.9 to 6.9 (another agent's builds and benchmarks shared the machine
  on CPUs outside 1-9); treat differences under about 10% as noise
- commands, per thread count N in 1, 2, 4, 8:
  `run_codec_bench.py --codec raw --runs 1 --cpu 1-9 --preset fast --preset balanced --e2e-runs 2
  --work-dir <hdd> --create-arg=--threads --create-arg=N` on `corpus-sizes` and `corpus-real`;
  raw results are in `sizes-tN/results.json` and `real-tN/results.json`, the tables below come
  from `tools/bench/threads_summary.py`
- source: commit 3482cb4 (results.json records 65dd0fd, the unsplit work-in-progress commit with
  the same source tree)
- presets: fast is LZ4 level 0, balanced is zstd level 3; 1 MiB fixed chunks

## Determinism

Archive bytes are identical for every thread count in every row (the `archive bytes` column).
The only byte that differs is the advisory `workers` field of the writer metadata, plus the CRCs
and digests that cover it; `pipeline_test.cpp` checks that every DATA record, the INDEX record and
the manifest apart from that field are byte-identical between 1 and 2, 3 or 8 workers.

## Memory

The pipeline allocates everything once: an input ring of `2 x workers x chunk size`, an output
ring of the same size (none for raw), `16 x workers` slot descriptors and one encoder per worker
plus one for the writer thread. Ring pages are left uninitialized, so RSS counts only what a run
touches. At 8 workers and 1 MiB chunks the bound is 16 MiB + 16 MiB of rings plus 9 encoders
(each holds a compress-bound output buffer and its codec context: about 1.3 MiB for zstd 3, about
17 MiB for zstd 19). Measured peak RSS at 8 threads: 42 MiB (fast) and 48 MiB (balanced) on 1 GiB
of large files, against 8-10 MiB single-threaded; docs grows from 31 to 78 MiB, of which about
22 MiB already present at one thread is the writer's entry, name and manifest buffers for 24k
paths.

## Reading the results

- Large files scale close to linearly with balanced (zstd 3): 7.5x at 8 threads on size-1G and
  on the whole sizes corpus, 7.6x on binaries. Fast (LZ4) stops near 4.5-5x because the writer
  thread (reading input, CRC, writing records) becomes the bottleneck at about 1.7-1.9 GB/s.
- Many small files (docs, 24085 files averaging 21 KiB) reach 4.2x with balanced and 2.4x with
  fast: the writer thread's per-file work (directory walk, lstat, open, read, close) is serial.
  In an earlier unpinned check, before record writes were coalesced and before small chunks could
  queue behind a large one, docs at 8 threads took 1.24 s with balanced; it now takes 0.79 s.
- Tiny inputs (size-1M, 15 MiB of sources) gain little or lose a few milliseconds: there is too
  little work to spread, and thread start-up costs about 4 ms at 8 threads.

## Synthetic sizes corpus (`corpus-sizes`)

- corpus: 7bcddc28a3846c3ac37c04975aa80ff2f029f03a62c596451d1e3442fbebe952

| target | preset | input MiB | threads | archive MiB | archive bytes | create s | create MB/s | speedup | create RSS KiB |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| size-1M | fast | 1.0 | 1 | 0.70 | 739087 | 0.009 | 118.2 | 1.00x | 7972 |
| size-1M | fast | 1.0 | 2 | 0.70 | 739087 | 0.009 | 112.7 | 0.95x | 10148 |
| size-1M | fast | 1.0 | 4 | 0.70 | 739087 | 0.010 | 100.3 | 0.85x | 11976 |
| size-1M | fast | 1.0 | 8 | 0.70 | 739087 | 0.013 | 80.3 | 0.68x | 16292 |
| size-1M | balanced | 1.0 | 1 | 0.42 | 436291 | 0.015 | 67.7 | 1.00x | 8804 |
| size-1M | balanced | 1.0 | 2 | 0.42 | 436291 | 0.016 | 64.6 | 0.95x | 11052 |
| size-1M | balanced | 1.0 | 4 | 0.42 | 436291 | 0.017 | 61.1 | 0.90x | 13156 |
| size-1M | balanced | 1.0 | 8 | 0.42 | 436291 | 0.021 | 50.3 | 0.74x | 17252 |
| size-10M | fast | 10.0 | 1 | 7.82 | 8203885 | 0.032 | 332.7 | 1.00x | 7844 |
| size-10M | fast | 10.0 | 2 | 7.82 | 8203885 | 0.018 | 577.5 | 1.74x | 14372 |
| size-10M | fast | 10.0 | 4 | 7.82 | 8203885 | 0.018 | 596.5 | 1.79x | 21420 |
| size-10M | fast | 10.0 | 8 | 7.82 | 8203885 | 0.021 | 506.9 | 1.52x | 28076 |
| size-10M | balanced | 10.0 | 1 | 3.95 | 4142864 | 0.070 | 149.0 | 1.00x | 8996 |
| size-10M | balanced | 10.0 | 2 | 3.95 | 4142864 | 0.036 | 287.9 | 1.93x | 16676 |
| size-10M | balanced | 10.0 | 4 | 3.95 | 4142864 | 0.031 | 342.3 | 2.30x | 26140 |
| size-10M | balanced | 10.0 | 8 | 3.95 | 4142864 | 0.026 | 402.0 | 2.70x | 36260 |
| size-100M | fast | 100.0 | 1 | 72.68 | 76208201 | 0.279 | 376.2 | 1.00x | 8036 |
| size-100M | fast | 100.0 | 2 | 72.68 | 76208201 | 0.127 | 824.9 | 2.19x | 15532 |
| size-100M | fast | 100.0 | 4 | 72.68 | 76208201 | 0.080 | 1312.1 | 3.49x | 24300 |
| size-100M | fast | 100.0 | 8 | 72.68 | 76208201 | 0.077 | 1369.1 | 3.64x | 41636 |
| size-100M | balanced | 100.0 | 1 | 41.96 | 43997015 | 0.664 | 157.8 | 1.00x | 9132 |
| size-100M | balanced | 100.0 | 2 | 41.96 | 43997015 | 0.317 | 330.9 | 2.10x | 17068 |
| size-100M | balanced | 100.0 | 4 | 41.96 | 43997015 | 0.177 | 591.4 | 3.75x | 26852 |
| size-100M | balanced | 100.0 | 8 | 41.96 | 43997015 | 0.132 | 797.2 | 5.05x | 46820 |
| size-500M | fast | 500.0 | 1 | 358.71 | 376132364 | 1.386 | 378.4 | 1.00x | 8236 |
| size-500M | fast | 500.0 | 2 | 358.71 | 376132364 | 0.602 | 870.5 | 2.30x | 15332 |
| size-500M | fast | 500.0 | 4 | 358.71 | 376132364 | 0.335 | 1565.5 | 4.14x | 24544 |
| size-500M | fast | 500.0 | 8 | 358.71 | 376132364 | 0.305 | 1721.0 | 4.55x | 41828 |
| size-500M | balanced | 500.0 | 1 | 213.99 | 224388512 | 3.498 | 149.9 | 1.00x | 9380 |
| size-500M | balanced | 500.0 | 2 | 213.99 | 224388512 | 1.650 | 317.7 | 2.12x | 16940 |
| size-500M | balanced | 500.0 | 4 | 213.99 | 224388512 | 0.805 | 651.4 | 4.35x | 27308 |
| size-500M | balanced | 500.0 | 8 | 213.99 | 224388512 | 0.568 | 923.0 | 6.16x | 48224 |
| size-1G | fast | 1024.0 | 1 | 730.57 | 766054553 | 2.914 | 368.4 | 1.00x | 8420 |
| size-1G | fast | 1024.0 | 2 | 730.57 | 766054553 | 1.242 | 864.8 | 2.35x | 15532 |
| size-1G | fast | 1024.0 | 4 | 730.57 | 766054553 | 0.651 | 1649.2 | 4.48x | 24604 |
| size-1G | fast | 1024.0 | 8 | 730.57 | 766054553 | 0.640 | 1678.7 | 4.56x | 42476 |
| size-1G | balanced | 1024.0 | 1 | 443.08 | 464598811 | 7.050 | 152.3 | 1.00x | 9572 |
| size-1G | balanced | 1024.0 | 2 | 443.08 | 464598811 | 3.199 | 335.7 | 2.20x | 17252 |
| size-1G | balanced | 1024.0 | 4 | 443.08 | 464598811 | 1.686 | 636.7 | 4.18x | 28004 |
| size-1G | balanced | 1024.0 | 8 | 443.08 | 464598811 | 0.937 | 1146.0 | 7.52x | 48548 |
| all | fast | 1635.0 | 1 | 1170.48 | 1227337767 | 4.707 | 364.2 | 1.00x | 8804 |
| all | fast | 1635.0 | 2 | 1170.48 | 1227337767 | 1.900 | 902.1 | 2.48x | 15716 |
| all | fast | 1635.0 | 4 | 1170.48 | 1227337767 | 1.093 | 1567.9 | 4.30x | 24492 |
| all | fast | 1635.0 | 8 | 1170.48 | 1227337767 | 0.935 | 1833.2 | 5.03x | 42788 |
| all | balanced | 1635.0 | 1 | 703.39 | 737563052 | 11.428 | 150.0 | 1.00x | 9580 |
| all | balanced | 1635.0 | 2 | 703.39 | 737563052 | 4.999 | 342.9 | 2.29x | 17548 |
| all | balanced | 1635.0 | 4 | 703.39 | 737563052 | 2.730 | 628.1 | 4.19x | 28004 |
| all | balanced | 1635.0 | 8 | 703.39 | 737563052 | 1.525 | 1124.3 | 7.49x | 49280 |

## Real data (`corpus-real`: source, binaries, docs)

- corpus: af927ec773c8b2497e29ad74dfe47116aaeffa8e9446190bd0a08ec90dc8a9ea

| target | preset | input MiB | threads | archive MiB | archive bytes | create s | create MB/s | speedup | create RSS KiB |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| source | fast | 15.0 | 1 | 9.86 | 10341169 | 0.066 | 238.3 | 1.00x | 8804 |
| source | fast | 15.0 | 2 | 9.86 | 10341169 | 0.036 | 437.8 | 1.84x | 15532 |
| source | fast | 15.0 | 4 | 9.86 | 10341169 | 0.038 | 413.3 | 1.73x | 18220 |
| source | fast | 15.0 | 8 | 9.86 | 10341169 | 0.040 | 390.6 | 1.64x | 19332 |
| source | balanced | 15.0 | 1 | 8.54 | 8956196 | 0.113 | 139.1 | 1.00x | 10872 |
| source | balanced | 15.0 | 2 | 8.54 | 8956196 | 0.051 | 307.6 | 2.21x | 19440 |
| source | balanced | 15.0 | 4 | 8.54 | 8956196 | 0.041 | 382.0 | 2.75x | 27632 |
| source | balanced | 15.0 | 8 | 8.54 | 8956196 | 0.047 | 336.9 | 2.42x | 38084 |
| binaries | fast | 341.9 | 1 | 202.18 | 212001768 | 0.991 | 361.9 | 1.00x | 8812 |
| binaries | fast | 341.9 | 2 | 202.18 | 212001768 | 0.410 | 874.5 | 2.42x | 17060 |
| binaries | fast | 341.9 | 4 | 202.18 | 212001768 | 0.234 | 1532.5 | 4.23x | 27044 |
| binaries | fast | 341.9 | 8 | 202.18 | 212001768 | 0.190 | 1887.7 | 5.22x | 47204 |
| binaries | balanced | 341.9 | 1 | 154.52 | 162024540 | 2.732 | 131.2 | 1.00x | 10148 |
| binaries | balanced | 341.9 | 2 | 154.52 | 162024540 | 1.282 | 279.5 | 2.13x | 20160 |
| binaries | balanced | 341.9 | 4 | 154.52 | 162024540 | 0.652 | 549.4 | 4.19x | 31652 |
| binaries | balanced | 341.9 | 8 | 154.52 | 162024540 | 0.361 | 991.7 | 7.56x | 56996 |
| docs | fast | 496.0 | 1 | 227.76 | 238821796 | 1.661 | 313.1 | 1.00x | 29888 |
| docs | fast | 496.0 | 2 | 227.76 | 238821796 | 0.806 | 645.0 | 2.06x | 38020 |
| docs | fast | 496.0 | 4 | 227.76 | 238821796 | 0.748 | 695.2 | 2.22x | 47700 |
| docs | fast | 496.0 | 8 | 227.76 | 238821796 | 0.694 | 749.1 | 2.39x | 63784 |
| docs | balanced | 496.0 | 1 | 181.43 | 190240395 | 3.267 | 159.2 | 1.00x | 31560 |
| docs | balanced | 496.0 | 2 | 181.43 | 190240395 | 1.469 | 353.9 | 2.22x | 42528 |
| docs | balanced | 496.0 | 4 | 181.43 | 190240395 | 0.958 | 543.1 | 3.41x | 53040 |
| docs | balanced | 496.0 | 8 | 181.43 | 190240395 | 0.788 | 659.9 | 4.15x | 77864 |
| all | fast | 857.2 | 1 | 441.94 | 463408508 | 2.773 | 324.2 | 1.00x | 30628 |
| all | fast | 857.2 | 2 | 441.94 | 463408508 | 1.250 | 719.0 | 2.22x | 38768 |
| all | fast | 857.2 | 4 | 441.94 | 463408508 | 0.966 | 930.3 | 2.87x | 49092 |
| all | fast | 857.2 | 8 | 441.94 | 463408508 | 0.902 | 996.5 | 3.07x | 68812 |
| all | balanced | 857.2 | 1 | 345.76 | 362557360 | 6.126 | 146.7 | 1.00x | 34580 |
| all | balanced | 857.2 | 2 | 345.76 | 362557360 | 2.736 | 328.6 | 2.24x | 43460 |
| all | balanced | 857.2 | 4 | 345.76 | 362557360 | 1.630 | 551.3 | 3.76x | 55596 |
| all | balanced | 857.2 | 8 | 345.76 | 362557360 | 1.174 | 765.9 | 5.22x | 80528 |
