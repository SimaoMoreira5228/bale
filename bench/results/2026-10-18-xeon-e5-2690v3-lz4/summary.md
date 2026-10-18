# LZ4 against zstd for the fast and restore-fast presets

- machine: Intel Xeon E5-2690 v3, pinned to CPU 5, performance governor, Release build of 7623c39
- LZ4 1.10.0 frame format (codec 2), zstd 1.5.7, fixed 1 MiB chunks, 3 codec runs and 3 end-to-end runs
- real corpus af927ec7… (source 15.8 MB, binaries 358 MB, docs 520 MB), see `real/`
- synthetic size-100M group of corpus 7bcddc28…, run through a hard-linked one-group copy, see `size-100M/`
- load average was 1.5 to 1.8 when each run started. Another build started during the real
  corpus end-to-end pass and pushed the load to about 9 by the end, which is why the `all` rows
  have the widest spreads. The codec rows and the per-group rankings didn't change.

`lz4:0` and `lz4:1` are the same compressor. Every LZ4 frame level below 3 runs the fast
compressor, so the bytes are identical and the timing gap between them is noise.

## Codec rows, deduplication off

| group | codec | stored MiB | ratio | encode MB/s | decode MB/s |
|---|---|---:|---:|---:|---:|
| source | lz4:0 | 9.7 | 0.6443 | 691 | 3143 |
| source | lz4:9 | 9.0 | 0.5956 | 33 | 2687 |
| source | zstd:1 | 8.5 | 0.5653 | 284 | 779 |
| binaries | lz4:0 | 202.1 | 0.5913 | 512 | 3316 |
| binaries | lz4:9 | 171.5 | 0.5016 | 26 | 2613 |
| binaries | zstd:1 | 166.3 | 0.4866 | 281 | 927 |
| docs | lz4:0 | 245.1 | 0.4941 | 568 | 2991 |
| docs | lz4:9 | 213.8 | 0.4310 | 39 | 2416 |
| docs | zstd:1 | 197.8 | 0.3987 | 278 | 883 |
| size-100M | lz4:0 | 72.7 | 0.7267 | 611 | 3425 |
| size-100M | lz4:9 | 60.6 | 0.6064 | 13 | 4474 |
| size-100M | zstd:1 | 46.0 | 0.4597 | 341 | 1027 |

## End to end, deduplication on (median seconds)

| target | profile | archive MiB | ratio | create s | extract s |
|---|---|---:|---:|---:|---:|
| all real | lz4:0 | 441.9 | 0.5156 | 3.122 | 2.782 |
| all real | lz4:9 | 383.2 | 0.4471 | 27.274 | 2.908 |
| all real | zstd:1 | 362.7 | 0.4232 | 4.485 | 3.819 |
| source | lz4:0 | 9.9 | 0.6558 | 0.072 | 0.104 |
| source | zstd:1 | 8.7 | 0.5770 | 0.114 | 0.135 |
| binaries | lz4:0 | 202.2 | 0.5914 | 1.050 | 0.390 |
| binaries | zstd:1 | 166.4 | 0.4867 | 1.517 | 0.677 |
| docs | lz4:0 | 227.8 | 0.4592 | 1.796 | 2.249 |
| docs | zstd:1 | 186.4 | 0.3758 | 2.644 | 2.812 |
| size-100M | lz4:0 | 72.7 | 0.7268 | 0.245 | 0.103 |
| size-100M | zstd:1 | 46.0 | 0.4598 | 0.387 | 0.179 |

## Decision

`fast` becomes `lz4` level 0. Of the profiles that compress, it creates archives fastest in every
group, and its min-max create times never overlap zstd:1's (all real data: 2.98-4.07 s against
4.44-5.23 s). The price is size. The archive comes out 22% bigger on the real corpus (441.9
against 362.7 MiB) and 58% bigger on size-100M (72.7 against 46.0 MiB). `raw` creates faster
still, but it doesn't compress, so it stays a codec choice instead of a preset.

`restore-fast` also becomes `lz4` level 0. It extracts faster than zstd:1 in every group, from
23% on source to 42% on binaries, again without overlap. lz4:9 doesn't beat it. It decodes 15-21%
slower on all three real groups and only wins on the synthetic size-100M group. End to end, where
the filesystem dominates (docs, source), extraction is a tie. lz4:9 also takes 7 to 35 times
longer to create, so its 13% smaller archive doesn't earn the slot. restore-fast costs the same
size as fast.
