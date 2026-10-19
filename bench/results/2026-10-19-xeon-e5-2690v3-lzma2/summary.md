# lzma2 vs zstd at high levels: not worth it for `small`

- machine: Intel Xeon E5-2690 v3, performance governor; run-a-threads is the default
  8-worker build, run-b-pinned1 is pinned to CPU 3 with `--threads 1`
- corpus 3bc638c2df85ac5ba8dfd3a069b5df1e4d87e19a9164ab3e44365109cd646ac2, built with
  `make_corpus.py --add bale-src=src` (synthetic groups plus this repo's source)
- fixed 1 MiB chunks; codec rows use deduplication off, end-to-end rows deduplication on;
  raw `results.json` files sit next to the per-run `summary.md` files

## What the numbers say

Codec rows (identical chunks, dedup off, run A medians):

```text
group         zstd:19 ratio  enc/dec MB/s   lzma2:6 ratio  enc/dec MB/s   lzma2:9 ratio  enc/dec MB/s
text          0.2570         2.2 / 568      0.2556         1.2 / 53       0.2556         2.3 / 97
bale-src      0.2493         1.4 / 217      0.2582         1.3 / 19       0.2582         0.9 / 47
structured    0.5061         3.6 / 451      0.4413         2.9 / 43       0.4413         2.5 / 45
small-files   0.3581         21.1 / 214     0.4434         0.4 / 4.3      0.4434         1.0 / 22
repeated      0.8150         tie, both fall back to raw on shifted 1 MiB chunks
```

End to end with dedup on (`all` target, 20.1 MiB):

```text
preset    archive MiB  create s A / B   extract s A / B   create RSS KiB A / B
small     14.4         0.73 / 3.24      0.080 / 0.081     177492 / 27144
lzma2:6   14.2         1.88 / 6.17      0.215 / 0.213     227256 / 35904
lzma2:9   14.2         1.83 / 7.31      0.244 / 0.247     620504 / 84196
```

Single 32 MiB file (single-file extraction latency):

```text
preset    create s A / B   extract s A / B   create RSS KiB A / B
small     1.51 / 9.04      0.065 / 0.066     179676 / 25740
lzma2:6   1.93 / 12.16     0.573 / 0.573     234512 / 34248
lzma2:9   2.64 / 14.10     0.592 / 0.589     626660 / 83392
```

## Verdict: presets stay as they are

The claim behind whitepaper 5.4.1 halves cleanly. Slower: yes, everywhere, by a
lot (chunk decode 5-11x, single-file extract ~9x, small-file create 37x from
per-chunk encoder setup). Compresses more: only sometimes (structured 13%
relative, prose under 1%), and it loses on source code and small files where xz
framing overhead dominates. lzma2:9 stores byte-identical totals to lzma2:6 on
every group, and zstd:22 matches zstd:19 everywhere, so neither top level earns
its keep at 1 MiB chunks.

The whitepaper's gate for `small` is a size gain that warrants the memory and
latency cost. Saving 0.2 of 14.4 MiB while extract gets 2.7x slower, single-file
extract 9x slower and create RSS climbs (up to 3.5x at 8 workers for level 9)
does not clear it. `small` stays zstd:19. lzma2 remains an explicit
`--codec lzma2 --level 0-9` choice; the portable profile is untouched.
