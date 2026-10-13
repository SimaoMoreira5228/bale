# bale

bale is two things that share one engine. It's an archive format of its own, built around content addressing, append-only snapshots and strict framing. It's also an archiver that opens the formats you already have, ZIP and TAR for now, with more on the way.

It's early. The native format isn't frozen: `bale create` writes `.bale` files so the design can be tested, but a later build may not read them. Native archives use deduplicated, BLAKE3-verified chunks, compressed with zstd or LZ4 unless a chunk would come out bigger, in which case it's stored as is.

## What you can do with it right now

```sh
bale create backup.bale ./project
bale create --preset small backup.bale ./project
bale update backup.bale ./project
bale info backup.bale
bale compact backup.bale compacted.bale
bale test backup.bale
bale list archive.zip
bale list --long backup.tar
bale test archive.zip
bale extract backup.tar -o restored
bale formats
```

`extract` never writes outside the output directory. Paths with `..`, absolute paths, drive letters and Windows device names are refused. So are symlinks, unless you pass `--allow-symlinks`, and then only links that stay inside the output get created. Existing files are left alone unless you ask for `--replace` or `--skip-existing`. Every file is written to a temporary name first. It only moves into place once all of it is written and, if the format has a checksum, the checksum matches. A corrupt entry never shows up half-written under its real name.

`create` and `update` take a preset: `fast`, `balanced` (the default), `small`, `restore-fast` or `portable`. Today they all map to zstd at different levels, with `fast` and `restore-fast` waiting on LZ4 and every choice waiting on the codec benchmark. The names describe what you're after, not a guarantee that a preset wins on your data. If you want to experiment, `--codec raw|zstd` and `--level N` pick the settings directly. Whatever you choose gets written into the snapshot, and `bale info` shows it back to you.

`update` adds a new snapshot from the directory you pass. The snapshot becomes the archive's visible contents, and chunks already in the archive are reused when their contents match.

Earlier snapshots stay in the file. `compact` writes the current snapshot and its referenced chunks to a new archive, leaving the source and its history alone.

Names from the archive are escaped before they reach your terminal. A file called `\x1b[31m...` can't recolor your shell or hide behind a bidi override.

Exit codes tell you what went wrong:

| code | meaning |
|---|---|
| 0 | everything worked |
| 2 | bad command line |
| 3 | format or feature not supported |
| 4 | the archive is malformed or truncated |
| 5 | a checksum didn't match |
| 6 | a password is needed |
| 7 | an entry had an unsafe path |
| 8 | I/O error |
| 9 | a size or count limit was hit |
| 10 | the target already exists |

## Building

You need CMake 3.25 or newer, a C++23 compiler (GCC 14+ or Clang 18+), and Ninja if you have it. zlib-ng, zstd, LZ4 and BLAKE3 are fetched and pinned by hash on the first configure. Pass `-DBALE_USE_SYSTEM_CODECS=ON` to use the copies your system already has.

```sh
./dev build
./dev test
./dev run bale list some.zip
```

On Windows, register a per-user File Explorer submenu for single files, folders and `.bale` archives:

```powershell
powershell -ExecutionPolicy Bypass -File tools/install-windows-context-menu.ps1 C:\path\to\bale.exe
```

It creates `<item>.bale`, or extracts a `.bale` archive beside itself or into a folder. Run the same
script with `-Uninstall` to remove the menu. This uses static registry verbs; Windows 11 may show it
under **Show more options**.

`./dev` wraps the usual chores: `sanitize` runs the tests under ASan and UBSan, `cover` gives a coverage summary, `lint` runs clang-tidy, `format` runs clang-format, and `check` does format, lint and tests in one go. Configuring also links `compile_commands.json` into the repo root, so clangd works in any editor without extra setup.

## Benchmarks

Presets are supposed to be picked from measurements, not hunches, so there's a harness for that. Build it with `-DBALE_BUILD_BENCHMARKS=ON` in a Release build, make a corpus, and run it:

```sh
python3 tools/bench/make_corpus.py corpus --add source=../some-repo
python3 tools/bench/run_codec_bench.py --bench build/release/bench/bale_bench_codecs \
    --bale build/release/src/cli/bale --corpus corpus --out results --cpu 3
```

The corpus generator writes deterministic synthetic groups (prose, lots of small JSON files, shifted repeats, structured records, random bytes) and hashes everything into `corpus.json`. `--add` copies real directories in as extra groups, which matters: synthetic data only tells you so much. `--sizes 1M,100M,1G` adds one group per size, each a single file of mixed content where every megabyte is different, so deduplication can't flatter the big ones. Use `--no-synthetic` if the sizes are all you want. Put large corpora and `--work-dir` on a real disk, not a RAM-backed `/tmp`. Codecs are compared on identical fixed chunks with deduplication off, each in its own process, with medians and spread over repeated runs. A second pass times `bale create` and `bale extract` for every group and preset with deduplication on, and records their peak memory through `/usr/bin/time`. That's the pass that shows how speed and memory hold up as files grow; per-chunk compression ratios barely move with file size, because every file is cut into the same independent chunks. `results/summary.md` is the readable version and `results.json` keeps everything, including the machine description. Numbers from different machines shouldn't be merged into one ranking.

## Layout

```text
src/base       errors, checked arithmetic, byte order
src/io         bounded byte reader, positional file I/O
src/checksum   CRC-32, CRC32C and domain-separated BLAKE3
src/codecs     DEFLATE, zstd and LZ4 frame encoders and decoders
src/format     native wire format: ULEB128, canonical TLV, superblock, records, footer
src/archive    native archive: chunk, manifest, index and commit schemas, writer, reader
src/formats    ZIP, TAR and gzip readers, format detection
src/security   archive path rules, case-fold collisions, resource budgets
src/extract    directory-relative extraction with atomic staging
src/cli        the bale command
tests          one doctest suite, organised the same way
```

## License

Apache-2.0. See [LICENSE](LICENSE). Bundled codecs keep their own licenses: zlib-ng under the zlib license, zstd and LZ4 under BSD, BLAKE3 under CC0 or Apache-2.0.
