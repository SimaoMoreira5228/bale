# bale

bale is two things that share one engine. It's an archive format of its own, built around content addressing, append-only snapshots and strict framing. It's also an archiver that reads and writes the formats you already have, ZIP and TAR (plain, gzip or zstd, plus reads of xz and bzip2) for now, with more on the way.

It's early. The native format isn't frozen: `bale create` writes `.bale` files so the design can be tested, but a later build may not read them. Native archives use deduplicated, BLAKE3-verified chunks, compressed with zstd, LZ4 or LZMA2 unless a chunk would come out bigger, in which case it's stored as is.

## What you can do with it right now

```sh
bale create backup.bale ./project
bale create --preset small backup.bale ./project
bale create backup.zip ./project
bale create backup.tar.zst ./project --level 19
bale convert backup.tar.gz backup.bale
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

`create` and `update` take a preset: `fast`, `balanced` (the default), `small`, `restore-fast` or `portable`. `fast` and `restore-fast` use LZ4, which won both create and extract time against zstd in every measured group, at the cost of archives a fifth to over half bigger. The others are zstd at different levels. `small` is zstd:19 on purpose: LZMA2 was measured against it and lost (see `bench/results/2026-10-19-xeon-e5-2690v3-lzma2`), saving under 2% on mixed data while extracting several times slower, so LZMA2 stays opt-in. The names describe what you're after, not a guarantee that a preset wins on your data. If you want to experiment, `--codec raw|zstd|lz4|lzma2` and `--level N` (zstd 1-22, lz4 0-12, lzma2 0-9) pick the settings directly. Whatever you choose gets written into the snapshot, and `bale info` shows it back to you. Chunks are hashed and compressed on `--threads N` workers (default: one per CPU, at most 8); the archive comes out the same for any thread count apart from the recorded worker count. Chunking stays fixed at 1 MiB unless you pass `--chunking cdc`. Then cut points come from the file bytes, so inserting a byte near the start stops shifting every chunk after it. That costs roughly half the create speed and twice the create-time memory, and it only pays off on data with big shifted repeats: 56% smaller on the bench corpus's repeated group, no change anywhere else. The default 256K/1M/4M min/target/max triple is tuned for that trade; `--chunk-min`, `--chunk-target` and `--chunk-max` move it if your data wants bigger chunks.

`create` picks the format from the archive name (`.bale`, `.zip`, `.tar`, `.tar.gz` or `.tgz`, `.tar.zst` or `.tzst`); `--format` overrides it. ZIP entries are deflated unless deflate doesn't shrink them, in which case they're stored: entries up to 1 MiB are compressed in memory and compared exactly, larger ones decide on their first MiB. ZIP64 records only appear when sizes, offsets or the entry count need them. TAR output is POSIX ustar with pax headers only for long or non-ASCII names, big sizes and sub-second times. Output for the same tree is byte-identical across runs: entries are sorted and owner names are left out. `--level` takes 0-9 for zip (0 stores everything), 1-9 for tar.gz and 1-22 for tar.zst; presets, codecs, threads and chunk sizes only apply to `.bale`. `convert` rewrites a bale, ZIP or TAR archive entry by entry into any of those formats without unpacking it to disk.

`update` adds a new snapshot from the directory you pass. The snapshot becomes the archive's visible contents, and chunks already in the archive are reused when their contents match.

Earlier snapshots stay in the file. `compact` writes the current snapshot and its referenced chunks to a new archive, leaving the source and its history alone.

## Experimental encrypted archives

Pass `--experimental-encryption` to `create` (bale only) to seal names, contents, sizes and counts under XChaCha20-Poly1305 with a password slot (Argon2id), an optional `--recipient` slot, or both. `update`, `compact`, `list`, `test`, `info` and `extract` take the same flag plus `--key-file` for recipient keys; the password still comes from the terminal. This is provisional: the wire values are not frozen, slot bytes just changed once already (the slot epoch is now bound into the seal), and a later build may not read these archives at all.

Without the password nothing leaks beyond the format magic and a flag that says a password is needed: `list`, `test`, `info` and `extract` all stop at the password prompt (exit 6) before touching any entry. Slots that claim an Argon2id cost above ops 8 or 1 GiB of memory are rejected before any KDF work runs, and an archive holds at most 64 keyslots, so a hostile file cannot force unbounded derivation.

Two known properties are pinned by tests so nobody "fixes" them into something worse. Truncating an archive back to a complete older generation opens cleanly as that generation with no warning; rollback detection is impossible in any append-only archive (plaintext behaves the same) and generations stay fully readable on purpose. And a wrong password (exit 6, password required) is deliberately distinct from a damaged archive (exit 5, integrity): merging them would only tell the user to retry a password when the file is actually corrupt.

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

You need CMake 3.25 or newer, a C++23 compiler (GCC 14+ or Clang 18+), and Ninja if you have it. zlib-ng, zstd, LZ4, BLAKE3, xz (liblzma), bzip2 and libsodium are fetched and pinned by hash on the first configure. Pass `-DBALE_USE_SYSTEM_CODECS=ON` to use the copies your system already has.

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
src/fswalk     sorted, non-following directory walk shared by every writer
src/checksum   CRC-32, CRC32C and domain-separated BLAKE3
src/codecs     DEFLATE, zstd and LZ4 frame encoders and decoders
src/format     native wire format: ULEB128, canonical TLV, superblock, records, footer
src/archive    native archive: chunk, manifest, index and commit schemas, writer, reader
src/formats    ZIP, TAR, gzip and zstd readers and writers, format detection
src/security   archive path rules, case-fold collisions, resource budgets
src/extract    directory-relative extraction with atomic staging
src/cli        the bale command
tests          one doctest suite, organised the same way
```

## License

Apache-2.0. See [LICENSE](LICENSE). Bundled codecs keep their own licenses: zlib-ng under the zlib license, zstd and LZ4 under BSD, BLAKE3 under CC0 or Apache-2.0, liblzma under 0BSD, bzip2 under its BSD-style license, libsodium under the ISC license.
