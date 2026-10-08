# bale

bale is two things that share one engine. It's an archive format of its own, built around content addressing, append-only snapshots and strict framing. It's also an archiver that opens the formats you already have, ZIP and TAR for now, with more on the way.

It's early. The native format isn't frozen: `bale create` writes `.bale` files so the design can be tested, but a later build may not read them. Native archives use deduplicated, BLAKE3-verified chunks, stored raw by default or compressed with zstd when requested.

## What you can do with it right now

```sh
bale create backup.bale ./project
bale create --codec zstd backup.bale ./project
bale test backup.bale
bale list archive.zip
bale list --long backup.tar
bale test archive.zip
bale extract backup.tar -o restored
bale formats
```

`extract` never writes outside the output directory. Paths with `..`, absolute paths, drive letters and Windows device names are refused. So are symlinks, unless you pass `--allow-symlinks`, and then only links that stay inside the output get created. Existing files are left alone unless you ask for `--replace` or `--skip-existing`. Every file is written to a temporary name first. It only moves into place once all of it is written and, if the format has a checksum, the checksum matches. A corrupt entry never shows up half-written under its real name.

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

You need CMake 3.25 or newer, a C++23 compiler (GCC 14+ or Clang 18+), and Ninja if you have it. zlib-ng, zstd and BLAKE3 are fetched and pinned by hash on the first configure. Pass `-DBALE_USE_SYSTEM_CODECS=ON` to use the copies your system already has.

```sh
./dev build
./dev test
./dev run bale list some.zip
```

`./dev` wraps the usual chores: `sanitize` runs the tests under ASan and UBSan, `cover` gives a coverage summary, `lint` runs clang-tidy, `format` runs clang-format, and `check` does format, lint and tests in one go. Configuring also links `compile_commands.json` into the repo root, so clangd works in any editor without extra setup.

## Layout

```text
src/base       errors, checked arithmetic, byte order
src/io         bounded byte reader, positional file I/O
src/checksum   CRC-32, CRC32C and domain-separated BLAKE3
src/codecs     streaming DEFLATE and zstd decoders
src/format     native wire format: ULEB128, canonical TLV, superblock, records, footer
src/archive    native archive: chunk, manifest, index and commit schemas, writer, reader
src/formats    ZIP, TAR and gzip readers, format detection
src/security   archive path rules, case-fold collisions, resource budgets
src/extract    directory-relative extraction with atomic staging
src/cli        the bale command
tests          one doctest suite, organised the same way
```

## License

Apache-2.0. See [LICENSE](LICENSE). Bundled codecs keep their own licenses: zlib-ng under the zlib license, zstd under BSD, BLAKE3 under CC0 or Apache-2.0.
