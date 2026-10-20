# WIM test fixtures

Golden files in `../data` come from two sources. Both are read-only inputs;
no test writes WIM files.

## Generated goldens (`make_fixtures.py`)

`basic.wim`, `multi.wim`, `rich.wim` and `solid_stored.wim` are produced by
`python3 make_fixtures.py --out ../data [--check]`. The generator is
clean-room layout code plus `hashlib` SHA-1 for the lookup table; it emits
stored resources only, except for one COMPRESSED-flag resource in
`basic.wim` whose chunks are all stored raw (legal per the format and a
workout for the chunk table without any codec).

`--check` verifies every fixture with an independent reader, currently
7-Zip 26.04 (`7z l` plus `7z x` byte comparison), and prints the result.
Status as of October 2026:

- `basic.wim`, `multi.wim`, `rich.wim`: accepted by wimlib-imagex 1.14.5
  and bale; rejected by 7-Zip 26.04 for unknown strictness reasons despite
  being valid per the MS-WIM layout (byte-identical structure to accepted
  files was verified field by field). Treated as wimlib-validated.
- `solid_stored.wim`: hermetic only. It uses a solid resource with
  compression format None, which is valid per the layout but implemented
  by neither wimlib (rejects the compression type) nor 7-Zip.

## Reference goldens (`wl_*.wim`)

`wl_none.wim`, `wl_xpress.wim`, `wl_lzx.wim` and `wl_lzms.wim` were captured
with `wimlib-imagex capture` from wimlib 1.14.5 (built from source,
`--compress=none|xpress|lzx`, `--compress=LZMS --solid`, `--no-acls`) from
a four-entry tree with a hard link and a symlink. They cover the refusal
paths for XPRESS, LZX and LZMS with real-world bytes.

## Regenerating

Run `make_fixtures.py --out ../data --check` from this directory. The
`wl_*` files are recorded as-is (small, deterministic content); recapture
with the same wimlib version if they ever need to change.
