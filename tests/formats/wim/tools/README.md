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

## Reference goldens (`wl_*.wim`, `lzx_*.wim`)

`wl_none.wim`, `wl_xpress.wim`, `wl_lzx.wim` and `wl_lzms.wim` were captured
with `wimlib-imagex capture` from wimlib 1.14.5 (built from source,
`--compress=none|xpress|lzx`, `--compress=LZMS --solid`, `--no-acls`) from
a four-entry tree with a hard link and a symlink. `wl_xpress.wim` and
`wl_lzms.wim` cover the XPRESS/LZMS refusal paths; `wl_lzx.wim` now decodes
(its metadata resource is LZX-compressed).

`lzx_multi.wim`, `lzx_solid.wim` and `lzx_chunk64.wim` were captured with
wimlib-imagex 1.14.5 (built from source, `--no-acls`) from a tree with a
100 KiB mixed-content file (four LZX chunks), a 12 KiB x86 binary (E8-heavy),
links and an empty file:

- `lzx_multi.wim`: `--compress=lzx` (32 KiB chunks, non-solid)
- `lzx_solid.wim`: `--compress=lzx --solid --solid-compress=LZX`
- `lzx_chunk64.wim`: `--compress=lzx --chunk-size=64K` (24-bit block sizes,
  32 offset slots, blocks crossing 32 KiB with no frame padding)

All three extract byte-identical to 7-Zip 26.04 (`7z x`); the hashes pinned
in `../lzx_test.cpp` are that extraction.

## Hermetic vectors (`lzx_vectors.hpp`)

`lzx_vectors.hpp` is baked by `python3 gen_lzx_vectors.py` from
`lzx_wim_enc.py`, a WIM-framed LZX chunk encoder built on the CAB
generator's Huffman/token core (`tests/formats/cab/tools/lzx_enc.py`) with
WIM framing swapped in: no stream header, 1 flag bit plus 16 size bits (24
at 64 KiB windows and above), unconditional E8 with filesize 12000000
applied per chunk, no 32 KiB frame padding, no tree delta across chunks. The
vectors cover raw blocks with E8 and odd pads, coded chunk splits, small
verbatim blocks, mixed raw/verbatim/aligned blocks, a 64 KiB chunk with a
block crossing 32 KiB, and E8 edge cases. They pin framing details, not the
framing itself: ground truth stays the wimlib goldens above plus the
real-tool differential (7-Zip 26.04).

A lone raw block can never satisfy the chunk size rule (its framing overhead
always exceeds the payload), so raw-block coverage rides as the second
block of a full chunk; the container rejects stored chunks larger than
their uncompressed size, matching what real writers emit.

## Regenerating

Run `make_fixtures.py --out ../data --check` from this directory. The
`wl_*` files are recorded as-is (small, deterministic content); recapture
with the same wimlib version if they ever need to change.
