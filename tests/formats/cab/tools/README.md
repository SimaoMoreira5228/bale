# CAB fixture tools

Clean-room test-vector pipeline for the read-only CAB support:

- `lzx_enc.py` — independent LZX/CAB writer built only from the public
  format descriptions ([MS-CAB], [MS-PATCH] 2.1/2.3-2.7). Knows the same
  framing rules as the C++ decoder (32 KiB frame alignment, aligned-offset
  split at footer >= 3, per-section two-symbol minimum) because real
  cabinets require them.
- `generate.py` — emits the `*.cab` fixtures plus the expected per-folder
  `.f0.bin` streams into an output directory.
- `export_fixtures.py` — bakes validated outputs into
  `../cab_fixture.hpp` as C++ arrays (full bytes under 512 B, FNV-1a
  length+hash above).

Trust basis, per fixture: the generator's input, bale's output, and the
independent decoders cabextract 1.11 and 7-Zip must all agree byte for byte
(`verify_fixtures.py <bale> <workdir> <cabs...>` replays the bale side of
that check; the repo's unit tests pin the same bytes/hashes afterwards).

Regenerate after any generator change, then re-run the triple check plus
`bale_tests -tc="cab *"` before exporting.
