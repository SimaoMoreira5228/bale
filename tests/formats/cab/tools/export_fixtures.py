#!/usr/bin/env python3
"""Export validated CAB fixtures as a C++ header for bale's unit tests.

Reads triple-validated generator outputs (generator == bale == cabextract
1.11 == 7-Zip, byte for byte) and emits tests/formats/cab/cab_fixture.hpp
with raw LZX streams, expected outputs, and two complete cabinets.
"""
import os
import struct
import sys

OUT = '/tmp/opencode/regen'
DEST = '/home/simao/.local/share/opencode/worktree/f612b1/cab-read/tests/formats/cab/cab_fixture.hpp'

# name -> (cab file, window bits, description)
STREAMS = [
    ('LzxMicroMatch', 'micro_match', 15, 'literals plus one R0 match; smallest LZX block'),
    ('LzxSplit', 'lzx_split', 15, 'single verbatim block (tested split across CFDATA)'),
    ('LzxAligned', 'lzx_aligned', 15, 'aligned-offset block, slots incl. large offsets'),
    ('LzxSlots89', 'lzx_slots89', 15, 'aligned block using slots 8/9 (footer >= 3 rule)'),
    ('LzxE8', 'lzx_e8', 15, 'E8 translation frame'),
    ('LzxLiterals', 'lzx_literals', 15, 'all-literal block with dummy match/length symbols'),
    ('LzxOddRaw', 'lzx_oddraw', 15, 'odd-size uncompressed (raw) block with pad byte'),
    ('LzxBig21', 'lzx_big21', 21, 'window-21 block, 257-byte matches, 32K frame alignment'),
    ('MszipBasic', 'mszip_basic', 0, 'MSZIP folder stream (deflate blocks with CK header)'),
]

FULL_CABS = [
    ('CabMicroMatch', 'micro_match', 'complete tiny cabinet: open/list/extract smoke'),
    ('CabSlots89', 'lzx_slots89', 'complete cabinet covering the slot 8/9 rule'),
]

# expected outputs above this size are verified by length + FNV-1a hash
# (byte-identity itself is established by the cabextract/7-Zip differentials)
FULL_OUT_LIMIT = 512


def fnv1a(data):
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def cab_stream(cab_path):
    f = open(cab_path, 'rb').read()
    start, nblocks, typ = struct.unpack('<IHH', f[36:44])
    off = start
    parts = []
    for _ in range(nblocks):
        csum, cb, cu = struct.unpack('<IHH', f[off:off + 8])
        parts.append(f[off + 8:off + 8 + cb])
        off += 8 + cb
    return b''.join(parts), typ


def fmt_array(data, name):
    lines = ['inline constexpr std::array<std::byte, %d> %s = {' % (len(data), name)]
    for i in range(0, len(data), 5):
        chunk = data[i:i + 5]
        lines.append('    ' + ', '.join('std::byte{0x%02x}' % b for b in chunk) + ',')
    lines.append('};')
    return '\n'.join(lines)


def main():
    parts = []
    parts.append('#pragma once')
    parts.append('')
    parts.append('// CAB unit-test fixtures. Provenance: every byte below comes from')
    parts.append('// tests/formats/cab/tools (generate.py + lzx_enc.py, clean-room')
    parts.append('// LZX/MS-CAB writer), and every stream decodes byte-identically in')
    parts.append('// four independent implementations: the generator itself, bale,')
    parts.append('// cabextract 1.11 and 7-Zip 26.04. Regenerate with')
    parts.append('// tools/export_fixtures.py after touching the generator; the triple')
    parts.append('// check is tools/verify_fixtures.py (bale side) plus cabextract/7-Zip.')
    parts.append('')
    parts.append('#include <array>')
    parts.append('#include <cstddef>')
    parts.append('#include <cstdint>')
    parts.append('')
    parts.append('namespace bale::cab::test {')
    parts.append('')
    for tag, cabname, window, desc in STREAMS:
        cab = os.path.join(OUT, cabname + '.cab')
        stream, typ = cab_stream(cab)
        method = typ & 15
        if method == 1:
            wb = 0
        else:
            wb = (typ >> 8) & 0x1F
            assert wb == window, (tag, wb, window)
        exp = open(os.path.join(OUT, cabname + '.f0.bin'), 'rb').read()
        parts.append(
            '// %s: method %d, window %d, %d stream bytes -> %d output bytes.'
            % (cabname, method, wb, len(stream), len(exp))
        )
        parts.append('// %s.' % desc)
        parts.append(fmt_array(stream, 'k' + tag + 'Stream'))
        parts.append('')
        if len(exp) > FULL_OUT_LIMIT:
            parts.append('inline constexpr std::uint64_t k' + tag + 'OutHash = 0x%016xULL;  // FNV-1a'
                         % fnv1a(exp))
            parts.append('inline constexpr std::size_t k' + tag + 'OutSize = %d;' % len(exp))
        else:
            parts.append(fmt_array(exp, 'k' + tag + 'Out'))
        parts.append('')
    for tag, cabname, desc in FULL_CABS:
        cab = os.path.join(OUT, cabname + '.cab')
        data = open(cab, 'rb').read()
        parts.append('// Complete %s (%d bytes): %s.' % (cabname + '.cab', len(data), desc))
        parts.append(fmt_array(data, 'k' + tag))
        parts.append('')
    parts.append('}  // namespace bale::cab::test')
    parts.append('')
    text = '\n'.join(parts)
    # NOTE: array packing follows the repo .clang-format; run it when
    # available so regeneration never breaks `fmt --check`.
    import shutil
    import subprocess as sp

    open(DEST, 'w').write(text)
    if shutil.which('clang-format') is not None:
        sp.run(['clang-format', '-i', DEST], check=True)
        print('wrote + formatted', DEST)
    else:
        print('wrote (clang-format not found)', DEST)


main()
