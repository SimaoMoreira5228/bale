#!/usr/bin/env python3
"""WIM-framed LZX test-vector encoder for bale's WIM reader tests.

Built from the same public descriptions as the CAB encoder it extends
(tests/formats/cab/tools/lzx_enc.py: [MS-PATCH] 2.1/2.3-2.7 base bitstream,
[MS-WIM] chunk layout, and the public WIM LZX notes): no stream header, 1
flag bit plus 16 size bits (24 at 64 KiB windows and above), unconditional
E8 with filesize 12000000 applied per chunk, no 32 KiB frame alignment, and
no tree delta across chunks. Huffman/token machinery is inherited unchanged
from the CAB encoder; only the framing differs.

Usage: imported by gen_lzx_vectors.py. Not read by any test directly.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "cab", "tools"))

from lzx_enc import LzxEncoder

WIM_E8_FILESIZE = 12000000


class WimLzxEncoder(LzxEncoder):
    def __init__(self, window_bits=15):
        super().__init__(window_bits=window_bits)
        # NOTE: one encoder per chunk: no stream header, no cross-chunk
        # tree delta, and the E8 base restarts at zero for every chunk.
        self.wrote_header = True

    @staticmethod
    def e8_forward_wim(data):
        # NOTE: WIM E8 preprocessing with the fixed 12000000 filesize and a
        # zero chunk base. Unlike the CAB variant, a target past the filesize
        # wraps (compensating translation) instead of skipping.
        data = bytearray(data)
        if len(data) <= 10:
            return bytes(data)
        index = 0
        bound = len(data) - 10
        while index < bound:
            if data[index] == 0xE8:
                disp = struct.unpack_from("<i", data, index + 1)[0]
                if -index <= disp < WIM_E8_FILESIZE:
                    if disp < WIM_E8_FILESIZE - index:
                        target = disp + index
                    else:
                        target = disp - WIM_E8_FILESIZE
                    struct.pack_into("<i", data, index + 1, target)
                index += 5
            else:
                index += 1
        return bytes(data)

    def block_header(self, block_type, size):
        bw = self.bw
        bw.put(block_type, 3)
        if size == 32768:
            bw.put(1, 1)
        else:
            bw.put(0, 1)
            if self.window >= 65536:
                bw.put((size >> 16) & 0xFF, 8)
            bw.put((size >> 8) & 0xFF, 8)
            bw.put(size & 0xFF, 8)

    def block_uncompressed(self, data, r0=1, r1=1, r2=1):
        import struct

        bw = self.bw
        self.block_header(3, len(data))
        bw.align()
        head = bw.take_bytes()
        raw = struct.pack("<III", r0, r1, r2) + bytes(data)
        if len(data) & 1:
            raw += b"\x00"
        return head + raw

    def block_coded(self, data, aligned):
        tokens = self.find_matches(data)
        resolved = self.resolve(tokens, aligned)
        main_freq = [0] * (256 + 8 * self.num_slots)
        len_freq = [0] * 249
        al_freq = [0] * 8
        for item in resolved:
            if item[0] == "lit":
                main_freq[item[1]] += 1
            else:
                _, m, lfoot, _, _, abits = item
                main_freq[m] += 1
                if lfoot is not None:
                    len_freq[lfoot] += 1
                if abits is not None:
                    al_freq[abits] += 1
        from lzx_enc import (
            canonical_codes,
            ensure_two,
            huffman_lengths,
        )

        main_freq = ensure_two(main_freq[:256], (0, 1)) + ensure_two(
            main_freq[256:], (0, 1)
        )
        len_freq = ensure_two(len_freq, (0, 1))
        al_freq = ensure_two(al_freq, (0, 1)) if aligned else al_freq
        main_lengths = huffman_lengths(main_freq)
        length_lengths = huffman_lengths(len_freq)
        aligned_lengths = huffman_lengths(al_freq) if aligned else None
        bw = self.bw
        self.block_header(2 if aligned else 1, len(data))
        if aligned:
            for doc in aligned_lengths:
                bw.put(doc, 3)
            aligned_codes = canonical_codes(aligned_lengths)
        self.emit_lengths(main_lengths[:256], self.prev_main[:256])
        self.emit_lengths(main_lengths[256:], self.prev_main[256:])
        self.emit_lengths(length_lengths, self.prev_len)
        self.prev_main = list(main_lengths)
        self.prev_len = list(length_lengths)
        main_codes = canonical_codes(main_lengths)
        length_codes = canonical_codes(length_lengths)
        produced = 0
        for item in resolved:
            if item[0] == "lit":
                code, ln = main_codes[item[1]]
                bw.put(code, ln)
                produced += 1
            else:
                _, m, lfoot, verb, vbits, abits = item
                code, ln = main_codes[m]
                bw.put(code, ln)
                if lfoot is not None:
                    code2, ln2 = length_codes[lfoot]
                    bw.put(code2, ln2)
                if vbits:
                    bw.put(verb, vbits)
                if abits is not None:
                    code3, ln3 = aligned_codes[abits]
                    bw.put(code3, ln3)
                produced += (lfoot + 9) if lfoot is not None else (m & 7) + 2
        assert produced == len(data)


def encode_chunk(data, window_bits=15, e8=True, pieces=None):
    """Encode one WIM chunk; pieces lists (kind, aligned, start, end) spans.

    E8 runs over the whole chunk first, so span offsets address the
    translated bytes, exactly like the decoder's per-chunk undo scope.
    """
    if e8:
        data = WimLzxEncoder.e8_forward_wim(bytes(data))
    else:
        data = bytes(data)
    enc = WimLzxEncoder(window_bits=window_bits)
    out = bytearray()
    if pieces is None:
        pieces = [("coded", False, 0, len(data))]
    for kind, aligned, start, end in pieces:
        span = data[start:end]
        if kind == "raw":
            out += enc.block_uncompressed(bytes(span))
        else:
            enc.block_coded(bytes(span), aligned)
    out += enc.bw.finish()
    return bytes(out)
