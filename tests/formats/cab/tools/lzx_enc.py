#!/usr/bin/env python3
"""Independent CAB/LZX test-vector generator for bale's cab reader tests.

Written from the public format descriptions ([MS-CAB] for the container,
[MS-PATCH] sections 2.1/2.3-2.7 for the base LZX bitstream) and intentionally
independent of bale's C++ decoder: agreement between this generator,
cabextract 1.11 (differential oracle) and the C++ decoder is the basis of
trust. No existing LZX implementation was read, copied or transliterated.

Usage: generate.py <outdir>
Writes *.cab fixtures plus *.bin expected folder streams.
"""
import heapq
import struct
import sys
import zlib

WINDOW_SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}


def slot_tables(num_slots):
    base = [0, 1, 2, 3]
    footer = [0, 0, 0, 0]
    for slot in range(4, num_slots):
        if slot <= 37:
            half = slot >> 1
            if slot & 1:
                base.append((1 << half) + (1 << (half - 1)))
            else:
                base.append(1 << half)
            footer.append(half - 1)
        else:
            base.append(262144 + (slot - 36) * 131072)
            footer.append(17)
    return base[:num_slots], footer[:num_slots]


class BitWriter:
    """MSB-first codes packed into little-endian 16-bit words."""

    def __init__(self):
        self.words = []
        self.cache = 0
        self.bits = 0
        self.total = 0

    def put(self, value, count):
        self.total += count
        while count > 0:
            room = 16 - self.bits
            take = count if count < room else room
            shift = count - take
            chunk = (value >> shift) & ((1 << take) - 1)
            self.cache = (self.cache << take) | chunk
            self.bits += take
            count -= take
            if self.bits == 16:
                self.words.append(self.cache)
                self.cache = 0
                self.bits = 0

    def align(self):
        self.put(0, 16 - self.bits if self.bits else 16)

    def align_frame(self):
        # NOTE: after each 32768th output byte the LZX bit buffer is padded
        # with 0-15 zero bits to a 16-bit boundary ([MS-CAB] cabinet blocks).
        self.put(0, (16 - self.bits) % 16)

    def bytes_written(self):
        return len(self.words) * 2 + (2 if self.bits else 0)

    def take_bytes(self):
        assert self.bits == 0
        out = bytearray()
        for w in self.words:
            out += struct.pack('<H', w)
        self.words = []
        return bytes(out)

    def finish(self):
        out = bytearray()
        for w in self.words:
            out += struct.pack('<H', w)
        if self.bits:
            out += struct.pack('<H', self.cache << (16 - self.bits))
        return bytes(out)


def huffman_lengths(freqs):
    order = [s for s in range(len(freqs)) if freqs[s] > 0]
    if not order:
        return [0] * len(freqs)
    if len(order) == 1:
        lengths = [0] * len(freqs)
        lengths[order[0]] = 1
        return lengths
    heap = [(freqs[s], s) for s in order]
    heapq.heapify(heap)
    nxt = len(freqs)
    tree = {}
    while len(heap) > 1:
        a = heapq.heappop(heap)
        b = heapq.heappop(heap)
        node = nxt
        nxt += 1
        tree[node] = (a[1], b[1])
        heapq.heappush(heap, (a[0] + b[0], node))
    lengths = [0] * len(freqs)

    def walk(node, depth):
        if node < len(freqs):
            lengths[node] = depth
            return
        left, right = tree[node]
        walk(left, depth + 1)
        walk(right, depth + 1)

    walk(heap[0][1], 0)
    assert max(lengths) <= 16, max(lengths)
    return lengths


def canonical_codes(lengths):
    maxlen = max(lengths) if lengths else 0
    count = [0] * (maxlen + 1)
    for doc in lengths:
        if doc:
            count[doc] += 1
    code = 0
    nxt = {}
    for ln in range(1, maxlen + 1):
        code = (code + (count[ln - 1] if ln - 1 < len(count) else 0)) << 1
        nxt[ln] = code
    codes = {}
    for sym in sorted(range(len(lengths)), key=lambda s: (lengths[s], s)):
        ln = lengths[sym]
        if ln:
            codes[sym] = (nxt[ln], ln)
            nxt[ln] += 1
    return codes


def ensure_two(freqs, spots):
    """Ensure at least two nonzero frequencies in an encoded tree section.

    Strict readers build a decode table per section (first-256 literals,
    match half, length tree, aligned tree) and reject degenerate sections,
    even when a section is unused ([MS-PATCH] 2.4 asks encoders for at least
    two codes per tree). Dummy frequency-1 entries keep the emitted section
    valid for picky readers without changing the payload: Huffman rebalances
    across the whole tree, so the Kraft sum stays valid unlike patching
    lengths after the fact.
    """
    own = list(freqs)
    have = [i for i, f in enumerate(own) if f > 0]
    if len(have) >= 2:
        return own
    if not have:
        own[spots[0]] = 1
        own[spots[1]] = 1
        return own
    for spot in spots:
        if spot != have[0]:
            own[spot] = 1
            return own
    raise AssertionError('ensure_two needs a spare spot')


class LzxEncoder:
    def __init__(self, window_bits=15, e8=False, e8_filesize=0):
        assert 15 <= window_bits <= 21
        self.num_slots = WINDOW_SLOTS[window_bits]
        self.base, self.footer = slot_tables(self.num_slots)
        self.window = 1 << window_bits
        self.e8 = e8
        self.e8_filesize = e8_filesize
        self.bw = BitWriter()
        self.wrote_header = False
        self.prev_main = [0] * (256 + 8 * self.num_slots)
        self.prev_len = [0] * 249

    def stream_header(self):
        assert not self.wrote_header
        self.wrote_header = True
        self.bw.put(1 if self.e8 else 0, 1)
        if self.e8:
            self.bw.put((self.e8_filesize >> 16) & 0xFFFF, 16)
            self.bw.put(self.e8_filesize & 0xFFFF, 16)

    @staticmethod
    def e8_forward(data, chunk_offset, filesize):
        data = bytearray(data)
        if len(data) > 6 and chunk_offset < 0x40000000:
            i = 0
            bound = len(data) - 6
            while i < bound:
                if data[i] == 0xE8:
                    disp = struct.unpack_from('<i', data, i + 1)[0]
                    target = chunk_offset + i + disp
                    if 0 <= target < filesize + chunk_offset:
                        if target >= filesize:
                            target = disp - filesize
                        struct.pack_into('<i', data, i + 1, target)
                    i += 4
                i += 1
        return bytes(data)

    def find_matches(self, data):
        table = {}
        out = []
        i, n = 0, len(data)
        while i < n:
            best_len, best_off = 0, 0
            if i + 3 <= n:
                key = data[i:i + 3]
                for pos in reversed(table.get(key, [])[-16:]):
                    off = i - pos
                    if off <= 0 or off > self.window - 3 or off > i:
                        continue
                    if off > self.window:
                        continue
                    ln = 0
                    frame_end = ((i // 32768) + 1) * 32768
                    cap = frame_end - i
                    if cap > 257:
                        cap = 257
                    while i + ln < n and ln < cap and data[pos + ln] == data[i + ln]:
                        ln += 1
                    if ln >= 2 and ln > best_len:
                        best_len, best_off = ln, off
                        if ln == 257:
                            break
                table.setdefault(data[i:i + 3], []).append(i)
            if best_len >= 2:
                out.append(('match', best_off, best_len))
                for j in range(1, best_len):
                    if i + j + 3 <= n:
                        table.setdefault(data[i + j:i + j + 3], []).append(i + j)
                i += best_len
            else:
                out.append(('lit', data[i]))
                i += 1
        return out

    def resolve(self, tokens, aligned):
        """Per-token resolved tuples; updates repeat state like a decoder."""
        r = [1, 1, 1]
        resolved = []
        for tok in tokens:
            if tok[0] == 'lit':
                resolved.append(('lit', tok[1]))
                continue
            _, off, ln = tok
            if off == r[0]:
                fmt, slot = 0, 0
            elif off == r[1]:
                fmt, slot = 1, 1
                r[0], r[1] = r[1], r[0]
            elif off == r[2]:
                fmt, slot = 2, 2
                r[0], r[2] = r[2], r[0]
            else:
                fmt = off + 2
                r[2], r[1], r[0] = r[1], r[0], off
                slot = next(s for s in range(self.num_slots)
                            if self.base[s] <= fmt < self.base[s] + (1 << self.footer[s]))
            foot = self.footer[slot]
            if ln <= 8:
                lh, lfoot = ln - 2, None
            else:
                lh, lfoot = 7, ln - 9
            if aligned and foot >= 3:
                verb = (fmt - self.base[slot]) >> 3
                vbits = foot - 3
                abits = (fmt - self.base[slot]) & 7
            else:
                verb = fmt - self.base[slot]
                vbits = foot
                abits = None
            resolved.append(('match', 256 + (slot << 3) + lh, lfoot, verb, vbits, abits))
        return resolved

    def emit_lengths(self, lengths, prev=None):
        if prev is None:
            prev = [0] * len(lengths)
        codes = []
        i, n = 0, len(lengths)
        while i < n:
            v = lengths[i]
            if v == 0:
                j = i
                while j < n and lengths[j] == 0:
                    j += 1
                run = j - i
                while run >= 20:
                    take = min(run, 51)
                    codes.append(18)
                    codes.append(('raw', 5, take - 20))
                    run -= take
                    i += take
                while run >= 4:
                    take = min(run, 19)
                    codes.append(17)
                    codes.append(('raw', 4, take - 4))
                    run -= take
                    i += take
                for _ in range(run):
                    codes.append((prev[i] - 0) % 17)
                    i += 1
                continue
            j = i
            while j < n and lengths[j] == v:
                j += 1
            run = j - i
            if run >= 4:
                done = 0
                while run - done >= 4:
                    take = 5 if run - done >= 5 else 4
                    codes.append(19)
                    codes.append(('raw', 1, take - 4))
                    codes.append((prev[i + done] - v) % 17)
                    done += take
                i += done
                for _ in range(run - done):
                    codes.append((prev[i] - v) % 17)
                    i += 1
                continue
            codes.append((prev[i] - v) % 17)
            i += 1
        freq = [0] * 20
        for c in codes:
            if isinstance(c, int):
                freq[c] += 1
        pre_lengths = huffman_lengths(freq)
        pre_codes = canonical_codes(pre_lengths)
        for doc in pre_lengths:
            self.bw.put(doc, 4)
        for c in codes:
            if isinstance(c, int):
                code, ln = pre_codes[c]
                self.bw.put(code, ln)
            else:
                _, bits, val = c
                self.bw.put(val, bits)

    def block_uncompressed(self, data, r0=1, r1=1, r2=1):
        bw = self.bw
        bw.put(3, 3)
        size = len(data)
        bw.put((size >> 16) & 0xFF, 8)
        bw.put((size >> 8) & 0xFF, 8)
        bw.put(size & 0xFF, 8)
        bw.align()
        head = bw.take_bytes()
        raw = struct.pack('<III', r0, r1, r2) + bytes(data)
        if len(data) & 1:
            raw += b'\x00'
        return head + raw

    def block_coded(self, data, aligned):
        tokens = self.find_matches(data)
        resolved = self.resolve(tokens, aligned)
        main_freq = [0] * (256 + 8 * self.num_slots)
        len_freq = [0] * 249
        al_freq = [0] * 8
        for item in resolved:
            if item[0] == 'lit':
                main_freq[item[1]] += 1
            else:
                _, m, lfoot, _, _, abits = item
                main_freq[m] += 1
                if lfoot is not None:
                    len_freq[lfoot] += 1
                if abits is not None:
                    al_freq[abits] += 1
        main_freq = ensure_two(main_freq[:256], (0, 1)) + \
            ensure_two(main_freq[256:], (0, 1))
        len_freq = ensure_two(len_freq, (0, 1))
        al_freq = ensure_two(al_freq, (0, 1)) if aligned else al_freq
        main_lengths = huffman_lengths(main_freq)
        length_lengths = huffman_lengths(len_freq)
        aligned_lengths = huffman_lengths(al_freq) if aligned else None
        bw = self.bw
        bw.put(2 if aligned else 1, 3)
        size = len(data)
        bw.put((size >> 16) & 0xFF, 8)
        bw.put((size >> 8) & 0xFF, 8)
        bw.put(size & 0xFF, 8)
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
        trace = []
        produced = 0
        base_bits = bw.total
        next_frame = 32768
        for index, item in enumerate(resolved):
            if item[0] == 'lit':
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
            if produced >= next_frame:
                bw.align_frame()
                next_frame += 32768
            trace.append((produced, bw.total - base_bits))
        self.trace = trace
        self.trace_base = base_bits
