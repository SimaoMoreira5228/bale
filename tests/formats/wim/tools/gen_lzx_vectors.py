#!/usr/bin/env python3
"""Bakes hermetic WIM LZX vectors into lzx_vectors.hpp.

Each vector is one file's worth of chunks: stored LZX bytes plus the plain
bytes (in full under 512 B, else size plus FNV-1a for a formula-built plain
the C++ test reconstructs). Encoding runs through lzx_wim_enc, which shares
its Huffman/token core with the triple-checked CAB generator and only swaps
the framing to WIM. Ground truth for the framing itself comes from real
wimlib-imagex goldens, not from these vectors.

Usage: gen_lzx_vectors.py (writes ../lzx_vectors.hpp)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lzx_wim_enc import encode_chunk

HERE = os.path.dirname(os.path.abspath(__file__))


def fnv(data):
    h = 0xCBF29CE484222325
    for unit in data:
        h ^= unit
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def formula(length):
    return bytes((i * 31 + 7) % 251 for i in range(length))


def stamp(data, at, payload):
    data = bytearray(data)
    data[at:at + len(payload)] = payload
    return bytes(data)


def e8call(disp):
    return b"\xe8" + struct.pack("<i", disp)


FILL = b"0123456789ABCDEF"


def build_raw_mid_chunk():
    # NOTE: a lone raw block never fits the chunk size rule (its framing
    # overhead exceeds the payload), so the raw block with E8 and an odd
    # pad rides as the second block of a full chunk.
    para = b"The quick brown fox jumps over the lazy dog. 0123456789\n"
    head = bytearray(para * 584 + b"0123456789ABCDEFGHJ")
    assert len(head) == 32768 - 45, len(head)
    for at in (1000, 20000):
        head = bytearray(stamp(head, at, e8call(-(at % 251))))
    tail = bytearray(b"header-0123456789" + e8call(-8) + b"tail-pad-0123456789\x00abc")
    assert len(tail) == 45 and len(tail) & 1
    plain = bytes(head) + bytes(tail)
    return plain, [encode_chunk(
        plain, e8=True,
        pieces=[("coded", False, 0, len(head)), ("raw", False, len(head), len(plain))],
    )]


def build_coded_split():
    para = b"The quick brown fox jumps over the lazy dog. 0123456789\n"
    head = bytearray(para * 585 + b"01234567")
    assert len(head) == 32768, len(head)
    for at in (1000, 20000, 30000, 32700):
        head = bytearray(stamp(head, at, e8call(-(at % 251))))
    head = bytearray(stamp(head, 32768 - 16, FILL))
    tail = bytearray(para * 4 + b"0123456789ABCDEF")
    assert len(tail) == 240, len(tail)
    tail = bytearray(stamp(tail, 40, e8call(-7)))
    tail = bytearray(stamp(tail, len(tail) - 16, FILL))
    plain = bytes(head) + bytes(tail)
    return plain, [
        encode_chunk(bytes(head), e8=True, pieces=[("coded", False, 0, len(head))]),
        encode_chunk(bytes(tail), e8=True, pieces=[("coded", False, 0, len(tail))]),
    ]


def build_verbatim_small():
    plain = (
        b"The quick brown fox jumps. " * 6
        + b"repeat-repeat-repeat!"
        + e8call(-40)
        + b"end of the small verbatim vector. "
        + b"pack my box with five dozen liquor jugs. "
    )
    assert len(plain) < 512
    return plain, [encode_chunk(plain, e8=True, pieces=[("coded", False, 0, len(plain))])]


def build_aligned_cross64k():
    plain = bytearray(formula(50000))
    for slot in range(1, 8):
        plain = bytearray(stamp(plain, slot * 5000, plain[0:1000]))
    for at in (1000, 20000, 40000):
        plain = bytearray(stamp(plain, at, e8call(-(at % 251))))
    plain = bytearray(stamp(plain, len(plain) - 16, FILL))
    plain = bytes(plain)
    return plain, [encode_chunk(plain, window_bits=16, e8=True,
                                pieces=[("coded", True, 0, len(plain))])]


def build_mixed_blocks():
    raw = formula(120)
    near = b"lorem ipsum dolor sit amet " * 24
    assert len(near) == 648
    far = bytearray(formula(4000))
    for slot in range(1, 4):
        far = bytearray(stamp(far, slot * 1200, near[:400]))
    far = bytearray(stamp(far, len(far) - 16, FILL))
    plain = raw + near + bytes(far)
    return plain, [encode_chunk(
        plain, e8=True,
        pieces=[("raw", False, 0, len(raw)), ("coded", False, len(raw), len(raw) + len(near)),
                ("coded", True, len(raw) + len(near), len(plain))],
    )]


def build_e8_edges():
    # NOTE: same lone-raw-block rule as above: the edge payload rides as the
    # second block, and its last E8 starts in the last 10 bytes of the chunk.
    para = b"The quick brown fox jumps over the lazy dog. 0123456789\n"
    head = bytearray(para * 582 + b"0123456789ABCDEFGHI")
    assert len(head) == 32768 - 157, len(head)
    core = [
        e8call(0),
        b"ab",
        e8call(11999999),
        b"cd",
        e8call(12000000 - 40),
        b"ef",
        b"\xe8\x00\x1b\xb7\x00",  # NOTE: value 12000000 stays untouched.
        b"gh",
        b"\xe8\xff\xff\xff\x7f",  # NOTE: huge positive stays untouched.
        b"ij0123456789 tail!",
    ]
    tail = bytearray(b".".join(core))
    tail += b"\xe8\x01\x02\x03\x04"
    while len(tail) < 156 or len(tail) % 2 == 0:
        tail = tail[:-5] + b"." + tail[-5:]
    assert len(tail) == 157, len(tail)
    assert tail.index(b"\x01\x02\x03\x04") > len(tail) - 10
    plain = bytes(head) + bytes(tail)
    return plain, [encode_chunk(
        plain, e8=True,
        pieces=[("coded", False, 0, len(head)), ("raw", False, len(head), len(plain))],
    )]


def emit_array(name, data, provisional):
    provisional.append(f"inline constexpr std::array<std::byte, {len(data)}> {name} = {{")
    row = []
    for index, unit in enumerate(data):
        row.append(f"std::byte{{0x{unit:02X}}}")
        if len(row) == 12:
            provisional.append("    " + ", ".join(row) + ",")
            row = []
    if row:
        provisional.append("    " + ", ".join(row) + ",")
    provisional.append("};")


def main():
    vectors = {
        "raw_mid_chunk": build_raw_mid_chunk(),
        "coded_split": build_coded_split(),
        "verbatim_small": build_verbatim_small(),
        "aligned_cross64k": build_aligned_cross64k(),
        "mixed_blocks": build_mixed_blocks(),
        "e8_edges": build_e8_edges(),
    }
    provisional = [
        "// NOTE: generated by tests/formats/wim/tools/gen_lzx_vectors.py; do not edit.",
        "// Hermetic WIM LZX chunks: framing-only encoder output, ground truth is",
        "// the wimlib-imagex goldens plus the plains below.",
        "#pragma once",
        "",
        "#include <array>",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "namespace bale::wim::test {",
        "",
    ]
    for name, (plain, stored) in vectors.items():
        tag = name
        for index, chunk in enumerate(stored):
            emit_array(f"kLzx{tag}_c{index}", chunk, provisional)
        provisional.append(f"inline constexpr std::size_t kLzx{tag}_chunks = {len(stored)};")
        if len(plain) <= 512:
            emit_array(f"kLzx{tag}_plain", plain, provisional)
        else:
            provisional.append(
                f"inline constexpr std::size_t kLzx{tag}_plainSize = {len(plain)};"
            )
            provisional.append(
                f"inline constexpr std::uint64_t kLzx{tag}_plainHash = 0x{fnv(plain):016X}ULL;"
            )
        provisional.append("")
    provisional.append("}")
    provisional.append("")
    path = os.path.join(HERE, "..", "lzx_vectors.hpp")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(provisional))
    for name, (plain, stored) in vectors.items():
        print(f"{name}: plain={len(plain)} stored={[len(c) for c in stored]} "
              f"hash=0x{fnv(plain):016X}")


if __name__ == "__main__":
    main()
