#!/usr/bin/env python3
"""CAB container writer + fixture vectors (see lzx_enc.py provenance note)."""
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lzx_enc import LzxEncoder

MSCF = b'MSCF'


def dos_datetime(year, month, day, hour, minute, second):
    date = ((year - 1980) << 9) | (month << 5) | day
    time = (hour << 11) | (minute << 5) | (second // 2)
    return date, time


def checksum(cb_data, cb_uncomp, payload):
    # Real CFDATA checksum (reverse-fit against cabextract 1.11 with
    # chosen-plaintext probes): word1 ^ LE32 payload words ^ BE residue.
    word = ((cb_uncomp << 16) | cb_data) & 0xFFFFFFFF
    for i in range(0, len(payload) & ~3, 4):
        word ^= struct.unpack_from('<I', payload, i)[0]
    tail = payload[len(payload) & ~3:]
    residue = 0
    for byte in tail:
        residue = (residue << 8) | byte
    return (word ^ residue) & 0xFFFFFFFF


class FolderSpec:
    def __init__(self, method, window_bits=15):
        self.method = method
        self.window_bits = window_bits
        self.blocks = []  # (payload_bytes, uncompressed_bytes)


class FileSpec:
    def __init__(self, name, folder, offset, size, date, time, attribs=0x20):
        self.name = name
        self.folder = folder
        self.offset = offset
        self.size = size
        self.date = date
        self.time = time
        self.attribs = attribs


def build_cab(folders, files, flags=0, prev_names=(), next_names=(),
              reserve=(0, 0, 0), version=(3, 1), set_id=0x1234, index=0):
    cb_cfheader, cb_cffolder, cb_cfdata = reserve
    head = bytearray()
    head += MSCF
    head += struct.pack('<I', 0)
    head += struct.pack('<I', 0)  # cbCabinet placeholder
    head += struct.pack('<I', 0)
    head += struct.pack('<I', 0)  # coffFiles placeholder
    head += struct.pack('<I', 0)
    head += struct.pack('BB', version[0], version[1])
    head += struct.pack('<HHHH', len(folders), len(files), flags, set_id)
    head += struct.pack('<H', index)
    if flags & 4:
        head += struct.pack('<HBB', cb_cfheader, cb_cffolder, cb_cfdata)
        head += b'\x00' * cb_cfheader
    for name in prev_names:
        head += name + b'\x00'
    for name in next_names:
        head += name + b'\x00'
    folder_pos = len(head)
    for folder in folders:
        head += struct.pack('<IHH', 0, len(folder.blocks),
                            folder.method | (folder.window_bits << 8
                                             if folder.method in (2, 3) else 0))
        head += b'\x00' * cb_cffolder
    files_pos = len(head)
    file_table = bytearray()
    for f in files:
        if isinstance(f.folder, int):
            ifolder = f.folder
        else:
            ifolder = f.folder
        file_table += struct.pack('<IIHHHH', f.size, f.offset, ifolder,
                                  f.date, f.time, f.attribs)
        file_table += f.name + b'\x00'
    data_pos = files_pos + len(file_table)
    # patch folder coffCabStart + files offset
    out = bytearray(head) + file_table
    struct.pack_into('<I', out, 16, files_pos)
    coff = data_pos
    cursor = folder_pos
    for folder in folders:
        struct.pack_into('<I', out, cursor, coff)
        cursor += 8 + cb_cffolder
        for payload, uncomp in folder.blocks:
            out += struct.pack('<IHH', checksum(len(payload), uncomp, payload),
                               len(payload), uncomp)
            out += b'\x00' * cb_cfdata
            out += payload
            coff += 8 + cb_cfdata + len(payload)
    struct.pack_into('<I', out, 8, len(out))
    assert len(out) == coff
    return bytes(out)


def mszip_blocks(data, chunk=32768):
    blocks = []
    for i in range(0, max(len(data), 1), chunk):
        piece = data[i:i + chunk]
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        raw = comp.compress(piece) + comp.flush()
        blocks.append((b'CK' + raw, len(piece)))
    return blocks


def split_stream(stream_bytes, hdr_bits, trace, cuts):
    bounds = []
    for cut in cuts:
        byte_at = None
        for out_b, bitpos in trace:
            if hdr_bits + bitpos <= 0:
                continue
            if out_b <= cut:
                byte_at = (hdr_bits + bitpos + 7) // 8
            else:
                break
        assert byte_at is not None
        bounds.append((byte_at, cut))
    blocks = []
    prev_byte, prev_out = 0, 0
    for byte_at, cut in bounds:
        assert byte_at > prev_byte and cut > prev_out
        blocks.append((stream_bytes[prev_byte:byte_at], cut - prev_out))
        prev_byte, prev_out = byte_at, cut
    blocks.append((stream_bytes[prev_byte:], None))
    return blocks


def e8_test_bytes():
    # x86-ish: CALL rel32 with valid displacement + E8 inside operand + tail E8s
    out = bytearray(b'\x90' * 64)
    out[16] = 0xE8
    struct.pack_into('<i', out, 17, 0x40)  # target = 16+17... within file
    out[48] = 0xE8
    struct.pack_into('<i', out, 49, -8)
    out += b'A' * 20
    out += b'\xE8\x01\x02\xE8\x04'  # E8 inside operand region
    out += b'\x90' * 30
    return bytes(out)


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    saved = {}

    def save(name, cab, folder_streams):
        with open(os.path.join(outdir, name + '.cab'), 'wb') as f:
            f.write(cab)
        for i, stream in enumerate(folder_streams):
            with open(os.path.join(outdir, f'{name}.f{i}.bin'), 'wb') as f:
                f.write(stream)
        saved[name] = cab

    text = (b'The quick brown fox jumps over the lazy dog. ' * 40 +
            b'Pack my box with five dozen liquor jugs! ' * 40)
    binary = bytes((i * 31 + 7) & 0xFF for i in range(9000))
    x86 = e8_test_bytes() * 24

    # 1. stored, two files + directory + empty
    d, t = dos_datetime(2021, 5, 4, 12, 30, 10)
    folders = [FolderSpec(0)]
    folders[0].blocks = [(b'hello stored world', 18), (binary, len(binary))]
    files = [
        FileSpec(b'docs\\hello.txt', 0, 0, 18, d, t),
        FileSpec(b'docs', 0, 0, 0, d, t, attribs=0x10),
        FileSpec(b'blob.bin', 0, 18, len(binary), d, t, attribs=0x21),
        FileSpec(b'empty.txt', 0, 18 + len(binary), 0, d, t),
    ]
    save('stored_basic', build_cab(folders, files),
         [b'hello stored world' + binary])

    # 2. mszip, same logical layout
    stream = text + binary
    folders = [FolderSpec(1)]
    folders[0].blocks = mszip_blocks(stream)
    files = [
        FileSpec(b'a\\text.txt', 0, 0, len(text), d, t),
        FileSpec(b'a\\blob.bin', 0, len(text), len(binary), d, t),
    ]
    save('mszip_basic', build_cab(folders, files), [stream])

    # 3. lzx uncompressed-block only
    enc = LzxEncoder()
    enc.stream_header()
    stream_bytes = enc.block_uncompressed(text[:5000])
    folders = [FolderSpec(3)]
    folders[0].blocks = [(stream_bytes, len(text[:5000]))]
    files = [FileSpec(b'u\\raw.txt', 0, 0, len(text[:5000]), d, t)]
    save('lzx_uncompressed', build_cab(folders, files), [text[:5000]])

    # 4. lzx verbatim: two LZX blocks aligned to two CFDATA blocks
    rep = (b'abcdefgh' * 300 + b'ABCDEFGH' * 300 + b'abcdefgh' * 300 +
           b'0123456789' * 100 + b'abcdefgh' * 100)
    enc = LzxEncoder()
    enc.stream_header()
    mark = enc.bw.total
    enc.block_coded(rep[:4000], aligned=False)
    cut_bytes = (enc.bw.total + 7) // 8
    enc.block_coded(rep[4000:], aligned=False)
    stream_bytes = enc.bw.finish()
    folders = [FolderSpec(3)]
    folders[0].blocks = [(stream_bytes[:cut_bytes], 4000),
                         (stream_bytes[cut_bytes:], len(rep) - 4000)]
    files = [FileSpec(b'v\\rep.txt', 0, 0, len(rep), d, t)]
    save('lzx_verbatim', build_cab(folders, files), [rep])

    # 4b. lzx verbatim split mid-block at an odd byte (continuity check)
    enc = LzxEncoder()
    enc.stream_header()
    hdr_bits = enc.bw.total
    enc.block_coded(rep, aligned=False)
    stream_bytes = enc.bw.finish()
    want_bit = (hdr_bits + enc.trace[-1][1]) // 2
    want_byte = want_bit // 8
    if (want_byte & 1) == 0:
        want_byte += 1
    want_byte -= 1  # force odd
    assert want_byte >= 1
    produced = 0
    for out_b, bitpos in enc.trace:
        if hdr_bits + bitpos <= want_byte * 8:
            produced = out_b
    assert 0 < produced < len(rep)
    folders = [FolderSpec(3)]
    folders[0].blocks = [(stream_bytes[:want_byte], produced),
                         (stream_bytes[want_byte:], len(rep) - produced)]
    files = [FileSpec(b'v\\rep2.txt', 0, 0, len(rep), d, t)]
    save('lzx_split', build_cab(folders, files), [rep])

    # micro vectors for fault isolation
    micros = []
    enc = LzxEncoder()
    enc.stream_header()
    enc.block_coded(b'hello world, this is unique text! no repeats here...?',
                    aligned=False)
    micros.append(('micro_lit', enc.bw.finish(), b'hello world, this is unique text! no repeats here...?'))
    enc = LzxEncoder()
    enc.stream_header()
    enc.block_coded(b'ABCABCABCABC', aligned=False)
    micros.append(('micro_match', enc.bw.finish(), b'ABCABCABCABC'))
    for mname, mstream, mdata in micros:
        folders = [FolderSpec(3)]
        folders[0].blocks = [(mstream, len(mdata))]
        files = [FileSpec(mname.encode() + b'.txt', 0, 0, len(mdata), d, t)]
        save(mname, build_cab(folders, files), [mdata])
    enc = LzxEncoder()
    enc.stream_header()
    enc.block_coded(rep, aligned=True)
    stream_bytes = enc.bw.finish()
    folders = [FolderSpec(3)]
    folders[0].blocks = [(stream_bytes, len(rep))]
    files = [FileSpec(b'a\\al.txt', 0, 0, len(rep), d, t)]
    save('lzx_aligned', build_cab(folders, files), [rep])

    # 6. lzx with E8 translation
    enc = LzxEncoder(e8=True, e8_filesize=len(x86))
    enc.stream_header()
    pre = LzxEncoder.e8_forward(x86, 0, len(x86))
    enc.block_coded(pre, aligned=False)
    stream_bytes = enc.bw.finish()
    folders = [FolderSpec(3)]
    folders[0].blocks = [(stream_bytes, len(x86))]
    files = [FileSpec(b'e\\code.bin', 0, 0, len(x86), d, t)]
    save('lzx_e8', build_cab(folders, files), [x86])

    # 7. lzx 257-length match + window 21 header + multi-frame E8 (>64KB)
    para = (b'The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs! ' * 12 + b'\n') * 60
    big = para + b'Z' * 9000 + para[:20000]
    enc = LzxEncoder(window_bits=21, e8=True, e8_filesize=len(big))
    enc.stream_header()
    pre = LzxEncoder.e8_forward(big[:32768], 0, len(big)) + \
        LzxEncoder.e8_forward(big[32768:65536], 32768, len(big)) + \
        LzxEncoder.e8_forward(big[65536:], 65536, len(big))
    enc.block_coded(pre, aligned=True)
    stream_bytes = enc.bw.finish()
    hdr_bits = 1 + 32
    parts = split_stream(stream_bytes, hdr_bits, enc.trace, [32768, 65536])
    folders = [FolderSpec(3, window_bits=21)]
    total = 0
    for payload, uncomp in parts:
        if uncomp is None:
            uncomp = len(big) - total
        folders[0].blocks.append((payload, uncomp))
        total += uncomp
    assert total == len(big)
    files = [FileSpec(b'big\\big.bin', 0, 0, len(big), d, t)]
    save('lzx_big21', build_cab(folders, files), [big])

    # 8. spanning set member (refusal): reuse stored payload, flag next + FFFE
    folders = [FolderSpec(0)]
    folders[0].blocks = [(b'part', 4)]
    files = [FileSpec(b'split.bin', 0xFFFE, 0, 100, d, t)]
    save('span_next', build_cab(folders, files, flags=0x0002,
                                next_names=(b'disk2.cab', b'Disk 2')), [b'part'])

    # 9. quantum method (refusal)
    folders = [FolderSpec(2, window_bits=16)]
    folders[0].blocks = [(b'\x00' * 16, 16)]
    files = [FileSpec(b'q.bin', 0, 0, 16, d, t)]
    save('quantum', build_cab(folders, files), [b'\x00' * 16])

    # 10. unknown method (refusal)
    folders = [FolderSpec(7)]
    folders[0].blocks = [(b'\x00' * 8, 8)]
    files = [FileSpec(b'u.bin', 0, 0, 8, d, t)]
    save('unknown_method', build_cab(folders, files), [b'\x00' * 8])

    # 11. aligned block exercising slots 8/9 (formatted offsets 16-31):
    # matches at offsets 18..33 take the verbatim+aligned path only when the
    # footer split applies at footer >= 3 (MS-PATCH 2.6.3).
    pad = bytes((i * 37 + 11) & 0xFF for i in range(64))
    seg = b'0123456789ABCDEFGHIJ'  # 20 bytes; repeat at distance 20/22
    data89 = pad + seg + b'xx' + seg + pad
    enc = LzxEncoder()
    enc.stream_header()
    enc.block_coded(data89, aligned=True)
    stream_bytes = enc.bw.finish()
    folders = [FolderSpec(3)]
    folders[0].blocks = [(stream_bytes, len(data89))]
    files = [FileSpec(b'a\\s89.bin', 0, 0, len(data89), d, t)]
    save('lzx_slots89', build_cab(folders, files), [data89])

    # 12. all-literal LZX block: empty match half and unused length tree gain
    # dummy symbols so strict readers accept the trees.
    litdata = bytes((i * 131 + 17) & 0xFF for i in range(64))
    enc = LzxEncoder()
    enc.stream_header()
    enc.block_coded(litdata, aligned=False)
    stream_bytes = enc.bw.finish()
    folders = [FolderSpec(3)]
    folders[0].blocks = [(stream_bytes, len(litdata))]
    files = [FileSpec(b'l\\lit.bin', 0, 0, len(litdata), d, t)]
    save('lzx_literals', build_cab(folders, files), [litdata])

    # 13. odd-size uncompressed block (trailing pad byte in the raw block).
    oddraw = text[:3439]
    enc = LzxEncoder()
    enc.stream_header()
    stream_bytes = enc.block_uncompressed(oddraw)
    folders = [FolderSpec(3)]
    folders[0].blocks = [(stream_bytes, len(oddraw))]
    files = [FileSpec(b'u\\odd.txt', 0, 0, len(oddraw), d, t)]
    save('lzx_oddraw', build_cab(folders, files), [oddraw])

    # 14. two folders (stored + LZX) holding interleaved files: exercises
    # per-folder session switching in the reader.
    enc = LzxEncoder()
    enc.stream_header()
    enc.block_coded(rep[:1000], aligned=False)
    lzxpart = enc.bw.finish()
    folders = [FolderSpec(0), FolderSpec(3)]
    folders[0].blocks = [(b'second-folder-first', 19)]
    folders[1].blocks = [(lzxpart, 1000)]
    files = [
        FileSpec(b'm\\one.txt', 1, 0, 1000, d, t),
        FileSpec(b'm\\two.txt', 0, 0, 19, d, t),
    ]
    save('multi_folder', build_cab(folders, files), [b'second-folder-first', rep[:1000]])

    print('wrote', sorted(saved))


if __name__ == '__main__':
    main(sys.argv[1])
