"""Writes the deterministic libFuzzer seed corpora under tests/fuzz/corpus/<target>/."""

import gzip
import io
import shutil
import struct
import sys
import tarfile
import zipfile
import zlib
from compression import zstd
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "reference"))
import bale_reference as ref  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent / "tests" / "fuzz" / "corpus"
FIXED_TIME = 1700000000
DOS_TIME = (2023, 11, 14, 22, 13, 20)

LZ4_TEXT = (
    b"bale lz4 golden vector, bale lz4 golden vector, bale lz4 golden vector, golden end\n"
    b"stored block\n"
)
LZ4_FRAME = bytes.fromhex(
    "04224d1868406000000000000000e729000000ff0962616c65206c7a3420676f6c64656e20766563746f722c"
    "2018001db0676f6c64656e20656e640a0d00008073746f72656420626c6f636b0a00000000"
)

DEFLATE_TEXT = b"bale bale bale: golden deflate vector, golden deflate vector!\n"


def raw_deflate(data):
    packer = zlib.compressobj(9, zlib.DEFLATED, -15)
    return packer.compress(data) + packer.flush()


def zstd_frame(data, checksum=False):
    options = {
        zstd.CompressionParameter.compression_level: 3,
        zstd.CompressionParameter.checksum_flag: int(checksum),
    }
    return zstd.compress(data, options=options)


def trimmed_tar(build, tar_format):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tar_format) as archive:
        build(archive)
    data = buffer.getvalue().rstrip(b"\0")
    data += b"\0" * (-len(data) % 512)
    return data + b"\0" * 1024


def tar_member(archive, name, kind=tarfile.REGTYPE, data=b"", link="", **extra):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mtime = FIXED_TIME
    info.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
    info.uid = 1000
    info.gid = 1000
    info.uname = "bale"
    info.gname = "bale"
    info.linkname = link
    info.size = len(data)
    info.pax_headers = extra.get("pax", {})
    archive.addfile(info, io.BytesIO(data) if data else None)


def tar_tree(archive):
    tar_member(archive, "d", tarfile.DIRTYPE)
    tar_member(archive, "d/f", data=b"hello\n")
    tar_member(archive, "d/l", tarfile.SYMTYPE, link="f")
    tar_member(archive, "d/h", tarfile.LNKTYPE, link="d/f")


def tar_long(archive):
    tar_member(archive, "long/" + "n" * 120, data=b"long name\n")
    tar_member(archive, "s", tarfile.SYMTYPE, link="t" * 120)


def tar_pax(archive):
    tar_member(archive, "p" * 110, data=b"pax\n", pax={"mtime": "1700000000.25", "uid": "70000"})
    tar_member(archive, "dev", tarfile.FIFOTYPE)


def tar_corpus():
    return {
        "ustar.tar": trimmed_tar(tar_tree, tarfile.USTAR_FORMAT),
        "gnu.tar": trimmed_tar(tar_long, tarfile.GNU_FORMAT),
        "pax.tar": trimmed_tar(tar_pax, tarfile.PAX_FORMAT),
    }


def zip_bytes(build, **options):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", **options) as archive:
        build(archive)
    return buffer.getvalue()


def zip_member(archive, name, data, method=zipfile.ZIP_STORED, extra=b"", **write_options):
    info = zipfile.ZipInfo(name, DOS_TIME)
    info.compress_type = method
    info.external_attr = (0o100644 << 16) if not name.endswith("/") else (0o40755 << 16)
    info.create_system = 3
    info.extra = extra
    archive.writestr(info, data, **write_options)


def zip_plain(archive):
    zip_member(archive, "d/", b"")
    zip_member(archive, "d/stored.txt", b"stored\n")
    zip_member(archive, "d/deflated.txt", DEFLATE_TEXT * 4, zipfile.ZIP_DEFLATED)
    archive.comment = b"bale"


def zip_extras(archive):
    timestamp = struct.pack("<HHBI", 0x5455, 5, 1, FIXED_TIME)
    zip_member(archive, "café.txt", b"utf-8 name\n", extra=timestamp)


def zip_forced64(archive):
    with archive.open(zipfile.ZipInfo("big.txt", DOS_TIME), "w", force_zip64=True) as member:
        member.write(b"zip64\n")


def zip_corpus():
    return {
        "plain.zip": zip_bytes(zip_plain),
        "extras.zip": zip_bytes(zip_extras),
        "zip64.zip": zip_bytes(zip_forced64),
    }


def gzip_member(data, name=None, comment=None, extra=None, header_crc=False):
    flags = 0
    header = bytearray(b"\x1f\x8b\x08\x00" + struct.pack("<I", 0) + b"\x00\x03")
    tail = b""
    if extra is not None:
        flags |= 0x04
        tail += struct.pack("<H", len(extra)) + extra
    if name is not None:
        flags |= 0x08
        tail += name + b"\0"
    if comment is not None:
        flags |= 0x10
        tail += comment + b"\0"
    header[3] = flags | (0x02 if header_crc else 0)
    header += tail
    if header_crc:
        header += struct.pack("<H", zlib.crc32(header) & 0xFFFF)
    trailer = struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)
    return bytes(header) + raw_deflate(data) + trailer


def gzip_corpus():
    return {
        "plain.gz": gzip.compress(DEFLATE_TEXT, mtime=0),
        "fields.gz": gzip_member(
            DEFLATE_TEXT, name=b"text", comment=b"bale", extra=b"BA\x02\x00ok", header_crc=True
        ),
        "members.gz": gzip_member(b"one\n") + gzip_member(b"two\n") + b"\0" * 8,
    }


def zstd_corpus():
    skippable = struct.pack("<II", 0x184D2A50, 4) + b"skip"
    return {
        "plain.zst": zstd_frame(DEFLATE_TEXT),
        "checksum.zst": zstd_frame(DEFLATE_TEXT * 8, checksum=True),
        "frames.zst": skippable + zstd_frame(b"one\n") + zstd_frame(b"two\n"),
    }


def codec_input(selector, length, body):
    return struct.pack("<I", selector | (length << 8)) + body


def codecs_corpus():
    return {
        "zstd_chunk": codec_input(0, len(DEFLATE_TEXT), zstd_frame(DEFLATE_TEXT)),
        "lz4_chunk": codec_input(1, len(LZ4_TEXT), LZ4_FRAME),
        "inflate_stream": codec_input(2, 7, raw_deflate(DEFLATE_TEXT * 16)),
        "zstd_stream": codec_input(3, 13, zstd_frame(DEFLATE_TEXT * 16, checksum=True)),
    }


def data_payload(chunk, encoded=None):
    descriptor = ref.chunk_key(chunk)
    return ref.uleb128(len(descriptor)) + descriptor + (chunk if encoded is None else encoded)


class NativeArchive:
    def __init__(self):
        self.out = bytearray(ref.superblock(bytes(range(0x10, 0x20)), FIXED_TIME * 10**9))
        self.sequence = 0
        self.index = {}
        self.footer_offset = None
        self.commit_digest = b"\0" * 32
        self.generation = 0

    def append(self, record_type, payload, codec=ref.CODEC_RAW, decoded_length=None):
        offset = len(self.out)
        self.out += ref.record(record_type, payload, self.sequence, codec, decoded_length)
        self.sequence += 1
        return offset, len(self.out) - offset

    def chunk(self, chunk, codec=ref.CODEC_RAW, encoded=None):
        payload = data_payload(chunk, encoded)
        decoded = None if encoded is None else len(payload) - len(encoded) + len(chunk)
        offset, length = self.append(ref.RECORD_DATA, payload, codec, decoded)
        self.index[ref.chunk_key(chunk)] = (offset, length, codec)

    def commit(self, entries, comment=None):
        self.generation += 1
        manifest_payload = ref.unsigned(1, 1) + ref.field(2, ref.tlv_list(entries))
        if comment is not None:
            manifest_payload += ref.field(3, comment, critical=False)
        manifest_payload += ref.writer_metadata("bale", "fast", ref.CODEC_ZSTD, 1, 1 << 20)
        manifest = self.append(ref.RECORD_MANIFEST, manifest_payload)

        rows = [
            key + ref.unsigned(4, offset) + ref.unsigned(5, length) + ref.unsigned(6, codec)
            for key, (offset, length, codec) in sorted(self.index.items(), key=index_order)
        ]
        index_payload = ref.unsigned(1, 1) + ref.field(2, ref.tlv_list(rows))
        index = self.append(ref.RECORD_INDEX, index_payload)

        commit_payload = (
            ref.unsigned(1, 1)
            + ref.unsigned(2, self.generation)
            + ref.field(3, self.commit_digest)
            + ref.unsigned(4, 0)
            + ref.unsigned(5, manifest[0])
            + ref.unsigned(6, manifest[1])
            + ref.field(7, ref.derive_key(ref.CONTEXTS["manifest"], manifest_payload))
            + ref.unsigned(8, index[0])
            + ref.unsigned(9, index[1])
            + ref.field(10, ref.derive_key(ref.CONTEXTS["index"], index_payload))
        )
        if self.footer_offset is not None:
            commit_payload += ref.unsigned(12, self.footer_offset, critical=False)
        commit_offset, commit_length = self.append(ref.RECORD_COMMIT, commit_payload)

        self.commit_digest = ref.derive_key(ref.CONTEXTS["commit"], commit_payload)
        self.footer_offset = len(self.out)
        self.out += ref.footer(commit_offset, commit_length, self.generation, self.commit_digest)
        return manifest_payload, index_payload, commit_payload


def index_order(item):
    key = item[0]
    return key[5:37]


def symlink_entry(path, target):
    return ref.field(1, path.encode()) + ref.unsigned(2, 3) + ref.field(9, target.encode())


def hardlink_entry(path, target):
    return ref.field(1, path.encode()) + ref.unsigned(2, 4) + ref.field(10, target.encode())


def native_corpus():
    corpus = {"golden.bale": ref.golden_archive()}

    compressed = NativeArchive()
    text = DEFLATE_TEXT * 8
    compressed.chunk(text, ref.CODEC_ZSTD, zstd_frame(text))
    compressed.chunk(LZ4_TEXT, 2, LZ4_FRAME)
    compressed.commit(
        [
            ref.entry("lz4", ref.ENTRY_REGULAR, length=len(LZ4_TEXT), chunks=[LZ4_TEXT]),
            ref.entry("zstd", ref.ENTRY_REGULAR, length=len(text), chunks=[text]),
        ]
    )
    corpus["codecs.bale"] = bytes(compressed.out)

    links = NativeArchive()
    links.chunk(b"first")
    links.chunk(b"second")
    links.commit(
        [ref.entry("a", ref.ENTRY_REGULAR, length=5, chunks=[b"first"], mtime=0, mode=0o600)],
        comment=b"generation one",
    )
    links.commit(
        [
            ref.entry("a", ref.ENTRY_REGULAR, length=11, chunks=[b"first", b"second"]),
            hardlink_entry("b", "a"),
            ref.entry("d", ref.ENTRY_DIRECTORY),
            symlink_entry("d/s", "../a"),
        ]
    )
    corpus["generations.bale"] = bytes(links.out)
    return corpus


def records_corpus():
    archive = NativeArchive()
    archive.chunk(b"hello")
    manifest, index, commit = archive.commit(
        [ref.entry("f", ref.ENTRY_REGULAR, length=5, chunks=[b"hello"], mtime=1, mode=0o644)]
    )
    data = bytes(archive.out)
    return {
        "superblock": data[:64],
        "footer": data[-96:],
        "data_record": data[64 : 64 + 56 + len(data_payload(b"hello"))],
        "manifest": manifest,
        "index": index,
        "commit": commit,
        "data_payload": data_payload(b"hello"),
    }


def tlv_corpus():
    manifest = records_corpus()["manifest"]
    return {
        "whitepaper": bytes.fromhex("0202abcd070101"),
        "nested": ref.field(2, ref.tlv_list([ref.unsigned(1, 300), ref.signed64(2, -1)])),
        "manifest": manifest,
        "leb128": ref.uleb128(2**64 - 1),
    }


def path_corpus():
    return {
        "strict": b"\x04d\nd/f\nd/F\nCaf\xc3\xa9/x",
        "lenient": b"\x00./a//b/\nA/B\n../x\n/abs",
        "windows": b"\x09dir\\CON.txt\nC:\\x\nname. \nCOM\xc2\xb9",
        "unicode": b"\x18e\xcc\x81\xcc\xa3\n\xc3\xa9\xcc\xa3\n\xea\xb0\x80\n\xc4\xb0",
        "raw": b"\x10bad\xff/name\n\xed\xa0\x80",
    }


def terminal_corpus():
    return {
        "plain": "d/café.txt".encode(),
        "controls": b"a\x1b[31mred\x07\\b\x7f",
        "bidi": "evil‮txt.exe⁦x⁩".encode(),
        "invalid": b"bad\xff\xc0\x80\xed\xa0\x80\xc2\x85",
    }


def detect_corpus():
    tar = tar_corpus()["ustar.tar"]
    return {
        "archive.bale": ref.golden_archive(),
        "archive.zip": zip_corpus()["plain.zip"],
        "archive.tar": tar,
        "archive.tar.gz": gzip.compress(tar, mtime=0),
        "archive.tar.zst": zstd_frame(tar),
        "single.gz": gzip_corpus()["plain.gz"],
    }


def main():
    corpora = {
        "fuzz_archive_path": path_corpus(),
        "fuzz_codecs": codecs_corpus(),
        "fuzz_detect": detect_corpus(),
        "fuzz_gzip": gzip_corpus(),
        "fuzz_native_archive": native_corpus(),
        "fuzz_native_records": records_corpus(),
        "fuzz_tar": tar_corpus(),
        "fuzz_terminal_text": terminal_corpus(),
        "fuzz_tlv": tlv_corpus(),
        "fuzz_zip": zip_corpus(),
        "fuzz_zstd": zstd_corpus(),
    }
    for target, files in corpora.items():
        directory = ROOT / target
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
        for name, data in files.items():
            (directory / name).write_bytes(data)


if __name__ == "__main__":
    main()
