"""Build every committed golden and corrupt fixture under tests/reference.

Deterministic: fixed archive id, fixed timestamps, fixed options. Goldens with
only raw-codec data records are byte-reproduced by the C++ suite
(tests/reference/reference_test.cpp); codec goldens embed genuine C++ encoder
output (captured with a throwaway harness, see COMPRESSED_FRAMES) because this
module is stdlib-only; the encrypted fixture is structure-only (no XChaCha20
here) with clearly marked placeholder bytes, never valid ciphertext.
"""

import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bale_reference import (  # noqa: E402
    CDC_GEAR,
    CODEC_BROTLI,
    CODEC_LZ4,
    CODEC_LZMA2,
    CODEC_RAW,
    CODEC_ZSTD,
    ENTRY_DIRECTORY,
    ENTRY_HARDLINK,
    ENTRY_REGULAR,
    ENTRY_SYMLINK,
    FEATURE_ENCRYPTED,
    FLAG_ENCRYPTED,
    POLICY_CDC,
    POLICY_FIXED,
    RECORD_COMMIT,
    RECORD_DATA,
    RECORD_EXTENSION,
    RECORD_INDEX,
    RECORD_MANIFEST,
    CdcSplitter,
    chunk_key,
    commit_payload,
    crc32c,
    data_descriptor,
    derive_key,
    entry,
    footer,
    index_entry,
    index_payload,
    keyslot_payload_password,
    manifest_payload,
    record,
    superblock,
    validate_cdc_params,
    writer_metadata,
)

ARCHIVE_ID = bytes(range(0x10, 0x20))
CREATION_TIME = 1700000000000000000
FILE_TIME = 1700000000123456789

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests",
                       "reference")


def hex_blob(text):
    return bytes(int(pair, 16) for pair in text.split())


# NOTE: genuine C++ ChunkEncoder output for 4096 repetitions of one byte,
# captured from the pinned deps in this environment. Embedded (not generated)
# because this module is stdlib-only and must not gain zstd/lz4/brotli deps.
# Format per chunk: one exact stream (zstd frame, LZ4 frame v1.6.x independent
# blocks with content size, xz stream via liblzma easy encoder, brotli stream).
COMPRESSED_FRAMES = {
    # 4096 x 'u', zstd level 3.
    ("u", CODEC_ZSTD): hex_blob(
        "28 B5 2F FD 60 00 0F 4D 00 00 10 75 75 01 00 FB F7 01 16"),
    # 4096 x 'v', lz4 level 0 (header checksum 0x58 covers content size 4096).
    ("v", CODEC_LZ4): hex_blob(
        "04 22 4D 18 68 40 00 10 00 00 00 00 00 00 58 1A 00 00 00 1F 76 01 00 FF "
        "FF FF FF FF FF FF FF FF FF FF FF FF FF FF F6 50 76 76 76 76 76 00 00 00 "
        "00"),
    # 4096 x 'w', lzma2 level 6 (xz stream).
    ("w", CODEC_LZMA2): hex_blob(
        "FD 37 7A 58 5A 00 00 01 69 22 DE 36 03 C0 21 80 20 21 01 16 00 00 00 00 "
        "B7 B1 68 DF E0 0F FF 00 19 5D 00 3B EF FB BF FE A3 B1 5E E5 F8 3F B2 AA "
        "26 55 F8 68 70 41 70 15 0E 24 18 CF 00 00 00 00 3B F9 31 21 00 01 35 80 "
        "20 00 00 00 6F 5D 36 86 3E 30 0D 8B 02 00 00 00 00 01 59 5A"),
    # 4096 x 'x', brotli quality 6.
    ("x", CODEC_BROTLI): hex_blob(
        "1B FF 0F 00 24 F0 E2 B1 40 72 0F 00 00"),
}


class ArchiveBuilder:
    """Plain-archive builder mirroring the writer's observable layout."""

    def __init__(self, archive_id=ARCHIVE_ID, creation_time=CREATION_TIME,
                 compression=("balanced", CODEC_ZSTD, 3), chunk_size=1 << 20,
                 chunk_policy=POLICY_FIXED, cdc=(256 * 1024, 1024 * 1024, 4 * 1024 * 1024),
                 workers=1, comment=""):
        self.archive_id = archive_id
        self.creation_time = creation_time
        self.preset_name, self.codec, self.level = compression
        self.chunk_size = chunk_size
        self.chunk_policy = chunk_policy
        self.cdc = cdc
        self.workers = workers
        self.comment = comment
        self.out = bytearray(superblock(archive_id, creation_time))
        self.sequence = 0
        self.generation = 0
        self.previous_digest = b"\0" * 32
        self.previous_footer_offset = 0
        self.index = []  # (key_tlv, plain, codec, offset, length), first-use order
        self.table = {}  # (digest, length) -> position in self.index
        self.pending = []  # entries not yet finished into a manifest

    def _split(self, data):
        if not data:
            return []
        if self.chunk_policy == POLICY_CDC:
            splitter = CdcSplitter(*self.cdc)
            chunks = []
            current = bytearray()
            for byte in data:
                current.append(byte)
                if splitter.feed(byte):
                    chunks.append(bytes(current))
                    current = bytearray()
                    splitter.next_chunk()
            if current:
                chunks.append(bytes(current))
            return chunks
        size = self.chunk_size
        return [data[index:index + size] for index in range(0, len(data), size)] or [b""]

    def _add_chunk_reference(self, plain, codec, stored):
        key = (derive_key("bale 2026-10-17 v1 chunk", plain), len(plain))
        if key in self.table:
            return self.table[key]
        position = len(self.index)
        self.table[key] = position
        self.index.append([chunk_key(plain), plain, codec, stored, 0, 0])
        return position

    def add_directory(self, path, mtime=None, mode=None):
        self.pending.append({"path": path, "kind": ENTRY_DIRECTORY, "length": 0,
                             "chunks": [], "mtime": mtime, "mode": mode, "target": None})

    def add_symlink(self, path, target, mtime=None):
        self.pending.append({"path": path, "kind": ENTRY_SYMLINK, "length": 0,
                             "chunks": [], "mtime": mtime, "mode": None, "target": target})

    def add_hardlink(self, path, target):
        self.pending.append({"path": path, "kind": ENTRY_HARDLINK, "length": 0,
                             "chunks": [], "mtime": None, "mode": None, "target": target})

    def add_file(self, path, data, mtime=None, mode=None, codec=CODEC_RAW, stored=None):
        plains = self._split(data)
        positions = []
        for plain in plains:
            if codec == CODEC_RAW:
                positions.append(self._add_chunk_reference(plain, CODEC_RAW, plain))
            else:
                assert stored is not None
                positions.append(self._add_chunk_reference(plain, codec, stored))
        first = positions[0] if positions else 0
        self.pending.append({"path": path, "kind": ENTRY_REGULAR, "length": len(data),
                             "chunks": positions, "first": first,
                             "mtime": mtime, "mode": mode, "target": None})

    def _resolve_hardlinks(self, entries):
        by_path = {item["path"]: index for index, item in enumerate(entries)}
        root_of = list(range(len(entries)))
        first_of = list(range(len(entries)))

        for index, item in enumerate(entries):
            if item["kind"] != ENTRY_HARDLINK:
                continue
            target = by_path.get(item["target"])
            assert target is not None, "dangling hardlink in golden: %r" % item
            assert entries[target]["kind"] == ENTRY_REGULAR, "link to non-regular in golden"
            root_of[index] = target
            if index < first_of[target]:
                first_of[target] = index

        for index, item in enumerate(entries):
            root = root_of[index]
            first = first_of[root]
            if index != root and item["kind"] == ENTRY_HARDLINK:
                item["target"] = entries[first]["path"]
            if index != root or first == root:
                continue
            owner = entries[first]
            former = entries[root]
            owner["kind"] = ENTRY_REGULAR
            owner["length"] = former["length"]
            owner["chunks"] = former["chunks"]
            owner["mtime"] = former["mtime"]
            owner["mode"] = former["mode"]
            former["kind"] = ENTRY_HARDLINK
            former["length"] = 0
            former["chunks"] = []
            former["mtime"] = None
            former["mode"] = None
            former["target"] = owner["path"]

    def _emit_data(self, position):
        key_tlv, plain, codec, stored, _, _ = self.index[position]
        descriptor, payload = data_descriptor(key_tlv)
        if codec == CODEC_RAW:
            payload = descriptor + plain
            decoded = len(payload)
        else:
            payload = descriptor + stored
            decoded = len(descriptor) + len(plain)
        blob = record(RECORD_DATA, payload, self.sequence, codec, decoded)
        self.sequence += 1
        offset = len(self.out)
        self.out += blob
        self.index[position][4] = offset
        self.index[position][5] = len(blob)

    def finish(self):
        entries = sorted(self.pending, key=lambda item: item["path"])
        paths = [item["path"] for item in entries]
        assert len(set(paths)) == len(paths), "duplicate path in golden"
        self._resolve_hardlinks(entries)
        for position in range(len(self.index)):
            if self.index[position][5] == 0:
                self._emit_data(position)
        manifest_entries = []
        for item in entries:
            if item["kind"] == ENTRY_REGULAR and item["chunks"]:
                manifest_entries.append(entry(
                    item["path"], ENTRY_REGULAR, length=item["length"],
                    chunks=[self.index[position][1] for position in item["chunks"]],
                    mtime=item["mtime"], mode=item["mode"]))
            elif item["kind"] == ENTRY_REGULAR:
                manifest_entries.append(entry(item["path"], ENTRY_REGULAR,
                                              length=0, mtime=item["mtime"], mode=item["mode"]))
            elif item["kind"] == ENTRY_DIRECTORY:
                manifest_entries.append(entry(item["path"], ENTRY_DIRECTORY,
                                              mtime=item["mtime"], mode=item["mode"]))
            elif item["kind"] == ENTRY_SYMLINK:
                manifest_entries.append(entry(item["path"], ENTRY_SYMLINK,
                                              mtime=item["mtime"], target=item["target"]))
            else:
                manifest_entries.append(entry(item["path"], ENTRY_HARDLINK,
                                              target=item["target"]))
        manifest_bytes = manifest_payload(
            1, manifest_entries, self.comment,
            writer_metadata("bale", self.preset_name, self.codec, self.level,
                            self.cdc[1] if self.chunk_policy == POLICY_CDC else self.chunk_size,
                            chunk_policy=self.chunk_policy, workers=self.workers,
                            **self._cdc_kwargs()))
        manifest_offset = len(self.out)
        manifest_blob = record(RECORD_MANIFEST, manifest_bytes, self.sequence)
        self.sequence += 1
        self.out += manifest_blob

        # NOTE: index order is the canonical key order: algorithm, digest, length.
        indexed = sorted(self.index, key=lambda row: row[0])
        index_rows = [index_entry(row[0], row[4], row[5], row[2]) for row in indexed]
        index_bytes = index_payload(index_rows)
        index_offset = len(self.out)
        index_blob = record(RECORD_INDEX, index_bytes, self.sequence)
        self.sequence += 1
        self.out += index_blob

        self.generation += 1
        commit_kwargs = {}
        if self.generation > 1:
            commit_kwargs["previous_footer_offset"] = self.previous_footer_offset
        commit_bytes = commit_payload(
            self.generation, self.previous_digest, 0,
            manifest_offset, len(manifest_blob),
            derive_key("bale 2026-10-17 v1 manifest", manifest_bytes),
            index_offset, len(index_blob),
            derive_key("bale 2026-10-17 v1 index", index_bytes),
            **commit_kwargs)
        commit_offset = len(self.out)
        commit_blob = record(RECORD_COMMIT, commit_bytes, self.sequence)
        self.sequence += 1
        self.out += commit_blob
        commit_digest = derive_key("bale 2026-10-17 v1 commit", commit_bytes)
        footer_offset = len(self.out)
        self.out += footer(commit_offset, len(commit_blob), self.generation, commit_digest)
        self.previous_digest = commit_digest
        self.previous_footer_offset = footer_offset
        self.pending = []
        return bytes(self.out)

    def _cdc_kwargs(self):
        if self.chunk_policy != POLICY_CDC:
            return {}
        return {"chunk_min": self.cdc[0], "chunk_target": self.cdc[1],
                "chunk_max": self.cdc[2], "chunk_algorithm": CDC_GEAR}


def build_plain():
    builder = ArchiveBuilder()
    builder.add_directory("d", mtime=0, mode=0o755)
    builder.add_file("d/f", b"hello", mtime=FILE_TIME, mode=0o644)
    builder.add_file("d/g", b"hello", mtime=FILE_TIME, mode=0o644)
    builder.add_file("e", b"")
    return builder.finish()


LINE = b"line 42 of a compressible file\n"


def noise(length, seed):
    value = seed | 1
    out = bytearray(length)
    for index in range(length):
        value ^= (value << 13) & 0xFFFFFFFF
        value ^= value >> 17
        value ^= (value << 5) & 0xFFFFFFFF
        out[index] = value & 0xFF
    return bytes(out)


def build_cdc():
    validate_cdc_params(4096, 8192, 65536)
    builder = ArchiveBuilder(compression=(None, CODEC_RAW, 0), chunk_policy=POLICY_CDC,
                             cdc=(4096, 8192, 65536))
    data = noise(93000, 99)
    builder.add_directory("a")
    builder.add_file("a/data.bin", data)
    builder.add_file("a/copy.bin", data)
    return builder.finish()


def build_codecs():
    builder = ArchiveBuilder()
    builder.add_file("brotli", b"x" * 4096, codec=CODEC_BROTLI,
                     stored=COMPRESSED_FRAMES[("x", CODEC_BROTLI)])
    builder.add_file("lz4", b"v" * 4096, codec=CODEC_LZ4,
                     stored=COMPRESSED_FRAMES[("v", CODEC_LZ4)])
    builder.add_file("lzma2", b"w" * 4096, codec=CODEC_LZMA2,
                     stored=COMPRESSED_FRAMES[("w", CODEC_LZMA2)])
    builder.add_file("raw", b"t" * 4096)
    builder.add_file("zstd", b"u" * 4096, codec=CODEC_ZSTD,
                     stored=COMPRESSED_FRAMES[("u", CODEC_ZSTD)])
    return builder.finish()


def build_snapshot2():
    builder = ArchiveBuilder()
    builder.add_file("old", b"v1-bytes")
    gen1 = builder.finish()
    builder.add_file("new", b"v1-bytes")
    return builder.finish()


def build_meta():
    builder = ArchiveBuilder(compression=("small", CODEC_ZSTD, 19), chunk_size=65536,
                             comment="snapshot comment")
    builder.add_directory("d", mtime=0, mode=0o755)
    builder.add_file("d/f", b"hello", mtime=FILE_TIME, mode=0o644)
    builder.add_file("e", b"")
    builder.add_hardlink("a", "z")
    builder.add_hardlink("h", "d/f")
    builder.add_symlink("l", "d/f", mtime=1)
    builder.add_file("z", b"data", mtime=7, mode=0o600)
    return builder.finish()


def build_encrypted_structure():
    """Envelope-only encrypted archive. Placeholder bytes are fixed patterns,
    never valid ciphertext; both sides must answer PasswordRequired."""
    archive_id = ARCHIVE_ID
    out = bytearray(superblock(archive_id, CREATION_TIME, required_features=FEATURE_ENCRYPTED))
    epoch = 1
    salt = bytes(range(0xA0, 0xB0))
    nonce = bytes(range(0xC0, 0xD8))
    wrapped = bytes([0xE5]) * 48
    slot = keyslot_payload_password(epoch, salt, 2, 1 << 20, nonce, wrapped)
    out += record(RECORD_EXTENSION, slot, 0, CODEC_RAW, flags=FLAG_ENCRYPTED)

    object_id = bytes(range(0x20))
    data_nonce = bytes([0xD1]) * 24
    data_seal = bytes([0xD2]) * 21
    data_head = object_id + struct.pack("<Q", epoch) + data_nonce
    out += record(RECORD_DATA, data_head + data_seal, 1, CODEC_RAW, flags=FLAG_ENCRYPTED)

    manifest_sealed = bytes([0xB1]) * 64
    manifest_nonce = bytes([0xB0]) * 24
    manifest_offset = len(out)
    manifest_blob = record(RECORD_MANIFEST, manifest_nonce + manifest_sealed, 2, CODEC_RAW,
                           flags=FLAG_ENCRYPTED)
    out += manifest_blob

    index_sealed = bytes([0xB2]) * 64
    index_nonce = bytes([0xB3]) * 24
    index_offset = len(out)
    index_blob = record(RECORD_INDEX, index_nonce + index_sealed, 3, CODEC_RAW,
                        flags=FLAG_ENCRYPTED)
    out += index_blob

    # NOTE: the commit TLV plaintext (offsets, digests, epoch) is what a real
    # writer would seal here; without a key only the sealed bytes exist.
    commit_sealed = bytes([0xB4]) * 80
    commit_nonce = bytes([0xB5]) * 24
    commit_offset = len(out)
    commit_blob = record(RECORD_COMMIT, commit_nonce + commit_sealed, 4, CODEC_RAW,
                         flags=FLAG_ENCRYPTED)
    out += commit_blob
    out += footer(commit_offset, len(commit_blob), 1,
                  derive_key("bale 2026-10-17 v1 commit", commit_nonce + commit_sealed))
    return bytes(out)


def record_spans(data):
    """Yield (offset, length, type, flags, payload_offset) for each record."""
    position = 64
    spans = []
    while position + 56 <= len(data):
        if data[position:position + 4] != b"BLR1":
            break
        record_type, flags = struct.unpack("<HH", data[position + 4:position + 8])
        payload_length = struct.unpack("<Q", data[position + 8:position + 16])[0]
        total = payload_length + 56
        spans.append((position, total, record_type, flags, position + 48))
        position += total
    return spans


def fix_prefix_crc(data, offset):
    prefix = bytearray(data[offset:offset + 48])
    prefix[36:40] = b"\0\0\0\0"
    data[offset + 36:offset + 40] = struct.pack("<I", crc32c(bytes(prefix)))


def fix_trailer_crc(data, payload_offset, payload_length):
    payload = bytes(data[payload_offset:payload_offset + payload_length])
    data[payload_offset + payload_length:payload_offset + payload_length + 4] = struct.pack(
        "<I", crc32c(payload))


def fix_superblock_crc(data):
    data[56:60] = struct.pack("<I", crc32c(bytes(data[:56])))


def build_corrupts(plain):
    fixtures = {}

    bad = bytearray(plain)
    bad[0] ^= 0x01
    fixtures["corrupt-bad-magic.bale"] = bytes(bad)

    fixtures["corrupt-small-file.bale"] = plain[:10]
    fixtures["corrupt-truncated.bale"] = plain[:400]

    spans = record_spans(plain)
    data_offset, data_length, _, _, payload_offset = spans[0]
    assert plain[data_offset:data_offset + 4] == b"BLR1"

    flipped = bytearray(plain)
    flipped[payload_offset + 43] ^= 0x01
    fixtures["corrupt-payload-crc.bale"] = bytes(flipped)

    forged = bytearray(plain)
    forged[payload_offset + 43] ^= 0x01
    fix_trailer_crc(forged, payload_offset, data_length - 56)
    fixtures["corrupt-payload-crc-fixed.bale"] = bytes(forged)

    manifest_offset, manifest_length, _, _, manifest_payload_offset = spans[1]
    damaged = bytearray(plain)
    damaged[manifest_payload_offset + 5] ^= 0x02
    fix_trailer_crc(damaged, manifest_payload_offset, manifest_length - 56)
    fixtures["corrupt-manifest-digest.bale"] = bytes(damaged)

    commit_offset, commit_length, _, _, commit_payload_offset = spans[3]
    damaged_commit = bytearray(plain)
    damaged_commit[commit_payload_offset + 9] ^= 0x02
    fix_trailer_crc(damaged_commit, commit_payload_offset, commit_length - 56)
    fixtures["corrupt-commit-digest.bale"] = bytes(damaged_commit)

    flagged = bytearray(plain)
    flagged[data_offset + 6] = 0x02
    fix_prefix_crc(flagged, data_offset)
    fixtures["corrupt-unknown-flag.bale"] = bytes(flagged)

    featured = bytearray(plain)
    featured[16:20] = struct.pack("<I", 0x80000000)
    fix_superblock_crc(featured)
    fixtures["corrupt-unknown-feature.bale"] = bytes(featured)

    enc_in_plain = bytearray(plain)
    enc_in_plain[data_offset + 6] = 0x01
    fix_prefix_crc(enc_in_plain, data_offset)
    fixtures["corrupt-encrypted-in-plain.bale"] = bytes(enc_in_plain)

    index_offset, _, _, _, _ = spans[2]
    bad_type = bytearray(plain)
    bad_type[index_offset + 4] = 0x06
    fix_prefix_crc(bad_type, index_offset)
    fixtures["corrupt-bad-record-type.bale"] = bytes(bad_type)

    return fixtures


GOLDENS = [
    ("plain.bale", build_plain, "gen1, fixed 1MiB, balanced/zstd:3, dedup hello"),
    ("cdc.bale", build_cdc, "gen1, cdc 4K/8K/64K gear, raw, dedup copy"),
    ("codecs.bale", build_codecs, "gen1, raw+zstd+lz4+lzma2+brotli frames"),
    ("snapshot2.bale", build_snapshot2, "gen1 old + gen2 new sharing one chunk"),
    ("meta.bale", build_meta, "gen1, small/zstd:19 64K, links, comment"),
    ("encrypted-structure.bale", build_encrypted_structure,
     "envelope-only encrypted shape, placeholder seal bytes"),
]


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    manifest = {"generator": "tools/reference/make_goldens.py",
                "archive_id": ARCHIVE_ID.hex(), "creation_time_ns": CREATION_TIME,
                "files": []}
    blobs = {}
    for name, build, _ in GOLDENS:
        blobs[name] = build()
    plain = blobs["plain.bale"]
    for name, blob in build_corrupts(plain).items():
        blobs[name] = blob
    descriptions = {name: note for name, _, note in GOLDENS}
    for name, blob in blobs.items():
        path = os.path.join(OUT_DIR, name)
        with open(path, "wb") as handle:
            handle.write(blob)
        manifest["files"].append(
            {"path": name, "sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob),
             "note": descriptions.get(name, "corrupt fixture derived from plain.bale")})
    with open(os.path.join(OUT_DIR, "manifest.json"), "w") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    print("wrote %d files to %s" % (len(blobs), OUT_DIR))


if __name__ == "__main__":
    main()
