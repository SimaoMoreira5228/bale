"""Independent structural verifier for BALE archives (whitepaper sections 5A.2-5A.5).

Written from the schema description, not from the C++ sources. Re-derives every
checksum (CRC32C), digest (BLAKE3), length and ordering claim instead of trusting
the bytes under test.

Verification boundary (exact):

  Independently verified: superblock magic/version/size/checksum/reserved bytes,
  every record prefix (magic, type, flags, lengths, sequence, codec, header CRC,
  reserved bytes) and trailer (payload CRC, end marker), all TLV framing
  (minimal ULEB128, strictly increasing field numbers, criticality, lengths),
  chunk-key fields, data descriptors, manifest/index/commit payloads, the digest
  chain (manifest/index/commit BLAKE3 against the commit and footer), the
  generation walk (footer adjacency, parent digests, generation numbers), record
  sequencing, index ordering and location checks, raw chunk bytes (rehashed and
  compared to the indexed key), and refusal behavior (unknown required record
  flags, unknown required features, unknown critical fields, unknown record
  types, encrypted records without a key).

  Opaque (checked for framing, length and presence only, never decompressed or
  decrypted): compressed chunk payloads (zstd/lz4/lzma2/brotli need third-party
  decoders; this tool is stdlib-only by design) and all encrypted bytes
  (keyslot wraps/seals, sealed manifests/indexes/commits, sealed chunk bodies).
  For opaque payloads the verifier still checks the envelope CRCs, the
  descriptor/index key agreement, decoded-length consistency and the digest
  chain over the stored bytes, so a flipped ciphertext byte is still caught by
  CRC or digest mismatch; only the plaintext behind the compression or the seal
  is not re-derived.

Error kinds mirror the C++ reader (Truncated, Malformed, Unsupported, Integrity,
LimitExceeded, PasswordRequired) and reuse the same reason strings for the
cases the differential fixtures pin, so verdicts can be compared directly.
"""

import struct
import sys

from bale_reference import (
    COMMIT_ENCRYPTED_FEATURE,
    FEATURE_ENCRYPTED,
    FLAG_ENCRYPTED,
    HASH_BLAKE3,
    HASH_ENCRYPTED_OBJECT,
    MAX_CHUNK_SIZE,
    REQUIRED_FLAG_MASK,
    crc32c,
    derive_key,
)

CONTEXTS = {
    "chunk": "bale 2026-10-17 v1 chunk",
    "manifest": "bale 2026-10-17 v1 manifest",
    "index": "bale 2026-10-17 v1 index",
    "commit": "bale 2026-10-17 v1 commit",
}

SUPERBLOCK_SIZE = 64
RECORD_PREFIX_SIZE = 48
RECORD_TRAILER_SIZE = 8
RECORD_FRAMING_SIZE = 56
FOOTER_SIZE = 96

KNOWN_RECORD_TYPES = (1, 2, 3, 4, 5)
KNOWN_REQUIRED_FLAGS = FLAG_ENCRYPTED
KNOWN_REQUIRED_FEATURES = FEATURE_ENCRYPTED
KNOWN_COMMIT_FEATURES = COMMIT_ENCRYPTED_FEATURE
KNOWN_CODECS = (0, 1, 2, 3, 4)

MAX_LEB128_SIZE = 10
MAX_TLV_FIELD = (1 << 29) - 1
MAX_DATA_DESCRIPTOR = 128
MAX_COMMIT_PAYLOAD = 4096
MAX_METADATA_BYTES = 256 << 20
MAX_GENERATIONS = 100000

RECORD_NAMES = {1: "DATA", 2: "MANIFEST", 3: "INDEX", 4: "COMMIT", 5: "EXTENSION"}


class Error(Exception):
    def __init__(self, kind, message, offset=None):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.offset = offset

    def verdict(self):
        return {"verdict": "reject", "kind": self.kind, "message": self.message,
                "offset": self.offset}


def decode_uleb(data, pos, base=0):
    value = 0
    for index in range(min(len(data) - pos, MAX_LEB128_SIZE)):
        byte = data[pos + index]
        group = byte & 0x7F
        if index == MAX_LEB128_SIZE - 1 and group > 1:
            raise Error("Malformed", "ULEB128 value exceeds 64 bits", base + pos + index)
        value |= group << (7 * index)
        if byte & 0x80 == 0:
            if byte == 0 and index > 0:
                raise Error("Malformed", "non-minimal ULEB128 encoding", base + pos + index)
            return value, index + 1
    if len(data) - pos >= MAX_LEB128_SIZE:
        raise Error("Malformed", "ULEB128 encoding longer than 10 bytes",
                    base + pos + MAX_LEB128_SIZE - 1)
    raise Error("Truncated", "unexpected end of ULEB128", base + len(data))


class TlvField:
    def __init__(self, number, critical, value, offset):
        self.number = number
        self.critical = critical
        self.value = value
        self.offset = offset


class TlvReader:
    def __init__(self, data, base=0):
        self.data = data
        self.base = base
        self.pos = 0
        self.last_number = 0

    def next(self):
        if self.pos == len(self.data):
            return None
        field_offset = self.base + self.pos
        key, key_size = decode_uleb(self.data, self.pos, self.base)
        number = key >> 1
        if number == 0:
            raise Error("Malformed", "TLV field number zero", field_offset)
        if number > MAX_TLV_FIELD:
            raise Error("Malformed", "TLV field number out of range", field_offset)
        if number <= self.last_number:
            raise Error("Malformed", "TLV fields not in strictly increasing order", field_offset)
        length_pos = self.pos + key_size
        length, length_size = decode_uleb(self.data, length_pos, self.base)
        value_pos = length_pos + length_size
        if length > len(self.data) - value_pos:
            raise Error("Truncated", "TLV field value extends past end of structure",
                        self.base + value_pos)
        field = TlvField(number, bool(key & 1), self.data[value_pos:value_pos + length],
                         field_offset)
        self.last_number = number
        self.pos = value_pos + length
        return field


def require_critical(field, expected):
    if field.critical != expected:
        raise Error("Malformed", "TLV field has the wrong criticality", field.offset)


def skip_unknown(field):
    if field.critical:
        raise Error("Unsupported", "unknown critical TLV field", field.offset)


def decode_unsigned(field):
    value, size = decode_uleb(field.value, 0, field.offset)
    if size != len(field.value):
        raise Error("Malformed", "trailing bytes after TLV integer", field.offset)
    return value


def decode_signed64(field):
    if len(field.value) != 8:
        raise Error("Malformed", "TLV signed integer is not 8 bytes", field.offset)
    return struct.unpack("<q", field.value)[0]


def read_tlv_list(field, max_count):
    count, count_size = decode_uleb(field.value, 0, field.offset)
    if count > max_count:
        raise Error("LimitExceeded", "TLV list has too many elements", field.offset)
    if count > len(field.value) - count_size:
        raise Error("Truncated", "TLV list count exceeds the bytes available", field.offset)
    elements = []
    pos = count_size
    for _ in range(count):
        size, size_size = decode_uleb(field.value, pos, field.offset)
        start = pos + size_size
        if size > len(field.value) - start:
            raise Error("Truncated", "TLV list element extends past end of list",
                        field.offset + start)
        elements.append((field.value[start:start + size], field.offset + start))
        pos = start + size
    if pos != len(field.value):
        raise Error("Malformed", "trailing bytes after TLV list", field.offset + pos)
    return elements


def decode_superblock(data):
    if len(data) < SUPERBLOCK_SIZE:
        raise Error("Truncated", "file too small for a superblock", len(data))
    block = data[:SUPERBLOCK_SIZE]
    if block[:8] != b"BALE\r\n\x1a\n":
        raise Error("Malformed", "not a bale archive", 0)
    major = struct.unpack("<H", block[8:10])[0]
    if major != 1:
        raise Error("Unsupported", "unsupported format major version", 8)
    if struct.unpack("<I", block[12:16])[0] != SUPERBLOCK_SIZE:
        raise Error("Malformed", "unexpected superblock size", 12)
    stored = struct.unpack("<I", block[56:60])[0]
    if stored != crc32c(block[:56]):
        raise Error("Integrity", "superblock checksum mismatch", 56)
    if block[48:56] != b"\0" * 8 or block[60:64] != b"\0" * 4:
        bad = 48 if block[48:56] != b"\0" * 8 else 60
        raise Error("Malformed", "superblock reserved bytes not zero", bad)
    required = struct.unpack("<I", block[16:20])[0]
    if required & ~KNOWN_REQUIRED_FEATURES:
        raise Error("Unsupported", "unknown required feature", 16)
    return {
        "minor": struct.unpack("<H", block[10:12])[0],
        "required": required,
        "optional": struct.unpack("<I", block[20:24])[0],
        "archive_id": block[24:40],
        "creation_time": struct.unpack("<q", block[40:48])[0],
    }


def prefix_checksum(prefix):
    zeroed = bytearray(prefix)
    zeroed[36:40] = b"\0\0\0\0"
    return crc32c(bytes(zeroed))


def decode_record_prefix(data, pos, max_payload=1 << 40, max_decoded=1 << 40):
    if len(data) - pos < RECORD_PREFIX_SIZE:
        raise Error("Truncated", "record prefix truncated", len(data))
    prefix = data[pos:pos + RECORD_PREFIX_SIZE]
    if prefix[:4] != b"BLR1":
        raise Error("Malformed", "bad record magic", pos)
    if struct.unpack("<I", prefix[36:40])[0] != prefix_checksum(prefix):
        raise Error("Integrity", "record header checksum mismatch", pos + 36)
    if prefix[40:48] != b"\0" * 8:
        raise Error("Malformed", "record reserved bytes not zero", pos + 40)
    record_type = struct.unpack("<H", prefix[4:6])[0]
    if record_type not in KNOWN_RECORD_TYPES:
        raise Error("Unsupported", "unknown record type", pos + 4)
    flags = struct.unpack("<H", prefix[6:8])[0]
    if flags & REQUIRED_FLAG_MASK & ~KNOWN_REQUIRED_FLAGS:
        raise Error("Unsupported", "unknown required record flag", pos + 6)
    payload_length = struct.unpack("<Q", prefix[8:16])[0]
    decoded_length = struct.unpack("<Q", prefix[16:24])[0]
    sequence = struct.unpack("<Q", prefix[24:32])[0]
    codec = struct.unpack("<I", prefix[32:36])[0]
    if payload_length > max_payload:
        raise Error("LimitExceeded", "record payload length exceeds limit", pos + 8)
    if payload_length > (1 << 64) - RECORD_FRAMING_SIZE:
        raise Error("LimitExceeded", "record size overflows 64 bits", pos + 8)
    if decoded_length > max_decoded:
        raise Error("LimitExceeded", "record decoded length exceeds limit", pos + 16)
    if codec == 0 and decoded_length != payload_length:
        raise Error("Malformed", "raw record decoded length differs from stored length", pos + 16)
    return {
        "type": record_type,
        "flags": flags,
        "payload_length": payload_length,
        "decoded_length": decoded_length,
        "sequence": sequence,
        "codec": codec,
        "size": payload_length + RECORD_FRAMING_SIZE,
    }


def verify_trailer(data, payload_pos, payload_length):
    trailer_pos = payload_pos + payload_length
    if len(data) - trailer_pos < RECORD_TRAILER_SIZE:
        raise Error("Truncated", "record trailer truncated", len(data))
    trailer = data[trailer_pos:trailer_pos + RECORD_TRAILER_SIZE]
    if trailer[4:8] != b"END1":
        raise Error("Malformed", "missing record end marker", trailer_pos + 4)
    payload = data[payload_pos:payload_pos + payload_length]
    if struct.unpack("<I", trailer[:4])[0] != crc32c(payload):
        raise Error("Integrity", "record payload checksum mismatch", trailer_pos)
    return trailer_pos + RECORD_TRAILER_SIZE


def read_record(data, pos, max_payload=1 << 40, max_decoded=1 << 40):
    header = decode_record_prefix(data, pos, max_payload, max_decoded)
    if header["size"] > len(data) - pos:
        raise Error("Truncated", "record extends past end of data", len(data))
    payload_pos = pos + RECORD_PREFIX_SIZE
    verify_trailer(data, payload_pos, header["payload_length"])
    header["offset"] = pos
    header["payload"] = data[payload_pos:payload_pos + header["payload_length"]]
    return header


def decode_chunk_key(element, base):
    reader = TlvReader(element, base)
    algorithm = digest = length = None
    has_algorithm = has_digest = has_length = False
    while True:
        field = reader.next()
        if field is None:
            break
        if field.number < 1 or field.number > 3:
            skip_unknown(field)
            continue
        require_critical(field, True)
        if field.number == 1:
            algorithm = decode_unsigned(field)
            if algorithm not in (HASH_BLAKE3, HASH_ENCRYPTED_OBJECT):
                raise Error("Unsupported", "unknown chunk hash algorithm", field.offset)
            has_algorithm = True
        elif field.number == 2:
            if len(field.value) != 32:
                raise Error("Malformed", "chunk digest is not 32 bytes", field.offset)
            digest = bytes(field.value)
            has_digest = True
        else:
            length = decode_unsigned(field)
            if length == 0:
                raise Error("Malformed", "empty chunk", field.offset)
            if length > MAX_CHUNK_SIZE:
                raise Error("LimitExceeded", "chunk length exceeds the format maximum",
                            field.offset)
            has_length = True
    if not (has_algorithm and has_digest and has_length):
        raise Error("Malformed", "chunk key is missing a field", base)
    return {"algorithm": algorithm, "digest": digest, "length": length}


def decode_data_payload(payload, base):
    size, size_size = decode_uleb(payload, 0, base)
    if size > MAX_DATA_DESCRIPTOR:
        raise Error("LimitExceeded", "data descriptor too large", base)
    if size > len(payload) - size_size:
        raise Error("Truncated", "data descriptor extends past payload", base)
    key = decode_chunk_key(payload[size_size:size_size + size], base + size_size)
    if key["algorithm"] != HASH_BLAKE3:
        raise Error("Unsupported", "unknown chunk hash algorithm", base)
    prefix = size_size + size
    return {"key": key, "descriptor_size": prefix, "encoded": payload[prefix:]}


def check_path(path, base):
    try:
        text = bytes(path).decode("utf-8")
    except UnicodeDecodeError:
        raise Error("UnsafePath", "manifest path is not valid UTF-8", base)
    if not text or len(text.encode("utf-8")) > 4096:
        raise Error("UnsafePath", "manifest path empty or too long", base)
    if "\\" in text or "\0" in text:
        raise Error("UnsafePath", "manifest path has a bad character", base)
    if text.startswith("/") or text.endswith("/") or "//" in text:
        raise Error("UnsafePath", "manifest path is not canonical", base)
    for component in text.split("/"):
        if component in ("", ".", ".."):
            raise Error("UnsafePath", "manifest path is not canonical", base)
    return text


def decode_manifest(payload, base):
    reader = TlvReader(payload, base)
    version = entries = comment = writer = None
    has_version = has_entries = False
    while True:
        field = reader.next()
        if field is None:
            break
        if field.number > 4:
            skip_unknown(field)
            continue
        require_critical(field, field.number in (1, 2))
        if field.number == 1:
            version = decode_unsigned(field)
            if version != 1:
                raise Error("Unsupported", "unsupported manifest schema version", field.offset)
            has_version = True
        elif field.number == 2:
            if not has_version:
                raise Error("Malformed", "manifest entries before schema version", field.offset)
            entries = decode_manifest_entries(field)
            has_entries = True
        else:
            if len(field.value) == 0:
                raise Error("Malformed", "explicit empty optional manifest field", field.offset)
            if field.number == 3:
                comment = bytes(field.value).decode("utf-8", errors="replace")
            else:
                writer = decode_writer_metadata(field)
    if not has_version or not has_entries:
        raise Error("Malformed", "manifest missing a required field", base)
    decoded_entries, decoded_chunks, decoded_object_ids = entries
    return {"entries": decoded_entries, "chunks": decoded_chunks,
            "object_ids": decoded_object_ids, "comment": comment or "", "writer": writer or {}}


def decode_manifest_entries(field):
    raw_elements = read_tlv_list(field, 10_000_000)
    entries = []
    chunks = []
    object_ids = []
    for element, offset in raw_elements:
        entry = decode_manifest_entry(element, offset, chunks, object_ids)
        if entries and entry["path"] <= entries[-1]["path"]:
            raise Error("Malformed", "manifest paths not in strictly increasing byte order",
                        offset)
        entries.append(entry)
    check_tree(entries, field.offset)
    return entries, chunks, object_ids


def decode_manifest_entry(data, base, chunks, object_ids):
    reader = TlvReader(data, base)
    path = kind = length = None
    mtime = mode = symlink = hardlink = None
    has_path = has_kind = has_length = has_chunks = False
    first_chunk = len(chunks)
    chunk_count = 0
    while True:
        field = reader.next()
        if field is None:
            break
        if field.number not in (1, 2, 3, 4, 5, 6, 9, 10):
            skip_unknown(field)
            continue
        require_critical(field, field.number not in (5, 6))
        if field.number == 1:
            path = check_path(field.value, field.offset)
            has_path = True
        elif field.number == 2:
            kind = decode_unsigned(field)
            has_kind = True
        elif field.number == 3:
            length = decode_unsigned(field)
            has_length = True
        elif field.number == 4:
            if not has_length:
                raise Error("Malformed", "chunk list without a file length", field.offset)
            chunk_count = decode_chunk_list(field, length, chunks, object_ids)
            has_chunks = True
        elif field.number == 5:
            mtime = decode_signed64(field)
        elif field.number == 6:
            mode = decode_unsigned(field)
        elif field.number == 9:
            symlink = bytes(field.value)
            if b"\0" in symlink:
                raise Error("Malformed", "NUL byte in symlink target", field.offset)
        else:
            hardlink = check_path(field.value, field.offset)
    if not has_path or not has_kind:
        raise Error("Malformed", "manifest entry without path or kind", base)
    if kind not in (1, 2, 3, 4):
        raise Error("Unsupported", "unknown manifest entry kind", base)
    regular = kind == 1
    if has_length != regular:
        raise Error("Malformed", "file length present on the wrong entry kind", base)
    if regular and length != 0 and not has_chunks:
        raise Error("Malformed", "non-empty file without chunks", base)
    if (symlink is not None) != (kind == 3):
        raise Error("Malformed", "symlink target present on the wrong entry kind", base)
    if (hardlink is not None) != (kind == 4):
        raise Error("Malformed", "hard link target present on the wrong entry kind", base)
    if mode is not None and kind in (3, 4):
        raise Error("Malformed", "mode present on a link entry", base)
    if mtime is not None and kind == 4:
        raise Error("Malformed", "modification time present on a hard link", base)
    if mode is not None and mode > 0o7777:
        raise Error("Malformed", "mode has bits outside the permission bits", base)
    if symlink is not None:
        if len(symlink) == 0 or len(symlink) > 4096:
            raise Error("Malformed", "symlink target empty or too long", base)
        symlink = symlink.decode("utf-8", errors="replace")
    return {"path": path, "kind": kind, "length": length or 0, "mtime": mtime, "mode": mode,
            "target": symlink if symlink is not None else hardlink,
            "first_chunk": first_chunk, "chunk_count": chunk_count}


def decode_chunk_list(field, declared_length, chunks, object_ids):
    raw_elements = read_tlv_list(field, 0xFFFFFFFF)
    if len(raw_elements) == 0:
        raise Error("Malformed", "explicit empty chunk list", field.offset)
    first_lists = len(chunks) == 0 and len(object_ids) == 0
    encrypted = None
    total = 0
    for element, offset in raw_elements:
        has_object = scan_for_field(element, offset, 10)
        if encrypted is None:
            encrypted = has_object
            if not first_lists:
                reference_encrypted = len(object_ids) > 0
                if encrypted != reference_encrypted:
                    raise Error("Malformed", "mixed plain and encrypted chunk lists", offset)
        elif has_object != encrypted:
            raise Error("Malformed", "mixed plain and encrypted chunk lists", offset)
        if encrypted:
            key, object_id = decode_encrypted_extent(element, offset)
            chunks.append(key)
            object_ids.append(object_id)
        else:
            chunks.append(decode_chunk_key(element, offset))
        total += chunks[-1]["length"]
        if total > declared_length:
            raise Error("Malformed", "chunk lengths exceed the file length", offset)
    if total != declared_length:
        raise Error("Malformed", "chunk lengths do not add up to the file length", field.offset)
    return len(raw_elements)


def scan_for_field(element, base, wanted):
    reader = TlvReader(element, base)
    while True:
        field = reader.next()
        if field is None:
            return False
        if field.number == wanted:
            return True
        if field.number > wanted:
            return False


def decode_encrypted_extent(element, base):
    reader = TlvReader(element, base)
    algorithm = digest = length = object_id = None
    has_algorithm = has_digest = has_length = has_object = False
    while True:
        field = reader.next()
        if field is None:
            break
        if field.number == 10:
            require_critical(field, True)
            if len(field.value) != 32:
                raise Error("Malformed", "object id has a bad size", field.offset)
            object_id = bytes(field.value)
            has_object = True
            continue
        if field.number < 1 or field.number > 3:
            skip_unknown(field)
            continue
        require_critical(field, True)
        if field.number == 1:
            algorithm = decode_unsigned(field)
            if algorithm not in (HASH_BLAKE3, HASH_ENCRYPTED_OBJECT):
                raise Error("Unsupported", "unknown chunk hash algorithm", field.offset)
            has_algorithm = True
        elif field.number == 2:
            if len(field.value) != 32:
                raise Error("Malformed", "chunk digest is not 32 bytes", field.offset)
            digest = bytes(field.value)
            has_digest = True
        else:
            length = decode_unsigned(field)
            if length == 0:
                raise Error("Malformed", "empty chunk", field.offset)
            if length > MAX_CHUNK_SIZE:
                raise Error("LimitExceeded", "chunk length exceeds the format maximum",
                            field.offset)
            has_length = True
    if not (has_algorithm and has_digest and has_length):
        raise Error("Malformed", "chunk key is missing a field", base)
    if not has_object:
        raise Error("Malformed", "encrypted extent missing object id", base)
    return {"algorithm": algorithm, "digest": digest, "length": length}, object_id


def check_tree(entries, base):
    by_path = {entry["path"]: entry for entry in entries}
    for entry in entries:
        path = entry["path"]
        slash = path.find("/")
        while slash != -1:
            parent = by_path.get(path[:slash])
            if parent is None or parent["kind"] != 2:
                raise Error("Malformed", "manifest entry without a parent directory entry", base)
            slash = path.find("/", slash + 1)
        if entry["kind"] != 4:
            continue
        target = by_path.get(entry["target"])
        if target is None or target["kind"] != 1:
            raise Error("Malformed", "hard link target is not a regular entry", base)
        if not entry["target"] < path:
            raise Error("Malformed", "hard link target does not precede the link", base)


def decode_writer_metadata(field):
    reader = TlvReader(field.value, field.offset)
    metadata = {}
    while True:
        nested = reader.next()
        if nested is None:
            break
        known = 1 <= nested.number <= 12 and nested.number != 7
        if not known:
            skip_unknown(nested)
            continue
        require_critical(nested, False)
        if nested.number == 1:
            metadata["name"] = bytes(nested.value).decode("utf-8", errors="replace")
        elif nested.number == 4:
            metadata["level"] = decode_signed64(nested)
        else:
            metadata[nested.number] = decode_unsigned(nested)
    if not metadata:
        raise Error("Malformed", "explicit empty writer metadata", field.offset)
    names = {2: "preset", 3: "codec", 5: "chunk_policy", 6: "chunk_size", 8: "workers",
             9: "chunk_min", 10: "chunk_target", 11: "chunk_max", 12: "chunk_algorithm"}
    return {names.get(number, number): value for number, value in metadata.items()}


def decode_index(payload, base, max_entries=0xFFFFFFFF):
    reader = TlvReader(payload, base)
    version = None
    entries = None
    has_version = has_entries = False
    while True:
        field = reader.next()
        if field is None:
            break
        if field.number > 2:
            skip_unknown(field)
            continue
        require_critical(field, True)
        if field.number == 1:
            version = decode_unsigned(field)
            if version != 1:
                raise Error("Unsupported", "unsupported index schema version", field.offset)
            has_version = True
        else:
            if not has_version:
                raise Error("Malformed", "index entries before schema version", field.offset)
            entries = decode_index_entries(field, max_entries)
            has_entries = True
    if not has_version or not has_entries:
        raise Error("Malformed", "index missing a required field", base)
    return entries


def decode_index_entries(field, max_entries):
    raw_elements = read_tlv_list(field, max_entries)
    entries = []
    for element, offset in raw_elements:
        entry = decode_index_entry(element, offset)
        if entries and (entry["key"]["algorithm"], entry["key"]["digest"],
                        entry["key"]["length"]) <= (entries[-1]["key"]["algorithm"],
                                                   entries[-1]["key"]["digest"],
                                                   entries[-1]["key"]["length"]):
            raise Error("Malformed", "index keys not in strictly increasing order", offset)
        entries.append(entry)
    return entries


def decode_index_entry(element, base):
    reader = TlvReader(element, base)
    algorithm = digest = key_length = None
    has_algorithm = has_digest = has_key_length = False
    record_offset = record_length = codec = None
    has_offset = has_length = has_codec = False
    while True:
        field = reader.next()
        if field is None:
            break
        if field.number <= 3:
            require_critical(field, True)
            if field.number == 1:
                algorithm = decode_unsigned(field)
                if algorithm not in (HASH_BLAKE3, HASH_ENCRYPTED_OBJECT):
                    raise Error("Unsupported", "unknown chunk hash algorithm", field.offset)
                has_algorithm = True
            elif field.number == 2:
                if len(field.value) != 32:
                    raise Error("Malformed", "chunk digest is not 32 bytes", field.offset)
                digest = bytes(field.value)
                has_digest = True
            else:
                key_length = decode_unsigned(field)
                if key_length == 0:
                    raise Error("Malformed", "empty chunk", field.offset)
                if key_length > MAX_CHUNK_SIZE:
                    raise Error("LimitExceeded", "chunk length exceeds the format maximum",
                                field.offset)
                has_key_length = True
            continue
        if field.number > 6:
            skip_unknown(field)
            continue
        require_critical(field, True)
        value = decode_unsigned(field)
        if field.number == 4:
            record_offset, has_offset = value, True
        elif field.number == 5:
            record_length, has_length = value, True
        else:
            if value > 0xFFFFFFFF:
                raise Error("Malformed", "codec ID exceeds 32 bits", field.offset)
            codec, has_codec = value, True
    if not (has_algorithm and has_digest and has_key_length):
        raise Error("Malformed", "chunk key is missing a field", base)
    if not (has_offset and has_length and has_codec):
        raise Error("Malformed", "index entry is missing a field", base)
    if record_offset < SUPERBLOCK_SIZE:
        raise Error("Malformed", "index record offset inside superblock", base)
    if record_length <= RECORD_FRAMING_SIZE:
        raise Error("Malformed", "index record length too short", base)
    if record_offset + record_length < record_offset:
        raise Error("Malformed", "index record span overflows", base)
    return {"key": {"algorithm": algorithm, "digest": digest, "length": key_length},
            "record_offset": record_offset, "record_length": record_length, "codec": codec}


def decode_commit(payload, base):
    reader = TlvReader(payload, base)
    values = {}
    digests = {}
    seen = 0
    has_previous_footer = False
    previous_footer_offset = 0
    has_epoch = False
    epoch = 0
    while True:
        field = reader.next()
        if field is None:
            break
        if field.number == 12:
            require_critical(field, False)
            if has_previous_footer:
                raise Error("Malformed", "duplicate previous footer field", field.offset)
            previous_footer_offset = decode_unsigned(field)
            has_previous_footer = True
            continue
        if field.number == 13:
            require_critical(field, True)
            if has_epoch:
                raise Error("Malformed", "duplicate epoch field", field.offset)
            epoch = decode_unsigned(field)
            if epoch == 0:
                raise Error("Malformed", "commit epoch is zero", field.offset)
            has_epoch = True
            continue
        if field.number > 10:
            skip_unknown(field)
            continue
        require_critical(field, True)
        seen |= 1 << field.number
        if field.number in (3, 7, 10):
            if len(field.value) != 32:
                raise Error("Malformed", "commit digest is not 32 bytes", field.offset)
            digests[field.number] = bytes(field.value)
        else:
            values[field.number] = decode_unsigned(field)
    all_fields = sum(1 << number for number in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
    if seen != all_fields:
        raise Error("Malformed", "commit missing a required field", base)
    if values[1] != 1:
        raise Error("Unsupported", "unsupported commit schema version", base)
    if values[4] & ~KNOWN_COMMIT_FEATURES:
        raise Error("Unsupported", "unknown required commit feature", base)
    if values[2] == 0:
        raise Error("Malformed", "commit generation zero", base)
    if values[2] > 1 and not has_previous_footer:
        raise Error("Malformed", "commit is missing its previous footer", base)
    if values[2] == 1 and has_previous_footer:
        raise Error("Malformed", "first generation has a previous footer", base)
    encrypted = bool(values[4] & COMMIT_ENCRYPTED_FEATURE)
    if encrypted and not has_epoch:
        raise Error("Malformed", "encrypted commit missing epoch", base)
    if not encrypted and has_epoch:
        raise Error("Malformed", "plain commit has an epoch", base)
    return {
        "generation": values[2],
        "previous": digests[3],
        "required_features": values[4],
        "manifest": {"offset": values[5], "length": values[6], "digest": digests[7]},
        "index": {"offset": values[8], "length": values[9], "digest": digests[10]},
        "previous_footer_offset": previous_footer_offset,
        "has_previous_footer": has_previous_footer,
        "epoch": epoch,
    }


def decode_footer(data, pos):
    if len(data) - pos < FOOTER_SIZE:
        raise Error("Truncated", "footer truncated", pos + len(data) - pos)
    block = data[pos:pos + FOOTER_SIZE]
    if block[:8] != b"BALEFTR1":
        raise Error("Malformed", "bad footer magic", pos)
    zeroed = bytearray(block)
    zeroed[64:68] = b"\0\0\0\0"
    if struct.unpack("<I", block[64:68])[0] != crc32c(bytes(zeroed)):
        raise Error("Integrity", "footer checksum mismatch", pos + 64)
    if block[68:96] != b"\0" * 28:
        raise Error("Malformed", "footer reserved bytes not zero", pos + 68)
    commit_offset = struct.unpack("<Q", block[8:16])[0]
    commit_length = struct.unpack("<Q", block[16:24])[0]
    generation = struct.unpack("<Q", block[24:32])[0]
    if commit_length < RECORD_FRAMING_SIZE:
        raise Error("Malformed", "footer commit length shorter than record framing", pos + 16)
    if commit_offset < SUPERBLOCK_SIZE:
        raise Error("Malformed", "footer commit offset inside superblock", pos + 8)
    if commit_offset + commit_length < commit_offset or commit_offset + commit_length > pos:
        raise Error("Malformed", "footer commit record does not precede footer", pos + 8)
    return {"commit_offset": commit_offset, "commit_length": commit_length,
            "generation": generation, "digest": bytes(block[32:64])}


def decode_keyslot(payload, base):
    reader = TlvReader(payload, base)
    values = {}
    blobs = {}
    while True:
        field = reader.next()
        if field is None:
            break
        if field.number > 21:
            skip_unknown(field)
            continue
        known = field.number in (1, 2, 3, 4, 10, 11, 12, 13, 14, 20, 21)
        if not known:
            skip_unknown(field)
            continue
        require_critical(field, True)
        if field.number in (10, 13, 14, 20, 21):
            blobs[field.number] = bytes(field.value)
        else:
            values[field.number] = decode_unsigned(field)
    for number in (1, 2, 3, 4):
        if number not in values:
            raise Error("Malformed", "keyslot missing a required field", base)
    if values[1] != 1:
        raise Error("Unsupported", "unknown extension kind", base)
    if values[2] != 1:
        raise Error("Unsupported", "unsupported keyslot version", base)
    if values[3] == 0:
        raise Error("Malformed", "keyslot epoch is zero", base)
    if values[4] not in (0, 1):
        raise Error("Malformed", "unknown slot kind", base)
    if values[4] == 0:
        for number in (10, 11, 12, 13, 14):
            if number not in blobs and number not in values:
                raise Error("Malformed", "password slot missing a field", base)
        if 20 in blobs or 21 in blobs:
            raise Error("Malformed", "password slot has recipient fields", base)
        if len(blobs.get(10, b"")) != 16:
            raise Error("Malformed", "keyslot salt has a bad size", base)
        if values.get(11, 0) == 0:
            raise Error("Malformed", "keyslot opslimit is zero", base)
        if values.get(11, 0) > 8:
            raise Error("LimitExceeded", "keyslot opslimit exceeds the bale ceiling", base)
        if values.get(12, 0) == 0:
            raise Error("Malformed", "keyslot memlimit is zero", base)
        if values.get(12, 0) > (1 << 30):
            raise Error("LimitExceeded", "keyslot memlimit exceeds the bale ceiling", base)
        if len(blobs.get(13, b"")) != 24:
            raise Error("Malformed", "keyslot nonce has a bad size", base)
        if len(blobs.get(14, b"")) != 48:
            raise Error("Malformed", "keyslot wrap has a bad size", base)
    else:
        for number in (20, 21):
            if number not in blobs:
                raise Error("Malformed", "recipient slot missing a field", base)
        if any(number in blobs or number in values for number in (10, 11, 12, 13, 14)):
            raise Error("Malformed", "recipient slot has password fields", base)
        if len(blobs[20]) != 32:
            raise Error("Malformed", "recipient key has a bad size", base)
        if len(blobs[21]) != 80:
            raise Error("Malformed", "recipient seal has a bad size", base)
    return {"epoch": values[3], "kind": values[4]}


class Archive:
    def __init__(self, data):
        self.data = data
        self.superblock = None
        self.encrypted = False
        self.generations = []
        self.footer = None
        self.footer_offset = 0
        self.commit = None
        self.commit_digest = b""
        self.manifest = None
        self.index = None
        self.stats = {"records": 0, "data_records": 0, "unindexed": 0, "chunks_verified": 0,
                      "bytes_verified": 0, "codecs": {}, "opaque_bytes": 0}


def find_footer(data):
    if len(data) < SUPERBLOCK_SIZE:
        raise Error("Truncated", "file too small for a superblock", len(data))
    if len(data) - SUPERBLOCK_SIZE < FOOTER_SIZE:
        raise Error("Truncated", "no footer found: the archive is incomplete or truncated")
    candidates = []
    start = 0
    while True:
        at = data.find(b"BALEFTR1", start)
        if at < 0:
            break
        candidates.append(at)
        start = at + 1
    nearest = None
    attempts = 0
    for at in reversed(candidates):
        if attempts >= 64:
            break
        if at < SUPERBLOCK_SIZE or len(data) - at < FOOTER_SIZE:
            continue
        try:
            archive = try_footer(data, at)
            return archive
        except Error as error:
            if nearest is None:
                nearest = error
            attempts += 1
    if nearest is not None:
        raise nearest
    raise Error("Truncated", "no footer found: the archive is incomplete or truncated")


def try_footer(data, footer_offset):
    superblock = decode_superblock(data)
    encrypted = bool(superblock["required"] & FEATURE_ENCRYPTED)
    footer = decode_footer(data, footer_offset)
    if footer["commit_offset"] + footer["commit_length"] != footer_offset:
        raise Error("Malformed", "footer does not directly follow its commit", footer_offset)
    record = read_record(data, footer["commit_offset"], MAX_COMMIT_PAYLOAD, MAX_COMMIT_PAYLOAD)
    if record["type"] != 4:
        raise Error("Malformed", "record has an unexpected type", footer["commit_offset"])
    if record["codec"] != 0:
        raise Error("Malformed", "commit record is not stored raw", footer["commit_offset"])
    digest = derive_key(CONTEXTS["commit"], record["payload"])
    if digest != footer["digest"]:
        raise Error("Integrity", "commit digest mismatch", footer["commit_offset"])
    archive = Archive(data)
    archive.superblock = superblock
    archive.encrypted = encrypted
    archive.footer = footer
    archive.footer_offset = footer_offset
    if encrypted:
        # NOTE: sealed bytes are opaque without a key (stdlib only, no XChaCha20).
        # What is checked: superblock, every record prefix/trailer and CRC,
        # sequencing, the ENCRYPTED flag on every record, footer adjacency and
        # the commit digest over the sealed bytes, plus keyslot and data-header
        # shapes. Manifest/index/commit plaintexts stay sealed.
        if not record["flags"] & FLAG_ENCRYPTED:
            raise Error("Malformed", "plain record inside an encrypted archive",
                        footer["commit_offset"])
        archive.generations = [{"footer": footer, "commit": None, "digest": digest,
                                "footer_offset": footer_offset}]
        archive.commit = {"generation": footer["generation"]}
        archive.commit_digest = digest
        sweep_encrypted_records(archive)
        return archive
    if record["flags"] & FLAG_ENCRYPTED:
        raise Error("Unsupported", "encrypted record in a plain archive",
                    footer["commit_offset"])
    commit = decode_commit(record["payload"], footer["commit_offset"] + RECORD_PREFIX_SIZE)
    if commit["generation"] != footer["generation"]:
        raise Error("Malformed", "footer and commit disagree on generation", footer_offset)
    generations = [{"footer": footer, "commit": commit, "digest": digest,
                    "footer_offset": footer_offset}]
    parent = commit
    while parent["generation"] > 1:
        if len(generations) >= MAX_GENERATIONS:
            raise Error("LimitExceeded", "archive generation limit exceeded", footer_offset)
        if (parent["previous"] == b"\0" * 32 or
                parent["previous_footer_offset"] >= generations[-1]["footer_offset"]):
            raise Error("Malformed", "invalid previous commit footer", footer_offset)
        previous_offset = parent["previous_footer_offset"]
        if previous_offset + FOOTER_SIZE > generations[-1]["footer_offset"]:
            raise Error("Malformed", "invalid previous commit footer", footer_offset)
        parent_footer = decode_footer(data, previous_offset)
        if (parent_footer["generation"] + 1 != parent["generation"] or
                parent_footer["digest"] != parent["previous"] or
                parent_footer["commit_offset"] + parent_footer["commit_length"] !=
                previous_offset):
            raise Error("Integrity", "previous footer does not match commit chain", footer_offset)
        parent_record = read_record(data, parent_footer["commit_offset"], MAX_COMMIT_PAYLOAD,
                                    MAX_COMMIT_PAYLOAD)
        if parent_record["type"] != 4:
            raise Error("Malformed", "record has an unexpected type",
                        parent_footer["commit_offset"])
        if parent_record["codec"] != 0:
            raise Error("Malformed", "commit record is not stored raw",
                        parent_footer["commit_offset"])
        parent_commit = decode_commit(parent_record["payload"],
                                      parent_footer["commit_offset"] + RECORD_PREFIX_SIZE)
        parent_digest = derive_key(CONTEXTS["commit"], parent_record["payload"])
        if (parent_digest != parent_footer["digest"] or
                parent_commit["generation"] != parent_footer["generation"] or
                parent_commit["generation"] + 1 != parent["generation"]):
            raise Error("Integrity", "parent commit does not match footer",
                        parent_footer["commit_offset"])
        for reference, domain in ((parent_commit["manifest"], "manifest"),
                                  (parent_commit["index"], "index")):
            if (reference["offset"] < SUPERBLOCK_SIZE or
                    reference["offset"] + reference["length"] > parent_footer["commit_offset"]):
                raise Error("Malformed", "parent metadata reference outside its generation")
            metadata = read_record(data, reference["offset"], MAX_METADATA_BYTES,
                                   MAX_METADATA_BYTES)
            if derive_key(CONTEXTS[domain], metadata["payload"]) != reference["digest"]:
                raise Error("Integrity", "parent metadata record failed validation",
                            reference["offset"])
        generations.append({"footer": parent_footer, "commit": parent_commit,
                            "digest": parent_digest, "footer_offset": previous_offset})
        parent = parent_commit
    if parent["previous"] != b"\0" * 32 or parent["generation"] != 1:
        raise Error("Malformed", "first generation has a parent commit", footer_offset)
    generations.reverse()
    archive.generations = generations
    archive.commit = commit
    archive.commit_digest = digest
    load_metadata(archive)
    check_locations(archive)
    return archive


def sweep_encrypted_records(archive):
    """Framing sweep over an encrypted archive. No keys, no decryption.

    Checks every record prefix/trailer, CRCs, sequence order, the ENCRYPTED
    flag, keyslot TLV shapes and encrypted data-header sizes. Anything sealed
    stays opaque. Raises the structural error, or returns with stats filled.
    """
    data = archive.data
    stats = archive.stats
    position = SUPERBLOCK_SIZE
    keyslots = 0
    while position < archive.footer_offset:
        if archive.footer_offset - position < RECORD_FRAMING_SIZE:
            raise Error("Malformed", "stray bytes before the footer", position)
        header = decode_record_prefix(data, position)
        if header["size"] > archive.footer_offset - position:
            raise Error("Malformed", "record extends past the footer", position)
        if header["sequence"] != stats["records"]:
            raise Error("Malformed", "record sequence number out of order", position)
        if not header["flags"] & FLAG_ENCRYPTED:
            raise Error("Malformed", "plain record inside an encrypted archive", position)
        payload_pos = position + RECORD_PREFIX_SIZE
        verify_trailer(data, payload_pos, header["payload_length"])
        payload = data[payload_pos:payload_pos + header["payload_length"]]
        if header["type"] == 1:
            # NOTE: object id (32) + epoch (8) + record nonce (24), then the seal.
            if header["payload_length"] < 64:
                raise Error("Malformed", "encrypted data record shorter than its header",
                            position)
            if header["decoded_length"] != header["payload_length"]:
                raise Error("Malformed", "encrypted data decoded length differs from stored",
                            position)
            stats["data_records"] += 1
            stats["opaque_bytes"] += header["payload_length"] - 64
        elif header["type"] == 5:
            decode_keyslot(payload, payload_pos)
            keyslots += 1
        elif header["type"] in (2, 3, 4):
            # NOTE: record nonce (24) + seal; the TLV plaintext stays sealed.
            if header["payload_length"] < 24:
                raise Error("Malformed", "encrypted metadata record shorter than its nonce",
                            position)
            stats["opaque_bytes"] += header["payload_length"] - 24
        elif header["type"] not in KNOWN_RECORD_TYPES:
            raise Error("Unsupported", "unknown record type", position)
        stats["records"] += 1
        position += header["size"]
    archive.stats["keyslots"] = keyslots


def load_metadata(archive):
    commit = archive.commit
    for reference in (commit["manifest"], commit["index"]):
        if (reference["offset"] < SUPERBLOCK_SIZE or
                reference["offset"] + reference["length"] > archive.footer["commit_offset"]):
            raise Error("Malformed", "metadata record outside the committed region")
    manifest_ref = commit["manifest"]
    index_ref = commit["index"]
    if (manifest_ref["offset"] < index_ref["offset"] + index_ref["length"] and
            index_ref["offset"] < manifest_ref["offset"] + manifest_ref["length"]):
        raise Error("Malformed", "manifest and index records overlap")
    manifest_record = read_record(archive.data, manifest_ref["offset"], MAX_METADATA_BYTES,
                                  MAX_METADATA_BYTES)
    if manifest_record["type"] != 2:
        raise Error("Malformed", "record has an unexpected type", manifest_ref["offset"])
    index_record = read_record(archive.data, index_ref["offset"], MAX_METADATA_BYTES,
                               MAX_METADATA_BYTES)
    if index_record["type"] != 3:
        raise Error("Malformed", "record has an unexpected type", index_ref["offset"])
    if manifest_record["codec"] != 0:
        raise Error("Unsupported", "compressed manifest records are not supported",
                    manifest_ref["offset"])
    if index_record["codec"] != 0:
        raise Error("Unsupported", "compressed index records are not supported",
                    index_ref["offset"])
    if derive_key(CONTEXTS["manifest"], manifest_record["payload"]) != manifest_ref["digest"]:
        raise Error("Integrity", "manifest digest mismatch", manifest_ref["offset"])
    if derive_key(CONTEXTS["index"], index_record["payload"]) != index_ref["digest"]:
        raise Error("Integrity", "index digest mismatch", index_ref["offset"])
    archive.index = decode_index(index_record["payload"],
                                 index_ref["offset"] + RECORD_PREFIX_SIZE)
    archive.manifest = decode_manifest(manifest_record["payload"],
                                       manifest_ref["offset"] + RECORD_PREFIX_SIZE)
    keys = {(entry["key"]["algorithm"], entry["key"]["digest"], entry["key"]["length"])
            for entry in archive.index}
    for key in archive.manifest["chunks"]:
        if (key["algorithm"], key["digest"], key["length"]) not in keys:
            raise Error("Malformed", "manifest references a chunk missing from the index",
                        manifest_ref["offset"])


def check_locations(archive):
    by_offset = sorted(archive.index, key=lambda entry: entry["record_offset"])
    previous_end = SUPERBLOCK_SIZE
    for entry in by_offset:
        if entry["record_offset"] < previous_end:
            raise Error("Malformed", "indexed records overlap", entry["record_offset"])
        for reference in (archive.commit["manifest"], archive.commit["index"]):
            if (entry["record_offset"] < reference["offset"] + reference["length"] and
                    reference["offset"] < entry["record_offset"] + entry["record_length"]):
                raise Error("Malformed", "indexed record overlaps metadata or the commit",
                            entry["record_offset"])
        if (entry["record_offset"] + entry["record_length"] < entry["record_offset"] or
                entry["record_offset"] + entry["record_length"] > archive.footer["commit_offset"]):
            raise Error("Malformed", "indexed record overlaps metadata or the commit",
                        entry["record_offset"])
        previous_end = entry["record_offset"] + entry["record_length"]
        if entry["codec"] != 0:
            continue
        descriptor = descriptor_size(entry["key"])
        if entry["record_length"] != RECORD_FRAMING_SIZE + descriptor + entry["key"]["length"]:
            raise Error("Malformed", "indexed raw record length does not match its chunk",
                        entry["record_offset"])


def descriptor_size(key):
    # NOTE: exact descriptor size without hashing: a chunk-key TLV is 39 bytes
    # plus the ULEB128 of the length (field headers are 1 byte each here and the
    # digest is always 32 bytes), prefixed by its own 1-byte ULEB128 length.
    length = key["length"]
    size = 0
    while True:
        size += 1
        length >>= 7
        if not length:
            break
    return 40 + size


def walk_records(archive):
    data = archive.data
    stats = archive.stats
    max_payload = max(MAX_METADATA_BYTES, 1 + MAX_DATA_DESCRIPTOR + MAX_CHUNK_SIZE)
    by_offset = sorted(archive.index, key=lambda entry: entry["record_offset"])
    next_indexed = 0
    generation = 0
    generations = archive.generations
    position = SUPERBLOCK_SIZE
    while position < archive.footer_offset:
        if generation < len(generations) and position == generations[generation]["footer_offset"]:
            position += FOOTER_SIZE
            generation += 1
            continue
        if archive.footer_offset - position < RECORD_FRAMING_SIZE:
            raise Error("Malformed", "stray bytes before the footer", position)
        header = decode_record_prefix(data, position, max_payload, max_payload)
        size = header["payload_length"] + RECORD_FRAMING_SIZE
        if size > archive.footer_offset - position:
            raise Error("Malformed", "record extends past the footer", position)
        if header["sequence"] != stats["records"]:
            raise Error("Malformed", "record sequence number out of order", position)
        is_encrypted = bool(header["flags"] & FLAG_ENCRYPTED)
        if archive.encrypted and not is_encrypted:
            raise Error("Malformed", "plain record inside an encrypted archive", position)
        if not archive.encrypted and is_encrypted:
            raise Error("Unsupported", "encrypted record in a plain archive", position)
        expected = True
        payload_pos = position + RECORD_PREFIX_SIZE
        if header["type"] == 1:
            stats["data_records"] += 1
            stats["codecs"][header["codec"]] = stats["codecs"].get(header["codec"], 0) + 1
            if (next_indexed < len(by_offset) and
                    by_offset[next_indexed]["record_offset"] == position):
                entry = by_offset[next_indexed]
                expected = (entry["record_length"] == size and
                            entry["codec"] == header["codec"])
                next_indexed += 1
            else:
                stats["unindexed"] += 1
            # NOTE: like the C++ walk, DATA payloads (and their trailers) are
            # not re-read here; the content phase below reads every indexed
            # record in full, which is where payload CRCs are checked.
        elif header["type"] in (2, 3, 4):
            kind = {2: "manifest", 3: "index", 4: "commit"}[header["type"]]
            if generation < len(generations):
                if kind == "manifest":
                    reference = generations[generation]["commit"]["manifest"]
                elif kind == "index":
                    reference = generations[generation]["commit"]["index"]
                else:
                    reference = {"offset": generations[generation]["footer"]["commit_offset"],
                                 "length": generations[generation]["footer"]["commit_length"],
                                 "digest": generations[generation]["digest"]}
                expected = position == reference["offset"] and size == reference["length"]
                if expected:
                    verify_trailer(data, payload_pos, header["payload_length"])
                    payload = data[payload_pos:payload_pos + header["payload_length"]]
                    expected = derive_key(CONTEXTS[kind], payload) == reference["digest"]
            else:
                expected = False
        else:
            # NOTE: plain archives never carry keyslots; like the C++ walk,
            # EXTENSION payloads are not re-read here, only sequenced.
            # Keyslot shape is enforced inside encrypted archives, where the
            # sweep above decodes it.
            pass
        if not expected:
            raise Error("Malformed", "record does not match the committed metadata", position)
        stats["records"] += 1
        position += size
    if next_indexed != len(by_offset):
        raise Error("Malformed", "index entry does not point at a record boundary")
    if generation + 1 != len(generations):
        raise Error("Malformed", "generation footer is missing from the record stream")
    return stats


def verify_content(archive):
    stats = archive.stats
    for entry in archive.index:
        record = read_record(archive.data, entry["record_offset"],
                             1 + MAX_DATA_DESCRIPTOR + MAX_CHUNK_SIZE,
                             1 + MAX_DATA_DESCRIPTOR + MAX_CHUNK_SIZE)
        if record["codec"] != entry["codec"]:
            raise Error("Malformed", "data record codec differs from the index",
                        entry["record_offset"])
        payload_pos = entry["record_offset"] + RECORD_PREFIX_SIZE
        parsed = decode_data_payload(record["payload"], payload_pos)
        key = parsed["key"]
        if (key["algorithm"], key["digest"], key["length"]) != (entry["key"]["algorithm"],
                                                               entry["key"]["digest"],
                                                               entry["key"]["length"]):
            raise Error("Malformed", "data record holds a different chunk than indexed",
                        payload_pos)
        if record["decoded_length"] != parsed["descriptor_size"] + key["length"]:
            raise Error("Malformed", "data record decoded length does not match its chunk",
                        entry["record_offset"])
        if record["codec"] == 0:
            if len(parsed["encoded"]) != key["length"]:
                raise Error("Malformed", "raw chunk length does not match its key", payload_pos)
            actual = derive_key(CONTEXTS["chunk"], parsed["encoded"])
            if actual != key["digest"]:
                raise Error("Integrity", "chunk content does not match its BLAKE3 digest",
                            payload_pos + parsed["descriptor_size"])
            stats["chunks_verified"] += 1
            stats["bytes_verified"] += len(parsed["encoded"])
        else:
            if record["codec"] not in KNOWN_CODECS:
                raise Error("Unsupported", "chunk codec not supported", payload_pos)
            if entry["key"]["length"] > MAX_CHUNK_SIZE:
                raise Error("LimitExceeded", "compressed chunk exceeds the supported size")
            stats["opaque_bytes"] += len(parsed["encoded"])
    return stats


def verify(data, content=True):
    """Verify an archive image. Returns a report dict; raises Error on failure."""
    archive = find_footer(data)
    if archive.encrypted:
        # NOTE: the framing sweep already ran inside try_footer, so reaching
        # here means the envelope is structurally sound; without a key the
        # sealed plaintexts stay opaque and the verdict is password-required,
        # exactly like Reader::open without unlock credentials.
        raise Error("PasswordRequired", "archive is encrypted")
    walk_records(archive)
    if content:
        verify_content(archive)
    report = {"verdict": "ok", "encrypted": archive.encrypted,
              "generations": len(archive.generations),
              "generation": archive.commit["generation"],
              "records": archive.stats["records"],
              "data_records": archive.stats["data_records"],
              "unindexed": archive.stats["unindexed"],
              "chunks_verified": archive.stats["chunks_verified"],
              "bytes_verified": archive.stats["bytes_verified"],
              "opaque_bytes": archive.stats["opaque_bytes"],
              "codecs": archive.stats["codecs"]}
    if archive.encrypted:
        report["content"] = "opaque (no key)"
    return report


def main(arguments):
    if len(arguments) != 2:
        print("usage: bale_verify.py <archive>", file=sys.stderr)
        return 2
    with open(arguments[1], "rb") as handle:
        data = handle.read()
    try:
        report = verify(data)
    except Error as error:
        print("reject %s: %s (offset %s)" % (error.kind, error.message, error.offset))
        return 1
    print("ok generations=%d records=%d data=%d chunks_verified=%d bytes=%d opaque=%d "
          "codecs=%s%s" % (report["generations"], report["records"], report["data_records"],
                           report["chunks_verified"], report["bytes_verified"],
                           report["opaque_bytes"], report["codecs"],
                           " ENCRYPTED(structure only)" if report["encrypted"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
