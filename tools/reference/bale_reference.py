"""Second, independent encoder for BALE golden vectors (whitepaper sections 5A.2-5A.5).

Pure Python with its own BLAKE3 and CRC32C, written from the schema description rather
than from the C++ sources, so a golden archive produced here checks the C++ writer
instead of echoing it.

Coverage: all record types (DATA, MANIFEST, INDEX, COMMIT, EXTENSION), all codecs
(RAW, ZSTD, LZ4, LZMA2, BROTLI), record flags (provisional ENCRYPTED bit marked as
such), superblock required/optional features, chunk policies (FIXED, CDC) with the
pinned gear table, writer-metadata fields including the CDC triple, multi-generation
appends, and the provisional encrypted envelope shape (structure only: this module
has no XChaCha20-Poly1305 and never seals anything; sealed bytes are opaque
placeholders, never valid ciphertext).
"""

import struct
import sys

IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
MESSAGE_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6
BLOCK_LEN = 64
CHUNK_LEN = 1024
MASK = 0xFFFFFFFF


def rotate_right(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & MASK


def mix(state, a, b, c, d, x, y):
    state[a] = (state[a] + state[b] + x) & MASK
    state[d] = rotate_right(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotate_right(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + y) & MASK
    state[d] = rotate_right(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotate_right(state[b] ^ state[c], 7)


def compress(chaining_value, block_words, counter, block_len, flags):
    state = list(chaining_value) + list(IV[:4]) + [
        counter & MASK,
        (counter >> 32) & MASK,
        block_len,
        flags,
    ]
    message = list(block_words)
    for round_index in range(7):
        mix(state, 0, 4, 8, 12, message[0], message[1])
        mix(state, 1, 5, 9, 13, message[2], message[3])
        mix(state, 2, 6, 10, 14, message[4], message[5])
        mix(state, 3, 7, 11, 15, message[6], message[7])
        mix(state, 0, 5, 10, 15, message[8], message[9])
        mix(state, 1, 6, 11, 12, message[10], message[11])
        mix(state, 2, 7, 8, 13, message[12], message[13])
        mix(state, 3, 4, 9, 14, message[14], message[15])
        if round_index < 6:
            message = [message[index] for index in MESSAGE_PERMUTATION]
    for index in range(8):
        state[index] ^= state[index + 8]
        state[index + 8] ^= chaining_value[index]
    return state


def words_of(block):
    return struct.unpack("<16I", block.ljust(BLOCK_LEN, b"\0"))


def chunk_output(key_words, chunk, counter, flags):
    chaining_value = key_words
    blocks = [chunk[start : start + BLOCK_LEN] for start in range(0, len(chunk), BLOCK_LEN)] or [b""]
    for position, block in enumerate(blocks):
        block_flags = flags
        if position == 0:
            block_flags |= CHUNK_START
        if position == len(blocks) - 1:
            return (chaining_value, words_of(block), counter, len(block), block_flags | CHUNK_END)
        chaining_value = compress(chaining_value, words_of(block), counter, BLOCK_LEN, block_flags)[:8]
    raise AssertionError("unreachable")


def parent_output(left, right, key_words, flags):
    return (key_words, tuple(left) + tuple(right), 0, BLOCK_LEN, flags | PARENT)


def chaining_value_of(output):
    return compress(*output)[:8]


def blake3(data, key_words=IV, flags=0, length=32):
    chunks = [data[start : start + CHUNK_LEN] for start in range(0, len(data), CHUNK_LEN)] or [b""]
    stack = []
    for counter, chunk in enumerate(chunks[:-1]):
        chaining_value = chaining_value_of(chunk_output(key_words, chunk, counter, flags))
        total = counter + 1
        while total & 1 == 0:
            chaining_value = chaining_value_of(parent_output(stack.pop(), chaining_value, key_words, flags))
            total >>= 1
        stack.append(chaining_value)

    output = chunk_output(key_words, chunks[-1], len(chunks) - 1, flags)
    while stack:
        output = parent_output(stack.pop(), chaining_value_of(output), key_words, flags)

    chaining_value, block_words, _, block_len, output_flags = output
    result = b""
    counter = 0
    while len(result) < length:
        words = compress(chaining_value, block_words, counter, block_len, output_flags | ROOT)
        result += struct.pack("<16I", *words)
        counter += 1
    return result[:length]


def derive_key(context, material):
    context_key = blake3(context.encode(), flags=DERIVE_KEY_CONTEXT)
    return blake3(material, key_words=struct.unpack("<8I", context_key), flags=DERIVE_KEY_MATERIAL)


# NOTE: table-driven CRC32C (Castagnoli, reflected, init/xor 0xFFFFFFFF), verified
# against the bitwise reference in tests/format/envelope_test.cpp.
def _build_crc_table():
    table = []
    for value in range(256):
        remainder = value
        for _ in range(8):
            remainder = (remainder >> 1) ^ (0x82F63B78 if remainder & 1 else 0)
        table.append(remainder)
    return table


_CRC_TABLE = _build_crc_table()


def crc32c(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


CONTEXTS = {
    "chunk": "bale 2026-10-17 v1 chunk",
    "manifest": "bale 2026-10-17 v1 manifest",
    "index": "bale 2026-10-17 v1 index",
    "commit": "bale 2026-10-17 v1 commit",
}


def uleb128(value):
    out = bytearray()
    while True:
        group = value & 0x7F
        value >>= 7
        if value:
            out.append(group | 0x80)
        else:
            out.append(group)
            return bytes(out)


def field(number, value, critical=True):
    return uleb128((number << 1) | int(critical)) + uleb128(len(value)) + value


def unsigned(number, value, critical=True):
    return field(number, uleb128(value), critical)


def signed64(number, value, critical=False):
    return field(number, struct.pack("<q", value), critical)


def tlv_list(elements):
    return uleb128(len(elements)) + b"".join(uleb128(len(element)) + element for element in elements)


def chunk_key(chunk, algorithm=1):
    digest = derive_key(CONTEXTS["chunk"], chunk)
    return unsigned(1, algorithm) + field(2, digest) + unsigned(3, len(chunk))


def encrypted_extent(chunk, object_id, algorithm=1):
    return chunk_key(chunk, algorithm) + field(10, object_id)


# Record types.
RECORD_DATA = 1
RECORD_MANIFEST = 2
RECORD_INDEX = 3
RECORD_COMMIT = 4
RECORD_EXTENSION = 5

# Codec IDs: one exact stream per chunk (see record.hpp note).
CODEC_RAW = 0
CODEC_ZSTD = 1
CODEC_LZ4 = 2
CODEC_LZMA2 = 3
CODEC_BROTLI = 4

# Record flags: low byte required, high byte optional. Bit 0 is provisional.
REQUIRED_FLAG_MASK = 0x00FF
FLAG_ENCRYPTED = 0x0001  # provisional experimental value; format unfrozen

# Superblock features. Bit 0 is provisional.
FEATURE_ENCRYPTED = 0x00000001  # provisional experimental value; format unfrozen

# Hash algorithms.
HASH_BLAKE3 = 1
HASH_ENCRYPTED_OBJECT = 2  # provisional experimental value; format unfrozen

# Manifest entry kinds.
ENTRY_REGULAR = 1
ENTRY_DIRECTORY = 2
ENTRY_SYMLINK = 3
ENTRY_HARDLINK = 4

# Chunk policies and CDC algorithm.
POLICY_FIXED = 1
POLICY_CDC = 2
CDC_GEAR = 1
CDC_MIN_DEFAULT = 256 * 1024
CDC_TARGET_DEFAULT = 1024 * 1024
CDC_MAX_DEFAULT = 4 * 1024 * 1024
CDC_TABLE_SEED = 0x243F6A8885A308D3

# Keyslot extension (all provisional experimental values; format unfrozen).
KEYSLOT_KIND = 1
KEYSLOT_VERSION = 1
SLOT_PASSWORD = 0
SLOT_RECIPIENT = 1

# Commit fields beyond the plain shape.
COMMIT_PREVIOUS_FOOTER_FIELD = 12
COMMIT_EPOCH_FIELD = 13
COMMIT_ENCRYPTED_FEATURE = 0x00000001  # provisional; later builds may not read it

MIN_CHUNK_SIZE = 4 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024

PRESETS = {"fast": 1, "balanced": 2, "small": 3, "restore-fast": 4, "portable": 5}


def record(record_type, payload, sequence, codec=CODEC_RAW, decoded_length=None, flags=0):
    if decoded_length is None:
        decoded_length = len(payload)
    prefix = bytearray(
        b"BLR1"
        + struct.pack("<HHQQQI", record_type, flags, len(payload), decoded_length, sequence, codec)
        + b"\0" * 12
    )
    struct.pack_into("<I", prefix, 36, crc32c(bytes(prefix)))
    return bytes(prefix) + payload + struct.pack("<I", crc32c(payload)) + b"END1"


def superblock(archive_id, creation_time, required_features=0, optional_features=0, minor=0):
    header = bytearray(
        b"BALE\r\n\x1a\n"
        + struct.pack("<HHIII", 1, minor, 64, required_features, optional_features)
        + archive_id
        + struct.pack("<q", creation_time)
        + b"\0" * 8
    )
    header += struct.pack("<I", crc32c(bytes(header))) + b"\0" * 4
    return bytes(header)


def footer(commit_offset, commit_length, generation, commit_digest):
    body = bytearray(
        b"BALEFTR1"
        + struct.pack("<QQQ", commit_offset, commit_length, generation)
        + commit_digest
        + b"\0" * 32
    )
    struct.pack_into("<I", body, 64, crc32c(bytes(body)))
    return bytes(body)


def data_descriptor(key_tlv, chunk=b""):
    descriptor = uleb128(len(key_tlv)) + key_tlv
    return descriptor, descriptor + chunk


def writer_metadata(
    name,
    preset,
    codec,
    level,
    chunk_size,
    chunk_policy=POLICY_FIXED,
    workers=1,
    chunk_min=None,
    chunk_target=None,
    chunk_max=None,
    chunk_algorithm=None,
):
    body = field(1, name.encode(), critical=False)
    if preset is not None:
        body += unsigned(2, PRESETS[preset] if isinstance(preset, str) else preset, critical=False)
    if codec is not None:
        body += unsigned(3, codec, critical=False)
    if level is not None:
        body += signed64(4, level)
    body += unsigned(5, chunk_policy, critical=False)
    if chunk_size is not None:
        body += unsigned(6, chunk_size, critical=False)
    # NOTE: field 7 is reserved and never emitted.
    if workers is not None:
        body += unsigned(8, workers, critical=False)
    if chunk_min is not None:
        body += unsigned(9, chunk_min, critical=False)
    if chunk_target is not None:
        body += unsigned(10, chunk_target, critical=False)
    if chunk_max is not None:
        body += unsigned(11, chunk_max, critical=False)
    if chunk_algorithm is not None:
        body += unsigned(12, chunk_algorithm, critical=False)
    return field(4, body, critical=False)


def entry(
    path,
    kind,
    length=None,
    chunks=(),
    mtime=None,
    mode=None,
    target=None,
    encrypted_objects=(),
):
    body = field(1, path.encode()) + unsigned(2, kind)
    if kind == ENTRY_REGULAR:
        body += unsigned(3, length)
        if chunks:
            if encrypted_objects:
                elements = [
                    encrypted_extent(chunk, object_id)
                    for chunk, object_id in zip(chunks, encrypted_objects)
                ]
            else:
                elements = [chunk_key(chunk) for chunk in chunks]
            body += field(4, tlv_list(elements))
    if mtime is not None:
        body += signed64(5, mtime)
    if mode is not None:
        body += unsigned(6, mode, critical=False)
    if kind == ENTRY_SYMLINK:
        body += field(9, target.encode())
    if kind == ENTRY_HARDLINK:
        body += field(10, target.encode())
    return body


def manifest_payload(version, entries, comment="", writer=b""):
    payload = unsigned(1, version) + field(2, tlv_list(entries))
    if comment:
        payload += field(3, comment.encode(), critical=False)
    payload += writer
    return payload


def index_payload(entries):
    return unsigned(1, 1) + field(2, tlv_list(entries))


def index_entry(key_tlv, record_offset, record_length, codec=CODEC_RAW):
    return key_tlv + unsigned(4, record_offset) + unsigned(5, record_length) + unsigned(6, codec)


def commit_payload(
    generation,
    previous,
    required_features,
    manifest_offset,
    manifest_length,
    manifest_digest,
    index_offset,
    index_length,
    index_digest,
    previous_footer_offset=None,
    epoch=None,
):
    payload = (
        unsigned(1, 1)
        + unsigned(2, generation)
        + field(3, previous)
        + unsigned(4, required_features)
        + unsigned(5, manifest_offset)
        + unsigned(6, manifest_length)
        + field(7, manifest_digest)
        + unsigned(8, index_offset)
        + unsigned(9, index_length)
        + field(10, index_digest)
    )
    if previous_footer_offset is not None:
        payload += unsigned(12, previous_footer_offset, critical=False)
    if epoch is not None:
        payload += unsigned(13, epoch)
    return payload


def keyslot_payload_password(epoch, salt, opslimit, memlimit, nonce, wrapped):
    return (
        unsigned(1, KEYSLOT_KIND)
        + unsigned(2, KEYSLOT_VERSION)
        + unsigned(3, epoch)
        + unsigned(4, SLOT_PASSWORD)
        + field(10, salt)
        + unsigned(11, opslimit)
        + unsigned(12, memlimit)
        + field(13, nonce)
        + field(14, wrapped)
    )


def keyslot_payload_recipient(epoch, public_key, sealed):
    return (
        unsigned(1, KEYSLOT_KIND)
        + unsigned(2, KEYSLOT_VERSION)
        + unsigned(3, epoch)
        + unsigned(4, SLOT_RECIPIENT)
        + field(20, public_key)
        + field(21, sealed)
    )


def splitmix64_step(value):
    merged = (value + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    merged = ((merged ^ (merged >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    merged = ((merged ^ (merged >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return (merged ^ (merged >> 31)) & 0xFFFFFFFFFFFFFFFF


def gear_table():
    table = []
    state = CDC_TABLE_SEED
    for _ in range(256):
        state = splitmix64_step(state)
        table.append(state)
    return table


GEAR = gear_table()


def validate_cdc_params(chunk_min, chunk_target, chunk_max):
    for value in (chunk_min, chunk_target, chunk_max):
        if value < MIN_CHUNK_SIZE or value > MAX_CHUNK_SIZE:
            raise ValueError("cdc chunk size outside the supported range")
    if not (chunk_min <= chunk_target <= chunk_max):
        raise ValueError("cdc chunk sizes out of order: min, target, max")


class CdcSplitter:
    """Content-defined chunk cutter. Mirrors the schema recurrence from scratch."""

    def __init__(self, chunk_min, chunk_target, chunk_max):
        # NOTE: no range check here; the writer validates params separately
        # and the splitter itself accepts any triple, like the C++ cutter.
        self.min = chunk_min
        self.target = chunk_target
        self.max = chunk_max
        self.masked = chunk_target != 0 and (chunk_target & (chunk_target - 1)) == 0
        self.mask = chunk_target - 1 if self.masked else 0
        self.reset()

    def reset(self):
        self.digest = 0
        self.length = 0

    def next_chunk(self):
        self.length = 0

    def feed(self, byte):
        self.digest = ((self.digest << 1) + GEAR[byte]) & 0xFFFFFFFFFFFFFFFF
        self.length += 1
        if self.length >= self.max:
            return True
        if self.length < self.min:
            return False
        if self.masked:
            return (self.digest & self.mask) == 0
        return self.digest % self.target == 0


def cdc_chunks(data, chunk_min, chunk_target, chunk_max):
    splitter = CdcSplitter(chunk_min, chunk_target, chunk_max)
    chunks = []
    current = bytearray()
    for byte in data:
        current.append(byte)
        if splitter.feed(byte):
            chunks.append(bytes(current))
            current = bytearray()
            splitter.next_chunk()
    if current or not chunks:
        chunks.append(bytes(current))
    return chunks


def golden_archive():
    """Directory "d", files "d/f" and "d/g" holding "hello" (one shared DATA record), empty "e"."""
    archive_id = bytes(range(0x10, 0x20))
    file_time = 1700000000123456789
    out = bytearray(superblock(archive_id, 1700000000000000000))

    chunk = b"hello"
    descriptor = chunk_key(chunk)
    data_offset = len(out)
    data = record(RECORD_DATA, uleb128(len(descriptor)) + descriptor + chunk, 0)
    out += data

    entries = [
        entry("d", ENTRY_DIRECTORY, mtime=0, mode=0o755),
        entry("d/f", ENTRY_REGULAR, length=5, chunks=[chunk], mtime=file_time, mode=0o644),
        entry("d/g", ENTRY_REGULAR, length=5, chunks=[chunk], mtime=file_time, mode=0o644),
        entry("e", ENTRY_REGULAR, length=0),
    ]
    manifest_payload_bytes = (
        unsigned(1, 1)
        + field(2, tlv_list(entries))
        + writer_metadata("bale", "balanced", CODEC_ZSTD, 3, 1 << 20)
    )
    manifest_offset = len(out)
    manifest = record(RECORD_MANIFEST, manifest_payload_bytes, 1)
    out += manifest

    index_entry_bytes = chunk_key(chunk) + unsigned(4, data_offset) + unsigned(5, len(data)) + unsigned(6, CODEC_RAW)
    index_payload_bytes = unsigned(1, 1) + field(2, tlv_list([index_entry_bytes]))
    index_offset = len(out)
    index = record(RECORD_INDEX, index_payload_bytes, 2)
    out += index

    commit_payload_bytes = (
        unsigned(1, 1)
        + unsigned(2, 1)
        + field(3, b"\0" * 32)
        + unsigned(4, 0)
        + unsigned(5, manifest_offset)
        + unsigned(6, len(manifest))
        + field(7, derive_key(CONTEXTS["manifest"], manifest_payload_bytes))
        + unsigned(8, index_offset)
        + unsigned(9, len(index))
        + field(10, derive_key(CONTEXTS["index"], index_payload_bytes))
    )
    commit_offset = len(out)
    commit = record(RECORD_COMMIT, commit_payload_bytes, 3)
    out += commit
    out += footer(commit_offset, len(commit), 1, derive_key(CONTEXTS["commit"], commit_payload_bytes))
    return bytes(out)


def as_hex(data, width=24):
    rows = [data[start : start + width] for start in range(0, len(data), width)]
    return "\n".join(" ".join(f"{byte:02X}" for byte in row) for row in rows)


if __name__ == "__main__":
    if sys.argv[1:] == ["golden"]:
        print(as_hex(golden_archive()))
    elif len(sys.argv) == 4 and sys.argv[1] == "derive-key":
        print(derive_key(sys.argv[2], open(sys.argv[3], "rb").read()).hex())
    else:
        print("usage: bale_reference.py golden | derive-key <context> <file>", file=sys.stderr)
        sys.exit(2)
