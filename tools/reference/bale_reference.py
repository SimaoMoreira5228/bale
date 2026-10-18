"""Second, independent encoder for BALE golden vectors (whitepaper section 17.8).

Pure Python with its own BLAKE3 and CRC32C, written from the schema description rather than from
the C++ sources, so a golden archive produced here checks the C++ writer instead of echoing it.
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


def crc32c(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
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


def chunk_key(chunk):
    digest = derive_key(CONTEXTS["chunk"], chunk)
    return unsigned(1, 1) + field(2, digest) + unsigned(3, len(chunk))


RECORD_DATA = 1
RECORD_MANIFEST = 2
RECORD_INDEX = 3
RECORD_COMMIT = 4
CODEC_RAW = 0
CODEC_ZSTD = 1


def record(record_type, payload, sequence, codec=CODEC_RAW, decoded_length=None):
    if decoded_length is None:
        decoded_length = len(payload)
    prefix = bytearray(
        b"BLR1"
        + struct.pack("<HHQQQI", record_type, 0, len(payload), decoded_length, sequence, codec)
        + b"\0" * 12
    )
    struct.pack_into("<I", prefix, 36, crc32c(bytes(prefix)))
    return bytes(prefix) + payload + struct.pack("<I", crc32c(payload)) + b"END1"


def superblock(archive_id, creation_time):
    header = bytearray(
        b"BALE\r\n\x1a\n"
        + struct.pack("<HHIII", 1, 0, 64, 0, 0)
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


ENTRY_REGULAR = 1
ENTRY_DIRECTORY = 2

PRESETS = {"fast": 1, "balanced": 2, "small": 3, "restore-fast": 4, "portable": 5}


def writer_metadata(name, preset, codec, level, chunk_size):
    body = field(1, name.encode(), critical=False)
    if preset is not None:
        body += unsigned(2, PRESETS[preset], critical=False)
    body += unsigned(3, codec, critical=False)
    body += signed64(4, level)
    body += unsigned(5, 1, critical=False)
    body += unsigned(6, chunk_size, critical=False)
    body += unsigned(8, 1, critical=False)
    return field(4, body, critical=False)


def entry(path, kind, length=None, chunks=(), mtime=None, mode=None):
    body = field(1, path.encode()) + unsigned(2, kind)
    if kind == ENTRY_REGULAR:
        body += unsigned(3, length)
        if chunks:
            body += field(4, tlv_list([chunk_key(chunk) for chunk in chunks]))
    if mtime is not None:
        body += signed64(5, mtime)
    if mode is not None:
        body += unsigned(6, mode, critical=False)
    return body


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
    manifest_payload = (
        unsigned(1, 1)
        + field(2, tlv_list(entries))
        + writer_metadata("bale", "balanced", CODEC_ZSTD, 3, 1 << 20)
    )
    manifest_offset = len(out)
    manifest = record(RECORD_MANIFEST, manifest_payload, 1)
    out += manifest

    index_entry = descriptor + unsigned(4, data_offset) + unsigned(5, len(data)) + unsigned(6, CODEC_RAW)
    index_payload = unsigned(1, 1) + field(2, tlv_list([index_entry]))
    index_offset = len(out)
    index = record(RECORD_INDEX, index_payload, 2)
    out += index

    commit_payload = (
        unsigned(1, 1)
        + unsigned(2, 1)
        + field(3, b"\0" * 32)
        + unsigned(4, 0)
        + unsigned(5, manifest_offset)
        + unsigned(6, len(manifest))
        + field(7, derive_key(CONTEXTS["manifest"], manifest_payload))
        + unsigned(8, index_offset)
        + unsigned(9, len(index))
        + field(10, derive_key(CONTEXTS["index"], index_payload))
    )
    commit_offset = len(out)
    commit = record(RECORD_COMMIT, commit_payload, 3)
    out += commit
    out += footer(commit_offset, len(commit), 1, derive_key(CONTEXTS["commit"], commit_payload))
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
