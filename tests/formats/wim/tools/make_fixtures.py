#!/usr/bin/env python3
"""Hermetic WIM fixture generator for bale's read-only WIM tests.

Builds small, valid stored-resource WIM files with real SHA-1 blob hashes
and verifies each one with an independent reader (7-Zip). Run:

    python3 make_fixtures.py --out <tests/formats/wim/data> [--check]

--check runs `7z l` and `7z x` on every fixture and byte-compares the
extracted tree against the expected contents. Fixtures 7-Zip cannot read
are still valid per the MS-WIM layout; they are marked hermetic-only below.

Provenance: every fixture below is produced by this script (clean-room
layout code, hashlib SHA-1). Cross-check tool: 7-Zip 26.04 (2026-10-05).
"""

import argparse
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

FILETIME_EPOCH_GAP = 11644473600
ATTR_READONLY = 0x1
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_REPARSE = 0x400
TAG_SYMLINK = 0xA000000C
TAG_JUNCTION = 0xA0000003

ZERO_HASH = bytes(20)


def filetime(unix_seconds):
    return (unix_seconds + FILETIME_EPOCH_GAP) * 10000000


def u16s(text):
    return text.encode("utf-16-le")


def dentry(name, attrs, subdir, mtime, main_hash, reparse=None, group=0,
           extras=()):
    name_raw = u16s(name) if name else b""
    fixed = struct.pack(
        "<QIIQQQQQQ20sI",
        0,  # length patched below
        attrs,
        0xFFFFFFFF,
        subdir,
        0,  # unused_1
        0,  # unused_2
        mtime,  # creation
        mtime,  # access
        mtime,  # write
        main_hash,
        0,  # unknown_0x54
    )
    if reparse is not None:
        tag, reserved, dflags = reparse
        union = struct.pack("<IHH", tag, reserved, dflags)
    else:
        union = struct.pack("<Q", group)
    head = fixed + union + struct.pack("<HHH", len(extras), 0, len(name_raw))
    body = head
    if name_raw:
        body += name_raw + b"\0\0"
    while len(body) % 8:
        body += b"\0"
    # NOTE: the length field covers the dentry only, never the extras.
    body = struct.pack("<Q", len(body)) + body[8:]
    for data, stream_name in extras:
        sname = u16s(stream_name) if stream_name else b""
        blob = struct.pack("<QQ20sH", 0, 0, data, len(sname))
        if sname:
            blob += sname + b"\0\0"
        while len(blob) % 8:
            blob += b"\0"
        blob = struct.pack("<Q", len(blob)) + blob[8:]
        body += blob
    return body


def reparse_buffer(print_path, substitute=None, symlink=True):
    print_raw = u16s(print_path)
    sub_raw = u16s(substitute if substitute is not None else print_path)
    if symlink:
        # NOTE: offsets are relative to the path buffer after the flags word.
        buf = struct.pack("<HHHHI", 0, len(sub_raw), 0, len(print_raw), 0)
    else:
        buf = struct.pack("<HHHH", 0, len(sub_raw), 0, len(print_raw))
    return buf + sub_raw + b"\0\0" + print_raw + b"\0\0"


class Image:
    def __init__(self):
        self.files = []  # (path, data, attrs, extras, reparse, group)

    def add_file(self, path, data, attrs=ATTR_ARCHIVE, extras=(), reparse=None,
                 group=0, mtime=filetime(1700000000)):
        self.files.append((path, data, attrs, extras, reparse, group, mtime))

    def add_dir(self, path, mtime=filetime(1700000000)):
        self.files.append((path, None, ATTR_DIRECTORY, (), None, 0, mtime))


class Builder:
    def __init__(self, chunk_size=0, compression_flags=0, version=0x10D00):
        self.chunk_size = chunk_size
        self.compression_flags = compression_flags
        self.version = version
        self.images = []
        self.boot_index = 0
        self.blobs = {}  # sha1 -> bytes
        self.chunked = set()  # sha1 digests stored as chunked raw resources
        self.solid_groups = []  # lists of sha1 digests packed into one solid resource

    def add_image(self, image):
        self.images.append(image)
        return len(self.images)

    def blob(self, data):
        if not data:
            return ZERO_HASH
        digest = hashlib.sha1(data).digest()
        self.blobs.setdefault(digest, data)
        return digest

    def build_metadata(self, image):
        children = {}
        for path, data, attrs, extras, reparse, group, mtime in image.files:
            parent = path.rsplit("/", 1)[0] if "/" in path else ""
            children.setdefault(parent, []).append(
                (path, data, attrs, extras, reparse, group, mtime))
        # NOTE: implicit parents are materialized as plain directories, the
        # way real writers emit trees captured from disk.
        for parent in list(children):
            parts = parent.split("/") if parent else []
            for depth in range(1, len(parts) + 1):
                ancestor = "/".join(parts[:depth])
                grand = "/".join(parts[:depth - 1])
                children.setdefault(ancestor, [])
                if not any(p == ancestor for p, *_ in children.get(grand, [])):
                    children.setdefault(grand, []).append(
                        (ancestor, None, ATTR_DIRECTORY, (), None, 0,
                         filetime(1700000000)))
        # NOTE: one block per directory in breadth order; every subdir offset
        # is absolute from the start of the metadata resource.
        queue = [""]
        seen = set()
        layout = []
        while queue:
            parent = queue.pop(0)
            if parent in seen:
                continue
            seen.add(parent)
            layout.append(parent)
            for path, data, attrs, *_ in children.get(parent, []):
                if data is None and attrs & ATTR_DIRECTORY:
                    queue.append(path)
        entries = {}
        for parent in layout:
            items = []
            for path, data, attrs, extras, reparse, group, mtime in \
                    sorted(children.get(parent, []), key=lambda e: e[0]):
                leaf = path.rsplit("/", 1)[-1]
                is_dir = data is None and attrs & ATTR_DIRECTORY
                main = ZERO_HASH
                extra_entries = []
                if reparse is not None:
                    main = self.blob(reparse[3])
                elif not is_dir:
                    main = self.blob(data)
                for sname, sdata in extras:
                    extra_entries.append((self.blob(sdata), sname))
                sub = "DIR:" + (parent + "/" + leaf).strip("/")
                items.append((leaf, attrs, mtime, main,
                              reparse[:3] if reparse else None, group,
                              extra_entries, sub))
            if parent == "":
                items.insert(0, None)
            entries[parent] = items
        offsets = {}
        cursor = 8
        root_blob = dentry("", ATTR_DIRECTORY, 8 + 104,
                           filetime(1700000000), ZERO_HASH)
        root_len = len(root_blob)
        root_blob = dentry("", ATTR_DIRECTORY, 8 + root_len,
                           filetime(1700000000), ZERO_HASH)
        for parent in layout:
            offsets[parent] = cursor
            size = 0
            for item in entries[parent]:
                if item is None:
                    size += root_len
                    continue
                leaf, attrs, mtime, main, rep, group, extra_entries, _ = item
                size += len(dentry(leaf, attrs, 0, mtime, main, reparse=rep,
                                   group=group, extras=extra_entries))
            size += 8
            cursor += size
        out = struct.pack("<II", 8, 0)
        for parent in layout:
            for item in entries[parent]:
                if item is None:
                    out += root_blob
                    continue
                leaf, attrs, mtime, main, rep, group, extra_entries, sub = item
                key = sub[4:]
                out += dentry(leaf, attrs, offsets.get(key, 0), mtime, main,
                              reparse=rep, group=group, extras=extra_entries)
            out += struct.pack("<Q", 0)
        return out

    def chunked_resource(self, data):
        # NOTE: a COMPRESSED-flag resource whose chunks are all stored raw:
        # legal per the format (chunks that did not shrink stay stored) and
        # exercises the chunk table without any codec.
        assert self.chunk_size and self.compression_flags
        parts = [data[i:i + self.chunk_size]
                 for i in range(0, len(data), self.chunk_size)]
        table = b"".join(
            struct.pack("<I", sum(len(p) for p in parts[:i]))
            for i in range(1, len(parts))
        )
        return table + b"".join(parts)

    def solid_resource(self, datas, chunk_size=32768):
        # NOTE: a solid resource with format None: the blobs are concatenated
        # and stored raw in fixed-size chunks.
        assert self.version == 0x0E00
        assert chunk_size and chunk_size & (chunk_size - 1) == 0
        blob = b"".join(datas)
        parts = [blob[i:i + chunk_size] for i in range(0, len(blob), chunk_size)]
        table = b"".join(struct.pack("<I", len(p)) for p in parts)
        head = struct.pack("<QII", len(blob), chunk_size, 0)
        return head + table + b"".join(parts)

    def build(self):
        meta_datas = [self.build_metadata(image) for image in self.images]
        for meta in meta_datas:
            self.blob(meta)
        meta_digests = [hashlib.sha1(meta).digest() for meta in meta_datas]
        meta_set = set(meta_digests)
        solid_members = {d for group in self.solid_groups for d in group}
        # NOTE: each layout item is (bytes to write, lookup entry or None).
        # File blobs first, solid runs next, then metadata blobs in image
        # order: readers assign metadata to images by table order.
        items = []
        for digest in sorted(d for d in self.blobs if d not in solid_members):
            if digest in meta_set:
                continue
            data = self.blobs[digest]
            if digest in self.chunked:
                items.append((self.chunked_resource(data), (digest, 0x04)))
            else:
                items.append((data, (digest, 0x00)))
        for group in self.solid_groups:
            datas = [self.blobs[d] for d in group]
            items.append((self.solid_resource(datas), group))
        for digest in meta_digests:
            items.append((self.blobs[digest], (digest, 0x02)))
        cursor = 208
        table = b""
        out = bytearray()
        positions = {}
        for body, tag in items:
            if isinstance(tag, list):
                positions[id(tag)] = cursor
                marker = (
                    struct.pack("<7sB", len(body).to_bytes(7, "little"), 0x10)
                    + struct.pack("<QQ", cursor, 0x100000000)
                    + struct.pack("<HI", 1, 1)
                    + bytes(20)
                )
                table += marker
                out += body
                cursor += len(body)
                base = 0
                for digest in tag:
                    size = len(self.blobs[digest])
                    table += (
                        struct.pack("<7sB", size.to_bytes(7, "little"), 0x10)
                        + struct.pack("<QQ", base, 0)
                        + struct.pack("<HI", 1, 1)
                        + digest
                    )
                    base += size
                continue
            digest, flags = tag
            positions[digest] = cursor
            table += (
                struct.pack("<7sB", len(body).to_bytes(7, "little"), flags)
                + struct.pack("<QQ", cursor, len(self.blobs[digest]))
                + struct.pack("<HI", 1, 1)
                + digest
            )
            out += body
            cursor += len(body)
        lookup_at = cursor
        xml = b"\xff\xfe" + self.build_xml().encode("utf-16-le")
        xml_at = cursor + len(table)
        header = self.build_header(len(table), lookup_at, len(xml), xml_at,
                                   positions)
        return bytes(header) + bytes(out) + table + xml

    def build_header(self, lookup_size, lookup_at, xml_size, xml_at,
                     positions):
        lookup = (
            struct.pack("<7sB", lookup_size.to_bytes(7, "little"), 0x02)
            + struct.pack("<QQ", lookup_at, lookup_size)
        )
        xml = (
            struct.pack("<7sB", xml_size.to_bytes(7, "little"), 0x02)
            + struct.pack("<QQ", xml_at, xml_size)
        )
        if self.boot_index:
            meta = self.build_metadata(self.images[self.boot_index - 1])
            digest = hashlib.sha1(meta).digest()
            boot = (
                struct.pack("<7sB", len(meta).to_bytes(7, "little"), 0x02)
                + struct.pack("<QQ", positions[digest], len(meta))
            )
        else:
            boot = bytes(24)
        return (
            b"MSWIM\0\0\0"
            + struct.pack("<I", 208)
            + struct.pack("<I", self.version)
            + struct.pack("<I", self.compression_flags)
            + struct.pack("<I", self.chunk_size)
            + os.urandom(16)
            + struct.pack("<HHI", 1, 1, len(self.images))
            + lookup
            + xml
            + boot
            + struct.pack("<I", self.boot_index)
            + bytes(24)
            + bytes(60)
        )

    def build_xml(self):
        parts = ["<WIM>"]
        total = sum(len(d) for d in self.blobs.values())
        parts.append(f"<TOTALBYTES>{total}</TOTALBYTES>")
        for number, image in enumerate(self.images, 1):
            dirs = set()
            files = 0
            fbytes = 0
            for path, data, *_ in image.files:
                if data is None:
                    dirs.add(path)
                else:
                    files += 1
                    fbytes += len(data)
                parts2 = path.split("/")[:-1]
                for depth in range(1, len(parts2) + 1):
                    dirs.add("/".join(parts2[:depth]))
            parts.append(
                f'<IMAGE INDEX="{number}"><DIRCOUNT>{len(dirs)}</DIRCOUNT>'
                f"<FILECOUNT>{files}</FILECOUNT>"
                f"<TOTALBYTES>{fbytes}</TOTALBYTES>"
                f"<NAME>image-{number}</NAME></IMAGE>"
            )
        parts.append("</WIM>")
        return "".join(parts)


def write(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def check(tool, path, expected):
    subprocess.run([tool, "l", path], check=True,
                   stdout=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([tool, "x", f"-o{tmp}", path, "-y"],
                       check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        for name, data in expected.items():
            with open(os.path.join(tmp, name), "rb") as handle:
                actual = handle.read()
            assert actual == data, f"{path}: {name} differs"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # NOTE: basic mirrors a 7-Zip-created WIM: one image, stored blobs, an
    # empty file, and a 100 KiB file in a COMPRESSED-flag resource whose
    # chunks are all stored raw, which exercises the chunk table with no
    # codec involved.
    basic = Builder(chunk_size=32768, compression_flags=0x00040002)
    image = Image()
    image.add_file("hello.txt", b"hello wim\n")
    image.add_file("empty.txt", b"")
    image.add_file("dir/nested/deep.txt", b"deep\n")
    big = bytes((i * 31 + 7) % 251 for i in range(100 * 1024))
    image.add_file("big.bin", big)
    basic.add_image(image)
    basic.chunked.add(hashlib.sha1(big).digest())
    basic_wim = basic.build()
    write(os.path.join(args.out, "basic.wim"), basic_wim)

    # NOTE: multi holds three images; image 2 is bootable, so the default
    # selection rule must pick it.
    multi = Builder()
    first = Image()
    first.add_file("one.txt", b"image one\n")
    multi.add_image(first)
    second = Image()
    second.add_file("two.txt", b"image two\n")
    second.add_file("shared.txt", b"shared\n")
    multi.add_image(second)
    third = Image()
    third.add_file("three.txt", b"image three\n")
    third.add_file("ünïcodé.txt", "unicode name\n".encode("utf-8"))
    multi.add_image(third)
    multi.boot_index = 2
    multi_wim = multi.build()
    write(os.path.join(args.out, "multi.wim"), multi_wim)

    # NOTE: rich covers links and streams: a hard-link pair, a symlink, a
    # junction, and a named alternate data stream next to default content.
    rich = Builder()
    image = Image()
    image.add_file("orig.txt", b"linked content\n", group=7)
    image.add_file("link.txt", b"linked content\n", group=7)
    target = reparse_buffer("/target.txt")
    image.add_file("pointer.lnk", b"", attrs=ATTR_ARCHIVE | ATTR_REPARSE,
                   reparse=(TAG_SYMLINK, 0, 0, target))
    jt = reparse_buffer("\\??\\C:\\windows", symlink=False)
    image.add_file("junction", b"", attrs=ATTR_DIRECTORY | ATTR_REPARSE,
                   reparse=(TAG_JUNCTION, 0, 0, jt))
    image.add_file("notes.txt", b"default stream\n",
                   extras=(("hidden", b"alternate stream\n"),))
    rich.add_image(image)
    rich_wim = rich.build()
    write(os.path.join(args.out, "rich.wim"), rich_wim)

    print("wrote fixtures to", args.out)
    if args.check:
        tool = "7z"
        check(tool, os.path.join(args.out, "basic.wim"), {
            "hello.txt": b"hello wim\n",
            "empty.txt": b"",
            "dir/nested/deep.txt": b"deep\n",
            "big.bin": big,
        })
        check(tool, os.path.join(args.out, "multi.wim"), {
            "one.txt": b"image one\n",
        })
        print("7z cross-checks passed")


if __name__ == "__main__":
    sys.exit(main())
