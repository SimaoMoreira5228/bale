"""Builds the versioned codec benchmark corpus described in whitepaper section 5.4.2."""

import argparse
import hashlib
import json
import random
import shutil
import struct
import sys
from pathlib import Path

CORPUS_VERSION = 1
MEBIBYTE = 1 << 20

WORDS = (
    "the of and to in a is that for it as was with be by on not he this are or his from at which "
    "but have an they you were her she there been one all we their has would when if so no what up "
    "out who them some more could my time do into its only than other then about any these two may "
    "first new very just where most over such after also our through back years work well should "
    "archive chunk record index manifest commit footer codec stream window budget digest snapshot"
).split()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def prose(rng, size):
    weights = [1.0 / (rank + 1) for rank in range(len(WORDS))]
    out = []
    length = 0
    while length < size:
        sentence = " ".join(rng.choices(WORDS, weights=weights, k=rng.randint(6, 18)))
        sentence = sentence.capitalize() + (". " if rng.random() < 0.85 else ".\n\n")
        out.append(sentence)
        length += len(sentence)
    return "".join(out).encode()[:size]


def text_group(root, rng, scale):
    for index in range(4 * scale):
        write(root / f"chapter-{index:03}.txt", prose(rng, 256 * 1024))


def small_files_group(root, rng, scale):
    for index in range(1000 * scale):
        record = {
            "id": index,
            "name": " ".join(rng.choices(WORDS, k=3)),
            "tags": rng.sample(WORDS, rng.randint(1, 5)),
            "score": round(rng.random() * 100, 3),
            "enabled": rng.random() < 0.5,
        }
        body = json.dumps(record, indent=2) * rng.randint(1, 8)
        write(root / f"{index // 100:02}" / f"item-{index:05}.json", body.encode())


def repeated_group(root, rng, scale):
    block = rng.randbytes(MEBIBYTE)
    out = bytearray()
    while len(out) < 8 * scale * MEBIBYTE:
        shift = rng.randint(0, 4096)
        out += rng.randbytes(shift) + block[: rng.randint(MEBIBYTE // 2, MEBIBYTE)]
    write(root / "repeated-and-shifted.bin", bytes(out))


def structured_group(root, rng, scale):
    rows = bytearray()
    timestamp = 1_700_000_000
    for row in range(200_000 * scale):
        timestamp += rng.randint(0, 5)
        rows += struct.pack(
            "<IqdhB3x",
            row,
            timestamp,
            20.0 + rng.gauss(0, 2.5),
            rng.randint(-500, 500),
            rng.randint(0, 3),
        )
    write(root / "records.bin", bytes(rows))


def incompressible_group(root, rng, scale):
    write(root / "random.bin", rng.randbytes(4 * scale * MEBIBYTE))


def parse_size(text):
    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
    multiplier = units.get(text[-1:].upper(), 1)
    digits = text[:-1] if text[-1:].upper() in units else text
    if not digits.isdigit() or int(digits) == 0:
        raise argparse.ArgumentTypeError(f"bad size {text!r}")
    return int(digits) * multiplier


class MixedSegments:
    def __init__(self, rng):
        self.rng = rng
        self.sentences = prose(rng, 4 * MEBIBYTE).split(b". ")
        self.records = bytearray()
        for row in range(MEBIBYTE // 24 + 1):
            self.records += struct.pack(
                "<IqdhB3x",
                row,
                1_700_000_000 + row * 3,
                20.0 + row % 97 / 10,
                row % 1000,
                row % 4,
            )
        del self.records[MEBIBYTE:]
        self.blocks = [rng.randbytes(64 * 1024) for _ in range(8)]

    def text(self):
        out = bytearray()
        while len(out) < MEBIBYTE:
            out += self.rng.choice(self.sentences) + b". "
        return bytes(out[:MEBIBYTE])

    def structured(self):
        out = bytearray(self.records)
        timestamps = out[4::24]
        out[4::24] = self.rng.randbytes(len(timestamps))
        return bytes(out)

    def repeated(self):
        out = bytearray()
        while len(out) < MEBIBYTE:
            out += self.rng.randbytes(self.rng.randint(0, 512)) + self.rng.choice(self.blocks)
        return bytes(out[:MEBIBYTE])

    def random(self):
        return self.rng.randbytes(MEBIBYTE)

    def segment(self):
        kinds = [self.text, self.structured, self.repeated, self.random]
        return self.rng.choices(kinds, weights=[4, 3, 2, 1])[0]()


def sized_group(root, rng, size):
    segments = MixedSegments(rng)
    root.mkdir(parents=True, exist_ok=True)
    with open(root / "mixed.bin", "wb") as handle:
        remaining = size
        while remaining > 0:
            data = segments.segment()[:remaining]
            handle.write(data)
            remaining -= len(data)


def size_label(size):
    for unit, factor in (("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)):
        if size % factor == 0:
            return f"{size // factor}{unit}"
    return str(size)


GENERATORS = {
    "text": text_group,
    "small-files": small_files_group,
    "repeated": repeated_group,
    "structured": structured_group,
    "incompressible": incompressible_group,
}


def copy_tree(source, destination):
    for path in sorted(source.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(MEBIBYTE), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest(root, seed, scale, sizes, added):
    files = []
    overall = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "corpus.json":
            continue
        digest = file_sha256(path)
        relative = path.relative_to(root).as_posix()
        files.append({"path": relative, "size": path.stat().st_size, "sha256": digest})
        overall.update(f"{relative}\0{digest}\n".encode())

    groups = {}
    for item in files:
        group = groups.setdefault(item["path"].split("/", 1)[0], {"files": 0, "bytes": 0})
        group["files"] += 1
        group["bytes"] += item["size"]

    return {
        "version": CORPUS_VERSION,
        "seed": seed,
        "scale": scale,
        "sizes": sizes,
        "python": sys.version.split()[0],
        "added": added,
        "groups": groups,
        "sha256": overall.hexdigest(),
        "files": files,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--seed", type=int, default=20261018)
    parser.add_argument("--scale", type=int, default=1, help="multiplies every synthetic group size")
    parser.add_argument(
        "--sizes",
        default="",
        help="comma-separated file sizes such as 1M,500M,1G; each becomes a size-<n> group of one mixed file",
    )
    parser.add_argument(
        "--no-synthetic",
        action="store_true",
        help="skip the content-type groups, for example when only --sizes or --add are wanted",
    )
    parser.add_argument(
        "--add",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="copy a real directory (source tree, binaries, media) in as its own group",
    )
    arguments = parser.parse_args()

    if arguments.output.exists() and any(arguments.output.iterdir()):
        parser.error(f"{arguments.output} is not empty")

    if not arguments.no_synthetic:
        for name, generate in GENERATORS.items():
            generate(arguments.output / name, random.Random(f"{arguments.seed}:{name}"), arguments.scale)

    sizes = [parse_size(text) for text in arguments.sizes.split(",") if text]
    for size in sizes:
        label = size_label(size)
        sized_group(arguments.output / f"size-{label}", random.Random(f"{arguments.seed}:size:{label}"), size)

    added = {}
    for spec in arguments.add:
        name, _, source = spec.partition("=")
        if not name or not source or name in GENERATORS or "/" in name:
            parser.error(f"bad --add {spec!r}")
        copy_tree(Path(source), arguments.output / name)
        added[name] = source

    result = manifest(arguments.output, arguments.seed, arguments.scale, sizes, added)
    (arguments.output / "corpus.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"corpus {result['sha256']}")
    for name, group in result["groups"].items():
        print(f"  {name:<16} {group['files']:>6} files {group['bytes']:>12} bytes")


if __name__ == "__main__":
    main()
