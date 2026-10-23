"""Runs the bale CLI against archives written by Python's own tarfile, zipfile, gzip and zstd."""

import filecmp
import gzip
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import unicodedata
from pathlib import Path

try:
    from compression import zstd
except ImportError:
    zstd = None

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNSUPPORTED = 3
EXIT_INVALID = 4
EXIT_INTEGRITY = 5
EXIT_UNSAFE_PATH = 7
EXIT_IO = 8
EXIT_ALREADY_EXISTS = 10

BALE = Path(sys.argv[1]).resolve()
REFERENCE = Path(__file__).resolve().parents[2] / "tools" / "reference" / "bale_reference.py"
failures = []


def run(*args, cwd):
    return subprocess.run(
        [str(BALE), *map(str, args)],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def check(name, condition, detail=""):
    if not condition:
        failures.append(f"{name}: {detail}")


def expect_exit(name, result, code):
    check(name, result.returncode == code, f"exit {result.returncode}, wanted {code}\n{result.stderr}")


def make_tree(root):
    (root / "docs" / "deep").mkdir(parents=True)
    (root / "empty").mkdir()
    (root / "hello.txt").write_bytes(b"hello\n")
    (root / "docs" / "notes.md").write_bytes(b"# notes\n" * 500)
    (root / "docs" / "deep" / "random.bin").write_bytes(os.urandom(300_000))
    (root / "docs" / "deep" / "copy.bin").write_bytes((root / "docs" / "deep" / "random.bin").read_bytes())
    (root / "zero.dat").write_bytes(b"")


def same_tree(left, right):
    comparison = filecmp.dircmp(left, right)
    if comparison.left_only or comparison.right_only or comparison.funny_files:
        return False
    _, mismatch, errors = filecmp.cmpfiles(left, right, comparison.common_files, shallow=False)
    if mismatch or errors:
        return False
    return all(same_tree(Path(left) / name, Path(right) / name) for name in comparison.common_dirs)


def tar_bytes(source, mode):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode, format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(source.rglob("*")):
            archive.add(path, arcname=path.relative_to(source).as_posix(), recursive=False)
    return buffer.getvalue()


def zip_bytes(source, compression):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for path in sorted(source.rglob("*")):
            name = path.relative_to(source).as_posix()
            archive.write(path, arcname=name + "/" if path.is_dir() else name)
    return buffer.getvalue()


def round_trip(name, work, source, archive_name, payload):
    archive = work / archive_name
    archive.write_bytes(payload)
    output = work / (archive_name + ".out")

    expect_exit(f"{name} test", run("test", archive, cwd=work), EXIT_OK)
    listed = run("list", archive, cwd=work)
    expect_exit(f"{name} list", listed, EXIT_OK)
    check(f"{name} list", "docs/deep/random.bin" in listed.stdout, listed.stdout)

    converted = work / (archive_name + ".converted")
    expect_exit(
        f"{name} convert to tar",
        run("convert", "--format", "tar", archive, converted, cwd=work),
        EXIT_OK,
    )
    check(f"{name} converted", tar_members(converted, "r:") == expected_members(source))

    expect_exit(f"{name} extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    check(f"{name} contents", same_tree(source, output), "extracted tree differs")


def test_round_trips(work, source):
    round_trip("tar", work, source, "plain.tar", tar_bytes(source, "w"))
    round_trip("tar.gz", work, source, "packed.tgz", tar_bytes(source, "w:gz"))
    round_trip("tar.xz", work, source, "packed.tar.xz", tar_bytes(source, "w:xz"))
    round_trip("tar.bz2", work, source, "packed.tar.bz2", tar_bytes(source, "w:bz2"))
    round_trip("zip stored", work, source, "stored.zip", zip_bytes(source, zipfile.ZIP_STORED))
    round_trip("zip deflate", work, source, "deflate.zip", zip_bytes(source, zipfile.ZIP_DEFLATED))
    if zstd is not None:
        round_trip("tar.zst", work, source, "packed.tar.zst", zstd.compress(tar_bytes(source, "w")))


def test_native(work, source):
    archive = work / "native.bale"
    created = run("create", archive, source, cwd=work)
    expect_exit("bale create", created, EXIT_OK)
    expect_exit("bale create again", run("create", archive, source, cwd=work), EXIT_ALREADY_EXISTS)
    expect_exit("bale test", run("test", archive, cwd=work), EXIT_OK)

    small = work / "small.bale"
    expect_exit("bale create small", run("create", small, source, "--preset", "small", cwd=work), EXIT_OK)
    info = run("info", small, cwd=work)
    expect_exit("bale info", info, EXIT_OK)
    check("bale info preset", "preset: small" in info.stdout and "zstd level 19" in info.stdout, info.stdout)

    output = work / "native.out"
    expect_exit("bale extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    check("bale contents", same_tree(source, output), "extracted tree differs")

    updated_source = work / "updated-source"
    updated_source.mkdir()
    (updated_source / "replacement.txt").write_text("new snapshot\n", encoding="utf-8")
    expect_exit("bale update", run("update", archive, updated_source, cwd=work), EXIT_OK)
    expect_exit("bale updated test", run("test", archive, cwd=work), EXIT_OK)
    listing = run("list", archive, cwd=work)
    expect_exit("bale updated list", listing, EXIT_OK)
    check("updated snapshot entry", "replacement.txt" in listing.stdout, listing.stdout)
    check("old snapshot entry removed", "docs/deep/random.bin" not in listing.stdout, listing.stdout)

    archive_size = archive.stat().st_size
    compacted = work / "compacted.bale"
    expect_exit("bale compact", run("compact", archive, compacted, cwd=work), EXIT_OK)
    expect_exit("bale compacted test", run("test", compacted, cwd=work), EXIT_OK)
    check("compact preserves source", archive.stat().st_size == archive_size)
    compacted_listing = run("list", compacted, cwd=work)
    expect_exit("bale compacted list", compacted_listing, EXIT_OK)
    check(
        "compacted snapshot entry",
        "replacement.txt" in compacted_listing.stdout,
        compacted_listing.stdout,
    )

    for codec, level, shown in (("zstd", "9", "zstd level 9"), ("lz4", "12", "lz4 level 12")):
        compressed = work / f"{codec}.bale"
        expect_exit(
            f"bale {codec} create",
            run("create", "--level", level, "--codec", codec, compressed, source, cwd=work),
            EXIT_OK,
        )
        expect_exit(f"bale {codec} test", run("test", compressed, cwd=work), EXIT_OK)
        info = run("info", compressed, cwd=work)
        check(f"bale {codec} info", shown in info.stdout, info.stdout)
        compressed_output = work / f"{codec}.out"
        expect_exit(
            f"bale {codec} extract",
            run("extract", compressed, "-o", compressed_output, cwd=work),
            EXIT_OK,
        )
        check(f"bale {codec} contents", same_tree(source, compressed_output), "extracted tree differs")

    rejected = work / "rejected.bale"
    for codec, level in (("zstd", "0"), ("zstd", "23"), ("lz4", "-1"), ("lz4", "13"), ("raw", "1")):
        expect_exit(
            f"bale {codec} level {level}",
            run("create", "--codec", codec, "--level", level, rejected, source, cwd=work),
            EXIT_USAGE,
        )

    corrupt = work / "corrupt.bale"
    data = bytearray(archive.read_bytes())
    data[200] ^= 0x01
    corrupt.write_bytes(bytes(data))
    result = run("test", corrupt, cwd=work)
    check("bale corrupt", result.returncode in (EXIT_INVALID, EXIT_INTEGRITY), result.stderr)


def test_native_unicode_paths(work):
    source = work / "origem-ação-東京"
    source.mkdir()
    (source / "資料.txt").write_text("arquivo com acentos\n", encoding="utf-8")
    archive = work / "arquivo-ação.bale"
    expect_exit("unicode bale create", run("create", archive, source, cwd=work), EXIT_OK)
    expect_exit("unicode bale test", run("test", archive, cwd=work), EXIT_OK)

    output = work / "extração-東京"
    expect_exit("unicode bale extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    check("unicode bale contents", same_tree(source, output), "extracted tree differs")

    context_source = work / "contexto-ação-東京"
    context_source.mkdir()
    (context_source / "arquivo.txt").write_text("context menu\n", encoding="utf-8")
    context_archive = Path(str(context_source) + ".bale")
    expect_exit(
        "context add directory",
        run("context", "add", context_source, cwd=work),
        EXIT_OK,
    )
    original = work / "contexto-original"
    context_source.rename(original)
    expect_exit(
        "context extract folder",
        run("context", "extract-folder", context_archive, cwd=work),
        EXIT_OK,
    )
    check("context directory contents", same_tree(original, context_source), "extracted tree differs")

    single_dir = work / "context-single"
    single_dir.mkdir()
    single_file = single_dir / "nota-東京.txt"
    single_file.write_text("single file\n", encoding="utf-8")
    single_archive = Path(str(single_file) + ".bale")
    expect_exit("context add file", run("context", "add", single_file, cwd=work), EXIT_OK)
    single_file.unlink()
    expect_exit(
        "context extract here",
        run("context", "extract-here", single_archive, cwd=work),
        EXIT_OK,
    )
    check("context file contents", single_file.read_text(encoding="utf-8") == "single file\n")


def load_reference():
    spec = importlib.util.spec_from_file_location("bale_reference", REFERENCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reference_archive(work):
    archive = work / "reference.bale"
    archive.write_bytes(load_reference().golden_archive())

    expect_exit("reference test", run("test", archive, cwd=work), EXIT_OK)
    listed = run("list", archive, cwd=work)
    check("reference list", listed.stdout.split() == ["d", "d/f", "d/g", "e"], listed.stdout)

    output = work / "reference.out"
    expect_exit("reference extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    check("reference contents", (output / "d" / "g").read_bytes() == b"hello")


def test_single_gzip(work):
    archive = work / "note.txt.gz"
    archive.write_bytes(gzip.compress(b"just one file\n" * 100))
    output = work / "gz.out"
    expect_exit("gzip extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    extracted = list(output.iterdir())
    check("gzip extract", len(extracted) == 1, str(extracted))
    if extracted:
        check("gzip contents", extracted[0].read_bytes() == b"just one file\n" * 100)


def test_single_xz(work):
    import lzma

    archive = work / "note.txt.xz"
    archive.write_bytes(lzma.compress(b"just one file\n" * 100, preset=6))
    output = work / "xz.out"
    expect_exit("xz list", run("list", archive, cwd=work), EXIT_OK)
    expect_exit("xz test", run("test", archive, cwd=work), EXIT_OK)
    expect_exit("xz extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    extracted = list(output.iterdir())
    check("xz extract", len(extracted) == 1, str(extracted))
    if extracted:
        check("xz names", extracted[0].name == "note.txt", str(extracted))
        check("xz contents", extracted[0].read_bytes() == b"just one file\n" * 100)


def test_single_bz2(work):
    import bz2

    archive = work / "note.txt.bz2"
    archive.write_bytes(bz2.compress(b"just one file\n" * 100, compresslevel=9))
    output = work / "bz2.out"
    expect_exit("bzip2 list", run("list", archive, cwd=work), EXIT_OK)
    expect_exit("bzip2 test", run("test", archive, cwd=work), EXIT_OK)
    expect_exit("bzip2 extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    extracted = list(output.iterdir())
    check("bzip2 extract", len(extracted) == 1, str(extracted))
    if extracted:
        check("bzip2 names", extracted[0].name == "note.txt", str(extracted))
        check("bzip2 contents", extracted[0].read_bytes() == b"just one file\n" * 100)


def test_hostile_tar(work):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in [("../escape.txt", b"x"), ("/absolute.txt", b"x"), ("ok/fine.txt", b"fine")]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

        link = tarfile.TarInfo("ok/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

        through = tarfile.TarInfo("ok/link/pwned.txt")
        through.size = 5
        archive.addfile(through, io.BytesIO(b"pwned"))

    archive = work / "hostile.tar"
    archive.write_bytes(buffer.getvalue())
    output = work / "hostile.out"
    outside = work / "outside"
    outside.mkdir()

    result = run("extract", archive, "-o", output, "--allow-symlinks", cwd=work)
    expect_exit("hostile tar", result, EXIT_UNSAFE_PATH)
    check("hostile tar contained", not any(outside.iterdir()), "wrote outside the output")
    check("hostile tar escape", not (work / "escape.txt").exists(), "escaped the output")
    fine = output / "ok" / "fine.txt"
    check("hostile tar kept good entry", fine.is_file() and fine.read_bytes() == b"fine")


def test_corrupt_zip(work):
    payload = bytearray(zip_bytes_single(b"A" * 1000))
    offset = payload.index(b"A" * 1000)
    payload[offset] = ord("B")
    archive = work / "crc.zip"
    archive.write_bytes(bytes(payload))
    output = work / "crc.out"

    expect_exit("zip crc test", run("test", archive, cwd=work), EXIT_INTEGRITY)
    expect_exit("zip crc extract", run("extract", archive, "-o", output, cwd=work), EXIT_INTEGRITY)
    check("zip crc leftovers", not output.exists() or not any(output.rglob("*")), "partial file left")


def test_cp437_zip_name(work):
    archive = work / "cp437.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("aaaa.txt", b"legacy name\n")

    payload = archive.read_bytes()
    check("cp437 fixture headers", payload.count(b"aaaa.txt") == 2, "unexpected ZIP layout")
    archive.write_bytes(payload.replace(b"aaaa.txt", b"caf\x82.txt"))

    listed = run("list", archive, cwd=work)
    expect_exit("cp437 ZIP list", listed, EXIT_OK)
    check("cp437 ZIP name", "café.txt" in listed.stdout, listed.stdout)

    output = work / "cp437.out"
    expect_exit("cp437 ZIP extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    extracted = output / "café.txt"
    check(
        "cp437 ZIP contents",
        extracted.is_file() and extracted.read_bytes() == b"legacy name\n",
        "decoded path or contents differ",
    )


def zip_bytes_single(data):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("data.bin", data)
    return buffer.getvalue()


def test_truncated_tgz(work, source):
    payload = tar_bytes(source, "w:gz")
    archive = work / "cut.tgz"
    archive.write_bytes(payload[: len(payload) // 2])
    expect_exit("truncated tgz", run("test", archive, cwd=work), EXIT_INVALID)

    for name, mode in (("cut.tar.xz", "w:xz"), ("cut.tar.bz2", "w:bz2")):
        payload = tar_bytes(source, mode)
        archive = work / name
        archive.write_bytes(payload[: len(payload) // 2])
        expect_exit(f"truncated {name}", run("test", archive, cwd=work), EXIT_INVALID)


def test_no_xz_bzip2_output(work, source):
    archive = work / "plain.tar"
    archive.write_bytes(tar_bytes(source, "w"))

    for name in ("out.tar.xz", "out.tar.bz2", "out.txz", "out.tbz2"):
        output = work / name
        expect_exit(
            f"no {name} output",
            run("convert", archive, output, cwd=work),
            EXIT_USAGE,
        )
        check(f"no {name} leftovers", not output.exists())
        expect_exit(
            f"no {name} create",
            run("create", output, source, cwd=work),
            EXIT_USAGE,
        )
        check(f"no {name} created", not output.exists())


def test_errors_and_escaping(work):
    junk = work / "junk.bin"
    junk.write_bytes(b"not an archive at all" * 10)
    expect_exit("unknown format", run("list", junk, cwd=work), EXIT_UNSUPPORTED)
    expect_exit("missing file", run("list", work / "missing.zip", cwd=work), EXIT_IO)
    expect_exit("bad command", run("frobnicate", cwd=work), EXIT_USAGE)
    expect_exit("no archive", run("list", cwd=work), EXIT_USAGE)

    archive = work / "escape.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("red\x1b[31mname", b"x")
    listed = run("list", archive, cwd=work)
    check("terminal escaping", "\x1b" not in listed.stdout and "\\x1b" in listed.stdout, listed.stdout)


def make_rich_tree(root):
    long_dir = root / ("d" * 120)
    long_dir.mkdir(parents=True)
    (long_dir / "inside.txt").write_bytes(b"split between prefix and name\n")
    (root / ("n" * 150 + ".txt")).write_bytes(b"needs a pax path\n")
    (root / "ação-東京").mkdir()
    (root / "ação-東京" / "資料.txt").write_text("unicode\n", encoding="utf-8")
    (root / "empty-dir" / "nested-empty").mkdir(parents=True)
    (root / "empty.txt").write_bytes(b"")
    (root / "text.txt").write_bytes(b"compressible line of text\n" * 20_000)
    (root / "random.bin").write_bytes(os.urandom(1_500_000))
    if os.name != "nt":
        os.symlink("text.txt", root / "link-to-text")
        os.symlink("l" * 120, root / "long-link")
    os.link(root / "text.txt", root / "hard-text")


def expected_members(source):
    members = {}
    for path in sorted(source.rglob("*")):
        name = path.relative_to(source).as_posix()
        if path.is_symlink():
            members[name] = ("symlink", os.readlink(path))
        elif path.is_dir():
            members[name] = ("dir", None)
        else:
            members[name] = ("file", path.read_bytes())
    return members


def member_difference(expected, actual):
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    changed = []
    for name in sorted(expected.keys() & actual.keys()):
        expected_kind, expected_value = expected[name]
        actual_kind, actual_value = actual[name]
        if expected_kind != actual_kind or expected_value != actual_value:
            expected_size = len(expected_value) if isinstance(expected_value, bytes) else None
            actual_size = len(actual_value) if isinstance(actual_value, bytes) else None
            changed.append((name, expected_kind, expected_size, actual_kind, actual_size))
    return f"missing={missing[:5]}, extra={extra[:5]}, changed={changed[:5]}"


def normalize_member_names(members):
    normalized = {}
    for name, value in members.items():
        canonical = unicodedata.normalize("NFC", name)
        if canonical in normalized:
            return None
        normalized[canonical] = value
    return normalized


def zip_members(archive):
    members = {}
    with zipfile.ZipFile(archive) as handle:
        check("python zip testzip", handle.testzip() is None)
        for info in handle.infolist():
            mode = info.external_attr >> 16
            name = info.filename.rstrip("/")
            if info.is_dir():
                members[name] = ("dir", None)
            elif (mode & 0o170000) == 0o120000:
                members[name] = ("symlink", handle.read(info).decode("utf-8"))
            else:
                members[name] = ("file", handle.read(info))
    return members


def tar_members(archive, mode):
    members = {}
    with tarfile.open(archive, mode) as handle:
        contents = {}
        for info in handle.getmembers():
            name = info.name.rstrip("/")
            if info.isdir():
                members[name] = ("dir", None)
            elif info.issym():
                members[name] = ("symlink", info.linkname)
            elif info.islnk():
                members[name] = ("file", contents[info.linkname])
            else:
                contents[info.name] = handle.extractfile(info).read()
                members[name] = ("file", contents[info.name])
    return members


def system_extract(name, command, output):
    output.mkdir()
    result = subprocess.run(command, cwd=output, capture_output=True)
    check(name, result.returncode == 0, result.stderr.decode("utf-8", "replace"))


def test_created_formats(work):
    source = work / "rich-source"
    make_rich_tree(source)
    expected = expected_members(source)

    readers = {
        "rich.zip": lambda path: zip_members(path),
        "rich.tar": lambda path: tar_members(path, "r:"),
        "rich.tgz": lambda path: tar_members(path, "r:gz"),
    }
    if zstd is not None:
        readers["rich.tar.zst"] = lambda path: tar_members(path, "r:zst")
    else:
        readers["rich.tar.zst"] = None

    for archive_name, reader in readers.items():
        archive = work / archive_name
        created = run("create", archive, source, cwd=work)
        expect_exit(f"create {archive_name}", created, EXIT_OK)
        if reader is not None:
            read_members = reader(archive)
            check(
                f"python reads {archive_name}",
                read_members == expected,
                member_difference(expected, read_members),
            )

        output = work / (archive_name + ".bale-out")
        extracted = run("extract", archive, "-o", output, "--allow-symlinks", cwd=work)
        expect_exit(f"bale extracts {archive_name}", extracted, EXIT_OK)
        extracted_members = expected_members(output)
        check(
            f"bale round trip {archive_name}",
            extracted_members == expected,
            member_difference(expected, extracted_members),
        )

    first = (work / "rich.tar").read_bytes()
    (work / "rich.tar").unlink()
    expect_exit("create tar again", run("create", work / "rich.tar", source, cwd=work), EXIT_OK)
    check("tar output is deterministic", (work / "rich.tar").read_bytes() == first)

    if os.name != "nt" and shutil.which("unzip"):
        output = work / "unzip-out"
        system_extract("system unzip", ["unzip", "-q", str(work / "rich.zip")], output)
        check("system unzip contents", expected_members(output) == expected)
    if os.name != "nt" and shutil.which("tar"):
        for archive_name in ("rich.tar", "rich.tgz"):
            output = work / (archive_name + ".tar-out")
            system_extract(f"system tar {archive_name}", ["tar", "-xf", str(work / archive_name)], output)
            expected_names = normalize_member_names(expected)
            actual = normalize_member_names(expected_members(output))
            if expected_names is None or actual is None:
                check(
                    f"system tar {archive_name} contents",
                    False,
                    "Unicode path normalization collision",
                )
                continue
            check(
                f"system tar {archive_name} contents",
                actual == expected_names,
                member_difference(expected_names, actual),
            )
    if shutil.which("zstd"):
        result = subprocess.run(["zstd", "-t", "-q", str(work / "rich.tar.zst")], capture_output=True)
        check("system zstd test", result.returncode == 0, result.stderr.decode("utf-8", "replace"))

    chain = ["rich.zip", "chain.tar.gz", "chain.bale", "chain.tar.zst", "chain.zip", "chain.tar"]
    for previous, following in zip(chain, chain[1:]):
        converted = run("convert", work / previous, work / following, cwd=work)
        expect_exit(f"convert {previous} to {following}", converted, EXIT_OK)
    check("converted chain", tar_members(work / "chain.tar", "r:") == expected)

    stored = work / "level0.zip"
    expect_exit("zip level 0", run("create", stored, source, "--level", "0", cwd=work), EXIT_OK)
    with zipfile.ZipFile(stored) as handle:
        check("zip level 0 stores", all(i.compress_type == zipfile.ZIP_STORED for i in handle.infolist()))
    with zipfile.ZipFile(work / "rich.zip") as handle:
        methods = {i.filename: i.compress_type for i in handle.infolist()}
        check("zip deflates text", methods["text.txt"] == zipfile.ZIP_DEFLATED)
        check("zip stores random", methods["random.bin"] == zipfile.ZIP_STORED)

    forced = work / "forced.bin"
    expect_exit("forced format", run("create", forced, source, "--format", "tar.gz", cwd=work), EXIT_OK)
    check("forced format is gzip", forced.read_bytes()[:2] == b"\x1f\x8b")

    for args in (
        ("create", work / "unknown.out", source),
        ("create", work / "bad.zip", source, "--threads", "2"),
        ("create", work / "bad.zip", source, "--preset", "small"),
        ("create", work / "bad.tar", source, "--level", "3"),
        ("create", work / "bad.zip", source, "--level", "10"),
        ("create", work / "bad.zip", source, "--format", "rar"),
        ("convert", work / "rich.zip", work / "bad.bale", "--level", "3"),
    ):
        expect_exit(f"usage {args[1:]}", run(*args, cwd=work), EXIT_USAGE)
        check(f"usage leaves nothing {args[1:]}", not Path(args[2] if args[0] == "convert" else args[1]).exists())

    expect_exit("zip refuses overwrite", run("create", work / "rich.zip", source, cwd=work), EXIT_ALREADY_EXISTS)
    check("zip kept on refusal", zip_members(work / "rich.zip") == expected)

    missing = work / "missing.zip"
    result = run("create", missing, work / "no-such-dir", cwd=work)
    check("missing source fails", result.returncode != EXIT_OK, result.stderr)
    check("partial output removed", not missing.exists())


def test_signatures(work, source):
    seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    pub = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    other_pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    other_seed = "ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00"
    keys = work / "sign.keys"
    keys.write_text(seed + "\n", encoding="utf-8")

    archive = work / "signed.bale"
    expect_exit(
        "signed create",
        run("create", archive, source, "--sign", keys, cwd=work),
        EXIT_OK,
    )
    expect_exit("signed test", run("test", archive, "--verify-key", pub, cwd=work), EXIT_OK)
    expect_exit(
        "signed test wrong key",
        run("test", archive, "--verify-key", other_pub, cwd=work),
        EXIT_INTEGRITY,
    )
    expect_exit("signed list", run("list", archive, "--verify-key", pub, cwd=work), EXIT_OK)
    info = run("info", archive, "--verify-key", pub, cwd=work)
    expect_exit("signed info", info, EXIT_OK)
    check("signed info signer", pub in info.stdout, info.stdout)
    expect_exit(
        "signed extract",
        run("extract", archive, "-o", work / "signed.out", "--verify-key", pub, cwd=work),
        EXIT_OK,
    )
    expect_exit(
        "signed extract wrong key",
        run("extract", archive, "-o", work / "signed.bad", "--verify-key", other_pub, cwd=work),
        EXIT_INTEGRITY,
    )
    check(
        "unsigned archive ignores signatures",
        run("test", work / "native.bale", cwd=work).returncode == EXIT_OK,
        "plain test regressed",
    )
    expect_exit(
        "unsigned archive with verify key",
        run("test", work / "native.bale", "--verify-key", pub, cwd=work),
        EXIT_INTEGRITY,
    )
    zipped = work / "plain.zip"
    expect_exit(
        "zip create",
        run("create", zipped, source, "--format", "zip", cwd=work),
        EXIT_OK,
    )
    expect_exit(
        "zip verify key rejected",
        run("test", zipped, "--verify-key", pub, cwd=work),
        EXIT_INVALID,
    )

    # NOTE: adoption path: an unsigned archive gains signatures on update; only the latest
    # NOTE: commit verifies, history stays readable.
    adopted = work / "adopted.bale"
    expect_exit("adopted create", run("create", adopted, source, cwd=work), EXIT_OK)
    keys.write_text(seed + "\n", encoding="utf-8")
    expect_exit(
        "adopted update",
        run("update", adopted, source, "--sign", keys, cwd=work),
        EXIT_OK,
    )
    expect_exit("adopted test", run("test", adopted, "--verify-key", pub, cwd=work), EXIT_OK)

    # NOTE: rotation: the second generation is signed by a new key, so the old key stops
    # NOTE: verifying and the new key starts.
    keys.write_text(other_seed + "\n", encoding="utf-8")
    expect_exit(
        "signed update",
        run("update", archive, source, "--sign", keys, cwd=work),
        EXIT_OK,
    )
    expect_exit(
        "rotated old key",
        run("test", archive, "--verify-key", pub, cwd=work),
        EXIT_INTEGRITY,
    )
    rotated_info = run("info", archive, cwd=work)
    expect_exit("rotated info", rotated_info, EXIT_OK)
    new_pub = ""
    for line in rotated_info.stdout.splitlines():
        if line.startswith("signer: "):
            new_pub = line.split()[1]
    check("rotated info shows new signer", len(new_pub) == 64 and new_pub != pub, rotated_info.stdout)
    if new_pub:
        expect_exit(
            "rotated new key",
            run("test", archive, "--verify-key", new_pub, cwd=work),
            EXIT_OK,
        )

    # NOTE: compact drops the old commit digest, so it refuses a signed source instead of
    # NOTE: emitting silently unsigned output; --sign re-signs the compacted archive.
    compacted = work / "signed-compact.bale"
    expect_exit(
        "compact signed refused",
        run("compact", archive, compacted, cwd=work),
        EXIT_INVALID,
    )
    expect_exit(
        "compact signed resigned",
        run("compact", archive, compacted, "--sign", keys, cwd=work),
        EXIT_OK,
    )
    expect_exit(
        "compacted verify",
        run("test", compacted, "--verify-key", new_pub or other_pub, cwd=work),
        EXIT_OK,
    )
    expect_exit(
        "sign missing key file",
        run("create", work / "missing.bale", source, "--sign", work / "nope.keys", cwd=work),
        EXIT_IO,
    )


def main():
    with tempfile.TemporaryDirectory(prefix="bale-cli-") as directory:
        work = Path(directory)
        source = work / "source"
        make_tree(source)

        checks = [
            lambda: test_round_trips(work, source),
            lambda: test_native(work, source),
            lambda: test_signatures(work, source),
            lambda: test_native_unicode_paths(work),
            lambda: test_reference_archive(work),
            lambda: test_single_gzip(work),
            lambda: test_single_xz(work),
            lambda: test_single_bz2(work),
            lambda: test_no_xz_bzip2_output(work, source),
            lambda: test_hostile_tar(work),
            lambda: test_corrupt_zip(work),
            lambda: test_cp437_zip_name(work),
            lambda: test_truncated_tgz(work, source),
            lambda: test_errors_and_escaping(work),
            lambda: test_created_formats(work),
        ]
        for index, run_check in enumerate(checks):
            try:
                run_check()
            except OSError as error:
                failures.append(f"check {index} crashed: {error}")

    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
