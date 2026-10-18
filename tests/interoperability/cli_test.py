"""Runs the bale CLI against archives written by Python's own tarfile, zipfile, gzip and zstd."""

import filecmp
import gzip
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
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

    expect_exit(f"{name} extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    check(f"{name} contents", same_tree(source, output), "extracted tree differs")


def test_round_trips(work, source):
    round_trip("tar", work, source, "plain.tar", tar_bytes(source, "w"))
    round_trip("tar.gz", work, source, "packed.tgz", tar_bytes(source, "w:gz"))
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

    output = work / "native.out"
    expect_exit("bale extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    check("bale contents", same_tree(source, output), "extracted tree differs")

    compressed = work / "compressed.bale"
    expect_exit(
        "bale zstd create",
        run("create", "--codec", "zstd", compressed, source, cwd=work),
        EXIT_OK,
    )
    expect_exit("bale zstd test", run("test", compressed, cwd=work), EXIT_OK)
    compressed_output = work / "compressed.out"
    expect_exit(
        "bale zstd extract",
        run("extract", compressed, "-o", compressed_output, cwd=work),
        EXIT_OK,
    )
    check("bale zstd contents", same_tree(source, compressed_output), "extracted tree differs")

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


def test_single_gzip(work):
    archive = work / "note.txt.gz"
    archive.write_bytes(gzip.compress(b"just one file\n" * 100))
    output = work / "gz.out"
    expect_exit("gzip extract", run("extract", archive, "-o", output, cwd=work), EXIT_OK)
    extracted = list(output.iterdir())
    check("gzip extract", len(extracted) == 1, str(extracted))
    if extracted:
        check("gzip contents", extracted[0].read_bytes() == b"just one file\n" * 100)


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


def main():
    with tempfile.TemporaryDirectory(prefix="bale-cli-") as directory:
        work = Path(directory)
        source = work / "source"
        make_tree(source)

        checks = [
            lambda: test_round_trips(work, source),
            lambda: test_native(work, source),
            lambda: test_native_unicode_paths(work),
            lambda: test_single_gzip(work),
            lambda: test_hostile_tar(work),
            lambda: test_corrupt_zip(work),
            lambda: test_cp437_zip_name(work),
            lambda: test_truncated_tgz(work, source),
            lambda: test_errors_and_escaping(work),
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
