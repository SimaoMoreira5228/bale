"""Python half of the differential suite (CTest: reference.differential).

Proves three things:
1. The committed goldens are exactly what the reference encoder emits
   (regenerate into a temp dir, byte-compare, check manifest.json hashes).
2. The reference decoder accepts every golden the C++ suite also accepts,
   with the same structural verdicts, including PasswordRequired for the
   encrypted envelope and opaque-but-checked compressed payloads.
3. Corrupt fixtures fail with the same kind and message the C++ suite pins
   in tests/reference/reference_test.cpp. Structure and content phases are
   checked separately, mirroring Reader::open vs Reader::verify.

Plus decoder self-tests that have no C++ counterpart: hostile TLV shapes
must fail here too, so the decoder cannot pass by echoing the encoder.
"""

import hashlib
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools", "reference"))

import bale_reference as reference
import bale_verify as verify
from make_goldens import GOLDENS, build_corrupts, build_plain

FAILURES = []


def check(label, condition, detail=""):
    print(("ok   " if condition else "FAIL ") + label + (" " + detail if detail else ""))
    if not condition:
        FAILURES.append(label)


def expect_error(label, data, kind, message, content):
    try:
        verify.verify(data, content=content)
    except verify.Error as error:
        check(label, error.kind == kind and message in error.message,
              "%s | %s" % (error.kind, error.message))
        return
    check(label, False, "accepted, wanted %s %s" % (kind, message))


def main():
    with open(os.path.join(HERE, "manifest.json")) as handle:
        manifest = json.load(handle)
    hashes = {item["path"]: item["sha256"] for item in manifest["files"]}

    with tempfile.TemporaryDirectory() as scratch:
        sys.argv = ["make_goldens"]
        old_dir = os.getcwd()
        os.chdir(scratch)
        try:
            blobs = {name: build() for name, build, _ in GOLDENS}
            blobs.update(build_corrupts(build_plain()))
        finally:
            os.chdir(old_dir)
        for name, blob in blobs.items():
            path = os.path.join(HERE, name)
            try:
                with open(path, "rb") as handle:
                    committed = handle.read()
            except FileNotFoundError:
                check("committed " + name, False, "missing file")
                continue
            check("byte-identical " + name, committed == blob,
                  "%d committed vs %d regenerated" % (len(committed), len(blob)))
            check("manifest hash " + name,
                  hashlib.sha256(committed).hexdigest() == hashes.get(name),
                  hashes.get(name, "missing")[:16])

    golden_ok = ["plain.bale", "cdc.bale", "codecs.bale", "snapshot2.bale", "meta.bale"]
    for name in golden_ok:
        with open(os.path.join(HERE, name), "rb") as handle:
            data = handle.read()
        try:
            report = verify.verify(data)
        except verify.Error as error:
            check("verify " + name, False, "%s | %s" % (error.kind, error.message))
            continue
        check("verify " + name, report["verdict"] == "ok",
              "gen=%d rec=%d chunks=%d opaque=%d codecs=%s" % (
                  report["generation"], report["records"], report["chunks_verified"],
                  report["opaque_bytes"], sorted(report["codecs"])))

    with open(os.path.join(HERE, "codecs.bale"), "rb") as handle:
        report = verify.verify(handle.read())
    check("codecs payloads opaque", report["opaque_bytes"] > 0 and report["verdict"] == "ok",
          "%d opaque bytes" % report["opaque_bytes"])

    try:
        verify.verify(open(os.path.join(HERE, "encrypted-structure.bale"), "rb").read())
        check("verify encrypted-structure.bale", False, "accepted without a key")
    except verify.Error as error:
        check("verify encrypted-structure.bale",
              error.kind == "PasswordRequired" and error.message == "archive is encrypted",
              "%s | %s" % (error.kind, error.message))

    archive = verify.find_footer(open(os.path.join(HERE, "encrypted-structure.bale"),
                                      "rb").read())
    check("encrypted framing swept",
          archive.stats["records"] == 5 and archive.stats.get("keyslots") == 1,
          "%d records %d keyslots" % (archive.stats["records"],
                                      archive.stats.get("keyslots", 0)))

    corrupt = {
        "corrupt-bad-magic.bale": ("Malformed", "not a bale archive", False),
        "corrupt-small-file.bale": ("Truncated", "file too small for a superblock", False),
        "corrupt-truncated.bale": ("Truncated", "no footer found", False),
        "corrupt-manifest-digest.bale": ("Integrity", "manifest digest mismatch", False),
        "corrupt-commit-digest.bale": ("Integrity", "commit digest mismatch", False),
        "corrupt-unknown-feature.bale": ("Unsupported", "unknown required feature", False),
        "corrupt-bad-record-type.bale": ("Unsupported", "unknown record type", False),
        # NOTE: DATA payloads are not re-read by the record walk (both sides),
        # so these pass structurally and fail at content time, like C++.
        "corrupt-payload-crc.bale": ("Integrity", "record payload checksum mismatch", True),
        "corrupt-payload-crc-fixed.bale": ("Integrity", "chunk content does not match", True),
        "corrupt-unknown-flag.bale": ("Unsupported", "unknown required record flag", False),
        "corrupt-encrypted-in-plain.bale": ("Unsupported", "encrypted record in a plain archive",
                                           False),
    }
    for name, (kind, message, needs_content) in corrupt.items():
        with open(os.path.join(HERE, name), "rb") as handle:
            data = handle.read()
        if needs_content:
            try:
                verify.verify(data, content=False)
                structure = "structure ok"
            except verify.Error as error:
                structure = "structure %s | %s" % (error.kind, error.message)
            check(name + " structure passes", structure == "structure ok", structure)
        expect_error(name, data, kind, message, needs_content)

    # NOTE: decoder self-tests. Each input is hostile TLV/ULEB, never produced
    # by the encoder above; a decoder that echoed the encoder would pass these
    # only by accident.
    try:
        verify.decode_uleb(bytes([0x80, 0x00]), 0)
        check("non-minimal uleb rejected", False, "accepted")
    except verify.Error as error:
        check("non-minimal uleb rejected", error.kind == "Malformed", error.message)
    try:
        reference.validate_cdc_params(1, 2, 3)
        check("bad cdc params refused", False, "accepted")
    except ValueError:
        check("bad cdc params refused", True)
    splitter = reference.CdcSplitter(16, 64, 256)
    data = bytes(list(range(256)) * 2)
    ends = []
    for byte in data:
        if splitter.feed(byte):
            ends.append(splitter.length)
            splitter.next_chunk()
    ends.append(splitter.length)
    check("cdc vector", ends == [45, 62, 110, 28, 56, 62, 110, 28, 11], str(ends[:3]))
    check("gear table pinned", reference.GEAR[0] == 0x2CB0F69F4ABEA221 and
          reference.GEAR[97] == 0x058132BC44352277 and
          reference.GEAR[255] == 0x4007DCF6E43C406C)

    print("%d failures" % len(FAILURES))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
