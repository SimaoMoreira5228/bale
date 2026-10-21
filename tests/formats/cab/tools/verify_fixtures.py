#!/usr/bin/env python3
"""Verify bale-extracted folders against expected .f0.bin streams.

Usage: verify_fixtures.py <bale-binary> <workdir> <cab> [<cab> ...]
Refusal fixtures (quantum/span_next/unknown_method, which have no .fN.bin)
are skipped: their contract is the error, covered by unit tests.
"""
import os
import struct
import subprocess
import sys

BALE = sys.argv[1] if len(sys.argv) > 3 else None
WORKDIR = sys.argv[2] if len(sys.argv) > 3 else None


def folder_stream(cab):
    f = open(cab, 'rb').read()
    n_files = struct.unpack('<H', f[28:30])[0]
    coff = struct.unpack('<I', f[16:20])[0]
    off = coff
    entries = []
    for _ in range(n_files):
        size, foff, fidx, dt, tm, attr = struct.unpack('<IIHHHH', f[off:off + 16])
        end = f[off + 16:].index(b'\0')
        name = f[off + 16:off + 16 + end].decode('latin1')
        entries.append((foff, size, fidx, name, attr))
        off += 16 + end + 1
    return entries


def main():
    if BALE is None:
        print(__doc__)
        return 2
    fails = 0
    for cab in sys.argv[3:]:
        base = os.path.basename(cab).replace('.cab', '')
        outdir = os.path.join(WORKDIR, base)
        subprocess.run(['rm', '-rf', outdir])
        os.makedirs(outdir)
        p = subprocess.run([BALE, 'extract', cab, '-o', outdir],
                           capture_output=True, text=True)
        status = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else '?'
        entries = folder_stream(cab)
        # group files by folder
        folders = {}
        for foff, size, fidx, name, attr in entries:
            if attr & 0x10:
                continue
            folders.setdefault(fidx, []).append((foff, size, name))
        ok = True
        for fidx, files in folders.items():
            files.sort()
            blob = bytearray()
            for foff, size, name in files:
                # bale converts backslashes to slashes on extract
                fp = os.path.join(outdir, name.replace('\\', '/'))
                if not os.path.exists(fp):
                    print('%s: MISSING %s' % (base, name))
                    ok = False
                    break
                data = open(fp, 'rb').read()
                if len(data) != size:
                    print('%s: SIZE %s %d != %d' % (base, name, len(data), size))
                    ok = False
                    break
                blob += data
            exp_path = cab.replace('.cab', '.f%d.bin' % fidx)
            if not os.path.exists(exp_path):
                continue
            exp = open(exp_path, 'rb').read()
            if bytes(blob) != exp:
                print('%s: folder %d BYTES DIFFER (%d vs %d)' % (base, fidx, len(blob), len(exp)))
                ok = False
        # empty-file edge: expected stream may be empty
        if ok:
            print('%s: IDENTICAL (%s)' % (base, status))
        else:
            fails += 1
    return fails


sys.exit(main())
