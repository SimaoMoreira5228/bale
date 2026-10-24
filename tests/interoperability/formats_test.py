import subprocess
import sys


def main():
    result = subprocess.run([sys.argv[1], "formats"], capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return 1

    formats = {}
    for line in result.stdout.splitlines()[1:]:
        columns = line.split(maxsplit=5)
        if len(columns) == 6:
            formats[columns[0]] = columns[1:]

    iso = formats.get("iso", [])
    sevenzip = formats.get("7z", [])
    wim = formats.get("wim", [])
    if len(iso) != 5 or iso[:4] != ["yes", "yes", "yes", "no"]:
        print("formats must report ISO as readable but not creatable", file=sys.stderr)
        return 1
    if "Rock Ridge" not in iso[4] or "El Torito" not in iso[4]:
        print("formats must describe ISO support", file=sys.stderr)
        return 1
    if len(sevenzip) != 5 or "main-codec+BCJ chain" not in sevenzip[4]:
        print("formats must report 7z BCJ filter chains", file=sys.stderr)
        return 1
    if len(wim) != 5 or wim[:4] != ["yes", "yes", "yes", "no"]:
        print("formats must report WIM as readable but not creatable", file=sys.stderr)
        return 1
    if "lzx resources" not in wim[4] or "no xpress or lzms" not in wim[4]:
        print("formats must describe supported and unsupported WIM codecs", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
