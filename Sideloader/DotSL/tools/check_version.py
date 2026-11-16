#!/usr/bin/env python3
"""Compare the version resource of the proxy against a pinned reference.

    check_version.py <reference.rc | real.dll> <proxy.dll>

Detection rules that cannot see a signature key on OriginalFilename and the
fixed-version fields, so the proxy must match its reference exactly. The
reference side is the pinned .rc from reference/ (or a live module).
"""
import re
import sys

import pefile

VALUE_RE = re.compile(r'VALUE\s+"((?:[^"\\]|\\.)*)"\s*,\s+"((?:[^"\\]|\\.)*)"')


def unescape(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i + 1]
            if n in '"\\':
                out.append(n)
                i += 2
                continue
            m = re.match(r'[0-7]{1,3}', s[i + 1:])
            if m:
                out.append(chr(int(m.group(0), 8)))
                i += 1 + len(m.group(0))
                continue
        out.append(c)
        i += 1
    return ''.join(out)


def rc_strings(path):
    text = open(path, encoding="utf-8").read()
    out = {}
    for k, v in VALUE_RE.findall(text):
        out[unescape(k)] = unescape(v)
    for key in ("FileVersion", "ProductVersion"):
        m = re.search(r'FILE(VERSION)\s+([\d,]+)', text) if key == "FileVersion" \
            else re.search(r'PRODUCTVERSION\s+([\d,]+)', text)
        if m:
            q = m.group(2 if key == "FileVersion" else 1)
            out["__" + key] = ".".join(str(int(x)) for x in q.split(","))
    m = re.search(r'FILEFLAGS\s+(0x[0-9a-fA-F]+)', text)
    if m:
        out["__FileFlags"] = hex(int(m.group(1), 16))
    return out


def pe_strings(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    out = {}
    for group in (getattr(pe, "FileInfo", None) or []):
        for entry in group:
            if entry.name == "StringFileInfo":
                for table in entry.StringTable:
                    for k, v in table.entries.items():
                        out[k.decode()] = v.decode()
    if hasattr(pe, "VS_FIXEDFILEINFO") and pe.VS_FIXEDFILEINFO:
        ffi = pe.VS_FIXEDFILEINFO[0]
        quad = lambda ms, ls: "%d.%d.%d.%d" % (ms >> 16, ms & 0xffff,
                                               ls >> 16, ls & 0xffff)
        out["__FileVersion"] = quad(ffi.FileVersionMS, ffi.FileVersionLS)
        out["__ProductVersion"] = quad(ffi.ProductVersionMS, ffi.ProductVersionLS)
        out["__FileFlags"] = hex(ffi.FileFlags)
    pe.close()
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    ref = sys.argv[1]
    real = rc_strings(ref) if ref.endswith(".rc") else pe_strings(ref)
    prox = pe_strings(sys.argv[2])

    bad = 0
    for key in sorted(real):
        want, got = real[key], prox.get(key)
        ok = want == got
        bad += not ok
        print(f"  {key:<20} {'OK' if ok else 'MISMATCH'}")
        if not ok:
            print(f"      real = {want!r}")
            print(f"      prox = {got!r}")
    print(f"\n{bad} mismatches")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
