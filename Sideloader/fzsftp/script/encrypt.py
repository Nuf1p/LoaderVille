#!/usr/bin/env python3
"""Encrypt a module/string for DecryptString in /src/utils.c
Algorithm (chained XOR with byte-feedback key schedule), mirrors the C side:
    key = 0xA7
    for i, p in enumerate(plain):
        c      = p ^ key
        key    = (key + c + i) & 0xFF
        out[i] = c

Output is a C array literal, e.g.:
    UCHAR sWinInetLib[ ] = { 0x.., 0x.., ..., 0x00 };
"""

import argparse
import sys

INITIAL_KEY = 0xA7


def encrypt(plain: bytes) -> bytes:
    key = INITIAL_KEY
    out = bytearray(len(plain))
    for i, p in enumerate(plain):
        c = p ^ key
        out[i] = c
        key = (key + c + i) & 0xFF
    return bytes(out)


def c_array(name: str, data: bytes) -> str:
    body = ", ".join(f"0x{b:02x}" for b in data) + ", 0x00"
    return f"UCHAR   {name}[ ] = {{ {body} }};"


def default_symbol(module: str) -> str:
    stem = module.split(".")[0]
    return "s" + stem[:1].upper() + stem[1:].lower() + "Lib"


def main() -> int:
    p = argparse.ArgumentParser(description="Encrypt a string for DecryptString().")
    p.add_argument("string", help="Plaintext to encrypt (e.g. 'Wininet.dll').")
    p.add_argument("-n", "--name", default=None,
                   help="C symbol name (default derived from input, e.g. sWininetLib).")
    args = p.parse_args()

    plain = args.string.encode("utf-8")
    enc = encrypt(plain)
    name = args.name or default_symbol(args.string)
    print(c_array(name, enc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
