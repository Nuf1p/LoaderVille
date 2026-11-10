#!/usr/bin/env python3
"""Compute HashCustom of a string — matches the C implementation in hash_algorithm.c."""

import argparse
import sys

SEED =  0xC0DEBABE
MASK = 0xFFFFFFFF


def rotl32(x: int, n: int) -> int:
    x &= MASK
    return ((x << n) | (x >> (32 - n))) & MASK


def hash_custom(data: bytes, length: int = 0, upper: bool = False) -> int:
    if data is None:
        return 0

    h = SEED
    i = 0
    end = length if length else len(data)
    while i < end:
        c = data[i] if i < len(data) else 0

        if length == 0 and c == 0:
            break
        if length != 0 and c == 0:
            i += 1
            if i >= end:
                break
            c = data[i] if i < len(data) else 0

        if upper and 0x61 <= c <= 0x7A:
            c -= 0x20

        h = (((h << 5) + h) & MASK) ^ c
        h = rotl32(h, 13)
        i += 1

    return h


def main() -> int:
    p = argparse.ArgumentParser(description="HashCustom of a string.")
    p.add_argument("string", help="Input string (UTF-8 encoded before hashing).")
    p.add_argument("-l", "--length", type=int, default=0,
                   help="Byte length; 0 (default) means hash until NUL.")
    p.add_argument("-u", "--upper", action="store_true",
                   help="Fold ASCII lowercase to uppercase before mixing.")
    args = p.parse_args()

    data = args.string.encode("utf-8")
    h = hash_custom(data, length=args.length, upper=args.upper)
    print(f"0x{h:08X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
