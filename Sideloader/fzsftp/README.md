# DLL Sideloading Loader with Encrypted Implant

## Overview

This project implements a DLL loader that embeds an encrypted implant shellcode
inside a legitimate-looking PE file. The resulting artifact is used in a DLL
sideloading scenario (`fzsftp.exe`) to execute the implant.

At runtime the loader decrypts the embedded payload, maps it into memory, and
transfers execution to the implant's entry point without writing additional
payloads to disk.

---

## How it works

- `fzsftp.exe` imports `libnettle-8.dll` (the nettle crypto library).
- We replace `libnettle-8.dll` with our loader. To keep FileZilla working, the
  loader **forwards** the 12 `nettle_gcm_*` exports to the real nettle, renamed
  `libneltte-8.dll`, sitting next to it (forwarders are emitted via `.drectve`
  linker directives in `SideeLoader.c`).
- On `DLL_PROCESS_ATTACH`, `DllMain` spawns `LoadSc` via `RtlCreateUserThread`
  (outside the loader lock). `LoadSc` locates its own mapped image, copies the
  `.nazgul` section, XOR-decrypts it with a repeating 8-byte key, and runs it.

```text
fzsftp.exe ──imports──> libnettle-8.dll (loader + .nazgul)
                         └─forwards nettle_gcm_* ──> libneltte-8.dll (real nettle)
                         └─DllMain → RtlCreateUserThread → LoadSc
                              └─read .nazgul → XOR-decrypt → execute agent
```

---

## Requirements

- GNU Make
- Python 3
- MinGW-w64 (`x86_64-w64-mingw32-gcc`, `x86_64-w64-mingw32-windres`)

---

## Build pipeline

### Step 1 — Build the loader

```bash
make
```

Runs `windres` on `resource.rc` (FileZilla version info) and compiles/links
`SideeLoader.c` into `loader.dll`. The DLL exports the 12 `nettle_gcm_*` symbols
as forwarders to `libneltte-8.*`.

Output: `loader.dll`

### Step 2 — Encrypt and embed the implant

```bash
python3 script/encrypt_and_embed.py.py \
    --pe loader.dll \
    --sc agent.x64.bin \
    --output libnettle-8.dll
```

Arguments:

- `--pe` — input PE (`loader.dll`)
- `--sc` — raw x64 shellcode blob (`shellcode.bin`)
- `--output` — output PE; **must be `libnettle-8.dll`** to match both the name
  `fzsftp.exe` imports and the name `LoadSc` looks up at runtime.

Output: `libnettle-8.dll`

---

## Deployment

### Step 3 — Stage the files

```bash
cp libnettle-8.dll bin/
```

Final `bin/` layout — all three in one directory:

| File | Role |
|---|---|
| `fzsftp.exe` | Legitimate sideloading target; imports `libnettle-8.dll` |
| `libnettle-8.dll` | Our loader + embedded agent (built in Step 2) |
| `libneltte-8.dll` | Real nettle crypto library (renamed); backs the forwarded `nettle_gcm_*` exports |

### Step 4 — Trigger sideloading

```bash
fzsftp.exe
```

Windows DLL search order loads `libnettle-8.dll` from the working directory,
which decrypts and executes the embedded implant.
