# DLL Sideloading Loader with Encrypted Implant

## Overview

This project implements a reflective DLL loader that embeds an encrypted implant shellcode inside a legitimate-looking PE file.  
The resulting artifact is designed to be used in a DLL sideloading scenario to achieve stealthy execution of the implant.

At runtime, the loader decrypts the embedded payload, maps it into memory, and transfers execution to the implant’s entry point without writing additional payloads to disk.

---

## Build Process

### Requirements

- GNU Make
- Python 3.x
- mingw-w64 toolchain (for Windows cross-compilation, if applicable)

---

### Step 1: Compile the Loader

Compile the loader using `make`.  
This produces a DLL named `loader.dll`.

```bash
make
```

---

### Step 2: Encrypt and Embed the Implant

Use the `encrypt_and_embed.py` script to encrypt the implant shellcode and embed it into a newly created section of the loader PE.

#### Example

```bash
python3 encrypt_and_embed.py \
    --pe loader.dll \
    --sc shellcode.bin \
    --output libnettle-8.dll
```

#### Parameters

- `--pe`  
  Input PE file containing the loader (`loader.dll`)

- `--sc`  
  Implant Shellcode to be encrypted and embedded

- `--output`  
  Output PE file containing the encrypted implant  
  **The filename must match the DLL name expected by the sideloading target**

---

## Deployment

### Step 3: Stage the Files

Copy the generated DLL into the execution directory (for example, `bin/`):

```bash
cp libnettle-8.dll bin/
```

Ensure the following files are present in the same directory:

- `fzsftp.exe`  
  Legitimate executable used as the sideloading target

- `libneltte-8.dll`  
  Legitimate dependency expected by `fzsftp.exe`

- `libnettle-8.dll`  
  Malicious loader with the encrypted implant embedded

---

### Step 4: Trigger Sideloading

Execute the target binary:

```bash
fzsftp.exe
```

Due to Windows DLL search order resolution, `libnettle-8.dll` is loaded automatically, triggering the loader and executing the embedded implant.

---

## Loader Execution Flow

Before executing the implant, the loader performs the following actions:

1. **Direct Implant Execution**  
   `DllMain` resolves `RtlCreateUserThread` and spawns `LoadSc` on its own thread at process attach, so the payload runs outside the loader lock: it decrypts the embedded shellcode into memory and invokes the implant’s entry point.

---

## Notes

- The output DLL name must exactly match the name expected by the sideloading target binary.
- The implant is decrypted and executed entirely in memory.
- No additional payloads are written to disk after initial load.
- Intended for controlled red team operations with appropriate OPSEC and authorization.
