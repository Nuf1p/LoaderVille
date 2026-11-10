# AppDomain Injection with Obfuscated Implant

## Overview

This project implements a AppDomain Injection leveraging built-in Windows system components.<br>
The resulting artifact is designed to spawn a new process in suspended state and queue an APC on the main thread.

---

## Build Process

### Requirements

- Python 3.x
- Mono CLR compiler: apt install mono-complete

---

### Step 1: Prepare the encrypted shellcode

RC4-encrypt the shellcode and emit it as a standalone C# source file.<br>
The implant bytes never exist in plaintext inside the assembly; a fresh random key is used on every run, so two builds of the same shellcode produce different output.

```bash
python3 scripts/Rc4Shellcode.py -f shellcode.bin -o shellcode.cs
```

#### Parameters

- `-f`  
  The raw shellcode file that will be injected

- `-o`  
  Output C# source containing the encrypted shellcode (`Shellcode.Decrypt()` inverts it at runtime)

---

### Step 2: Compile the loader

Use the mono toolchain to build the final dll.

#### Example

```bash
mcs /t:library /platform:x64 /out:"bin/AppVerifier.dll" Loader.cs shellcode.cs
```

#### Parameters

- `/t`  
  output type. dll in this case.

- `/out`  
  Output file

- `<>`  
  The C# source code to compile

---

## Deployment

### Step 3: Stage the Files

Ensure the following files are present in the bin/ directory:

- `KeePass.exe`  
  Legitimate executable.
- `KeePass.exe.config`  
  If this file is present in the same directory of KeePass.exe, the executable will follow the instruction inside this configuration file.
- `AppVerifier.dll`  
  Malicious loader with the encrypted shellcode embedded

---

### Step 4: Trigger Sideloading

Execute the target binary:

```bash
KeePass.exe
```

Due to the presence of the config file, the legitimate executable will automatically load the malicious library.
