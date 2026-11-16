# ngentask / mscorsvc — CWD phantom DLL hijacking

Type: DLL search-order hijacking (ATT&CK T1574.001, hijack type: phantom) — the
dependency is missing from every DLL search path and resolves from the CWD.

A Windows initial-access loader. A signed Microsoft host stays in its system
path and is never moved; the hijacked dependency is supplied from the working
directory. Nothing executable is dropped in the package.

```
test.pdf.lnk
  └─> ngentask.exe            WinSxS, Microsoft-signed, x64
        └─> mscorsvc.dll      resolved from the CWD
              └─> payload     runs from the DLL's own .text
```

The host is a pure managed assembly with **no import table**. Its dependency on
`mscorsvc.dll` is a .NET assembly reference that the CLR resolves with
`LoadLibrary`, so the loader falls through to the current directory which is
the folder the shortcut was opened from.

## Why it works

Only WinSxS copies of `ngentask.exe` are usable. The one under
`Microsoft.NET\Framework64\v4.0.30319\` is **dead** as `mscorsvc.dll` sits beside
it and the application directory is prioritized in the search.

## Properties

| | |
|---|---|
| Executable dropped | none |
| Proxy exports | 7, ordinals 1–7, real trampolines (no forwarder entries) |
| Trigger | an exported function, not `DllMain` |
| Payload location | the proxy's own `.text`, entered by a plain `call` |
| Allocation / RWX / threads | none |
| Imports | `ADVAPI32`, `KERNEL32`, `SHELL32` |

## Build

```
make            # builds bin/mscorsvc.dll and bin/payload.bin, runs the gates
```

Requires `x86_64-w64-mingw32-gcc`, `nasm`, `objcopy`, `objdump`. 

## Test

```
make test         # resolver: modules, exports, 40/40 forwarders, negative cases
make check-bind   # all 7 trampolines resolve to the real module
```

## Delivery

`delivery/make_delivery.ps1` builds a VHDX carrying one visible item — the
shortcut. The DLL and the decoy document are `Hidden+System`, file times are
backdated, and each file carries `ZoneId=0`. The decoy opens on execution.

```
powershell -ExecutionPolicy Bypass -File delivery\make_delivery.ps1 `
    -VhdPath C:\Users\<you>\Desktop\ngentask.vhd
```

The image is created from the exact `$VhdPath` given and detached in a
`finally`, so a failed run cannot leave it mounted.
