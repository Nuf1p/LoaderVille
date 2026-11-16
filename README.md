# LoaderVille

A collection of initial access loaders to use inside enterprise hardened enviroments

## Techniques

| Technique | Directory | Trigger | In short |
|---|---|---|---|
| AppDomain hijack | [`AppDomain_hijack/`](AppDomain_hijack/) | `KeePass.exe` + `.config` | `appDomainManagerAssembly` loads `AppVerifier.dll`; RC4 implant spawns a suspended process and queues an APC |
| CLR profiler injection | [`NETProfiler_hijack/`](NETProfiler_hijack/) | .NET Framework v4 app + `COR_*` env vars | Profiler DLL decodes dictionary-encoded shellcode and overwrites the entry point of a spawned `taskhostw.exe` |
| DLL sideloading | [`Sideloader/fzsftp/`](Sideloader/fzsftp/) | `fzsftp.exe` | Reflective loader decrypts an embedded implant and runs it in memory |
| CWD phantom DLL hijack | [`DLL-Search-Order-Hijacking/bellatrix/`](DLL-Search-Order-Hijacking/bellatrix/) | `ngentask.exe` (WinSxS) via shortcut | Proxy `mscorsvc.dll` is resolved from the working directory; payload lives in its `.text` |
| `.local` DLL redirection | [`DLL-Redirection/DotSL/`](DLL-Redirection/DotSL/) | `compattelrunner.exe` + `.exe.local` | Proxy `appraiser.dll` matches exports and runs the payload in place; delivered as a VHD |
| Electron `app.asar` backdoor | [`electron_backdoor/`](electron_backdoor/) | Electron app launch | `package.json` `main` is repointed to a stage that uses koffi FFI and thread-start spoofing; fully reversible |

## Layout

```text
LoaderVille/
├── AppDomain_hijack/       # C# AppDomainManager loader (Mono/mcs)
├── NETProfiler_hijack/     # CLR profiler DLL (MSVC)
├── Sideloader/
│   └── fzsftp/             # DLL sideloading loader (MinGW-w64)
├── DLL-Redirection/
│   └── DotSL/              # DotLocal shadow loading (MinGW-w64 + NASM)
├── DLL-Search-Order-Hijacking/
│   └── bellatrix/          # CWD phantom DLL hijack (MinGW-w64 + NASM)
└── electron_backdoor/      # app.asar patch + FFI stage (Node.js)
```

## Building

There is no root build; each project documents its own steps in its `README.md`.
Toolchains vary by project:

- **MSVC** (Visual Studio) — `NETProfiler_hijack`
- **MinGW-w64 + NASM + make** — `Sideloader/*`, `DLL-Redirection/DotSL`
- **Mono (`mcs`) + Python 3** — `AppDomain_hijack`
- **Node.js ≥ 18 + WSL2** — `electron_backdoor`


