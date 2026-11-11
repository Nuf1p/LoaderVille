/* module and export resolution through the PEB loader list */
#include "resolve.h"
#include "runtime.h"

/* hash */
/* Count comes from the UNICODE_STRING length, not from a NUL. */
static uint32_t hash_wide_lower(const uint16_t *s, uint32_t count)
{
    uint32_t h = BX_HASH_SEED, n;
    for (n = 0; n < count; n++) {
        h = (h ^ (uint32_t)((s[n] & 0xFFu) | 0x20u)) * BX_HASH_PRIME;
    }
    return h ^ BX_HASH_POST;
}

static uint32_t hash_ascii(const uint8_t *s, uint32_t max_bytes)
{
    uint32_t h = BX_HASH_SEED, n = 0;
    while (n < max_bytes && *s) {
        h = (h ^ (uint32_t)*s) * BX_HASH_PRIME;
        s++;
        n++;
    }
    return h ^ BX_HASH_POST;
}

/* bounds */
/* True when [rva, rva+need) lies inside an image of image_size bytes. */
static int rva_ok(uint32_t rva, uint32_t need, uint32_t image_size)
{
    return rva != 0 && rva <= image_size && need <= image_size - rva;
}

/* The size the loader mapped; the only trustworthy bound on image reads. */
static uint32_t module_mapped_size(bx_context *ctx, const void *base)
{
    bx_list_entry *head, *cur;
    uint32_t n = 0;

    if (!ctx || !ctx->peb || !ctx->peb->ldr)
        return 0;
    head = &ctx->peb->ldr->in_load_order;
    for (cur = head->flink; cur && cur != head && n < BX_MAX_MODULES;
         cur = cur->flink, n++) {
        bx_ldr_entry *e = (bx_ldr_entry *)cur;
        if (e->dll_base == base)
            return e->size_of_image;
    }
    return 0;
}

/* Export directory of a mapped image. mapped_size bounds every header read. */
#define BX_MAX_HEADERS 0x1000

static enum bx_status image_exports(const uint8_t *base, uint32_t mapped_size,
                                    uint32_t *exp_rva,
                                    uint32_t *exp_size, uint32_t *image_size)
{
    const bx_dos_header *dos = (const bx_dos_header *)base;
    const bx_nt64 *nt;
    uint32_t lfanew, hdr_limit;

    if (dos->magic[0] != 'M' || dos->magic[1] != 'Z')
        return BX_E_BAD_IMAGE;

    hdr_limit = mapped_size ? mapped_size : BX_MAX_HEADERS;
    lfanew = (uint32_t)dos->e_lfanew;
    if (dos->e_lfanew <= 0 || !rva_ok(lfanew, sizeof(bx_nt64), hdr_limit))
        return BX_E_BAD_IMAGE;

    nt = (const bx_nt64 *)(base + lfanew);
    if (nt->signature != BX_PE_SIGNATURE)
        return BX_E_BAD_IMAGE;
    if (nt->machine != BX_MACHINE_AMD64)
        return BX_E_BAD_IMAGE;
    if (nt->optional.magic != BX_OPT_MAGIC_PE32P)
        return BX_E_BAD_IMAGE;
    if (nt->optional.number_of_rva <= BX_DIR_EXPORT)
        return BX_E_NO_EXPORT;

    *image_size = nt->optional.size_of_image;
    if (*image_size == 0)
        return BX_E_BAD_IMAGE;
    /* Must not claim more than was mapped, and must contain the headers above. */
    if (mapped_size && *image_size > mapped_size)
        return BX_E_BAD_IMAGE;
    if (*image_size < lfanew + sizeof(bx_nt64))
        return BX_E_BAD_IMAGE;

    *exp_rva  = nt->optional.dir[BX_DIR_EXPORT].rva;
    *exp_size = nt->optional.dir[BX_DIR_EXPORT].size;

    if (!rva_ok(*exp_rva, sizeof(bx_export_dir), *image_size))
        return BX_E_BAD_IMAGE;

    return BX_OK;
}

/* module lookup */
/* Walk the loader list once; used by both the hash and the name lookup. */
static void *find_module(bx_context *ctx, uint32_t want_hash,
                         const uint8_t *want_name, uint32_t name_len)
{
    bx_list_entry *head;
    bx_list_entry *cur;
    uint32_t n = 0;

    if (!ctx || !ctx->peb || !ctx->peb->ldr)
        return 0;

    head = &ctx->peb->ldr->in_load_order;
    for (cur = head->flink; cur && cur != head && n < BX_MAX_MODULES;
         cur = cur->flink, n++) {
        bx_ldr_entry *e = (bx_ldr_entry *)cur;   /* in_load_order is first */
        uint32_t chars;
        if (!e->dll_base || !e->base_name.buffer || !e->base_name.length)
            continue;
        chars = e->base_name.length / 2;
        if (want_name) {
            if (bx_wide_eq_ci(e->base_name.buffer, chars, want_name, name_len))
                return e->dll_base;
        } else if (hash_wide_lower(e->base_name.buffer, chars) == want_hash) {
            return e->dll_base;
        }
    }
    return 0;
}

/* ASCII base name as the api-set schema spells it. */
static uint32_t module_name_ascii(bx_context *ctx, const void *base,
                                  uint8_t *out, uint32_t max)
{
    bx_list_entry *head, *cur;
    uint32_t n = 0;

    if (!ctx || !ctx->peb || !ctx->peb->ldr)
        return 0;
    head = &ctx->peb->ldr->in_load_order;
    for (cur = head->flink; cur && cur != head && n < BX_MAX_MODULES;
         cur = cur->flink, n++) {
        bx_ldr_entry *e = (bx_ldr_entry *)cur;
        uint32_t chars, k;

        if (e->dll_base != base || !e->base_name.buffer || !e->base_name.length)
            continue;
        chars = e->base_name.length / 2;
        if (!chars || chars >= max)
            return 0;
        for (k = 0; k < chars; k++)
            out[k] = (uint8_t)(e->base_name.buffer[k] & 0xFF);
        return chars;
    }
    return 0;
}

/* Case-insensitive prefix test; forwarder strings are free text. */
static int ci_prefix(const uint8_t *s, const char *p, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++) {
        uint8_t c = s[i];
        if (c >= 'A' && c <= 'Z')
            c = (uint8_t)(c - 'A' + 'a');
        if (c != (uint8_t)p[i])
            return 0;
    }
    return 1;
}

static int is_apiset_name(const uint8_t *s, uint32_t len)
{
    return (len >= 7 && ci_prefix(s, "api-ms-", 7))
        || (len >= 7 && ci_prefix(s, "ext-ms-", 7));
}


static int apiset_span(uint32_t off, uint32_t len, uint32_t size)
{
    return off <= size && len <= size - off;
}


static int apiset_span_n(uint32_t off, uint32_t count, uint32_t rec,
                         uint32_t size)
{
    if (!rec || count > size / rec)
        return 0;
    return apiset_span(off, count * rec, size);
}


static void *api_set_module(bx_context *ctx, const uint8_t *name,
                            uint32_t name_len,
                            const uint8_t *req, uint32_t req_len)
{
    const bx_apiset_ns *ns;
    const bx_apiset_entry *ent;
    uintptr_t base;
    uint32_t i, j, k, qhash, pass;

    if (!ctx || !ctx->peb || !ctx->peb->api_set_map)
        return 0;

    ns = (const bx_apiset_ns *)ctx->peb->api_set_map;
    if (ns->version != BX_APISET_VERSION)
        return 0;
    if (!ns->size || ns->size < sizeof(bx_apiset_ns))
        return 0;
    if (!ns->count || ns->count > BX_MAX_APISET)
        return 0;

    base = (uintptr_t)ns;
    if (!apiset_span_n(ns->entry_offset, ns->count,
                       sizeof(bx_apiset_entry), ns->size))
        return 0;
    ent = (const bx_apiset_entry *)(base + ns->entry_offset);

    /* Hash the query as the schema does: drop the trailing version segment. */
    qhash = 0;
    for (k = 0; k < name_len; k++)
        if (name[k] == '-')
            qhash = k;
    if (!qhash)
        return 0;

    for (i = 0; i < ns->count; i++) {
        const uint16_t *nm;
        const bx_apiset_value *val;

        /* The name and its hashed prefix must both be inside the namespace. */
        if (ent[i].hashed_length > ent[i].name_length)
            continue;
        if (!apiset_span(ent[i].name_offset, ent[i].name_length, ns->size))
            continue;
        nm = (const uint16_t *)(base + ent[i].name_offset);

        if (ent[i].hashed_length / 2 != qhash)
            continue;
        if (!bx_wide_eq_ci(nm, qhash, name, qhash))
            continue;
        if (!ent[i].value_count)
            return 0;

        if (!apiset_span_n(ent[i].value_offset, ent[i].value_count,
                           sizeof(bx_apiset_value), ns->size))
            return 0;
        val = (const bx_apiset_value *)(base + ent[i].value_offset);
        /* Alias names the requesting module, breaking circularity. */
        for (pass = 0; pass < 2; pass++) {
            for (j = 0; j < ent[i].value_count && j < BX_MAX_MODULES; j++) {
                const uint16_t *alias;
                uint32_t alen;
                const uint16_t *host;
                uint32_t hlen;
                uint8_t hostb[64];
                void *m;

                if (!apiset_span(val[j].name_offset, val[j].name_length,
                                 ns->size))
                    continue;
                if (!apiset_span(val[j].value_offset, val[j].value_length,
                                 ns->size))
                    continue;

                alias = (const uint16_t *)(base + val[j].name_offset);
                alen = val[j].name_length / 2;

                if (pass == 0) {
                    if (!alen || alen != req_len)
                        continue;
                    if (!bx_wide_eq_ci(alias, alen, req, req_len))
                        continue;
                } else {
                    if (alen)
                        continue;
                }

                host = (const uint16_t *)(base + val[j].value_offset);
                hlen = val[j].value_length / 2;
                if (!hlen || hlen >= sizeof hostb)
                    continue;
                for (k = 0; k < hlen; k++)
                    hostb[k] = (uint8_t)(host[k] & 0xFF);

                m = find_module(ctx, 0, hostb, hlen);
                if (m)
                    return m;
            }
        }
        return 0;
    }
    return 0;
}

enum bx_status bx_module_by_hash(bx_context *ctx, uint32_t hash, void **out)
{
    void *m;
    if (!out)
        return BX_E_BUFFER;
    m = find_module(ctx, hash, 0, 0);
    if (!m)
        return BX_E_NO_MODULE;
    *out = m;
    return BX_OK;
}

/* export lookup */
static enum bx_status export_lookup(const uint8_t *base, uint32_t mapped_size,
                                    uint32_t want_hash, int by_ordinal,
                                    uint16_t want_ordinal,
                                    uint32_t *fn_rva, uint32_t *exp_rva,
                                    uint32_t *exp_size, uint32_t *image_size)
{
    uint32_t rva, size, isz;
    const bx_export_dir *exp;
    uint32_t i, count;

    rva = size = 0;
    {
        enum bx_status s = image_exports(base, mapped_size,
                                         &rva, &size, image_size);
        if (s != BX_OK)
            return s;
    }
    exp = (const bx_export_dir *)(base + rva);
    isz = *image_size;

    if (by_ordinal) {
        /* The ordinal is external; subtract the base before indexing the EAT. */
        uint32_t idx;
        if (want_ordinal < exp->ordinal_base)
            return BX_E_NO_EXPORT;
        idx = (uint32_t)want_ordinal - exp->ordinal_base;
        if (idx >= exp->number_of_functions)
            return BX_E_NO_EXPORT;
        if (!rva_ok(exp->address_of_functions, (idx + 1) * 4, isz))
            return BX_E_BAD_IMAGE;
        *fn_rva = ((const uint32_t *)(base + exp->address_of_functions))[idx];
    } else {
        count = exp->number_of_names;
        if (count > BX_MAX_EXPORTS)
            count = BX_MAX_EXPORTS;
        if (!rva_ok(exp->address_of_names, count * 4, isz) ||
            !rva_ok(exp->address_of_name_ordinals, count * 2, isz))
            return BX_E_BAD_IMAGE;

        for (i = 0; i < count; i++) {
            uint32_t name_rva =
                ((const uint32_t *)(base + exp->address_of_names))[i];
            uint16_t ord;
            if (!rva_ok(name_rva, 1, isz))
                continue;
            if (hash_ascii(base + name_rva, isz - name_rva) != want_hash)
                continue;
            ord = ((const uint16_t *)(base + exp->address_of_name_ordinals))[i];
            if (!rva_ok(exp->address_of_functions,
                        ((uint32_t)ord + 1) * 4, isz))
                return BX_E_BAD_IMAGE;
            *fn_rva = ((const uint32_t *)(base + exp->address_of_functions))[ord];
            break;
        }
        if (i == count)
            return BX_E_NO_EXPORT;
    }

    if (!*fn_rva)
        return BX_E_NO_EXPORT;

    *exp_rva  = rva;
    *exp_size = size;
    return BX_OK;
}

/* A forwarder is an RVA inside the export directory pointing at "MODULE.FUNC". */
static enum bx_status resolve_forwarder(bx_context *ctx, const uint8_t *base,
                                        uint32_t fn_rva, uint32_t image_size,
                                        void **out, int depth,
                                        void **seen, int nseen);

static enum bx_status resolve_export(bx_context *ctx, const uint8_t *base,
                                     uint32_t want_hash, int by_ordinal,
                                     uint16_t want_ordinal, void **out,
                                     int depth, void **seen, int nseen)
{
    uint32_t fn_rva = 0, exp_rva = 0, exp_size = 0, image_size = 0;
    enum bx_status s;

    if (depth > BX_MAX_FORWARD_DEPTH)
        return BX_E_FORWARD_DEPTH;

    s = export_lookup(base, module_mapped_size(ctx, base),
                      want_hash, by_ordinal, want_ordinal,
                      &fn_rva, &exp_rva, &exp_size, &image_size);
    if (s != BX_OK)
        return s;

    if (fn_rva >= exp_rva && fn_rva - exp_rva < exp_size)
        return resolve_forwarder(ctx, base, fn_rva,
                                 image_size, out, depth + 1, seen, nseen);

    if (!rva_ok(fn_rva, 1, image_size))
        return BX_E_BAD_IMAGE;

    *out = (void *)(base + fn_rva);
    return BX_OK;
}

static enum bx_status resolve_forwarder(bx_context *ctx, const uint8_t *base,
                                        uint32_t fn_rva, uint32_t image_size,
                                        void **out, int depth,
                                        void **seen, int nseen)
{
    const uint8_t *s = base + fn_rva;
    uint32_t max = image_size - fn_rva;
    uint32_t n = 0, dot = 0;
    uint8_t mod[128];
    uint32_t mod_len;
    int has_ext, suffix;
    void *target;
    int i;

    if (max > 256)
        max = 256;
    while (n < max && s[n])
        n++;
    if (n == 0 || n >= max)
        return BX_E_BAD_IMAGE;

    /* Split at the last '.': the function name never contains one. */
    for (i = (int)n - 1; i >= 0; i--) {
        if (s[i] == '.') { dot = (uint32_t)i; break; }
    }
    if (dot == 0 || dot + 1 >= n)
        return BX_E_BAD_IMAGE;

    mod_len = dot;
    /* Forwarder names omit the extension; append ".dll" unless already present. */
    has_ext = 0;
    for (i = 0; i < (int)mod_len; i++)
        if (s[i] == '.') has_ext = 1;
    suffix = has_ext ? 0 : 4;

    if (mod_len + suffix >= sizeof mod)
        return BX_E_BUFFER;
    for (i = 0; i < (int)mod_len; i++)
        mod[i] = s[i];
    if (suffix) {
        mod[mod_len + 0] = '.';
        mod[mod_len + 1] = 'd';
        mod[mod_len + 2] = 'l';
        mod[mod_len + 3] = 'l';
    }
    mod[mod_len + suffix] = 0;
    mod_len += suffix;

    /* api-set targets are contracts: resolve the schema before looking up. */
    if (is_apiset_name(s, dot)) {
        uint8_t req[64];
        uint32_t req_len = module_name_ascii(ctx, base, req, sizeof req);
        target = api_set_module(ctx, s, dot, req, req_len);
    } else {
        target = find_module(ctx, 0, mod, mod_len);
    }
    if (!target)
        return BX_E_NO_MODULE;

    for (i = 0; i < nseen && i < BX_MAX_SEEN; i++) {
        if (seen[i * 2] == (void *)base &&
            seen[i * 2 + 1] == (void *)(uintptr_t)fn_rva)
            return BX_E_FORWARD_CYCLE;
    }
    if (nseen < BX_MAX_SEEN) {
        seen[nseen * 2] = (void *)base;
        seen[nseen * 2 + 1] = (void *)(uintptr_t)fn_rva;
        nseen++;
    }

    if (s[dot + 1] == '#') {
        uint32_t ord = 0, k = dot + 2;
        if (k >= n)
            return BX_E_BAD_IMAGE;
        for (; k < n; k++) {
            if (s[k] < '0' || s[k] > '9')
                return BX_E_BAD_IMAGE;
            ord = ord * 10 + (uint32_t)(s[k] - '0');
            if (ord > 0xFFFF)
                return BX_E_BAD_IMAGE;
        }
        return resolve_export(ctx, target, 0, 1, (uint16_t)ord, out,
                              depth, seen, nseen);
    }

    return resolve_export(ctx, target,
                          hash_ascii(s + dot + 1, n - dot - 1), 0, 0,
                          out, depth, seen, nseen);
}

enum bx_status bx_export_by_hash(bx_context *ctx, void *module, uint32_t hash,
                                 void **out)
{
    void *seen[BX_MAX_SEEN * 2];
    enum bx_status s;

    if (!ctx || !module || !out)
        return BX_E_BUFFER;
    s = resolve_export(ctx, (const uint8_t *)module, hash, 0, 0,
                       out, 0, seen, 0);
    if (s != BX_OK)
        ctx->last_status = (uint32_t)s;
    return s;
}

enum bx_status bx_export_by_ordinal(bx_context *ctx, void *module,
                                    uint16_t ordinal, void **out)
{
    void *seen[BX_MAX_SEEN * 2];
    enum bx_status s;

    if (!ctx || !module || !out)
        return BX_E_BUFFER;
    s = resolve_export(ctx, (const uint8_t *)module, 0, 1, ordinal,
                       out, 0, seen, 0);
    if (s != BX_OK)
        ctx->last_status = (uint32_t)s;
    return s;
}

enum bx_status bx_resolve_all(bx_context *ctx)
{
    void *fn;
    enum bx_status s;

    if (!ctx)
        return BX_E_BUFFER;

    s = bx_module_by_hash(ctx, BX_HASH_KERNEL32, &ctx->kernel32);
    if (s != BX_OK)
        return s;

    s = bx_export_by_hash(ctx, ctx->kernel32, BX_HASH_LOADLIBRARYA, &fn);
    if (s != BX_OK)
        return s;
    ctx->load_library_a = (bx_fn_load_library_a)fn;

    s = bx_export_by_hash(ctx, ctx->kernel32, BX_HASH_GETPROCADDRESS, &fn);
    if (s != BX_OK)
        return s;
    ctx->get_proc_address = (bx_fn_get_proc_address)fn;

    return BX_OK;
}
