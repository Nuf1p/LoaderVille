#include "implant.h"

typedef int (*fn_message_box_a)(void *hwnd, const char *text,
                                const char *caption, unsigned int type);

void bx_payload(bx_context *ctx)
{
    fn_message_box_a message_box_a;
    void *fn = 0;
    unsigned int name[4];
    char caption[8];
    char text[12];

    if (!ctx)
        return;
    if (bx_resolve_all(ctx) != BX_OK)
        return;

    /* "user32.dll" as immediates; a literal would land in .rdata and be dropped. */
    name[0] = 0x72657375u;   /* 'u' 's' 'e' 'r' */
    name[1] = 0x642E3233u;   /* '3' '2' '.' 'd' */
    name[2] = 0x00006C6Cu;   /* 'l' 'l' 0   0   */

    /* Prefer the module already mapped: loading it is the fallback. */
    if (bx_module_by_hash(ctx, BX_HASH_USER32, &ctx->user32) != BX_OK)
        ctx->user32 = ctx->load_library_a((const char *)name);

    if (!ctx->user32)
        return;
    if (bx_export_by_hash(ctx, ctx->user32, BX_HASH_MESSAGEBOXA, &fn) != BX_OK)
        return;

    message_box_a = (fn_message_box_a)fn;

    /* "test" / "bellatrix" as immediates; both terminated explicitly. */
    caption[0] = 't'; caption[1] = 'e'; caption[2] = 's'; caption[3] = 't';
    caption[4] = 0;

    text[0] = 'b'; text[1] = 'e'; text[2] = 'l'; text[3] = 'l';
    text[4] = 'a'; text[5] = 't'; text[6] = 'r'; text[7] = 'i';
    text[8] = 'x'; text[9] = 0;

    message_box_a(0, text, caption, 0u);
}
