/* C entry: proves the ABI and the section layout. */
#include "implant.h"

_Static_assert(sizeof(bx_context) == 64,
               "bx_context size must match BX_CTX_BYTES in asm/entry_x64.asm");
_Static_assert(sizeof(bx_context) % 16 == 0, "context must not break alignment");

void bx_main(bx_context *ctx)
{
    if (!ctx || !ctx->peb)
        return;
    bx_payload(ctx);
}
