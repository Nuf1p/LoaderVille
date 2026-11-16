/* stage-1 payload contract */
#ifndef BELLATRIX_IMPLANT_H
#define BELLATRIX_IMPLANT_H

#include "resolve.h"

/* Runs on the caller's thread. Allocates nothing. Returns normally. */
void bx_payload(bx_context *ctx);

#endif /* BELLATRIX_IMPLANT_H */
