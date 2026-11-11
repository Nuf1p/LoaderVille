/* bounded local runtime: no CRT, no allocation, no globals */
#ifndef BELLATRIX_RUNTIME_H
#define BELLATRIX_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

int bx_memcmp(const void *a, const void *b, size_t n);

/* Regions must not overlap. */
void *bx_memcpy(void *dst, const void *src, size_t n);

/* Case-insensitive exact match. A length mismatch is a mismatch. */
int bx_wide_eq_ci(const uint16_t *a, size_t alen,
                  const uint8_t *b, size_t blen);

/* volatile stores; without it the compiler drops the wipe as dead code. */
void bx_wipe(void *p, size_t n);

#endif /* BELLATRIX_RUNTIME_H */
