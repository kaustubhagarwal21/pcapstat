/*
 * hash.h - 64-bit FNV-1a, shared by the flow table and the fragment cache.
 *
 * FNV-1a is simple, fast for short keys, and spreads well enough for tables
 * indexed by the hash's low bits. It is not keyed, so it is not collision-
 * resistant against crafted input; see the README's limitations.
 */
#ifndef PCAPSTAT_HASH_H
#define PCAPSTAT_HASH_H

#include <stddef.h>
#include <stdint.h>

#define FNV64_OFFSET 0xcbf29ce484222325ull
#define FNV64_PRIME  0x100000001b3ull

/* Fold n bytes into the running hash h (start with FNV64_OFFSET). */
static inline uint64_t fnv1a(uint64_t h, const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= FNV64_PRIME;
    }
    return h;
}

#endif /* PCAPSTAT_HASH_H */
