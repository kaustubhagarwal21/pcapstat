/*
 * bytes.h - byte-order-explicit loads from untrusted buffers.
 *
 * Packet and file data is never accessed by casting the buffer to a struct or
 * to a wider integer pointer:
 *   - the data has no alignment guarantee (an Ethernet header is 14 bytes, so
 *     the IP header that follows it starts at an odd-looking offset), and an
 *     unaligned uint32_t load is undefined behaviour in C;
 *   - reading a uint8_t buffer through a uint32_t pointer breaks the strict
 *     aliasing rule;
 *   - struct layout (padding) is up to the compiler, not the wire format.
 * Assembling each value from single bytes avoids all three problems and makes
 * the byte order explicit, so the code gives the same answer on little- and
 * big-endian hosts. Compilers turn these into a single load (plus bswap).
 */
#ifndef PCAPSTAT_BYTES_H
#define PCAPSTAT_BYTES_H

#include <stdint.h>

static inline uint16_t load_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint16_t load_le16(const uint8_t *p)
{
    return (uint16_t)((p[1] << 8) | p[0]);
}

/* Each byte is widened to uint32_t before shifting: p[0] << 24 on a plain int
 * would overflow a signed int when p[0] >= 0x80, which is undefined. */
static inline uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint32_t load_le32(const uint8_t *p)
{
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

#endif /* PCAPSTAT_BYTES_H */
