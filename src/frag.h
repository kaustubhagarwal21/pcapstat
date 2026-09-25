/*
 * frag.h - give non-first IP fragments the ports of their datagram.
 *
 * Only the first fragment of a fragmented datagram carries the TCP/UDP
 * header, so a later fragment has no ports of its own and would otherwise
 * form a separate port-less flow, splitting one stream's bytes in two. But
 * every fragment of a datagram shares (IP version, source, destination,
 * protocol, identification). When a first fragment is seen, its ports are
 * remembered under that key; a later fragment with the same key borrows
 * them and so joins the right flow.
 *
 * The cache is direct-mapped: a fixed array in which each key has exactly
 * one slot, and a new entry simply overwrites whatever was there. Memory is
 * fixed however many fragments a capture holds, and there is nothing to
 * evict. A collision, or a later fragment that arrives before its first
 * fragment, just leaves that fragment port-less, as it would be without the
 * cache. This is attribution only; payloads are not reassembled.
 */
#ifndef PCAPSTAT_FRAG_H
#define PCAPSTAT_FRAG_H

#include <stddef.h>
#include <stdint.h>

#include "decode.h"

/* A power of two, so a slot is picked with `hash & (slots - 1)`. */
#define FRAG_CACHE_SLOTS 4096u

struct frag_entry {
    uint8_t in_use;
    uint8_t ip_version;
    uint8_t proto;
    uint32_t id;             /* IPv4 identification / IPv6 fragment ID */
    uint8_t src[16];
    uint8_t dst[16];
    uint16_t src_port;
    uint16_t dst_port;
};

struct frag_cache {
    struct frag_entry *slots; /* FRAG_CACHE_SLOTS entries */
};

/* Returns 0 on success, -1 if out of memory. */
int frag_cache_init(struct frag_cache *c);
void frag_cache_free(struct frag_cache *c);

/*
 * Feed one cleanly decoded packet (status DEC_OK). A first fragment with an
 * L4 header records its ports. A non-first fragment whose first fragment is
 * in the cache gets that fragment's ports copied into pi->src_port and
 * pi->dst_port (has_l4 stays 0: its own bytes were not decoded as L4).
 * Returns 1 if the ports were filled in, otherwise 0.
 */
int frag_cache_apply(struct frag_cache *c, struct packet_info *pi);

#endif /* PCAPSTAT_FRAG_H */
