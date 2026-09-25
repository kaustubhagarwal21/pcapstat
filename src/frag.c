/*
 * frag.c - direct-mapped cache that attributes later fragments to flows.
 */
#include "frag.h"

#include <stdlib.h>
#include <string.h>

#include "hash.h"

int frag_cache_init(struct frag_cache *c)
{
    c->slots = calloc(FRAG_CACHE_SLOTS, sizeof *c->slots);
    return c->slots == NULL ? -1 : 0;
}

void frag_cache_free(struct frag_cache *c)
{
    free(c->slots);
    c->slots = NULL;
}

/* Hash the key fields one by one (never the struct's bytes, whose padding
 * is unspecified). Addresses are always hashed as 16 bytes; IPv4 leaves the
 * last 12 zero. */
static size_t slot_for(const struct packet_info *pi)
{
    uint8_t head[6];
    uint64_t h;

    head[0] = pi->ip_version;
    head[1] = pi->ip_proto;
    head[2] = (uint8_t)(pi->frag_id >> 24);
    head[3] = (uint8_t)(pi->frag_id >> 16);
    head[4] = (uint8_t)(pi->frag_id >> 8);
    head[5] = (uint8_t)pi->frag_id;
    h = fnv1a(FNV64_OFFSET, head, sizeof head);
    h = fnv1a(h, pi->src_addr, sizeof pi->src_addr);
    h = fnv1a(h, pi->dst_addr, sizeof pi->dst_addr);
    return (size_t)h & (FRAG_CACHE_SLOTS - 1);
}

static int same_datagram(const struct frag_entry *e,
                         const struct packet_info *pi)
{
    return e->in_use && e->ip_version == pi->ip_version &&
           e->proto == pi->ip_proto && e->id == pi->frag_id &&
           memcmp(e->src, pi->src_addr, sizeof e->src) == 0 &&
           memcmp(e->dst, pi->dst_addr, sizeof e->dst) == 0;
}

int frag_cache_apply(struct frag_cache *c, struct packet_info *pi)
{
    struct frag_entry *e;

    if (c->slots == NULL || pi->status != DEC_OK || !pi->has_l3)
        return 0;

    if (pi->frag == FRAG_FIRST && pi->has_l4) {
        e = &c->slots[slot_for(pi)];
        e->in_use = 1;
        e->ip_version = pi->ip_version;
        e->proto = pi->ip_proto;
        e->id = pi->frag_id;
        memcpy(e->src, pi->src_addr, sizeof e->src);
        memcpy(e->dst, pi->dst_addr, sizeof e->dst);
        e->src_port = pi->src_port;
        e->dst_port = pi->dst_port;
        return 0;
    }
    if (pi->frag == FRAG_LATER) {
        e = &c->slots[slot_for(pi)];
        if (!same_datagram(e, pi))
            return 0;
        pi->src_port = e->src_port;
        pi->dst_port = e->dst_port;
        return 1;
    }
    return 0;
}
