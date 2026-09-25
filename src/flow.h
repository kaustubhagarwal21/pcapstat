/*
 * flow.h - bidirectional flow table.
 *
 * A flow is the set of packets between two endpoints (address, port) over
 * one IP protocol, in either direction. The key stores the two endpoints in
 * a canonical order (the "smaller" one first), so a request A -> B and its
 * reply B -> A land in the same flow.
 *
 * The table is an open-addressing hash table with linear probing: all flows
 * live in one flat array, a lookup hashes the key to a slot and walks
 * forward to the first matching or empty slot. The array doubles when it
 * becomes 70% full, which keeps probe sequences short.
 */
#ifndef PCAPSTAT_FLOW_H
#define PCAPSTAT_FLOW_H

#include <stddef.h>
#include <stdint.h>

#include "decode.h"

struct flow_key {
    uint8_t ip_version;  /* 4 or 6 */
    uint8_t proto;       /* IP protocol number */
    uint16_t port_a;     /* 0 for protocols without ports (ICMP, fragments) */
    uint16_t port_b;
    uint8_t addr_a[16];  /* IPv4 uses the first 4 bytes, the rest are 0 */
    uint8_t addr_b[16];
};

struct flow {
    struct flow_key key;
    uint64_t hash;           /* cached so growing never re-hashes keys */
    uint64_t packets;
    uint64_t bytes;          /* sum of original (on-the-wire) lengths */
    uint64_t first_ts_ns;
    uint64_t last_ts_ns;
    uint8_t tcp_flags;       /* union of all TCP flags seen, both directions */
    uint8_t first_from_b;    /* 1 if the first packet seen went B -> A */
    uint8_t in_use;          /* slot occupied */
};

struct flow_table {
    struct flow *slots;
    size_t capacity;         /* always a power of two */
    size_t count;            /* occupied slots */
};

/* Build the canonical key for a decoded packet. Returns 0 if the packet has
 * no valid IP layer (it cannot belong to a flow). *reversed is set to 1 when
 * the packet travelled from endpoint B to endpoint A. */
int flow_key_from_packet(const struct packet_info *pi, struct flow_key *key,
                         int *reversed);

/* capacity_hint is rounded up to a power of two (minimum 16).
 * Returns 0 on success, -1 if out of memory. */
int flow_table_init(struct flow_table *t, size_t capacity_hint);
void flow_table_free(struct flow_table *t);

/* Return the flow for `key`, inserting an empty one if needed (then
 * *inserted is set to 1). Returns NULL only if out of memory. The returned
 * pointer is valid until the next insertion. */
struct flow *flow_table_find_or_insert(struct flow_table *t,
                                       const struct flow_key *key,
                                       int *inserted);

/* Look up a flow without inserting. Returns NULL if absent. */
const struct flow *flow_table_find(const struct flow_table *t,
                                   const struct flow_key *key);

/* Account one decoded packet. Packets without a valid IP layer are ignored.
 * Returns 0 on success, -1 if out of memory. */
int flow_table_add_packet(struct flow_table *t, const struct packet_info *pi,
                          uint32_t wire_len, uint64_t ts_ns);

/* Iterate: size_t pos = 0; while ((f = flow_table_next(t, &pos))) ... */
const struct flow *flow_table_next(const struct flow_table *t, size_t *pos);

/* Fill out[] with the (at most) n flows with the most bytes, largest first.
 * Ties are broken by packets, then start time, then key, so the order is
 * fully deterministic. `out` must have room for n pointers. Returns the
 * number written: min(n, t->count). Runs in O(count * log n). */
size_t flow_table_top_n(const struct flow_table *t, size_t n,
                        const struct flow **out);

#endif /* PCAPSTAT_FLOW_H */
