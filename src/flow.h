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
 *
 * A second table of the same kind holds GTP-U tunnels. A tunnel key is the
 * outer sender, the outer receiver and the TEID, in that direction: a TEID is
 * chosen by the node that receives it, so the uplink and downlink halves of
 * one bearer use different TEIDs, and two nodes may pick the same value
 * independently. Tunnel keys are therefore never put in canonical order.
 */
#ifndef PCAPSTAT_FLOW_H
#define PCAPSTAT_FLOW_H

#include <stddef.h>
#include <stdint.h>

#include "decode.h"

struct flow_key {
    uint32_t teid;       /* GTP-U TEID in the tunnel table; 0 in flows */
    uint8_t ip_version;  /* 4 or 6 */
    uint8_t proto;       /* IP protocol number */
    uint16_t port_a;     /* 0 for protocols without ports (ICMP, fragments,
                            tunnels) */
    uint16_t port_b;
    uint8_t addr_a[16];  /* IPv4 uses the first 4 bytes, the rest are 0 */
    uint8_t addr_b[16];
};

/* The key takes 44 bytes (42 of fields, padded to a multiple of 4). The
 * single-byte fields fill the gap between it and the first uint64_t at
 * offset 48, so a slot is 88 bytes. */
struct flow {
    struct flow_key key;
    uint8_t tcp_flags;       /* union of all TCP flags seen, both directions */
    uint8_t first_from_b;    /* 1 if the first packet seen went B -> A */
    uint8_t in_use;          /* slot occupied */
    uint64_t hash;           /* cached so growing never re-hashes keys */
    uint64_t packets;
    uint64_t bytes;          /* sum of original (on-the-wire) lengths */
    uint64_t first_ts_ns;
    uint64_t last_ts_ns;
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

/* Build the tunnel key (outer source, outer destination, TEID; not
 * reordered) for a GTPv1-U packet. Returns 0 if the packet is not one. */
int tunnel_key_from_packet(const struct packet_info *pi,
                           struct flow_key *key);

/* Account one GTPv1-U packet in a table of tunnels; other packets are
 * ignored. The caller decides which messages count (pcapstat adds cleanly
 * decoded G-PDUs). Returns 0 on success, -1 if out of memory. */
int flow_table_add_tunnel(struct flow_table *t, const struct packet_info *pi,
                          uint32_t wire_len, uint64_t ts_ns);

/* Count the distinct TEIDs among the keys in `t`. Returns 0, or -1 if out
 * of memory. */
int flow_table_distinct_teids(const struct flow_table *t, size_t *count);

/* Iterate: size_t pos = 0; while ((f = flow_table_next(t, &pos))) ... */
const struct flow *flow_table_next(const struct flow_table *t, size_t *pos);

/* Fill out[] with the (at most) n flows with the most bytes, largest first.
 * Ties are broken by packets, then start time, then key, so the order is
 * fully deterministic. `out` must have room for n pointers. Returns the
 * number written: min(n, t->count). Runs in O(count * log n). */
size_t flow_table_top_n(const struct flow_table *t, size_t n,
                        const struct flow **out);

#endif /* PCAPSTAT_FLOW_H */
