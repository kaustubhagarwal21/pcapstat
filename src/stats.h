/*
 * stats.h - capture-wide counters.
 */
#ifndef PCAPSTAT_STATS_H
#define PCAPSTAT_STATS_H

#include <stdint.h>

#include "decode.h"

struct stats {
    uint64_t packets;
    uint64_t wire_bytes;       /* sum of original frame lengths */
    uint64_t captured_bytes;   /* sum of bytes actually saved in the file */
    uint64_t first_ts_ns;      /* valid when packets > 0 */
    uint64_t last_ts_ns;

    uint64_t ipv4;             /* packets with a valid IPv4 header */
    uint64_t ipv6;             /* packets with a valid IPv6 header */
    uint64_t non_ip;           /* valid Ethernet frames carrying something else */
    uint64_t vlan_tagged;      /* frames with at least one VLAN tag */

    uint64_t tcp;              /* by IP protocol, for packets with valid IP
                                  whose transport protocol is known */
    uint64_t udp;
    uint64_t icmp;
    uint64_t icmpv6;
    uint64_t other_l4;

    uint64_t frag_first;       /* first fragments (offset 0, more to come) */
    uint64_t frag_later;       /* non-first fragments (not L4-decoded) */
    uint64_t frag_matched;     /* non-first fragments given the ports of their
                                  datagram's first fragment (see frag.h) */

    uint64_t truncated;        /* sum of the truncation reasons below */
    uint64_t malformed;        /* sum of the malformation reasons below */
    uint64_t by_status[DEC_STATUS_COUNT];
};

void stats_init(struct stats *s);

/* Account one frame after decoding. */
void stats_add(struct stats *s, const struct packet_info *pi,
               uint32_t caplen, uint32_t wirelen, uint64_t ts_ns);

#endif /* PCAPSTAT_STATS_H */
