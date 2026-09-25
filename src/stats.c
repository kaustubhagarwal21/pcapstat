/*
 * stats.c - capture-wide counters.
 */
#include "stats.h"

#include <string.h>

void stats_init(struct stats *s)
{
    memset(s, 0, sizeof *s);
}

void stats_add(struct stats *s, const struct packet_info *pi,
               uint32_t caplen, uint32_t wirelen, uint64_t ts_ns)
{
    if (s->packets == 0 || ts_ns < s->first_ts_ns)
        s->first_ts_ns = ts_ns;
    if (s->packets == 0 || ts_ns > s->last_ts_ns)
        s->last_ts_ns = ts_ns;
    s->packets++;
    s->wire_bytes += wirelen;
    s->captured_bytes += caplen;

    /* The status is a valid enum value by construction, but it indexes an
     * array, so check the bound anyway rather than trust it. */
    if ((unsigned)pi->status < DEC_STATUS_COUNT)
        s->by_status[pi->status]++;
    if (pi->status != DEC_OK) {
        if (decode_status_is_truncation(pi->status))
            s->truncated++;
        else
            s->malformed++;
    }

    if (pi->vlan_count > 0)
        s->vlan_tagged++;

    if (!pi->has_l3) {
        /* A valid L2 header with a non-IP ethertype is "non-IP". A broken
         * IP header is not: it is already counted as malformed/truncated. */
        if (pi->has_l2 && pi->ethertype != ETHERTYPE_IPV4 &&
            pi->ethertype != ETHERTYPE_IPV6)
            s->non_ip++;
        return;
    }

    if (pi->ip_version == 4)
        s->ipv4++;
    else
        s->ipv6++;

    if (pi->frag == FRAG_FIRST)
        s->frag_first++;
    else if (pi->frag == FRAG_LATER)
        s->frag_later++;

    switch (pi->ip_proto) {
    case IPPROTO_NUM_TCP:    s->tcp++; break;
    case IPPROTO_NUM_UDP:    s->udp++; break;
    case IPPROTO_NUM_ICMP:   s->icmp++; break;
    case IPPROTO_NUM_ICMPV6: s->icmpv6++; break;
    default:                 s->other_l4++; break;
    }
}
