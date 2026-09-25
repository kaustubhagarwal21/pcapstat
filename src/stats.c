/*
 * stats.c - capture-wide counters.
 */
#include "stats.h"

#include <string.h>

void stats_init(struct stats *s)
{
    memset(s, 0, sizeof *s);
}

static void add_gtpu(struct gtpu_stats *g, const struct packet_info *pi)
{
    if (pi->frag == FRAG_FIRST && decode_is_gtpu_port(pi)) {
        g->fragmented++;
        return;
    }
    if (!pi->is_gtpu)
        return;
    g->packets++;

    if ((unsigned)pi->gtp_status < DEC_STATUS_COUNT)
        g->by_status[pi->gtp_status]++;
    /* A problem found after the GTP-U headers were read in full can only
     * be in a G-PDU's user packet. */
    if (pi->gtp_status != DEC_OK) {
        if (decode_status_is_truncation(pi->gtp_status)) {
            g->truncated++;
            if (pi->gtp_msg_ok)
                g->user_truncated++;
        } else {
            g->malformed++;
            if (pi->gtp_msg_ok)
                g->user_malformed++;
        }
    }

    /* A header cut off by the capture is a problem, counted above. A whole
     * header that is simply not GTPv1-U is not. */
    if (!pi->gtp_v1u) {
        if (pi->gtp_status == DEC_OK)
            g->not_v1u++;
        return;
    }

    switch (pi->gtp_msg_type) {
    case GTPU_MSG_GPDU:             g->gpdu++; break;
    case GTPU_MSG_ECHO_REQUEST:     g->echo_request++; break;
    case GTPU_MSG_ECHO_RESPONSE:    g->echo_response++; break;
    case GTPU_MSG_ERROR_INDICATION: g->error_indication++; break;
    case GTPU_MSG_END_MARKER:       g->end_marker++; break;
    default:                        g->other_type++; break;
    }
    if (pi->gtp_flags & GTPU_FLAG_S)
        g->with_seq++;
    if (pi->gtp_ext_count > 0)
        g->with_ext++;

    if (!pi->has_inner)
        return;
    if (pi->inner_version == 4)
        g->inner_ipv4++;
    else
        g->inner_ipv6++;
    /* As for the outer packet: a broken IPv6 extension chain means the
     * transport protocol is unknown. */
    if (pi->gtp_status == DEC_TRUNC_IPV6_EXT ||
        pi->gtp_status == DEC_BAD_IPV6_EXT)
        return;
    switch (pi->inner_proto) {
    case IPPROTO_NUM_TCP:    g->inner_tcp++; break;
    case IPPROTO_NUM_UDP:    g->inner_udp++; break;
    case IPPROTO_NUM_ICMP:   g->inner_icmp++; break;
    case IPPROTO_NUM_ICMPV6: g->inner_icmpv6++; break;
    default:                 g->inner_other++; break;
    }
    if (pi->gtp_nested)
        g->nested++;
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
    add_gtpu(&s->gtpu, pi);

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

    /* An IPv6 packet whose extension-header chain is broken never reached
     * its transport header, so there is no transport protocol to count. It
     * is already counted as truncated or malformed above. */
    if (pi->status == DEC_TRUNC_IPV6_EXT || pi->status == DEC_BAD_IPV6_EXT)
        return;

    switch (pi->ip_proto) {
    case IPPROTO_NUM_TCP:    s->tcp++; break;
    case IPPROTO_NUM_UDP:    s->udp++; break;
    case IPPROTO_NUM_ICMP:   s->icmp++; break;
    case IPPROTO_NUM_ICMPV6: s->icmpv6++; break;
    default:                 s->other_l4++; break;
    }
}
