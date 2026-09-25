/*
 * analyze.c - the read -> decode -> count pipeline.
 */
#include "analyze.h"

/* Starting size of the flow table; it doubles as needed. */
#define INITIAL_FLOW_SLOTS 1024u
/* Tunnels are far fewer than flows in most captures. */
#define INITIAL_TUNNEL_SLOTS 64u

int analysis_init(struct analysis *a)
{
    stats_init(&a->stats);
    if (flow_table_init(&a->flows, INITIAL_FLOW_SLOTS) != 0)
        return -1;
    if (flow_table_init(&a->tunnels, INITIAL_TUNNEL_SLOTS) != 0) {
        flow_table_free(&a->flows);
        return -1;
    }
    if (frag_cache_init(&a->frags) != 0) {
        flow_table_free(&a->tunnels);
        flow_table_free(&a->flows);
        return -1;
    }
    return 0;
}

int analysis_account(struct analysis *a, struct packet_info *pi,
                     uint32_t caplen, uint32_t wirelen, uint64_t ts_ns)
{
    /* Before the counters and the flow table see the packet, so a later
     * fragment is counted and keyed with its datagram's ports. */
    if (frag_cache_apply(&a->frags, pi))
        a->stats.frag_matched++;
    stats_add(&a->stats, pi, caplen, wirelen, ts_ns);

    /* Only cleanly decoded packets join a flow: a packet whose headers
     * were cut short or malformed may have missing or bogus ports. It is
     * still in the global counters above. */
    if (pi->status != DEC_OK)
        return 0;
    if (flow_table_add_packet(&a->flows, pi, wirelen, ts_ns) != 0)
        return -1;

    /* The same rule one level down: a G-PDU joins its tunnel only if the
     * GTP-U header and the user packet inside decoded cleanly. The outer
     * flow above counts it either way, since the outer headers are fine.
     * Echo and the other signalling messages are counted, not tunnelled. */
    if (pi->is_gtpu && pi->gtp_v1u && pi->gtp_status == DEC_OK &&
        pi->gtp_msg_type == GTPU_MSG_GPDU &&
        flow_table_add_tunnel(&a->tunnels, pi, wirelen, ts_ns) != 0)
        return -1;
    return 0;
}

enum pcap_status analysis_run(struct analysis *a, struct pcap_reader *r)
{
    struct pcap_record rec;
    struct packet_info pi;
    enum pcap_status st;

    while ((st = pcap_next(r, &rec)) == PCAP_OK) {
        decode_frame(rec.data, rec.caplen, rec.wirelen, &pi);
        if (analysis_account(a, &pi, rec.caplen, rec.wirelen, rec.ts_ns) != 0)
            return PCAP_ERR_NOMEM;
    }
    return st;
}

void analysis_free(struct analysis *a)
{
    flow_table_free(&a->flows);
    flow_table_free(&a->tunnels);
    frag_cache_free(&a->frags);
}
