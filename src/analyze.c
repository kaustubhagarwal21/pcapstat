/*
 * analyze.c - the read -> decode -> count pipeline.
 */
#include "analyze.h"

#include "decode.h"

/* Starting size of the flow table; it doubles as needed. */
#define INITIAL_FLOW_SLOTS 1024u

int analysis_init(struct analysis *a)
{
    stats_init(&a->stats);
    return flow_table_init(&a->flows, INITIAL_FLOW_SLOTS);
}

enum pcap_status analysis_run(struct analysis *a, struct pcap_reader *r)
{
    struct pcap_record rec;
    struct packet_info pi;
    enum pcap_status st;

    while ((st = pcap_next(r, &rec)) == PCAP_OK) {
        decode_frame(rec.data, rec.caplen, rec.wirelen, &pi);
        stats_add(&a->stats, &pi, rec.caplen, rec.wirelen, rec.ts_ns);

        /* Only cleanly decoded packets join a flow: a packet whose headers
         * were cut short or malformed may have missing or bogus ports. It is
         * still in the global counters above. */
        if (pi.status == DEC_OK &&
            flow_table_add_packet(&a->flows, &pi, rec.wirelen, rec.ts_ns) != 0)
            return PCAP_ERR_NOMEM;
    }
    return st;
}

void analysis_free(struct analysis *a)
{
    flow_table_free(&a->flows);
}
