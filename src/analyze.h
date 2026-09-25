/*
 * analyze.h - the read -> decode -> count pipeline.
 */
#ifndef PCAPSTAT_ANALYZE_H
#define PCAPSTAT_ANALYZE_H

#include "decode.h"
#include "flow.h"
#include "frag.h"
#include "pcap_reader.h"
#include "stats.h"

struct analysis {
    struct stats stats;
    struct flow_table flows;   /* outer 5-tuple flows */
    struct flow_table tunnels; /* GTP-U tunnels (see flow.h) */
    struct frag_cache frags;
};

/* Returns 0 on success, -1 if out of memory (nothing is left allocated). */
int analysis_init(struct analysis *a);

/*
 * Account one decoded packet: attribute it if it is a later fragment,
 * update the global counters and, if it decoded cleanly, its flow and, for
 * a G-PDU whose GTP-U headers decoded cleanly, its GTP-U tunnel (whatever
 * state the user packet inside is in). `pi` may be modified (a later
 * fragment can receive its datagram's ports). Returns 0, or -1 if a table
 * could not grow.
 */
int analysis_account(struct analysis *a, struct packet_info *pi,
                     uint32_t caplen, uint32_t wirelen, uint64_t ts_ns);

/*
 * Read every record from `r`, decode it and account it. Returns PCAP_EOF if
 * the whole input was consumed, otherwise the error that stopped the read
 * (PCAP_ERR_NOMEM if the flow table could not grow). Either way, the
 * counters describe every record read before the stop.
 */
enum pcap_status analysis_run(struct analysis *a, struct pcap_reader *r);

void analysis_free(struct analysis *a);

#endif /* PCAPSTAT_ANALYZE_H */
