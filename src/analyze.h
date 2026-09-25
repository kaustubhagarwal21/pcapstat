/*
 * analyze.h - the read -> decode -> count pipeline.
 */
#ifndef PCAPSTAT_ANALYZE_H
#define PCAPSTAT_ANALYZE_H

#include "flow.h"
#include "pcap_reader.h"
#include "stats.h"

struct analysis {
    struct stats stats;
    struct flow_table flows;
};

/* Returns 0 on success, -1 if out of memory. */
int analysis_init(struct analysis *a);

/*
 * Read every record from `r`, decode it and account it. Returns PCAP_EOF if
 * the whole input was consumed, otherwise the error that stopped the read
 * (PCAP_ERR_NOMEM if the flow table could not grow). Either way, the
 * counters describe every record read before the stop.
 */
enum pcap_status analysis_run(struct analysis *a, struct pcap_reader *r);

void analysis_free(struct analysis *a);

#endif /* PCAPSTAT_ANALYZE_H */
