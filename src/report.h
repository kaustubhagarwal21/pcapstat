/*
 * report.h - human-readable summary, top-N table and CSV export.
 */
#ifndef PCAPSTAT_REPORT_H
#define PCAPSTAT_REPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "addr.h"
#include "flow.h"
#include "pcap_reader.h"
#include "stats.h"

/* Room for "[" + IPv6 address + "]:" + 5-digit port. */
#define ENDPOINT_STR_LEN (ADDR_STR_LEN + 8)

/* Name of an IP protocol ("TCP", "UDP", ...) or its number as text. */
const char *proto_name(unsigned proto, char *buf, size_t len);

/* TCP flags as letters in bit order F S R P A U E C, e.g. SYN+ACK -> "SA".
 * `out` needs 9 bytes. */
void format_tcp_flags(uint8_t flags, char *out);

/* The flow's endpoints as text, oriented so `src` is the endpoint that sent
 * the first packet seen. Ports are shown for TCP and UDP only. */
void flow_endpoints(const struct flow *f, char *src, char *dst, size_t len);

void report_summary(FILE *out, const char *path,
                    const struct pcap_file_info *info, const struct stats *s,
                    size_t flow_count);

void report_top_flows(FILE *out, const struct flow *const *top, size_t n,
                      size_t flow_count);

/* Write every flow, largest first, with a header row. Returns 0 on success,
 * -1 on allocation or write failure. */
int report_csv(FILE *out, const struct flow_table *t);

/* The GTP-U part of the summary. Prints nothing if the capture held no
 * GTP-U. Returns 0, or -1 if out of memory. */
int report_gtpu(FILE *out, const struct stats *s,
                const struct flow_table *tunnels);

/* The largest GTP-U tunnels, as selected by flow_table_top_n() on the
 * tunnel table. */
void report_top_tunnels(FILE *out, const struct flow *const *top, size_t n,
                        size_t tunnel_count);

/* Write every tunnel, largest first, with a header row. Returns 0 on
 * success, -1 on allocation or write failure. */
int report_tunnels_csv(FILE *out, const struct flow_table *t);

#endif /* PCAPSTAT_REPORT_H */
