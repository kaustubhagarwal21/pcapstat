/*
 * report.c - human-readable summary, top-N table and CSV export.
 */
#include "report.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NS_PER_SEC 1000000000u

const char *proto_name(unsigned proto, char *buf, size_t len)
{
    switch (proto) {
    case IPPROTO_NUM_TCP:    return "TCP";
    case IPPROTO_NUM_UDP:    return "UDP";
    case IPPROTO_NUM_ICMP:   return "ICMP";
    case IPPROTO_NUM_ICMPV6: return "ICMPv6";
    default:
        snprintf(buf, len, "%u", proto);
        return buf;
    }
}

void format_tcp_flags(uint8_t flags, char *out)
{
    static const char letters[] = "FSRPAUEC"; /* bit 0 (FIN) .. bit 7 (CWR) */
    size_t n = 0;
    unsigned bit;

    for (bit = 0; bit < 8; bit++) {
        if (flags & (1u << bit))
            out[n++] = letters[bit];
    }
    out[n] = '\0';
}

static int has_ports(uint8_t proto)
{
    return proto == IPPROTO_NUM_TCP || proto == IPPROTO_NUM_UDP;
}

static void format_endpoint(const struct flow_key *k, const uint8_t *addr,
                            uint16_t port, char *buf, size_t len)
{
    char a[ADDR_STR_LEN];

    addr_format(k->ip_version, addr, a, sizeof a);
    if (!has_ports(k->proto))
        snprintf(buf, len, "%s", a);
    else if (k->ip_version == 6)
        snprintf(buf, len, "[%s]:%u", a, (unsigned)port); /* RFC 5952 sec. 6 */
    else
        snprintf(buf, len, "%s:%u", a, (unsigned)port);
}

void flow_endpoints(const struct flow *f, char *src, char *dst, size_t len)
{
    const struct flow_key *k = &f->key;

    if (!f->first_from_b) {
        format_endpoint(k, k->addr_a, k->port_a, src, len);
        format_endpoint(k, k->addr_b, k->port_b, dst, len);
    } else {
        format_endpoint(k, k->addr_b, k->port_b, src, len);
        format_endpoint(k, k->addr_a, k->port_a, dst, len);
    }
}

static double pct(uint64_t part, uint64_t whole)
{
    return whole ? 100.0 * (double)part / (double)whole : 0.0;
}

/* Print a timestamp as UTC date and time with microseconds. */
static void print_utc(FILE *out, uint64_t ts_ns)
{
    time_t sec = (time_t)(ts_ns / NS_PER_SEC);
    unsigned usec = (unsigned)(ts_ns % NS_PER_SEC / 1000u);
    const struct tm *tm = gmtime(&sec);
    char date[32];

    if (tm != NULL && strftime(date, sizeof date, "%Y-%m-%d %H:%M:%S", tm) > 0)
        fprintf(out, "%s.%06u UTC", date, usec);
    else
        fprintf(out, "%" PRIu64 ".%06u", ts_ns / NS_PER_SEC, usec);
}

void report_summary(FILE *out, const char *path,
                    const struct pcap_file_info *info, const struct stats *s,
                    size_t flow_count)
{
    uint64_t span_ns = s->packets ? s->last_ts_ns - s->first_ts_ns : 0;
    size_t i;

    fprintf(out, "File:        %s\n", path);
    fprintf(out, "Format:      pcap %u.%u, %s-endian, %s timestamps, "
                 "snaplen %" PRIu32 ", Ethernet\n",
            (unsigned)info->version_major, (unsigned)info->version_minor,
            info->big_endian ? "big" : "little",
            info->nsec ? "nanosecond" : "microsecond", info->snaplen);
    fprintf(out, "Packets:     %" PRIu64 "\n", s->packets);
    fprintf(out, "Bytes:       %" PRIu64 " on the wire, %" PRIu64
                 " captured\n", s->wire_bytes, s->captured_bytes);
    if (s->packets > 0) {
        double secs = (double)span_ns / 1e9;

        fprintf(out, "First:       ");
        print_utc(out, s->first_ts_ns);
        fprintf(out, "\nLast:        ");
        print_utc(out, s->last_ts_ns);
        fprintf(out, "\nDuration:    %" PRIu64 ".%06u s",
                span_ns / NS_PER_SEC,
                (unsigned)(span_ns % NS_PER_SEC / 1000u));
        if (secs > 0)
            fprintf(out, " (%.1f packets/s, %.3f Mbit/s)",
                    (double)s->packets / secs,
                    (double)s->wire_bytes * 8.0 / secs / 1e6);
        fprintf(out, "\n");
    }

    fprintf(out, "\nNetwork:     IPv4 %" PRIu64 " (%.1f%%), IPv6 %" PRIu64
                 " (%.1f%%), non-IP %" PRIu64 " (%.1f%%)\n",
            s->ipv4, pct(s->ipv4, s->packets), s->ipv6,
            pct(s->ipv6, s->packets), s->non_ip, pct(s->non_ip, s->packets));
    fprintf(out, "Transport:   TCP %" PRIu64 ", UDP %" PRIu64 ", ICMP %"
                 PRIu64 ", ICMPv6 %" PRIu64 ", other %" PRIu64 "\n",
            s->tcp, s->udp, s->icmp, s->icmpv6, s->other_l4);
    fprintf(out, "VLAN:        %" PRIu64 " tagged frames\n", s->vlan_tagged);
    fprintf(out, "Fragments:   %" PRIu64 " first, %" PRIu64
                 " non-first (%" PRIu64 " matched to their first fragment's "
                 "ports)\n", s->frag_first, s->frag_later, s->frag_matched);
    fprintf(out, "Flows:       %zu\n", flow_count);
    fprintf(out, "Problems:    %" PRIu64 " truncated, %" PRIu64
                 " malformed (excluded from flows)\n",
            s->truncated, s->malformed);
    for (i = 1; i < DEC_STATUS_COUNT; i++) {
        if (s->by_status[i] > 0)
            fprintf(out, "  %-40s %" PRIu64 "\n",
                    decode_status_str((enum decode_status)i), s->by_status[i]);
    }
}

void report_top_flows(FILE *out, const struct flow *const *top, size_t n,
                      size_t flow_count)
{
    char src[ENDPOINT_STR_LEN], dst[ENDPOINT_STR_LEN];
    int src_w = 3, dst_w = 3; /* at least as wide as the "src"/"dst" titles */
    size_t i;

    if (n == 0)
        return;

    /* Size the endpoint columns to the widest entry actually shown, so IPv4
     * tables stay narrow and IPv6 tables still line up. */
    for (i = 0; i < n; i++) {
        int ls, ld;

        flow_endpoints(top[i], src, dst, sizeof src);
        ls = (int)strlen(src);
        ld = (int)strlen(dst);
        if (ls > src_w)
            src_w = ls;
        if (ld > dst_w)
            dst_w = ld;
    }

    fprintf(out, "\nTop %zu of %zu flows by bytes "
                 "(src = sender of the first packet seen):\n", n, flow_count);
    fprintf(out, "%3s  %-6s  %-*s  %-*s  %8s  %10s  %12s  %s\n", "#", "proto",
            src_w, "src", dst_w, "dst", "packets", "bytes", "duration",
            "tcp flags");
    for (i = 0; i < n; i++) {
        const struct flow *f = top[i];
        uint64_t d = f->last_ts_ns - f->first_ts_ns;
        char pbuf[8], flags[9], dur[32];

        flow_endpoints(f, src, dst, sizeof src);
        if (f->key.proto == IPPROTO_NUM_TCP)
            format_tcp_flags(f->tcp_flags, flags);
        else
            snprintf(flags, sizeof flags, "-");
        snprintf(dur, sizeof dur, "%" PRIu64 ".%03u s", d / NS_PER_SEC,
                 (unsigned)(d % NS_PER_SEC / 1000000u));
        fprintf(out, "%3zu  %-6s  %-*s  %-*s  %8" PRIu64 "  %10" PRIu64
                     "  %12s  %s\n",
                i + 1, proto_name(f->key.proto, pbuf, sizeof pbuf), src_w, src,
                dst_w, dst, f->packets, f->bytes, dur, flags);
    }
}

/* Endpoint without port, for CSV where the port has its own column. */
static void csv_endpoint(const struct flow *f, int want_src, char *addr,
                         size_t len, unsigned *port)
{
    const struct flow_key *k = &f->key;
    int use_a = want_src ? !f->first_from_b : f->first_from_b;

    addr_format(k->ip_version, use_a ? k->addr_a : k->addr_b, addr, len);
    *port = use_a ? k->port_a : k->port_b;
}

int report_csv(FILE *out, const struct flow_table *t)
{
    const struct flow **all = NULL;
    size_t n = 0, i;

    if (t->count > 0) {
        all = malloc(t->count * sizeof *all); /* count < capacity: no overflow */
        if (all == NULL)
            return -1;
        n = flow_table_top_n(t, t->count, all);
    }

    fprintf(out, "src_addr,src_port,dst_addr,dst_port,protocol,ip_version,"
                 "packets,bytes,first_ts,last_ts,duration_s,tcp_flags\n");
    for (i = 0; i < n; i++) {
        const struct flow *f = all[i];
        char src[ADDR_STR_LEN], dst[ADDR_STR_LEN], pbuf[8], flags[9];
        unsigned sport, dport;
        uint64_t d = f->last_ts_ns - f->first_ts_ns;

        csv_endpoint(f, 1, src, sizeof src, &sport);
        csv_endpoint(f, 0, dst, sizeof dst, &dport);
        if (f->key.proto == IPPROTO_NUM_TCP)
            format_tcp_flags(f->tcp_flags, flags);
        else
            flags[0] = '\0';
        /* No field can contain a comma or a quote (addresses, numbers and
         * fixed names only), so no CSV quoting is needed. */
        fprintf(out, "%s,%u,%s,%u,%s,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64
                     ".%09u,%" PRIu64 ".%09u,%" PRIu64 ".%09u,%s\n",
                src, sport, dst, dport,
                proto_name(f->key.proto, pbuf, sizeof pbuf),
                (unsigned)f->key.ip_version, f->packets, f->bytes,
                f->first_ts_ns / NS_PER_SEC,
                (unsigned)(f->first_ts_ns % NS_PER_SEC),
                f->last_ts_ns / NS_PER_SEC,
                (unsigned)(f->last_ts_ns % NS_PER_SEC),
                d / NS_PER_SEC, (unsigned)(d % NS_PER_SEC), flags);
    }
    free(all);
    return ferror(out) ? -1 : 0;
}
