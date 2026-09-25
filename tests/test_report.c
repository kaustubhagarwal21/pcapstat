/*
 * test_report.c - end-to-end pipeline, summary, table and CSV tests.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analyze.h"
#include "builder.h"
#include "report.h"
#include "test.h"

#define SEC 1000000000ull

/* Read everything written to a temporary stream back as a string. */
static char *slurp(FILE *f)
{
    long size;
    char *text;

    fflush(f);
    size = ftell(f);
    if (size < 0)
        return NULL;
    text = malloc((size_t)size + 1);
    if (text == NULL)
        return NULL;
    rewind(f);
    if (fread(text, 1, (size_t)size, f) != (size_t)size) {
        free(text);
        return NULL;
    }
    text[size] = '\0';
    return text;
}

static void test_tcp_flags_string(void)
{
    char buf[9];

    format_tcp_flags(TCP_SYN | TCP_ACK, buf);
    CHECK(strcmp(buf, "SA") == 0);
    format_tcp_flags(0xFF, buf);
    CHECK(strcmp(buf, "FSRPAUEC") == 0);
    format_tcp_flags(0, buf);
    CHECK(strcmp(buf, "") == 0);
    format_tcp_flags(TCP_FIN | TCP_PSH | TCP_ACK, buf);
    CHECK(strcmp(buf, "FPA") == 0);
}

static struct packet_info pkt(int version, uint8_t proto, const uint8_t *src,
                              uint16_t sport, const uint8_t *dst,
                              uint16_t dport, uint8_t flags)
{
    struct packet_info pi;
    size_t alen = version == 4 ? 4 : 16;

    memset(&pi, 0, sizeof pi);
    pi.has_l2 = pi.has_l3 = pi.has_l4 = 1;
    pi.ip_version = (uint8_t)version;
    pi.ip_proto = proto;
    memcpy(pi.src_addr, src, alen);
    memcpy(pi.dst_addr, dst, alen);
    pi.src_port = sport;
    pi.dst_port = dport;
    pi.tcp_flags = flags;
    return pi;
}

static void test_csv_output(void)
{
    static const char expect[] =
        "src_addr,src_port,dst_addr,dst_port,protocol,ip_version,packets,"
        "bytes,first_ts,last_ts,duration_s,tcp_flags\n"
        "2001:db8::2,53,2001:db8::1,5353,UDP,6,1,200,"
        "1700000001.000000000,1700000001.000000000,0.000000000,\n"
        "10.0.0.1,40000,192.168.1.20,80,TCP,4,2,148,"
        "1700000000.000000001,1700000000.500000001,0.500000000,SA\n";
    struct flow_table t;
    struct packet_info p;
    FILE *f = tmpfile();
    char *text;

    CHECK(f != NULL);
    if (f == NULL)
        return;
    CHECK_EQ(flow_table_init(&t, 0), 0);
    p = pkt(4, 6, TEST_V4_A, 40000, TEST_V4_B, 80, TCP_SYN);
    flow_table_add_packet(&t, &p, 74, 1700000000ull * SEC + 1);
    p = pkt(4, 6, TEST_V4_B, 80, TEST_V4_A, 40000, TCP_SYN | TCP_ACK);
    flow_table_add_packet(&t, &p, 74, 1700000000ull * SEC + SEC / 2 + 1);
    /* First packet comes from the "larger" address: it must still be src. */
    p = pkt(6, 17, TEST_V6_B, 53, TEST_V6_A, 5353, 0);
    flow_table_add_packet(&t, &p, 200, 1700000001ull * SEC);

    CHECK_EQ(report_csv(f, &t), 0);
    text = slurp(f);
    CHECK(text != NULL && strcmp(text, expect) == 0);
    if (text != NULL && strcmp(text, expect) != 0)
        fprintf(stderr, "    got:\n%s    want:\n%s", text, expect);
    free(text);
    fclose(f);
    flow_table_free(&t);
}

static void test_csv_empty(void)
{
    struct flow_table t;
    FILE *f = tmpfile();
    char *text;

    CHECK(f != NULL);
    if (f == NULL)
        return;
    CHECK_EQ(flow_table_init(&t, 0), 0);
    CHECK_EQ(report_csv(f, &t), 0);
    text = slurp(f);
    CHECK(text != NULL && strncmp(text, "src_addr,", 9) == 0);
    CHECK(text != NULL && strchr(text, '\n') == text + strlen(text) - 1);
    free(text);
    fclose(f);
    flow_table_free(&t);
}

/* Build the mixed capture used by the pipeline tests. */
static void build_mixed_capture(struct bytebuf *cap)
{
    struct bytebuf fr;
    uint32_t t = 10;

    pcap_put_global(cap, 0, 0, 65535, 1);
#define ADD_FRAME(caplen_, wirelen_)                                        \
    do {                                                                    \
        pcap_put_record(cap, 0, t++, 0, fr.data, (uint32_t)(caplen_),       \
                        (uint32_t)(wirelen_));                              \
        bb_free(&fr);                                                       \
    } while (0)

    bb_init(&fr);
    frame_v4_tcp(&fr, TEST_V4_A, TEST_V4_B, 40000, 80, TCP_SYN, 0);
    ADD_FRAME(fr.len, fr.len);
    frame_v4_tcp(&fr, TEST_V4_B, TEST_V4_A, 80, 40000, TCP_SYN | TCP_ACK, 0);
    ADD_FRAME(fr.len, fr.len);
    frame_v4_tcp(&fr, TEST_V4_A, TEST_V4_B, 40000, 80, TCP_ACK, 100);
    ADD_FRAME(fr.len, fr.len);

    put_eth(&fr, ETHERTYPE_IPV6);                     /* UDP over IPv6 */
    put_ipv6(&fr, IPPROTO_NUM_UDP, TEST_V6_A, TEST_V6_B, 8 + 30);
    put_udp(&fr, 5353, 53, 30);
    bb_fill(&fr, 0, 30);
    ADD_FRAME(fr.len, fr.len);
    put_eth(&fr, ETHERTYPE_IPV6);
    put_ipv6(&fr, IPPROTO_NUM_UDP, TEST_V6_B, TEST_V6_A, 8 + 90);
    put_udp(&fr, 53, 5353, 90);
    bb_fill(&fr, 0, 90);
    ADD_FRAME(fr.len, fr.len);

    put_eth(&fr, ETHERTYPE_IPV4);                     /* ICMP echo */
    put_ipv4(&fr, IPPROTO_NUM_ICMP, TEST_V4_A, TEST_V4_B, 8, 0, 0);
    put_icmp(&fr, 8, 0);
    ADD_FRAME(fr.len, fr.len);

    put_eth(&fr, ETHERTYPE_ARP);                      /* non-IP */
    bb_fill(&fr, 0, 46);
    ADD_FRAME(fr.len, fr.len);

    put_eth(&fr, ETHERTYPE_VLAN);                     /* VLAN-tagged UDP */
    put_vlan(&fr, 100, ETHERTYPE_IPV4);
    put_ipv4(&fr, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 8, 0, 0);
    put_udp(&fr, 1000, 2000, 0);
    ADD_FRAME(fr.len, fr.len);

    put_eth(&fr, ETHERTYPE_IPV4);                     /* later fragment */
    put_ipv4(&fr, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 16, 0, 185);
    bb_fill(&fr, 0x77, 16);
    ADD_FRAME(fr.len, fr.len);

    frame_v4_tcp(&fr, TEST_V4_A, TEST_V4_B, 1, 2, TCP_SYN, 0); /* IHL 3 */
    fr.data[14] = 0x43;
    ADD_FRAME(fr.len, fr.len);

    frame_v4_tcp(&fr, TEST_V4_A, TEST_V4_B, 3, 4, TCP_ACK, 100); /* snapped */
    ADD_FRAME(14 + 20 + 10, fr.len);
#undef ADD_FRAME
}

static void test_pipeline_counts(void)
{
    struct bytebuf cap;
    struct pcap_reader r;
    struct analysis an;
    const struct stats *s = &an.stats;

    bb_init(&cap);
    build_mixed_capture(&cap);
    CHECK_EQ(pcap_open_mem(&r, cap.data, cap.len), PCAP_OK);
    CHECK_EQ(analysis_init(&an), 0);
    CHECK_EQ(analysis_run(&an, &r), PCAP_EOF);

    CHECK_EQ(s->packets, 11);
    CHECK_EQ(s->ipv4, 7);
    CHECK_EQ(s->ipv6, 2);
    CHECK_EQ(s->non_ip, 1);
    CHECK_EQ(s->tcp, 4);
    CHECK_EQ(s->udp, 4);
    CHECK_EQ(s->icmp, 1);
    CHECK_EQ(s->icmpv6, 0);
    CHECK_EQ(s->vlan_tagged, 1);
    CHECK_EQ(s->frag_later, 1);
    CHECK_EQ(s->frag_matched, 0);  /* its first fragment is not in the file */
    CHECK_EQ(s->truncated, 1);
    CHECK_EQ(s->malformed, 1);
    CHECK_EQ(s->by_status[DEC_TRUNC_TCP], 1);
    CHECK_EQ(s->by_status[DEC_BAD_IPV4_IHL], 1);
    CHECK_EQ(s->first_ts_ns, 10 * SEC);
    CHECK_EQ(s->last_ts_ns, 20 * SEC);
    CHECK(s->captured_bytes < s->wire_bytes); /* the snapped record */
    /* TCP 40000<->80, UDPv6, ICMP, VLAN UDP, portless fragment. The
     * malformed and truncated packets are not in any flow. */
    CHECK_EQ(an.flows.count, 5);

    analysis_free(&an);
    pcap_close(&r);
    bb_free(&cap);
}

static void test_pipeline_truncated_file(void)
{
    struct bytebuf cap;
    struct pcap_reader r;
    struct analysis an;

    bb_init(&cap);
    build_mixed_capture(&cap);
    cap.len -= 5; /* cut into the last record */
    CHECK_EQ(pcap_open_mem(&r, cap.data, cap.len), PCAP_OK);
    CHECK_EQ(analysis_init(&an), 0);
    CHECK_EQ(analysis_run(&an, &r), PCAP_ERR_TRUNC_RECORD);
    CHECK_EQ(an.stats.packets, 10); /* everything before the damage */
    analysis_free(&an);
    pcap_close(&r);
    bb_free(&cap);
}

/* Run a capture through the whole pipeline. */
static void analyze_capture(const struct bytebuf *cap, struct analysis *an)
{
    struct pcap_reader r;

    CHECK_EQ(pcap_open_mem(&r, cap->data, cap->len), PCAP_OK);
    CHECK_EQ(analysis_init(an), 0);
    CHECK_EQ(analysis_run(an, &r), PCAP_EOF);
    pcap_close(&r);
}

/* Regression for the review repro: three complete frames that end inside a
 * fixed-size header (IPv4, IPv6, VLAN) are malformed, and the same bytes
 * from 1514-byte frames cut by a snapshot length are truncated. */
static void test_short_complete_frames_counted_malformed(void)
{
    struct bytebuf cap, v4, v6, vl;
    struct analysis an;
    const struct stats *s = &an.stats;

    bb_init(&cap);
    bb_init(&v4);
    bb_init(&v6);
    bb_init(&vl);
    put_eth(&v4, ETHERTYPE_IPV4);
    bb_be32(&v4, 0x45000028u);
    bb_fill(&v4, 0, 6);                     /* 10 of 20 IPv4 header bytes */
    put_eth(&v6, ETHERTYPE_IPV6);
    bb_u8(&v6, 0x60);
    bb_fill(&v6, 0, 29);                    /* 30 of 40 IPv6 header bytes */
    put_eth(&vl, ETHERTYPE_VLAN);
    bb_be16(&vl, 5);                        /* 2 of 4 VLAN tag bytes */

    pcap_put_global(&cap, 0, 0, 65535, 1);
    pcap_put_record(&cap, 0, 1, 0, v4.data, (uint32_t)v4.len, (uint32_t)v4.len);
    pcap_put_record(&cap, 0, 1, 0, v6.data, (uint32_t)v6.len, (uint32_t)v6.len);
    pcap_put_record(&cap, 0, 1, 0, vl.data, (uint32_t)vl.len, (uint32_t)vl.len);
    pcap_put_record(&cap, 0, 1, 0, v4.data, (uint32_t)v4.len, 1514);
    pcap_put_record(&cap, 0, 1, 0, v6.data, (uint32_t)v6.len, 1514);
    pcap_put_record(&cap, 0, 1, 0, vl.data, (uint32_t)vl.len, 1514);

    analyze_capture(&cap, &an);
    CHECK_EQ(s->packets, 6);
    CHECK_EQ(s->truncated, 3);
    CHECK_EQ(s->malformed, 3);
    CHECK_EQ(s->by_status[DEC_BAD_SHORT_FRAME], 3);
    CHECK_EQ(s->by_status[DEC_TRUNC_IPV4], 1);
    CHECK_EQ(s->by_status[DEC_TRUNC_IPV6], 1);
    CHECK_EQ(s->by_status[DEC_TRUNC_VLAN], 1);
    CHECK_EQ(an.flows.count, 0);
    analysis_free(&an);
    bb_free(&cap);
    bb_free(&v4);
    bb_free(&v6);
    bb_free(&vl);
}

/* Later fragments join their datagram's flow when the first fragment has
 * been seen, instead of forming a port-less flow of their own. */
static void test_fragment_attribution(void)
{
    struct bytebuf cap, fr;
    struct analysis an;
    struct packet_info key_pkt;
    struct flow_key key;
    const struct flow *f;
    int rev;

    bb_init(&cap);
    bb_init(&fr);
    pcap_put_global(&cap, 0, 0, 65535, 1);

    /* Datagram 0x1234: first fragment (MF, offset 0) with the UDP header,
     * then two later fragments. put_ipv4 always writes ID 0x1234. */
    put_eth(&fr, ETHERTYPE_IPV4);
    put_ipv4(&fr, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 1480, 0, 0x2000);
    put_udp(&fr, 4444, 5555, 3000);
    bb_fill(&fr, 0, 1472);
    pcap_put_record(&cap, 0, 1, 0, fr.data, (uint32_t)fr.len, (uint32_t)fr.len);
    bb_free(&fr);
    put_eth(&fr, ETHERTYPE_IPV4);
    put_ipv4(&fr, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 1480, 0, 0x2000 | 185);
    bb_fill(&fr, 0, 1480);
    pcap_put_record(&cap, 0, 2, 0, fr.data, (uint32_t)fr.len, (uint32_t)fr.len);
    bb_free(&fr);
    put_eth(&fr, ETHERTYPE_IPV4);
    put_ipv4(&fr, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 48, 0, 370);
    bb_fill(&fr, 0, 48);
    pcap_put_record(&cap, 0, 3, 0, fr.data, (uint32_t)fr.len, (uint32_t)fr.len);

    /* A later fragment of another datagram (ID 0x9999), first one unseen. */
    fr.data[14 + 4] = 0x99;
    fr.data[14 + 5] = 0x99;
    pcap_put_record(&cap, 0, 4, 0, fr.data, (uint32_t)fr.len, (uint32_t)fr.len);
    bb_free(&fr);

    analyze_capture(&cap, &an);
    CHECK_EQ(an.stats.frag_first, 1);
    CHECK_EQ(an.stats.frag_later, 3);
    CHECK_EQ(an.stats.frag_matched, 2);
    CHECK_EQ(an.flows.count, 2);   /* the UDP flow, and the orphan */

    key_pkt = pkt(4, IPPROTO_NUM_UDP, TEST_V4_A, 4444, TEST_V4_B, 5555, 0);
    CHECK(flow_key_from_packet(&key_pkt, &key, &rev));
    f = flow_table_find(&an.flows, &key);
    CHECK(f != NULL && f->packets == 3);
    CHECK(f != NULL && f->bytes == (14 + 20 + 1480) * 2 + (14 + 20 + 48));
    analysis_free(&an);
    bb_free(&cap);
}

/* An IPv6 packet with a broken extension chain counts as IPv6 and as
 * malformed, but not under any transport protocol. */
static void test_broken_ipv6_chain_stats(void)
{
    struct bytebuf cap, fr;
    struct analysis an;
    const struct stats *s = &an.stats;

    bb_init(&cap);
    bb_init(&fr);
    put_eth(&fr, ETHERTYPE_IPV6);
    put_ipv6(&fr, 0, TEST_V6_A, TEST_V6_B, 8);
    bb_u8(&fr, IPPROTO_NUM_UDP);
    bb_u8(&fr, 4);                          /* 40 bytes in an 8-byte payload */
    bb_fill(&fr, 0, 6);
    pcap_put_global(&cap, 0, 0, 65535, 1);
    pcap_put_record(&cap, 0, 1, 0, fr.data, (uint32_t)fr.len, (uint32_t)fr.len);

    analyze_capture(&cap, &an);
    CHECK_EQ(s->ipv6, 1);
    CHECK_EQ(s->malformed, 1);
    CHECK_EQ(s->by_status[DEC_BAD_IPV6_EXT], 1);
    CHECK_EQ(s->tcp + s->udp + s->icmp + s->icmpv6 + s->other_l4, 0);
    analysis_free(&an);
    bb_free(&fr);
    bb_free(&cap);
}

static void test_summary_and_table(void)
{
    struct bytebuf cap;
    struct pcap_reader r;
    struct analysis an;
    const struct flow *top[3];
    FILE *f = tmpfile();
    char *text;
    size_t n;

    CHECK(f != NULL);
    if (f == NULL)
        return;
    bb_init(&cap);
    build_mixed_capture(&cap);
    CHECK_EQ(pcap_open_mem(&r, cap.data, cap.len), PCAP_OK);
    CHECK_EQ(analysis_init(&an), 0);
    CHECK_EQ(analysis_run(&an, &r), PCAP_EOF);

    report_summary(f, "mixed.pcap", &r.info, &an.stats, an.flows.count);
    n = flow_table_top_n(&an.flows, 3, top);
    report_top_flows(f, top, n, an.flows.count);
    text = slurp(f);
    CHECK(text != NULL);
    if (text != NULL) {
        CHECK(strstr(text, "Packets:     11\n") != NULL);
        CHECK(strstr(text, "IPv4 7 (63.6%), IPv6 2 (18.2%), non-IP 1") != NULL);
        CHECK(strstr(text, "1 truncated, 1 malformed") != NULL);
        CHECK(strstr(text, "truncated TCP header") != NULL);
        CHECK(strstr(text, "IPv4 header length < 20") != NULL);
        CHECK(strstr(text, "Top 3 of 5 flows by bytes") != NULL);
        /* Largest flow: the TCP handshake, shown client first. */
        CHECK(strstr(text, "  1  TCP") != NULL);
        CHECK(strstr(text, "10.0.0.1:40000") != NULL);
        CHECK(strstr(text, "[2001:db8::1]:5353") != NULL);
    }
    free(text);
    fclose(f);
    analysis_free(&an);
    pcap_close(&r);
    bb_free(&cap);
}

void run_report_tests(void)
{
    RUN_TEST(test_tcp_flags_string);
    RUN_TEST(test_csv_output);
    RUN_TEST(test_csv_empty);
    RUN_TEST(test_pipeline_counts);
    RUN_TEST(test_pipeline_truncated_file);
    RUN_TEST(test_short_complete_frames_counted_malformed);
    RUN_TEST(test_fragment_attribution);
    RUN_TEST(test_broken_ipv6_chain_stats);
    RUN_TEST(test_summary_and_table);
}
