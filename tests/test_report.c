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
    RUN_TEST(test_summary_and_table);
}
