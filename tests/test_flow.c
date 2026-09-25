/*
 * test_flow.c - flow key, hash table and top-N tests.
 */
#include <stdlib.h>
#include <string.h>

#include "addr.h"
#include "builder.h"
#include "flow.h"
#include "frag.h"
#include "test.h"

/* A decoded-packet stand-in with only the fields the flow code reads. */
static struct packet_info make_pkt(int version, uint8_t proto,
                                   const uint8_t *src, uint16_t sport,
                                   const uint8_t *dst, uint16_t dport,
                                   uint8_t flags)
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

static void test_flow_key_normalization(void)
{
    struct packet_info ab = make_pkt(4, 6, TEST_V4_A, 40000, TEST_V4_B, 80, 0);
    struct packet_info ba = make_pkt(4, 6, TEST_V4_B, 80, TEST_V4_A, 40000, 0);
    struct flow_key k1, k2;
    int r1, r2;

    CHECK(flow_key_from_packet(&ab, &k1, &r1));
    CHECK(flow_key_from_packet(&ba, &k2, &r2));
    CHECK(memcmp(&k1, &k2, sizeof k1) == 0);
    CHECK_EQ(r1, 0); /* 10.0.0.1 sorts before 192.168.1.20 */
    CHECK_EQ(r2, 1);
    CHECK(memcmp(k1.addr_a, TEST_V4_A, 4) == 0);
    CHECK_EQ(k1.port_a, 40000);

    /* Same address on both sides (e.g. loopback): ports decide. */
    ab = make_pkt(4, 17, TEST_V4_A, 9000, TEST_V4_A, 53, 0);
    ba = make_pkt(4, 17, TEST_V4_A, 53, TEST_V4_A, 9000, 0);
    CHECK(flow_key_from_packet(&ab, &k1, &r1));
    CHECK(flow_key_from_packet(&ba, &k2, &r2));
    CHECK(memcmp(&k1, &k2, sizeof k1) == 0);
    CHECK_EQ(k1.port_a, 53);
    CHECK(r1 != r2);
}

static void test_flow_key_requires_l3(void)
{
    struct packet_info pi;
    struct flow_key k;
    int rev;

    memset(&pi, 0, sizeof pi);
    pi.has_l2 = 1;
    CHECK(!flow_key_from_packet(&pi, &k, &rev));
}

static void test_bidirectional_merge(void)
{
    struct flow_table t;
    struct packet_info syn = make_pkt(4, 6, TEST_V4_A, 40000, TEST_V4_B, 80, TCP_SYN);
    struct packet_info synack = make_pkt(4, 6, TEST_V4_B, 80, TEST_V4_A, 40000, TCP_SYN | TCP_ACK);
    struct packet_info ack = make_pkt(4, 6, TEST_V4_A, 40000, TEST_V4_B, 80, TCP_ACK);
    struct packet_info fin = make_pkt(4, 6, TEST_V4_B, 80, TEST_V4_A, 40000, TCP_FIN | TCP_ACK);
    struct flow_key key;
    const struct flow *f;
    int rev;

    CHECK_EQ(flow_table_init(&t, 0), 0);
    CHECK_EQ(flow_table_add_packet(&t, &syn, 74, 1000), 0);
    CHECK_EQ(flow_table_add_packet(&t, &synack, 74, 2000), 0);
    CHECK_EQ(flow_table_add_packet(&t, &ack, 66, 3000), 0);
    CHECK_EQ(flow_table_add_packet(&t, &fin, 66, 4000), 0);
    CHECK_EQ(t.count, 1);

    CHECK(flow_key_from_packet(&synack, &key, &rev));
    f = flow_table_find(&t, &key);
    CHECK(f != NULL);
    if (f == NULL)
        goto out;
    CHECK_EQ(f->packets, 4);
    CHECK_EQ(f->bytes, 74 + 74 + 66 + 66);
    CHECK_EQ(f->first_ts_ns, 1000);
    CHECK_EQ(f->last_ts_ns, 4000);
    CHECK_EQ(f->tcp_flags, TCP_SYN | TCP_ACK | TCP_FIN);
    CHECK_EQ(f->first_from_b, 0);

    /* A flow first seen from the "larger" endpoint remembers that. */
    CHECK_EQ(flow_table_add_packet(&t, &synack, 60, 5000), 0);
    syn = make_pkt(4, 6, TEST_V4_B, 443, TEST_V4_A, 1234, TCP_SYN);
    CHECK_EQ(flow_table_add_packet(&t, &syn, 60, 6000), 0);
    CHECK_EQ(t.count, 2);
    CHECK(flow_key_from_packet(&syn, &key, &rev));
    f = flow_table_find(&t, &key);
    CHECK(f != NULL && f->first_from_b == 1);
out:
    flow_table_free(&t);
}

static void test_distinct_flows(void)
{
    struct flow_table t;
    struct packet_info p;

    CHECK_EQ(flow_table_init(&t, 64), 0);
    p = make_pkt(4, 6, TEST_V4_A, 1000, TEST_V4_B, 80, 0);
    CHECK_EQ(flow_table_add_packet(&t, &p, 60, 1), 0);
    p = make_pkt(4, 6, TEST_V4_A, 1001, TEST_V4_B, 80, 0);  /* other port */
    CHECK_EQ(flow_table_add_packet(&t, &p, 60, 2), 0);
    p = make_pkt(4, 17, TEST_V4_A, 1000, TEST_V4_B, 80, 0); /* other proto */
    CHECK_EQ(flow_table_add_packet(&t, &p, 60, 3), 0);
    p = make_pkt(6, 6, TEST_V6_A, 1000, TEST_V6_B, 80, 0);  /* IPv6 */
    CHECK_EQ(flow_table_add_packet(&t, &p, 60, 4), 0);
    p = make_pkt(4, 6, TEST_V4_B, 80, TEST_V4_A, 1000, 0);  /* reply: merges */
    CHECK_EQ(flow_table_add_packet(&t, &p, 60, 5), 0);
    CHECK_EQ(t.count, 4);
    flow_table_free(&t);
}

static void test_out_of_order_timestamps(void)
{
    struct flow_table t;
    struct packet_info p = make_pkt(4, 17, TEST_V4_A, 5, TEST_V4_B, 6, 0);
    struct packet_info r = make_pkt(4, 17, TEST_V4_B, 6, TEST_V4_A, 5, 0);
    size_t pos = 0;
    const struct flow *f;

    CHECK_EQ(flow_table_init(&t, 0), 0);
    CHECK_EQ(flow_table_add_packet(&t, &p, 100, 5000), 0);
    CHECK_EQ(flow_table_add_packet(&t, &r, 100, 3000), 0); /* earlier */
    CHECK_EQ(flow_table_add_packet(&t, &p, 100, 9000), 0);
    CHECK_EQ(flow_table_add_packet(&t, &p, 100, 7000), 0);
    f = flow_table_next(&t, &pos);
    CHECK(f != NULL);
    if (f != NULL) {
        CHECK_EQ(f->first_ts_ns, 3000);
        CHECK_EQ(f->last_ts_ns, 9000);
        CHECK_EQ(f->first_from_b, 1); /* the earliest packet went B -> A */
    }
    flow_table_free(&t);
}

/* Distinct flow number i: vary both address and port. */
static struct packet_info nth_flow_pkt(uint32_t i)
{
    uint8_t src[4] = {10, (uint8_t)(i >> 16), (uint8_t)(i >> 8), (uint8_t)i};
    return make_pkt(4, 6, src, (uint16_t)(1024 + i % 50000), TEST_V4_B, 443,
                    TCP_ACK);
}

static void test_table_growth(void)
{
    const uint32_t n = 20000;
    struct flow_table t;
    struct flow_key key;
    uint32_t i;
    int rev, all_found = 1, all_two = 1;

    CHECK_EQ(flow_table_init(&t, 0), 0);
    CHECK_EQ(t.capacity, 16);
    for (i = 0; i < n; i++) {
        struct packet_info p = nth_flow_pkt(i);
        CHECK_EQ(flow_table_add_packet(&t, &p, 100, i), 0);
    }
    CHECK_EQ(t.count, n);
    CHECK_EQ(t.capacity & (t.capacity - 1), 0);    /* power of two */
    CHECK(t.count * 10 <= t.capacity * 7);         /* load factor <= 0.7 */
    CHECK(t.capacity <= 2 * 32768);                /* and not wasteful */

    /* Second pass: every flow is found again, nothing new is inserted. */
    for (i = 0; i < n; i++) {
        struct packet_info p = nth_flow_pkt(i);
        CHECK_EQ(flow_table_add_packet(&t, &p, 100, n + i), 0);
    }
    CHECK_EQ(t.count, n);
    for (i = 0; i < n; i++) {
        struct packet_info p = nth_flow_pkt(i);
        const struct flow *f;

        flow_key_from_packet(&p, &key, &rev);
        f = flow_table_find(&t, &key);
        if (f == NULL)
            all_found = 0;
        else if (f->packets != 2 || f->first_ts_ns != i)
            all_two = 0;
    }
    CHECK(all_found);
    CHECK(all_two);
    flow_table_free(&t);
}

static void test_iteration_visits_all(void)
{
    struct flow_table t;
    const struct flow *f;
    size_t pos = 0, seen = 0;
    uint64_t packets = 0;
    uint32_t i;

    CHECK_EQ(flow_table_init(&t, 0), 0);
    for (i = 0; i < 500; i++) {
        struct packet_info p = nth_flow_pkt(i % 125);
        CHECK_EQ(flow_table_add_packet(&t, &p, 60, i), 0);
    }
    while ((f = flow_table_next(&t, &pos)) != NULL) {
        seen++;
        packets += f->packets;
    }
    CHECK_EQ(seen, 125);
    CHECK_EQ(packets, 500);
    flow_table_free(&t);
}

static void add_flow_with_bytes(struct flow_table *t, uint32_t id,
                                uint64_t bytes, unsigned packets)
{
    struct packet_info p = nth_flow_pkt(id);
    unsigned k;

    /* Spread `bytes` over `packets` packets; the last takes the remainder. */
    for (k = 0; k < packets; k++) {
        uint64_t part = bytes / packets + (k + 1 == packets ? bytes % packets : 0);
        flow_table_add_packet(t, &p, (uint32_t)part, 100 + id);
    }
}

static void test_top_n_ordering(void)
{
    struct flow_table t;
    const struct flow *top[10];
    size_t n;

    CHECK_EQ(flow_table_init(&t, 0), 0);
    add_flow_with_bytes(&t, 1, 500, 1);
    add_flow_with_bytes(&t, 2, 100, 1);
    add_flow_with_bytes(&t, 3, 900, 3);
    add_flow_with_bytes(&t, 4, 300, 1);
    add_flow_with_bytes(&t, 5, 700, 2);
    add_flow_with_bytes(&t, 6, 100, 2); /* ties flow 2 on bytes, more packets */

    n = flow_table_top_n(&t, 3, top);
    CHECK_EQ(n, 3);
    CHECK_EQ(top[0]->bytes, 900);
    CHECK_EQ(top[1]->bytes, 700);
    CHECK_EQ(top[2]->bytes, 500);

    n = flow_table_top_n(&t, 10, top); /* more than there are */
    CHECK_EQ(n, 6);
    CHECK_EQ(top[3]->bytes, 300);
    CHECK_EQ(top[4]->bytes, 100);
    CHECK_EQ(top[4]->packets, 2);      /* tie broken by packets */
    CHECK_EQ(top[5]->packets, 1);

    CHECK_EQ(flow_table_top_n(&t, 0, top), 0);
    flow_table_free(&t);
}

static int cmp_bytes_desc(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) - (x > y);
}

static void test_top_n_matches_full_sort(void)
{
    enum { FLOWS = 3000, N = 50 };
    struct flow_table t;
    const struct flow *top[N];
    uint64_t *expect = malloc(FLOWS * sizeof *expect);
    uint32_t i, lcg = 12345;
    size_t n, k;
    int same = 1;

    CHECK(expect != NULL);
    if (expect == NULL)
        return;
    CHECK_EQ(flow_table_init(&t, 0), 0);
    for (i = 0; i < FLOWS; i++) {
        lcg = lcg * 1103515245u + 12345u; /* fixed pseudo-random sizes */
        expect[i] = (lcg >> 8) % 100000;
        add_flow_with_bytes(&t, i, expect[i], 1);
    }
    qsort(expect, FLOWS, sizeof *expect, cmp_bytes_desc);
    n = flow_table_top_n(&t, N, top);
    CHECK_EQ(n, N);
    for (k = 0; k < n; k++) {
        if (top[k]->bytes != expect[k])
            same = 0;
    }
    CHECK(same);
    flow_table_free(&t);
    free(expect);
}

static void check_v6(const char *expect, const uint8_t addr[16])
{
    char buf[ADDR_STR_LEN];

    addr_format(6, addr, buf, sizeof buf);
    CHECK(strcmp(buf, expect) == 0);
    if (strcmp(buf, expect) != 0)
        fprintf(stderr, "    got \"%s\", want \"%s\"\n", buf, expect);
}

static void test_addr_format(void)
{
    static const uint8_t v4[4] = {192, 0, 2, 255};
    static const uint8_t zero[16] = {0};
    static const uint8_t loop[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t single[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1,
                                       0, 1, 0, 1, 0, 1, 0, 1};
    static const uint8_t longest[16] = {0x20, 0x01, 0, 0, 0, 0, 0, 1,
                                        0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t tie[16] = {0, 1, 0, 0, 0, 0, 0, 2,
                                    0, 0, 0, 0, 0, 3, 0, 4};
    static const uint8_t trailing[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t full[16] = {0xab, 0xcd, 0x00, 0x12, 0x10, 0x00,
                                     0xff, 0xff, 0x00, 0x0a, 0x00, 0xb0,
                                     0x0c, 0x00, 0xde, 0xad};
    char buf[ADDR_STR_LEN];

    addr_format(4, v4, buf, sizeof buf);
    CHECK(strcmp(buf, "192.0.2.255") == 0);
    check_v6("::", zero);
    check_v6("::1", loop);
    check_v6("2001:db8:0:1:1:1:1:1", single);  /* one zero group: kept */
    check_v6("2001:0:0:1::1", longest);        /* longest run wins */
    check_v6("1::2:0:0:3:4", tie);             /* equal runs: first wins */
    check_v6("fe80::", trailing);
    check_v6("abcd:12:1000:ffff:a:b0:c00:dead", full);
    check_v6("2001:db8::1", TEST_V6_A);

    addr_format(4, v4, buf, 4); /* too small: truncated but terminated */
    CHECK(strcmp(buf, "192") == 0);
}

static void test_addr_format_v4_mapped(void)
{
    static const uint8_t mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0xff, 0xff, 192, 0, 2, 1};
    static const uint8_t mapped0[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0xff, 0xff, 0, 0, 0, 0};
    static const uint8_t near[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0xff, 0xfe, 1, 2, 3, 4};
    static const uint8_t not_zero[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 1, 0xff, 0xff, 1, 2, 3, 4};
    static const uint8_t compat[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 1, 2, 3, 4};

    /* RFC 5952 section 5: mixed notation for the IPv4-mapped prefix. */
    check_v6("::ffff:192.0.2.1", mapped);
    check_v6("::ffff:0.0.0.0", mapped0);
    /* Not the mapped prefix: plain hex. */
    check_v6("::fffe:102:304", near);
    check_v6("::1:ffff:102:304", not_zero);
    /* The deprecated IPv4-compatible form (RFC 4291) stays hex. */
    check_v6("::102:304", compat);
}

/* A decoded fragment stand-in for the fragment cache. */
static struct packet_info frag_pkt(enum frag_kind kind, uint32_t id,
                                   uint16_t sport, uint16_t dport)
{
    struct packet_info pi;

    memset(&pi, 0, sizeof pi);
    pi.status = DEC_OK;
    pi.has_l2 = pi.has_l3 = 1;
    pi.has_l4 = kind != FRAG_LATER;
    pi.ip_version = 4;
    pi.ip_proto = IPPROTO_NUM_UDP;
    memcpy(pi.src_addr, TEST_V4_A, 4);
    memcpy(pi.dst_addr, TEST_V4_B, 4);
    pi.frag = kind;
    pi.frag_id = id;
    pi.src_port = sport;
    pi.dst_port = dport;
    return pi;
}

static void test_frag_cache(void)
{
    struct frag_cache c;
    struct packet_info first = frag_pkt(FRAG_FIRST, 77, 4444, 5555);
    struct packet_info later = frag_pkt(FRAG_LATER, 77, 0, 0);
    struct packet_info other_id = frag_pkt(FRAG_LATER, 78, 0, 0);
    struct packet_info other_dst = frag_pkt(FRAG_LATER, 77, 0, 0);
    struct packet_info early = frag_pkt(FRAG_LATER, 90, 0, 0);
    struct packet_info bad = frag_pkt(FRAG_LATER, 77, 0, 0);

    CHECK_EQ(frag_cache_init(&c), 0);

    /* A later fragment seen before its first one stays port-less. */
    CHECK_EQ(frag_cache_apply(&c, &early), 0);
    CHECK_EQ(early.src_port, 0);

    CHECK_EQ(frag_cache_apply(&c, &first), 0);  /* records, fills nothing */
    CHECK_EQ(frag_cache_apply(&c, &later), 1);
    CHECK_EQ(later.src_port, 4444);
    CHECK_EQ(later.dst_port, 5555);
    CHECK(!later.has_l4);                        /* still not L4-decoded */

    /* Same addresses, different datagram; same ID, different peer. */
    CHECK_EQ(frag_cache_apply(&c, &other_id), 0);
    CHECK_EQ(other_id.src_port, 0);
    other_dst.dst_addr[3] = 99;
    CHECK_EQ(frag_cache_apply(&c, &other_dst), 0);

    /* Only cleanly decoded packets take part. */
    bad.status = DEC_BAD_UDP_LEN;
    CHECK_EQ(frag_cache_apply(&c, &bad), 0);
    frag_cache_free(&c);
}

/* Many datagrams in flight: most still find their ports in the fixed-size
 * cache, and a collision only ever loses attribution, never mixes it up. */
static void test_frag_cache_many(void)
{
    enum { N = 1000 };
    struct frag_cache c;
    uint32_t id;
    int matched = 0, wrong = 0;

    CHECK_EQ(frag_cache_init(&c), 0);
    for (id = 0; id < N; id++) {
        struct packet_info first = frag_pkt(FRAG_FIRST, id,
                                            (uint16_t)(1000 + id), 53);
        frag_cache_apply(&c, &first);
    }
    for (id = 0; id < N; id++) {
        struct packet_info later = frag_pkt(FRAG_LATER, id, 0, 0);

        if (frag_cache_apply(&c, &later)) {
            matched++;
            if (later.src_port != (uint16_t)(1000 + id) ||
                later.dst_port != 53)
                wrong++;
        }
    }
    CHECK(matched > N / 2);
    CHECK_EQ(wrong, 0);
    frag_cache_free(&c);
}

void run_flow_tests(void)
{
    RUN_TEST(test_flow_key_normalization);
    RUN_TEST(test_flow_key_requires_l3);
    RUN_TEST(test_bidirectional_merge);
    RUN_TEST(test_distinct_flows);
    RUN_TEST(test_out_of_order_timestamps);
    RUN_TEST(test_table_growth);
    RUN_TEST(test_iteration_visits_all);
    RUN_TEST(test_top_n_ordering);
    RUN_TEST(test_top_n_matches_full_sort);
    RUN_TEST(test_addr_format);
    RUN_TEST(test_addr_format_v4_mapped);
    RUN_TEST(test_frag_cache);
    RUN_TEST(test_frag_cache_many);
}
