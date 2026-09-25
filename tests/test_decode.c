/*
 * test_decode.c - frame decoder tests.
 *
 * Frames are copied into a heap buffer of exactly caplen bytes before
 * decoding, so under AddressSanitizer any read past caplen is reported as a
 * heap-buffer-overflow instead of silently reading neighbouring bytes.
 */
#include <stdlib.h>
#include <string.h>

#include "builder.h"
#include "decode.h"
#include "test.h"

static enum decode_status decode_snap(const struct bytebuf *b, size_t caplen,
                                      size_t wirelen, struct packet_info *pi)
{
    uint8_t *exact = malloc(caplen ? caplen : 1);
    enum decode_status st;

    if (exact == NULL)
        abort();
    if (caplen > 0)
        memcpy(exact, b->data, caplen);
    st = decode_frame(exact, caplen, wirelen, pi);
    free(exact);
    return st;
}

static enum decode_status decode_all(const struct bytebuf *b,
                                     struct packet_info *pi)
{
    return decode_snap(b, b->len, b->len, pi);
}

static void test_ipv4_tcp(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    frame_v4_tcp(&b, TEST_V4_A, TEST_V4_B, 51234, 443, TCP_SYN | TCP_ACK, 10);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(pi.has_l2 && pi.has_l3 && pi.has_l4);
    CHECK_EQ(pi.ethertype, ETHERTYPE_IPV4);
    CHECK_EQ(pi.vlan_count, 0);
    CHECK_EQ(pi.ip_version, 4);
    CHECK_EQ(pi.ip_proto, IPPROTO_NUM_TCP);
    CHECK(memcmp(pi.src_addr, TEST_V4_A, 4) == 0);
    CHECK(memcmp(pi.dst_addr, TEST_V4_B, 4) == 0);
    CHECK_EQ(pi.src_port, 51234);
    CHECK_EQ(pi.dst_port, 443);
    CHECK_EQ(pi.tcp_flags, TCP_SYN | TCP_ACK);
    CHECK_EQ(pi.frag, FRAG_NONE);
    bb_free(&b);
}

static void test_ipv4_udp(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    frame_v4_udp(&b, TEST_V4_B, TEST_V4_A, 5353, 53, 32);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.ip_proto, IPPROTO_NUM_UDP);
    CHECK_EQ(pi.src_port, 5353);
    CHECK_EQ(pi.dst_port, 53);
    CHECK_EQ(pi.tcp_flags, 0);
    CHECK(pi.has_l4);
    bb_free(&b);
}

static void test_icmp(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV4);
    put_ipv4(&b, IPPROTO_NUM_ICMP, TEST_V4_A, TEST_V4_B, 8 + 56, 0, 0);
    put_icmp(&b, 8, 0); /* echo request */
    bb_fill(&b, 0x61, 56);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(pi.has_l4);
    CHECK_EQ(pi.ip_proto, IPPROTO_NUM_ICMP);
    CHECK_EQ(pi.icmp_type, 8);
    CHECK_EQ(pi.icmp_code, 0);
    CHECK_EQ(pi.src_port, 0);
    CHECK_EQ(pi.dst_port, 0);
    bb_free(&b);
}

static void test_icmpv6(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV6);
    put_ipv6(&b, IPPROTO_NUM_ICMPV6, TEST_V6_A, TEST_V6_B, 8);
    put_icmp(&b, 129, 0); /* echo reply */
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.ip_version, 6);
    CHECK_EQ(pi.ip_proto, IPPROTO_NUM_ICMPV6);
    CHECK_EQ(pi.icmp_type, 129);
    CHECK_EQ(pi.icmp_code, 0);
    bb_free(&b);
}

static void test_ipv6_tcp(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    frame_v6_tcp(&b, TEST_V6_A, TEST_V6_B, 443, 60000,
                 TCP_FIN | TCP_PSH | TCP_ACK, 100);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.ethertype, ETHERTYPE_IPV6);
    CHECK_EQ(pi.ip_version, 6);
    CHECK(memcmp(pi.src_addr, TEST_V6_A, 16) == 0);
    CHECK(memcmp(pi.dst_addr, TEST_V6_B, 16) == 0);
    CHECK_EQ(pi.src_port, 443);
    CHECK_EQ(pi.dst_port, 60000);
    CHECK_EQ(pi.tcp_flags, TCP_FIN | TCP_PSH | TCP_ACK);
    bb_free(&b);
}

static void test_single_vlan(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_VLAN);
    bb_be16(&b, (5u << 13) | 100); /* priority 5 must not leak into the ID */
    bb_be16(&b, ETHERTYPE_IPV4);
    put_ipv4(&b, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 8, 0, 0);
    put_udp(&b, 1000, 2000, 0);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.vlan_count, 1);
    CHECK_EQ(pi.vlan_ids[0], 100);
    CHECK_EQ(pi.ethertype, ETHERTYPE_IPV4);
    CHECK_EQ(pi.src_port, 1000);
    CHECK_EQ(pi.dst_port, 2000);
    bb_free(&b);
}

static void test_double_vlan(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_QINQ);          /* 802.1ad outer (service) tag */
    put_vlan(&b, 200, ETHERTYPE_VLAN);    /* 802.1Q inner (customer) tag */
    put_vlan(&b, 100, ETHERTYPE_IPV6);
    put_ipv6(&b, IPPROTO_NUM_TCP, TEST_V6_A, TEST_V6_B, 20);
    put_tcp(&b, 22, 50000, TCP_ACK);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.vlan_count, 2);
    CHECK_EQ(pi.vlan_ids[0], 200);
    CHECK_EQ(pi.vlan_ids[1], 100);
    CHECK_EQ(pi.ethertype, ETHERTYPE_IPV6);
    CHECK_EQ(pi.src_port, 22);
    CHECK_EQ(pi.dst_port, 50000);
    bb_free(&b);
}

static void test_vlan_errors(void)
{
    struct bytebuf b;
    struct packet_info pi;

    /* Three tags: more than we support. */
    bb_init(&b);
    put_eth(&b, ETHERTYPE_VLAN);
    put_vlan(&b, 1, ETHERTYPE_VLAN);
    put_vlan(&b, 2, ETHERTYPE_VLAN);
    put_vlan(&b, 3, ETHERTYPE_IPV4);
    put_ipv4(&b, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 8, 0, 0);
    put_udp(&b, 1, 2, 0);
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_VLAN_DEPTH);
    CHECK_EQ(pi.vlan_count, 2);
    CHECK(!pi.has_l3);
    bb_free(&b);

    /* Tag cut off after 2 of its 4 bytes. */
    put_eth(&b, ETHERTYPE_VLAN);
    bb_be16(&b, 7);
    CHECK_EQ(decode_all(&b, &pi), DEC_TRUNC_VLAN);
    bb_free(&b);
}

static void test_ipv4_options(void)
{
    struct bytebuf b;
    struct packet_info pi;
    unsigned words;

    /* IHL 6 .. 15: the TCP header must be found after the options. */
    for (words = 1; words <= 10; words++) {
        bb_init(&b);
        put_eth(&b, ETHERTYPE_IPV4);
        put_ipv4(&b, IPPROTO_NUM_TCP, TEST_V4_A, TEST_V4_B, 20, words, 0);
        put_tcp(&b, 1111, 2222, TCP_RST);
        CHECK_EQ(decode_all(&b, &pi), DEC_OK);
        CHECK_EQ(pi.src_port, 1111);
        CHECK_EQ(pi.dst_port, 2222);
        CHECK_EQ(pi.tcp_flags, TCP_RST);
        bb_free(&b);
    }
}

static void test_ipv4_options_snapped(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV4);
    put_ipv4(&b, IPPROTO_NUM_TCP, TEST_V4_A, TEST_V4_B, 20, 3, 0);
    put_tcp(&b, 1111, 2222, TCP_ACK);
    /* Capture stops 24 bytes into the 32-byte IP header. */
    CHECK_EQ(decode_snap(&b, 14 + 24, b.len, &pi), DEC_TRUNC_IPV4);
    CHECK(!pi.has_l3);
    bb_free(&b);
}

static void test_ipv4_nonfirst_fragment(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV4);
    /* Offset 185 * 8 = 1480 bytes into the datagram, last fragment. */
    put_ipv4(&b, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 16, 0, 185);
    put_udp(&b, 4444, 5555, 8); /* bytes that merely look like a header */
    bb_fill(&b, 0, 8);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(pi.has_l3);
    CHECK(!pi.has_l4);
    CHECK_EQ(pi.frag, FRAG_LATER);
    CHECK_EQ(pi.ip_proto, IPPROTO_NUM_UDP);
    CHECK_EQ(pi.src_port, 0);
    CHECK_EQ(pi.dst_port, 0);
    bb_free(&b);
}

static void test_ipv4_first_fragment(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV4);
    /* More-fragments set, offset 0. The UDP length (3000) describes the
     * whole datagram, which is longer than this fragment: that is legal. */
    put_ipv4(&b, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 1480, 0, 0x2000);
    put_udp(&b, 4444, 5555, 2992);
    bb_fill(&b, 0, 1472);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.frag, FRAG_FIRST);
    CHECK(pi.has_l4);
    CHECK_EQ(pi.src_port, 4444);
    CHECK_EQ(pi.dst_port, 5555);
    bb_free(&b);
}

/* IPv6 hop-by-hop options header, 8 bytes, with a PadN option. */
static void put_hopopts(struct bytebuf *b, unsigned next)
{
    bb_u8(b, next);
    bb_u8(b, 0);                /* length: (0 + 1) * 8 = 8 bytes */
    bb_u8(b, 1);                /* PadN */
    bb_u8(b, 4);
    bb_fill(b, 0, 4);
}

static void put_frag6(struct bytebuf *b, unsigned next, unsigned offset8,
                      int more)
{
    bb_u8(b, next);
    bb_u8(b, 0);
    bb_be16(b, (offset8 << 3) | (more ? 1u : 0u));
    bb_be32(b, 0xCAFEF00Du);    /* identification */
}

static void test_ipv6_hopbyhop_fragment(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV6);
    put_ipv6(&b, 0 /* hop-by-hop */, TEST_V6_A, TEST_V6_B, 8 + 8 + 8 + 16);
    put_hopopts(&b, 44);
    put_frag6(&b, IPPROTO_NUM_UDP, 0, 1); /* first fragment */
    put_udp(&b, 3478, 3479, 100);         /* whole datagram is larger */
    bb_fill(&b, 0x11, 16);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.frag, FRAG_FIRST);
    CHECK_EQ(pi.ip_proto, IPPROTO_NUM_UDP);
    CHECK(pi.has_l4);
    CHECK_EQ(pi.src_port, 3478);
    CHECK_EQ(pi.dst_port, 3479);
    bb_free(&b);

    /* The same chain in a later fragment: protocol known, no ports. */
    put_eth(&b, ETHERTYPE_IPV6);
    put_ipv6(&b, 0, TEST_V6_A, TEST_V6_B, 8 + 8 + 16);
    put_hopopts(&b, 44);
    put_frag6(&b, IPPROTO_NUM_UDP, 3, 0);
    bb_fill(&b, 0x22, 16);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.frag, FRAG_LATER);
    CHECK_EQ(pi.ip_proto, IPPROTO_NUM_UDP);
    CHECK(!pi.has_l4);
    CHECK_EQ(pi.src_port, 0);
    bb_free(&b);
}

static void test_ipv6_dstopts_routing(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV6);
    put_ipv6(&b, 60, TEST_V6_A, TEST_V6_B, 16 + 8 + 20);
    bb_u8(&b, 43);              /* destination options -> routing */
    bb_u8(&b, 1);               /* (1 + 1) * 8 = 16 bytes */
    bb_fill(&b, 0, 14);
    bb_u8(&b, IPPROTO_NUM_TCP); /* routing -> TCP */
    bb_u8(&b, 0);               /* 8 bytes */
    bb_fill(&b, 0, 6);
    put_tcp(&b, 8080, 50001, TCP_SYN);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.ip_proto, IPPROTO_NUM_TCP);
    CHECK_EQ(pi.src_port, 8080);
    CHECK_EQ(pi.tcp_flags, TCP_SYN);
    bb_free(&b);
}

static void build_dstopts_chain(struct bytebuf *b, unsigned count)
{
    unsigned i;

    put_eth(b, ETHERTYPE_IPV6);
    put_ipv6(b, 60, TEST_V6_A, TEST_V6_B, 8 * (size_t)count + 8);
    for (i = 0; i < count; i++)
        put_hopopts(b, i + 1 < count ? 60 : IPPROTO_NUM_UDP);
    put_udp(b, 1, 2, 0);
}

static void test_ipv6_ext_chain_limit(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    build_dstopts_chain(&b, 8); /* at the limit: accepted */
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.dst_port, 2);
    bb_free(&b);

    build_dstopts_chain(&b, 9); /* one more: rejected, loop stays bounded */
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_IPV6_EXT);
    bb_free(&b);
}

static void test_ipv6_ext_overrun(void)
{
    struct bytebuf b;
    struct packet_info pi;

    /* Hop-by-hop claims 48 bytes but the IPv6 payload is only 16. */
    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV6);
    put_ipv6(&b, 0, TEST_V6_A, TEST_V6_B, 16);
    bb_u8(&b, 59);
    bb_u8(&b, 5);
    bb_fill(&b, 0, 14);
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_IPV6_EXT);
    bb_free(&b);

    /* A consistent 48-byte header, but the capture stops inside it. */
    put_eth(&b, ETHERTYPE_IPV6);
    put_ipv6(&b, 0, TEST_V6_A, TEST_V6_B, 48);
    bb_u8(&b, 59);
    bb_u8(&b, 5);
    bb_fill(&b, 0, 46);
    CHECK_EQ(decode_snap(&b, 14 + 40 + 20, b.len, &pi), DEC_TRUNC_IPV6_EXT);
    bb_free(&b);
}

static void test_bad_ihl(void)
{
    struct bytebuf b;
    struct packet_info pi;
    unsigned ihl;

    for (ihl = 0; ihl < 5; ihl++) {
        bb_init(&b);
        frame_v4_tcp(&b, TEST_V4_A, TEST_V4_B, 1, 2, TCP_SYN, 0);
        b.data[14] = (uint8_t)(0x40 | ihl);
        CHECK_EQ(decode_all(&b, &pi), DEC_BAD_IPV4_IHL);
        CHECK(!pi.has_l3);
        bb_free(&b);
    }
}

static void test_bad_ipv4_total_len(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    frame_v4_tcp(&b, TEST_V4_A, TEST_V4_B, 1, 2, TCP_SYN, 0);
    b.data[16] = 0;
    b.data[17] = 19;            /* shorter than the header itself */
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_IPV4_TOTAL_LEN);
    b.data[16] = 0x05;
    b.data[17] = 0xDC;          /* 1500, in a 54-byte complete frame */
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_IPV4_TOTAL_LEN);
    bb_free(&b);
}

static void test_bad_tcp_doff(void)
{
    struct bytebuf b;
    struct packet_info pi;
    const size_t doff_at = 14 + 20 + 12;

    bb_init(&b);
    frame_v4_tcp(&b, TEST_V4_A, TEST_V4_B, 1, 2, TCP_SYN, 0);
    b.data[doff_at] = 4 << 4;   /* 16 bytes: below the 20-byte minimum */
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_TCP_DOFF);
    CHECK(!pi.has_l4);
    b.data[doff_at] = 0;
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_TCP_DOFF);
    b.data[doff_at] = 15 << 4;  /* 60 bytes, but the IP payload is 20 */
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_TCP_DOFF);
    bb_free(&b);
}

static void test_ipv6_payload_exceeds_caplen(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV6);
    put_ipv6(&b, IPPROTO_NUM_UDP, TEST_V6_A, TEST_V6_B, 1000);
    put_udp(&b, 53, 53, 992);
    bb_fill(&b, 0, 20);
    /* Complete frame (caplen == wirelen) yet 1000 bytes are claimed. */
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_IPV6_PAYLOAD_LEN);
    CHECK(!pi.has_l3);
    bb_free(&b);
}

static void test_snaplen_truncation_is_not_malformed(void)
{
    struct bytebuf b;
    struct packet_info pi;

    /* A 1000-byte payload captured with a small snapshot length: only the
     * headers are present, and the wire length says so. */
    bb_init(&b);
    frame_v6_tcp(&b, TEST_V6_A, TEST_V6_B, 443, 55555, TCP_ACK, 1000);
    CHECK_EQ(decode_snap(&b, 14 + 40 + 20, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.src_port, 443);
    CHECK_EQ(decode_snap(&b, 14 + 40 + 10, b.len, &pi), DEC_TRUNC_TCP);
    bb_free(&b);

    frame_v4_udp(&b, TEST_V4_A, TEST_V4_B, 123, 123, 1000);
    CHECK_EQ(decode_snap(&b, 14 + 20 + 8, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.dst_port, 123);
    CHECK_EQ(decode_snap(&b, 14 + 20 + 4, b.len, &pi), DEC_TRUNC_UDP);
    bb_free(&b);
}

static void test_ip_payload_too_short_for_l4(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV4);
    put_ipv4(&b, IPPROTO_NUM_TCP, TEST_V4_A, TEST_V4_B, 10, 0, 0);
    bb_fill(&b, 0, 10);
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_L4_LEN);
    CHECK(pi.has_l3);
    CHECK(!pi.has_l4);
    bb_free(&b);
}

static void test_bad_udp_len(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    frame_v4_udp(&b, TEST_V4_A, TEST_V4_B, 1, 2, 10);
    b.data[14 + 20 + 5] = 4;    /* UDP length 4 < 8 */
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_UDP_LEN);
    b.data[14 + 20 + 5] = 100;  /* beyond the 18-byte IP payload */
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_UDP_LEN);
    bb_free(&b);
}

static void test_wrong_ip_version(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    frame_v4_tcp(&b, TEST_V4_A, TEST_V4_B, 1, 2, TCP_SYN, 0);
    b.data[14] = 0x65;
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_IPV4_VERSION);
    bb_free(&b);

    frame_v6_tcp(&b, TEST_V6_A, TEST_V6_B, 1, 2, TCP_SYN, 0);
    b.data[14] = 0x40;
    CHECK_EQ(decode_all(&b, &pi), DEC_BAD_IPV6_VERSION);
    bb_free(&b);
}

static void test_truncated_ethernet(void)
{
    struct bytebuf b;
    struct packet_info pi;
    size_t len;

    bb_init(&b);
    frame_v4_tcp(&b, TEST_V4_A, TEST_V4_B, 1, 2, TCP_SYN, 0);
    for (len = 0; len < 14; len++) {
        CHECK_EQ(decode_snap(&b, len, b.len, &pi), DEC_TRUNC_ETHERNET);
        CHECK(!pi.has_l2);
    }
    CHECK_EQ(decode_snap(&b, 14 + 19, b.len, &pi), DEC_TRUNC_IPV4);
    bb_free(&b);
}

static void test_non_ip_frame(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_ARP);
    bb_fill(&b, 0, 28);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(pi.has_l2);
    CHECK(!pi.has_l3);
    CHECK_EQ(pi.ethertype, ETHERTYPE_ARP);
    bb_free(&b);
}

static void test_ethernet_padding(void)
{
    struct bytebuf b;
    struct packet_info pi;

    /* 14 + 20 + 8 + 2 = 44 bytes, padded to the 60-byte Ethernet minimum.
     * The IP total length, not the frame length, bounds the payload. */
    bb_init(&b);
    frame_v4_udp(&b, TEST_V4_A, TEST_V4_B, 7, 9, 2);
    bb_fill(&b, 0, 60 - b.len);
    CHECK_EQ(b.len, 60);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.dst_port, 9);
    bb_free(&b);
}

static void test_other_l4_protocol(void)
{
    struct bytebuf b;
    struct packet_info pi;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_IPV4);
    put_ipv4(&b, 47 /* GRE */, TEST_V4_A, TEST_V4_B, 4, 0, 0);
    bb_fill(&b, 0, 4);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(pi.has_l3);
    CHECK(!pi.has_l4);
    CHECK_EQ(pi.ip_proto, 47);
    bb_free(&b);
}

/* Decode every prefix of a valid frame, both as a snapped capture and as a
 * complete (short) frame. Nothing may crash or read out of bounds, and only
 * the full frame may decode cleanly. */
static void check_all_prefixes(const struct bytebuf *b)
{
    struct packet_info pi;
    size_t len;

    for (len = 0; len <= b->len; len++) {
        enum decode_status snapped = decode_snap(b, len, b->len, &pi);
        enum decode_status whole = decode_snap(b, len, len, &pi);

        CHECK((unsigned)snapped < DEC_STATUS_COUNT);
        CHECK((unsigned)whole < DEC_STATUS_COUNT);
        if (len == b->len) {
            CHECK_EQ(snapped, DEC_OK);
            CHECK_EQ(whole, DEC_OK);
        }
    }
}

static void test_every_prefix_is_safe(void)
{
    struct bytebuf b;

    bb_init(&b);
    put_eth(&b, ETHERTYPE_QINQ);
    put_vlan(&b, 10, ETHERTYPE_VLAN);
    put_vlan(&b, 20, ETHERTYPE_IPV4);
    put_ipv4(&b, IPPROTO_NUM_TCP, TEST_V4_A, TEST_V4_B, 20, 2, 0);
    put_tcp(&b, 1, 2, TCP_SYN);
    check_all_prefixes(&b);
    bb_free(&b);

    put_eth(&b, ETHERTYPE_IPV6);
    put_ipv6(&b, 0, TEST_V6_A, TEST_V6_B, 8 + 8 + 8);
    put_hopopts(&b, 44);
    put_frag6(&b, IPPROTO_NUM_UDP, 0, 1);
    put_udp(&b, 1, 2, 100);
    check_all_prefixes(&b);
    bb_free(&b);
}

static void test_status_strings(void)
{
    unsigned i, j;

    for (i = 0; i < DEC_STATUS_COUNT; i++) {
        const char *s = decode_status_str((enum decode_status)i);
        CHECK(s != NULL && s[0] != '\0' && strcmp(s, "unknown") != 0);
        for (j = 0; j < i; j++)
            CHECK(strcmp(s, decode_status_str((enum decode_status)j)) != 0);
    }
    CHECK(!decode_status_is_truncation(DEC_OK));
    CHECK(decode_status_is_truncation(DEC_TRUNC_ETHERNET));
    CHECK(decode_status_is_truncation(DEC_TRUNC_ICMP));
    CHECK(!decode_status_is_truncation(DEC_BAD_VLAN_DEPTH));
    CHECK(!decode_status_is_truncation(DEC_BAD_UDP_LEN));
}

void run_decode_tests(void)
{
    RUN_TEST(test_ipv4_tcp);
    RUN_TEST(test_ipv4_udp);
    RUN_TEST(test_icmp);
    RUN_TEST(test_icmpv6);
    RUN_TEST(test_ipv6_tcp);
    RUN_TEST(test_single_vlan);
    RUN_TEST(test_double_vlan);
    RUN_TEST(test_vlan_errors);
    RUN_TEST(test_ipv4_options);
    RUN_TEST(test_ipv4_options_snapped);
    RUN_TEST(test_ipv4_nonfirst_fragment);
    RUN_TEST(test_ipv4_first_fragment);
    RUN_TEST(test_ipv6_hopbyhop_fragment);
    RUN_TEST(test_ipv6_dstopts_routing);
    RUN_TEST(test_ipv6_ext_chain_limit);
    RUN_TEST(test_ipv6_ext_overrun);
    RUN_TEST(test_bad_ihl);
    RUN_TEST(test_bad_ipv4_total_len);
    RUN_TEST(test_bad_tcp_doff);
    RUN_TEST(test_ipv6_payload_exceeds_caplen);
    RUN_TEST(test_snaplen_truncation_is_not_malformed);
    RUN_TEST(test_ip_payload_too_short_for_l4);
    RUN_TEST(test_bad_udp_len);
    RUN_TEST(test_wrong_ip_version);
    RUN_TEST(test_truncated_ethernet);
    RUN_TEST(test_non_ip_frame);
    RUN_TEST(test_ethernet_padding);
    RUN_TEST(test_other_l4_protocol);
    RUN_TEST(test_every_prefix_is_safe);
    RUN_TEST(test_status_strings);
}
