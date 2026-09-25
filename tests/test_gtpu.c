/*
 * test_gtpu.c - GTP-U decoding, the tunnel table and tunnel output.
 *
 * As in test_decode.c, frames are copied into a heap buffer of exactly
 * caplen bytes before decoding, so under AddressSanitizer a read even one
 * byte past the capture is reported.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analyze.h"
#include "builder.h"
#include "decode.h"
#include "report.h"
#include "test.h"

#define SEC 1000000000ull

/* Transport addresses (the outer packet) and user addresses (inside). */
static const uint8_t RAN[4] = {172, 16, 1, 11};     /* base station */
static const uint8_t RAN2[4] = {172, 16, 1, 12};
static const uint8_t CORE[4] = {172, 16, 0, 1};     /* SGW-U or UPF */
static const uint8_t UE[4] = {100, 64, 0, 7};       /* the phone */
static const uint8_t SERVER[4] = {198, 51, 100, 20};

/* Bytes in front of the GTP-U header in an untagged IPv4 frame. */
#define GTP_AT (14 + 20 + 8)

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

/* A user packet: IPv4/TCP from the UE to a server, 40 bytes of headers
 * plus `payload` bytes. */
static void inner_v4_tcp(struct bytebuf *b, size_t payload)
{
    put_ipv4(b, IPPROTO_NUM_TCP, UE, SERVER, 20 + payload, 0, 0x4000);
    put_tcp(b, 40000, 443, TCP_SYN);
    bb_fill(b, 0xAB, payload);
}

/* Ethernet / IPv4 / UDP around a GTP-U message: the 8-byte header, whose
 * length field counts `rest`, then `rest` itself (optional fields,
 * extension headers and payload, already built). */
static void gtpu_frame4(struct bytebuf *b, const uint8_t src[4],
                        const uint8_t dst[4], unsigned sport, unsigned dport,
                        unsigned flags, unsigned type, uint32_t teid,
                        const struct bytebuf *rest)
{
    put_eth(b, ETHERTYPE_IPV4);
    put_ipv4(b, IPPROTO_NUM_UDP, src, dst, 8 + 8 + rest->len, 0, 0);
    put_udp(b, sport, dport, 8 + rest->len);
    put_gtpu(b, flags, type, rest->len, teid);
    bb_bytes(b, rest->data, rest->len);
}

/* The usual case: base station to core, port 2152 on both sides. */
static void gtpu_uplink(struct bytebuf *b, unsigned flags, unsigned type,
                        uint32_t teid, const struct bytebuf *rest)
{
    gtpu_frame4(b, RAN, CORE, GTPU_PORT, GTPU_PORT, flags, type, teid, rest);
}

static void test_gtpu_gpdu_ipv4_tcp(void)
{
    struct bytebuf in, b;
    struct packet_info pi;

    bb_init(&in);
    bb_init(&b);
    inner_v4_tcp(&in, 0);
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 0xDEADBEEFu, &in);
    CHECK_EQ(b.len, GTP_AT + 8 + 40);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);

    /* The outer fields still describe the transport packet. */
    CHECK(memcmp(pi.src_addr, RAN, 4) == 0);
    CHECK(memcmp(pi.dst_addr, CORE, 4) == 0);
    CHECK_EQ(pi.ip_proto, IPPROTO_NUM_UDP);
    CHECK_EQ(pi.src_port, GTPU_PORT);
    CHECK_EQ(pi.dst_port, GTPU_PORT);

    CHECK(pi.is_gtpu);
    CHECK(pi.gtp_v1u);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_flags, 0x30);
    CHECK_EQ(pi.gtp_msg_type, GTPU_MSG_GPDU);
    CHECK_EQ(pi.teid, 0xDEADBEEFu);  /* high bit set: no sign trouble */
    CHECK_EQ(pi.gtp_ext_count, 0);

    CHECK(pi.has_inner);
    CHECK(pi.inner_has_l4);
    CHECK_EQ(pi.inner_version, 4);
    CHECK_EQ(pi.inner_proto, IPPROTO_NUM_TCP);
    CHECK(memcmp(pi.inner_src, UE, 4) == 0);
    CHECK(memcmp(pi.inner_dst, SERVER, 4) == 0);
    CHECK_EQ(pi.inner_src_port, 40000);
    CHECK_EQ(pi.inner_dst_port, 443);
    CHECK(!pi.gtp_nested);
    bb_free(&b);
    bb_free(&in);
}

static void test_gtpu_inner_ipv6_udp(void)
{
    struct bytebuf in, b;
    struct packet_info pi;

    bb_init(&in);
    bb_init(&b);
    put_ipv6(&in, IPPROTO_NUM_UDP, TEST_V6_A, TEST_V6_B, 8 + 20);
    put_udp(&in, 5353, 53, 20);
    bb_fill(&in, 0, 20);
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 7, &in);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK(pi.has_inner && pi.inner_has_l4);
    CHECK_EQ(pi.inner_version, 6);
    CHECK_EQ(pi.inner_proto, IPPROTO_NUM_UDP);
    CHECK(memcmp(pi.inner_src, TEST_V6_A, 16) == 0);
    CHECK(memcmp(pi.inner_dst, TEST_V6_B, 16) == 0);
    CHECK_EQ(pi.inner_src_port, 5353);
    CHECK_EQ(pi.inner_dst_port, 53);
    CHECK_EQ(pi.ip_version, 4);      /* the transport is still IPv4 */
    bb_free(&b);
    bb_free(&in);
}

static void test_gtpu_optional_fields(void)
{
    struct bytebuf rest, b;
    struct packet_info pi;

    /* S set: 4 optional bytes follow the header, then the user packet. */
    bb_init(&rest);
    bb_init(&b);
    put_gtpu_opt(&rest, 0xBEEF, 0, 0);
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(&b, 0x32, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_seq, 0xBEEF);
    CHECK(pi.has_inner && pi.inner_has_l4);
    CHECK_EQ(pi.inner_src_port, 40000);
    bb_free(&b);
    bb_free(&rest);

    /* PN only: the optional bytes are there, but the sequence number is
     * not meaningful, so it is not taken. */
    put_gtpu_opt(&rest, 0xBEEF, 7, 0);
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(&b, 0x31, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_seq, 0);
    CHECK(pi.has_inner);
    bb_free(&b);
    bb_free(&rest);

    /* E clear: a non-zero next-type byte "shall not be interpreted", so
     * the user packet directly follows the optional bytes. */
    put_gtpu_opt(&rest, 1, 0, 0x85);
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(&b, 0x32, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_ext_count, 0);
    CHECK(pi.has_inner);
    CHECK_EQ(pi.inner_proto, IPPROTO_NUM_TCP);
    bb_free(&b);
    bb_free(&rest);
}

static void test_gtpu_one_extension(void)
{
    struct bytebuf rest, b;
    struct packet_info pi;

    /* 5G N3: E set and one PDU Session Container (type 0x85). Its length
     * is 1 unit = 4 bytes: length, PDU type (1 = uplink), QFI 9, next 0. */
    bb_init(&rest);
    bb_init(&b);
    put_gtpu_opt(&rest, 0, 0, 0x85);
    bb_u8(&rest, 1);
    bb_u8(&rest, 0x10);
    bb_u8(&rest, 9);
    bb_u8(&rest, 0);
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(&b, 0x34, GTPU_MSG_GPDU, 0x0A0B0C0Du, &rest);
    CHECK_EQ(b.len, GTP_AT + 8 + 4 + 4 + 40);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_flags & GTPU_FLAG_E, GTPU_FLAG_E);
    CHECK_EQ(pi.gtp_ext_count, 1);
    CHECK_EQ(pi.teid, 0x0A0B0C0Du);
    CHECK(pi.has_inner && pi.inner_has_l4);
    CHECK_EQ(pi.inner_dst_port, 443);
    bb_free(&b);
    bb_free(&rest);
}

static void test_gtpu_extension_chain(void)
{
    struct bytebuf rest, b;
    struct packet_info pi;

    /* A 2-unit (8-byte) header, then a 1-unit PDU Session Container. A
     * decoder that took the length as bytes instead of 4-byte units would
     * land in the middle of the first header. */
    bb_init(&rest);
    bb_init(&b);
    put_gtpu_opt(&rest, 5, 0, 0x81);
    put_gtpu_ext(&rest, 2, 0x85);
    put_gtpu_ext(&rest, 1, 0);
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(&b, 0x36, GTPU_MSG_GPDU, 3, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_ext_count, 2);
    CHECK_EQ(pi.gtp_seq, 5);
    CHECK(pi.has_inner && pi.inner_has_l4);
    CHECK_EQ(pi.inner_proto, IPPROTO_NUM_TCP);
    CHECK_EQ(pi.inner_src_port, 40000);
    bb_free(&b);
    bb_free(&rest);
}

static void test_gtpu_extension_length_zero(void)
{
    struct bytebuf rest, b;
    struct packet_info pi;

    bb_init(&rest);
    bb_init(&b);
    put_gtpu_opt(&rest, 0, 0, 0x85);
    bb_u8(&rest, 0);                 /* length 0: impossible */
    bb_u8(&rest, 0x10);
    bb_u8(&rest, 9);
    bb_u8(&rest, 0);
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(&b, 0x34, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);  /* the outer packet is fine */
    CHECK(pi.is_gtpu && pi.gtp_v1u);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_EXT_LEN);
    CHECK_EQ(pi.gtp_ext_count, 0);
    CHECK(!pi.has_inner);
    /* The 0 is in the captured bytes, so a snapshot length changes
     * nothing: it is still malformed. */
    CHECK_EQ(decode_snap(&b, b.len, b.len + 500, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_EXT_LEN);
    bb_free(&b);
    bb_free(&rest);
}

/* A chain of `count` 1-unit extension headers before an IPv4/TCP packet. */
static void build_ext_chain(struct bytebuf *b, unsigned count)
{
    struct bytebuf rest;
    unsigned i;

    bb_init(&rest);
    put_gtpu_opt(&rest, 0, 0, 0x85);
    for (i = 0; i < count; i++)
        put_gtpu_ext(&rest, 1, i + 1 < count ? 0x85 : 0);
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(b, 0x34, GTPU_MSG_GPDU, 1, &rest);
    bb_free(&rest);
}

static void test_gtpu_extension_overrun(void)
{
    struct bytebuf rest, b;
    struct packet_info pi;

    /* A 12-byte extension header with only 4 bytes left in the message:
     * malformed. */
    bb_init(&rest);
    bb_init(&b);
    put_gtpu_opt(&rest, 0, 0, 0x85);
    bb_u8(&rest, 3);
    bb_fill(&rest, 0, 3);
    gtpu_uplink(&b, 0x34, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_EXT);
    CHECK(!pi.has_inner);
    bb_free(&b);
    bb_free(&rest);

    /* The chain says another header follows, but the message ends. */
    put_gtpu_opt(&rest, 0, 0, 0x85);
    put_gtpu_ext(&rest, 1, 0x85);
    gtpu_uplink(&b, 0x34, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_EXT);
    CHECK_EQ(pi.gtp_ext_count, 1);
    bb_free(&b);
    bb_free(&rest);

    /* A consistent 12-byte header cut by the snapshot length: truncated,
     * and fine when captured in full. */
    put_gtpu_opt(&rest, 0, 0, 0x85);
    put_gtpu_ext(&rest, 3, 0);
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(&b, 0x34, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_snap(&b, GTP_AT + 8 + 4 + 6, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_TRUNC_GTPU_EXT);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK(pi.has_inner);
    bb_free(&b);
    bb_free(&rest);

    /* 16 headers are accepted; a 17th is refused, so a crafted chain
     * cannot make the walk run long. */
    build_ext_chain(&b, 16);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_ext_count, 16);
    CHECK(pi.has_inner);
    bb_free(&b);
    build_ext_chain(&b, 17);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_EXT);
    CHECK_EQ(pi.gtp_ext_count, 16);
    CHECK(!pi.has_inner);
    bb_free(&b);
}

static void test_gtpu_length_vs_payload(void)
{
    struct bytebuf in, rest, b;
    struct packet_info pi;

    bb_init(&in);
    bb_init(&rest);
    bb_init(&b);
    inner_v4_tcp(&in, 100);
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 1, &in);  /* GTP length 140 */

    /* One byte more than the UDP datagram holds. The UDP length is in the
     * captured bytes, so this is malformed even in a cut-short capture. */
    b.data[GTP_AT + 3]++;
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_LEN);
    CHECK(pi.gtp_v1u);               /* the header itself was read */
    CHECK_EQ(pi.teid, 1);
    CHECK(!pi.has_inner);
    CHECK_EQ(decode_snap(&b, GTP_AT + 8 + 40, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_LEN);
    b.data[GTP_AT + 3]--;

    /* The consistent message cut by a snapshot length at each layer. */
    CHECK_EQ(decode_snap(&b, GTP_AT + 4, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_TRUNC_GTPU);
    CHECK(pi.is_gtpu && !pi.gtp_v1u);
    CHECK_EQ(decode_snap(&b, GTP_AT + 8 + 10, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_TRUNC_IPV4);
    CHECK(!pi.has_inner);
    CHECK_EQ(decode_snap(&b, GTP_AT + 8 + 30, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_TRUNC_TCP);
    CHECK(pi.has_inner && !pi.inner_has_l4);
    /* Headers complete, user payload cut: nothing is missing that the
     * decoder needs. */
    CHECK_EQ(decode_snap(&b, GTP_AT + 8 + 40, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK(pi.inner_has_l4);
    bb_free(&b);

    /* A GTP-U length that covers only 60 bytes of the 140-byte user
     * packet, in a complete frame: the user packet contradicts it. */
    bb_bytes(&rest, in.data, 60);
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_IPV4_TOTAL_LEN);
    CHECK(!pi.has_inner);
    bb_free(&b);
    bb_free(&rest);

    /* S set, but the length leaves room for only 2 of the 4 optional
     * bytes. */
    bb_be16(&rest, 0x1234);
    gtpu_uplink(&b, 0x32, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_LEN);
    CHECK_EQ(decode_snap(&b, b.len, b.len + 100, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_LEN);
    bb_free(&b);
    bb_free(&rest);
    bb_free(&in);
}

static void test_gtpu_not_v1u(void)
{
    /* Version 2 (GTP-C), PT 0 (GTP', charging), version 0, version 7. */
    static const unsigned flags[] = {0x50, 0x20, 0x10, 0xF0};
    struct bytebuf in, b;
    struct packet_info pi;
    size_t i;

    bb_init(&in);
    bb_init(&b);
    inner_v4_tcp(&in, 0);
    for (i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        gtpu_uplink(&b, flags[i], GTPU_MSG_GPDU, 0x1234, &in);
        CHECK_EQ(decode_all(&b, &pi), DEC_OK);
        CHECK(pi.is_gtpu);
        CHECK(!pi.gtp_v1u);
        CHECK_EQ(pi.gtp_status, DEC_OK); /* not an error, just not GTP-U */
        CHECK_EQ(pi.teid, 0);            /* not decoded further */
        CHECK_EQ(pi.gtp_msg_type, 0);
        CHECK(!pi.has_inner);
        bb_free(&b);
    }
    bb_free(&in);
}

static void test_gtpu_echo(void)
{
    struct bytebuf rest, b;
    struct packet_info pi;

    /* Echo Request: S set, TEID 0, from a locally chosen port to 2152. */
    bb_init(&rest);
    bb_init(&b);
    put_gtpu_opt(&rest, 0x0102, 0, 0);
    gtpu_frame4(&b, RAN, CORE, 50000, GTPU_PORT, 0x32,
                GTPU_MSG_ECHO_REQUEST, 0, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(pi.is_gtpu && pi.gtp_v1u);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_msg_type, GTPU_MSG_ECHO_REQUEST);
    CHECK_EQ(pi.gtp_seq, 0x0102);
    CHECK_EQ(pi.teid, 0);
    CHECK(!pi.has_inner);
    bb_free(&b);
    bb_free(&rest);

    /* Echo Response: back to that port, with the Recovery IE (type 14,
     * restart counter), which is not decoded. */
    put_gtpu_opt(&rest, 0x0102, 0, 0);
    bb_u8(&rest, 14);
    bb_u8(&rest, 0);
    gtpu_frame4(&b, CORE, RAN, GTPU_PORT, 50000, 0x32,
                GTPU_MSG_ECHO_RESPONSE, 0, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_msg_type, GTPU_MSG_ECHO_RESPONSE);
    CHECK_EQ(pi.gtp_seq, 0x0102);
    CHECK(!pi.has_inner);
    bb_free(&b);
    bb_free(&rest);
}

static void test_gtpu_signalling_messages(void)
{
    struct bytebuf rest, b;
    struct packet_info pi;

    /* Error Indication: TEID Data I (type 16) and GTP-U Peer Address
     * (type 133, 4 bytes) information elements. */
    bb_init(&rest);
    bb_init(&b);
    put_gtpu_opt(&rest, 0, 0, 0);
    bb_u8(&rest, 16);
    bb_be32(&rest, 0xDEADBEEFu);
    bb_u8(&rest, 133);
    bb_be16(&rest, 4);
    bb_bytes(&rest, RAN, 4);
    gtpu_frame4(&b, CORE, RAN, GTPU_PORT, GTPU_PORT, 0x32,
                GTPU_MSG_ERROR_INDICATION, 0, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_msg_type, GTPU_MSG_ERROR_INDICATION);
    CHECK(!pi.has_inner);
    bb_free(&b);
    bb_free(&rest);

    /* End Marker: a bare 8-byte header on the tunnel's own TEID. */
    gtpu_frame4(&b, CORE, RAN, GTPU_PORT, GTPU_PORT, 0x30,
                GTPU_MSG_END_MARKER, 0x5678, &rest);
    CHECK_EQ(b.len, GTP_AT + 8);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_msg_type, GTPU_MSG_END_MARKER);
    CHECK_EQ(pi.teid, 0x5678);
    bb_free(&b);

    /* Type 31 (Supported Extension Headers Notification): counted as
     * "other", its contents not decoded. */
    put_gtpu_opt(&rest, 0, 0, 0);
    bb_u8(&rest, 141);
    bb_u8(&rest, 1);
    bb_u8(&rest, 0x85);
    gtpu_uplink(&b, 0x32, 31, 0, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.gtp_msg_type, 31);
    CHECK(!pi.has_inner);
    bb_free(&b);
    bb_free(&rest);
}

static void test_gtpu_inner_not_ip(void)
{
    struct bytebuf rest, b;
    struct packet_info pi;

    /* The payload does not start with IP version 4 or 6. */
    bb_init(&rest);
    bb_init(&b);
    bb_fill(&rest, 0x00, 20);
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_INNER);
    CHECK(!pi.has_inner);
    bb_free(&b);
    rest.data[0] = 0x50;
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_INNER);
    bb_free(&b);
    bb_free(&rest);

    /* A G-PDU with no payload at all. */
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_GTPU_INNER);
    bb_free(&b);

    /* The capture ends right after the header of a G-PDU that does have a
     * payload: truncated, not malformed. */
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_snap(&b, GTP_AT + 8, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_TRUNC_GTPU_INNER);
    /* Cut inside the user packet's IPv4 header: truncated too. */
    CHECK_EQ(decode_snap(&b, GTP_AT + 8 + 12, b.len, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_TRUNC_IPV4);
    bb_free(&b);

    /* The same 12 bytes as the whole G-PDU payload: the user packet is too
     * short for its own header, which is malformed. */
    rest.len = 12;
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_BAD_SHORT_FRAME);
    bb_free(&b);
    bb_free(&rest);
}

static void test_gtpu_in_gtpu_not_decoded(void)
{
    struct bytebuf inner_rest, inner_msg, in, b;
    struct packet_info pi;

    /* The user packet is IPv4/UDP to port 2152 carrying another G-PDU,
     * whose extension header has length 0. Decoded, that would be an
     * error; instead it is flagged and left alone. */
    bb_init(&inner_rest);
    bb_init(&inner_msg);
    bb_init(&in);
    bb_init(&b);
    put_gtpu_opt(&inner_rest, 0, 0, 0x85);
    bb_fill(&inner_rest, 0, 4);
    inner_v4_tcp(&inner_rest, 0);
    put_gtpu(&inner_msg, 0x34, GTPU_MSG_GPDU, inner_rest.len, 0x99);
    bb_bytes(&inner_msg, inner_rest.data, inner_rest.len);
    put_ipv4(&in, IPPROTO_NUM_UDP, UE, SERVER, 8 + inner_msg.len, 0, 0);
    put_udp(&in, GTPU_PORT, GTPU_PORT, inner_msg.len);
    bb_bytes(&in, inner_msg.data, inner_msg.len);
    gtpu_uplink(&b, 0x30, GTPU_MSG_GPDU, 0x11, &in);

    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.teid, 0x11);         /* the outer tunnel's TEID */
    CHECK(pi.has_inner && pi.inner_has_l4);
    CHECK_EQ(pi.inner_proto, IPPROTO_NUM_UDP);
    CHECK_EQ(pi.inner_src_port, GTPU_PORT);
    CHECK_EQ(pi.inner_dst_port, GTPU_PORT);
    CHECK(pi.gtp_nested);
    bb_free(&b);
    bb_free(&in);
    bb_free(&inner_msg);
    bb_free(&inner_rest);
}

static void test_gtpu_port_detection(void)
{
    struct bytebuf rest, b;
    struct packet_info pi;

    bb_init(&rest);
    bb_init(&b);
    inner_v4_tcp(&rest, 0);

    /* Only the source port is 2152, as in a reply to a request that came
     * from another port. */
    gtpu_frame4(&b, CORE, RAN, GTPU_PORT, 40000, 0x30, GTPU_MSG_GPDU, 1,
                &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(pi.is_gtpu && pi.has_inner);
    bb_free(&b);

    /* Only the destination port. */
    gtpu_frame4(&b, RAN, CORE, 40000, GTPU_PORT, 0x30, GTPU_MSG_GPDU, 1,
                &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(pi.is_gtpu && pi.has_inner);
    bb_free(&b);

    /* Neither: 2123 is GTP-C, which is not decoded. */
    gtpu_frame4(&b, RAN, CORE, 2123, 2123, 0x30, GTPU_MSG_GPDU, 1, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(!pi.is_gtpu && !pi.has_inner);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    bb_free(&b);

    /* 7 bytes of payload is too short for a GTP-U header: plain UDP. */
    frame_v4_udp(&b, RAN, CORE, GTPU_PORT, GTPU_PORT, 7);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(!pi.is_gtpu);
    bb_free(&b);
    bb_free(&rest);

    /* Exactly 8 bytes: a bare header, such as an End Marker, is GTP-U. */
    gtpu_uplink(&b, 0x30, GTPU_MSG_END_MARKER, 9, &rest);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(pi.is_gtpu);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    bb_free(&b);

    /* TCP to port 2152 is not GTP-U. */
    frame_v4_tcp(&b, RAN, CORE, 40000, GTPU_PORT, TCP_ACK, 20);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK(!pi.is_gtpu);
    bb_free(&b);

    /* A first IP fragment holds only part of the datagram, so it is not
     * decoded (there is no reassembly), though its port is still seen. */
    put_eth(&b, ETHERTYPE_IPV4);
    put_ipv4(&b, IPPROTO_NUM_UDP, RAN, CORE, 8 + 8 + 40, 0, 0x2000);
    put_udp(&b, GTPU_PORT, GTPU_PORT, 8 + 40 + 1400);
    put_gtpu(&b, 0x30, GTPU_MSG_GPDU, 40 + 1400, 1);
    inner_v4_tcp(&b, 0);
    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.frag, FRAG_FIRST);
    CHECK(!pi.is_gtpu);
    CHECK(decode_is_gtpu_port(&pi));
    bb_free(&b);
}

static void test_gtpu_outer_ipv6_vlan(void)
{
    static const uint8_t ue6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0, 0, 7,
                                    0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t srv6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0xff, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0x20};
    struct bytebuf rest, b;
    struct packet_info pi;

    /* N3 over IPv6 on VLAN 300: downlink, a PDU Session Container with
     * QFI 5, and an ICMPv6 echo reply inside. */
    bb_init(&rest);
    bb_init(&b);
    put_gtpu_opt(&rest, 0, 0, 0x85);
    bb_u8(&rest, 1);
    bb_u8(&rest, 0x00);
    bb_u8(&rest, 5);
    bb_u8(&rest, 0);
    put_ipv6(&rest, IPPROTO_NUM_ICMPV6, srv6, ue6, 8);
    put_icmp(&rest, 129, 0);
    put_eth(&b, ETHERTYPE_VLAN);
    put_vlan(&b, 300, ETHERTYPE_IPV6);
    put_ipv6(&b, IPPROTO_NUM_UDP, TEST_V6_A, TEST_V6_B, 8 + 8 + rest.len);
    put_udp(&b, GTPU_PORT, GTPU_PORT, 8 + rest.len);
    put_gtpu(&b, 0x34, GTPU_MSG_GPDU, rest.len, 0xCAFE);
    bb_bytes(&b, rest.data, rest.len);

    CHECK_EQ(decode_all(&b, &pi), DEC_OK);
    CHECK_EQ(pi.vlan_count, 1);
    CHECK_EQ(pi.ip_version, 6);
    CHECK(pi.is_gtpu);
    CHECK_EQ(pi.gtp_status, DEC_OK);
    CHECK_EQ(pi.teid, 0xCAFE);
    CHECK_EQ(pi.gtp_ext_count, 1);
    CHECK(pi.has_inner && pi.inner_has_l4);
    CHECK_EQ(pi.inner_version, 6);
    CHECK_EQ(pi.inner_proto, IPPROTO_NUM_ICMPV6);
    CHECK(memcmp(pi.inner_dst, ue6, 16) == 0);
    CHECK_EQ(pi.inner_src_port, 0);
    bb_free(&b);
    bb_free(&rest);
}

/*
 * Two sweeps over a GTP-U message `msg`:
 *  - each prefix as the whole payload of a complete UDP datagram (outer
 *    lengths agree with it): the frame is whole, so GTP-U decoding must
 *    never call it truncated, and every prefix shorter than the message
 *    contradicts the message's own length field;
 *  - the full frame cut by a snapshot length at every point: the result
 *    is always OK or truncated, never blamed on the packet.
 */
static void check_gtpu_prefixes(const struct bytebuf *msg)
{
    struct bytebuf b;
    struct packet_info pi;
    size_t k, len;

    for (k = 0; k <= msg->len; k++) {
        bb_init(&b);
        put_eth(&b, ETHERTYPE_IPV4);
        put_ipv4(&b, IPPROTO_NUM_UDP, RAN, CORE, 8 + k, 0, 0);
        put_udp(&b, GTPU_PORT, GTPU_PORT, k);
        bb_bytes(&b, msg->data, k);
        CHECK_EQ(decode_all(&b, &pi), DEC_OK);
        CHECK_EQ(pi.is_gtpu, k >= 8);
        CHECK(!decode_status_is_truncation(pi.gtp_status));
        if (k == msg->len)
            CHECK_EQ(pi.gtp_status, DEC_OK);
        else if (k >= 8)
            CHECK(pi.gtp_status != DEC_OK);
        bb_free(&b);
    }

    put_eth(&b, ETHERTYPE_IPV4);
    put_ipv4(&b, IPPROTO_NUM_UDP, RAN, CORE, 8 + msg->len, 0, 0);
    put_udp(&b, GTPU_PORT, GTPU_PORT, msg->len);
    bb_bytes(&b, msg->data, msg->len);
    for (len = 0; len <= b.len; len++) {
        enum decode_status st = decode_snap(&b, len, b.len, &pi);

        CHECK(st == DEC_OK || decode_status_is_truncation(st));
        CHECK(pi.gtp_status == DEC_OK ||
              decode_status_is_truncation(pi.gtp_status));
        if (len == b.len)
            CHECK(pi.is_gtpu && pi.gtp_status == DEC_OK && pi.has_inner);
    }
    bb_free(&b);
}

static void test_gtpu_every_prefix(void)
{
    struct bytebuf rest, msg;

    /* S and E, a 2-unit then a 1-unit extension header, and an IPv6 user
     * packet with a hop-by-hop header before its UDP header. */
    bb_init(&rest);
    bb_init(&msg);
    put_gtpu_opt(&rest, 9, 0, 0x81);
    put_gtpu_ext(&rest, 2, 0x85);
    put_gtpu_ext(&rest, 1, 0);
    put_ipv6(&rest, 0, TEST_V6_A, TEST_V6_B, 8 + 8 + 4);
    bb_u8(&rest, IPPROTO_NUM_UDP);
    bb_u8(&rest, 0);
    bb_fill(&rest, 0, 6);
    put_udp(&rest, 443, 50000, 4);
    bb_fill(&rest, 0x5A, 4);
    put_gtpu(&msg, 0x36, GTPU_MSG_GPDU, rest.len, 0x01020304u);
    bb_bytes(&msg, rest.data, rest.len);
    check_gtpu_prefixes(&msg);
    bb_free(&msg);
    bb_free(&rest);

    /* The plain case: no optional fields, IPv4/TCP inside. */
    inner_v4_tcp(&rest, 10);
    put_gtpu(&msg, 0x30, GTPU_MSG_GPDU, rest.len, 0x42);
    bb_bytes(&msg, rest.data, rest.len);
    check_gtpu_prefixes(&msg);
    bb_free(&msg);
    bb_free(&rest);
}

/* --- the pipeline: counters, tunnels, output ------------------------- */

static void add_record(struct bytebuf *cap, struct bytebuf *fr, uint32_t sec)
{
    pcap_put_record(cap, 0, sec, 0, fr->data, (uint32_t)fr->len,
                    (uint32_t)fr->len);
    bb_free(fr);
}

/*
 * A capture with one of everything. The comments give each frame's length.
 *
 *   1  G-PDU  RAN  -> CORE  TEID 0x100, TCP + 100 bytes     190
 *   2  G-PDU  RAN  -> CORE  TEID 0x100, TCP                  90
 *   3  G-PDU  CORE -> RAN   TEID 0x200, TCP + 500 bytes     590
 *   4  G-PDU  RAN2 -> CORE  TEID 0x100 (same value, other sender)
 *   5  G-PDU  CORE -> RAN   TEID 0x100 (same value, other direction)
 *   6  echo request   RAN:50000 -> CORE:2152
 *   7  echo response  CORE:2152 -> RAN:50000
 *   8  end marker     CORE -> RAN  TEID 0x200
 *   9  G-PDU  RAN  -> CORE  TEID 0x300, extension length 0 (malformed)
 *  10  GTP' (PT 0)    RAN  -> CORE
 *  11  error indication  CORE -> RAN
 *  12  type 31 (other)   RAN  -> CORE
 *  13  G-PDU  RAN  -> CORE  TEID 0x400, extension header, IPv6/UDP inside
 *  14  G-PDU  RAN  -> CORE  TEID 0x500, GTP-U inside (not decoded)
 *  15  first IP fragment on port 2152 (not decoded)
 */
static void build_gtpu_capture(struct bytebuf *cap)
{
    struct bytebuf fr, rest, msg;
    uint32_t t = 100;

    bb_init(&fr);
    bb_init(&rest);
    bb_init(&msg);
    pcap_put_global(cap, 0, 0, 65535, 1);

    inner_v4_tcp(&rest, 100);                                   /* 1 */
    gtpu_uplink(&fr, 0x30, GTPU_MSG_GPDU, 0x100, &rest);
    add_record(cap, &fr, t++);
    bb_free(&rest);
    inner_v4_tcp(&rest, 0);                                     /* 2 */
    gtpu_uplink(&fr, 0x30, GTPU_MSG_GPDU, 0x100, &rest);
    add_record(cap, &fr, t++);
    bb_free(&rest);
    inner_v4_tcp(&rest, 500);                                   /* 3 */
    gtpu_frame4(&fr, CORE, RAN, GTPU_PORT, GTPU_PORT, 0x30, GTPU_MSG_GPDU,
                0x200, &rest);
    add_record(cap, &fr, t++);
    bb_free(&rest);
    inner_v4_tcp(&rest, 0);                                     /* 4 */
    gtpu_frame4(&fr, RAN2, CORE, GTPU_PORT, GTPU_PORT, 0x30, GTPU_MSG_GPDU,
                0x100, &rest);
    add_record(cap, &fr, t++);
    gtpu_frame4(&fr, CORE, RAN, GTPU_PORT, GTPU_PORT, 0x30, GTPU_MSG_GPDU,
                0x100, &rest);                                  /* 5 */
    add_record(cap, &fr, t++);
    bb_free(&rest);

    put_gtpu_opt(&rest, 7, 0, 0);                               /* 6 */
    gtpu_frame4(&fr, RAN, CORE, 50000, GTPU_PORT, 0x32,
                GTPU_MSG_ECHO_REQUEST, 0, &rest);
    add_record(cap, &fr, t++);
    bb_u8(&rest, 14);                                           /* 7 */
    bb_u8(&rest, 0);
    gtpu_frame4(&fr, CORE, RAN, GTPU_PORT, 50000, 0x32,
                GTPU_MSG_ECHO_RESPONSE, 0, &rest);
    add_record(cap, &fr, t++);
    bb_free(&rest);

    gtpu_frame4(&fr, CORE, RAN, GTPU_PORT, GTPU_PORT, 0x30,     /* 8 */
                GTPU_MSG_END_MARKER, 0x200, &rest);
    add_record(cap, &fr, t++);

    put_gtpu_opt(&rest, 0, 0, 0x85);                            /* 9 */
    bb_fill(&rest, 0, 4);
    inner_v4_tcp(&rest, 0);
    gtpu_uplink(&fr, 0x34, GTPU_MSG_GPDU, 0x300, &rest);
    add_record(cap, &fr, t++);
    bb_free(&rest);

    inner_v4_tcp(&rest, 0);                                     /* 10 */
    gtpu_uplink(&fr, 0x20, GTPU_MSG_GPDU, 0x600, &rest);
    add_record(cap, &fr, t++);
    bb_free(&rest);

    put_gtpu_opt(&rest, 0, 0, 0);                               /* 11 */
    bb_u8(&rest, 16);
    bb_be32(&rest, 0x100);
    gtpu_frame4(&fr, CORE, RAN, GTPU_PORT, GTPU_PORT, 0x32,
                GTPU_MSG_ERROR_INDICATION, 0, &rest);
    add_record(cap, &fr, t++);
    gtpu_uplink(&fr, 0x32, 31, 0, &rest);                       /* 12 */
    add_record(cap, &fr, t++);
    bb_free(&rest);

    put_gtpu_opt(&rest, 0, 0, 0x85);                            /* 13 */
    put_gtpu_ext(&rest, 1, 0);
    put_ipv6(&rest, IPPROTO_NUM_UDP, TEST_V6_A, TEST_V6_B, 8 + 20);
    put_udp(&rest, 50000, 443, 20);
    bb_fill(&rest, 0, 20);
    gtpu_uplink(&fr, 0x34, GTPU_MSG_GPDU, 0x400, &rest);
    add_record(cap, &fr, t++);
    bb_free(&rest);

    put_gtpu(&msg, 0x30, GTPU_MSG_GPDU, 40, 0x999);             /* 14 */
    inner_v4_tcp(&msg, 0);
    put_ipv4(&rest, IPPROTO_NUM_UDP, UE, SERVER, 8 + msg.len, 0, 0);
    put_udp(&rest, GTPU_PORT, GTPU_PORT, msg.len);
    bb_bytes(&rest, msg.data, msg.len);
    gtpu_uplink(&fr, 0x30, GTPU_MSG_GPDU, 0x500, &rest);
    add_record(cap, &fr, t++);
    bb_free(&rest);
    bb_free(&msg);

    put_eth(&fr, ETHERTYPE_IPV4);                               /* 15 */
    put_ipv4(&fr, IPPROTO_NUM_UDP, RAN, CORE, 8 + 8 + 40, 0, 0x2000);
    put_udp(&fr, GTPU_PORT, GTPU_PORT, 8 + 40 + 1400);
    put_gtpu(&fr, 0x30, GTPU_MSG_GPDU, 40 + 1400, 0x700);
    inner_v4_tcp(&fr, 0);
    add_record(cap, &fr, t++);
}

static void analyze_capture(const struct bytebuf *cap, struct analysis *an)
{
    struct pcap_reader r;

    CHECK_EQ(pcap_open_mem(&r, cap->data, cap->len), PCAP_OK);
    CHECK_EQ(analysis_init(an), 0);
    CHECK_EQ(analysis_run(an, &r), PCAP_EOF);
    pcap_close(&r);
}

static void test_gtpu_stats(void)
{
    struct bytebuf cap;
    struct analysis an;
    const struct gtpu_stats *g = &an.stats.gtpu;

    bb_init(&cap);
    build_gtpu_capture(&cap);
    analyze_capture(&cap, &an);

    CHECK_EQ(an.stats.packets, 15);
    CHECK_EQ(an.stats.malformed, 0);   /* every outer packet is fine */
    CHECK_EQ(an.stats.udp, 15);
    CHECK_EQ(g->packets, 14);
    CHECK_EQ(g->fragmented, 1);
    CHECK_EQ(g->not_v1u, 1);
    CHECK_EQ(g->gpdu, 8);
    CHECK_EQ(g->echo_request, 1);
    CHECK_EQ(g->echo_response, 1);
    CHECK_EQ(g->error_indication, 1);
    CHECK_EQ(g->end_marker, 1);
    CHECK_EQ(g->other_type, 1);
    CHECK_EQ(g->with_seq, 4);
    CHECK_EQ(g->with_ext, 1);          /* frame 9's header failed */
    CHECK_EQ(g->inner_ipv4, 6);
    CHECK_EQ(g->inner_ipv6, 1);
    CHECK_EQ(g->inner_tcp, 5);
    CHECK_EQ(g->inner_udp, 2);
    CHECK_EQ(g->nested, 1);
    CHECK_EQ(g->truncated, 0);
    CHECK_EQ(g->malformed, 1);
    CHECK_EQ(g->by_status[DEC_BAD_GTPU_EXT_LEN], 1);

    /* Outer flows are as before GTP-U decoding existed: frame 9, with its
     * bad GTP-U header, still counts in the RAN <-> CORE flow. */
    CHECK_EQ(an.flows.count, 3);       /* RAN<->CORE, RAN2<->CORE, echo */
    analysis_free(&an);
    bb_free(&cap);
}

static void test_tunnel_table(void)
{
    struct bytebuf cap;
    struct analysis an;
    const struct flow *top[10];
    struct packet_info key_pkt;
    struct flow_key key;
    const struct flow *f;
    size_t n, teids;

    bb_init(&cap);
    build_gtpu_capture(&cap);
    analyze_capture(&cap, &an);

    /* (RAN, CORE, 0x100), (CORE, RAN, 0x200), (RAN2, CORE, 0x100),
     * (CORE, RAN, 0x100), (RAN, CORE, 0x400), (RAN, CORE, 0x500). */
    CHECK_EQ(an.tunnels.count, 6);
    CHECK_EQ(flow_table_distinct_teids(&an.tunnels, &teids), 0);
    CHECK_EQ(teids, 4);

    n = flow_table_top_n(&an.tunnels, 10, top);
    CHECK_EQ(n, 6);
    CHECK_EQ(top[0]->key.teid, 0x200);
    CHECK_EQ(top[0]->packets, 1);      /* the end marker is not user data */
    CHECK_EQ(top[0]->bytes, 590);
    CHECK(memcmp(top[0]->key.addr_a, CORE, 4) == 0);
    CHECK_EQ(top[1]->key.teid, 0x100);
    CHECK_EQ(top[1]->packets, 2);
    CHECK_EQ(top[1]->bytes, 190 + 90);
    CHECK(memcmp(top[1]->key.addr_a, RAN, 4) == 0);

    /* Direction matters: TEID 0x100 from CORE to RAN is its own tunnel. */
    memset(&key_pkt, 0, sizeof key_pkt);
    key_pkt.is_gtpu = key_pkt.gtp_v1u = 1;
    key_pkt.ip_version = 4;
    key_pkt.ip_proto = IPPROTO_NUM_UDP;
    key_pkt.teid = 0x100;
    memcpy(key_pkt.src_addr, CORE, 4);
    memcpy(key_pkt.dst_addr, RAN, 4);
    CHECK(tunnel_key_from_packet(&key_pkt, &key));
    f = flow_table_find(&an.tunnels, &key);
    CHECK(f != NULL && f->packets == 1 && f->bytes == 90);

    /* The malformed G-PDU (TEID 0x300) and GTP' are in no tunnel. */
    key_pkt.teid = 0x300;
    memcpy(key_pkt.src_addr, RAN, 4);
    memcpy(key_pkt.dst_addr, CORE, 4);
    CHECK(tunnel_key_from_packet(&key_pkt, &key));
    CHECK(flow_table_find(&an.tunnels, &key) == NULL);
    key_pkt.gtp_v1u = 0;
    CHECK(!tunnel_key_from_packet(&key_pkt, &key));
    analysis_free(&an);
    bb_free(&cap);
}

/* A cleanly decoded G-PDU stand-in with only the fields the tunnel table
 * reads. */
static struct packet_info gpdu_pkt(const uint8_t *src, const uint8_t *dst,
                                   uint32_t teid)
{
    struct packet_info pi;

    memset(&pi, 0, sizeof pi);
    pi.has_l2 = pi.has_l3 = pi.has_l4 = 1;
    pi.ip_version = 4;
    pi.ip_proto = IPPROTO_NUM_UDP;
    memcpy(pi.src_addr, src, 4);
    memcpy(pi.dst_addr, dst, 4);
    pi.src_port = pi.dst_port = GTPU_PORT;
    pi.is_gtpu = pi.gtp_v1u = 1;
    pi.gtp_msg_type = GTPU_MSG_GPDU;
    pi.teid = teid;
    return pi;
}

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

static void test_tunnels_csv(void)
{
    static const char expect[] =
        "teid,src_addr,dst_addr,ip_version,packets,bytes,first_ts,last_ts,"
        "duration_s\n"
        "0xabcdef01,172.16.0.1,172.16.1.11,4,1,1000,"
        "1700000001.000000000,1700000001.000000000,0.000000000\n"
        "0x00000001,172.16.1.11,172.16.0.1,4,2,300,"
        "1700000000.000000001,1700000000.500000001,0.500000000\n";
    struct flow_table t;
    struct packet_info p;
    FILE *f = tmpfile();
    char *text;

    CHECK(f != NULL);
    if (f == NULL)
        return;
    CHECK_EQ(flow_table_init(&t, 0), 0);
    p = gpdu_pkt(RAN, CORE, 1);
    CHECK_EQ(flow_table_add_tunnel(&t, &p, 100, 1700000000ull * SEC + 1), 0);
    CHECK_EQ(flow_table_add_tunnel(&t, &p, 200,
                                   1700000000ull * SEC + SEC / 2 + 1), 0);
    p = gpdu_pkt(CORE, RAN, 0xABCDEF01u);
    CHECK_EQ(flow_table_add_tunnel(&t, &p, 1000, 1700000001ull * SEC), 0);
    /* A packet that is not GTPv1-U is ignored. */
    p.is_gtpu = 0;
    CHECK_EQ(flow_table_add_tunnel(&t, &p, 5000, 1700000002ull * SEC), 0);
    CHECK_EQ(t.count, 2);

    CHECK_EQ(report_tunnels_csv(f, &t), 0);
    text = slurp(f);
    CHECK(text != NULL && strcmp(text, expect) == 0);
    if (text != NULL && strcmp(text, expect) != 0)
        fprintf(stderr, "    got:\n%s    want:\n%s", text, expect);
    free(text);
    fclose(f);
    flow_table_free(&t);
}

static void test_gtpu_report_text(void)
{
    struct bytebuf cap;
    struct analysis an;
    struct stats empty;
    const struct flow *top[2];
    FILE *f = tmpfile();
    char *text;
    size_t n;

    CHECK(f != NULL);
    if (f == NULL)
        return;
    bb_init(&cap);
    build_gtpu_capture(&cap);
    analyze_capture(&cap, &an);
    CHECK_EQ(report_gtpu(f, &an.stats, &an.tunnels), 0);
    n = flow_table_top_n(&an.tunnels, 2, top);
    report_top_tunnels(f, top, n, an.tunnels.count);
    text = slurp(f);
    CHECK(text != NULL);
    if (text != NULL) {
        CHECK(strstr(text, "\nGTP-U:       14 packets on UDP port 2152\n")
              != NULL);
        CHECK(strstr(text, "  Messages:  G-PDU 8, echo request 1, echo "
                           "response 1, error indication 1, end marker 1, "
                           "other 1\n") != NULL);
        CHECK(strstr(text, "  Options:   sequence number in 4, extension "
                           "headers in 1\n") != NULL);
        CHECK(strstr(text, "  Inner IP:  IPv4 6, IPv6 1; TCP 5, UDP 2, "
                           "ICMP 0, ICMPv6 0, other 0\n") != NULL);
        CHECK(strstr(text, "  Tunnels:   6 (4 distinct TEIDs)\n") != NULL);
        CHECK(strstr(text, "  Skipped:   1 GTP' or other version, 1 GTP-U "
                           "in GTP-U, 1 IP fragments on port 2152\n")
              != NULL);
        CHECK(strstr(text, "  Problems:  0 truncated, 1 malformed") != NULL);
        CHECK(strstr(text, "    GTP-U extension header length 0") != NULL);
        CHECK(strstr(text, "Top 2 of 6 GTP-U tunnels by bytes") != NULL);
        CHECK(strstr(text, "  1  0x00000200  172.16.0.1   172.16.1.11") !=
              NULL);
    }
    free(text);
    fclose(f);
    analysis_free(&an);
    bb_free(&cap);

    /* Nothing at all for a capture without GTP-U. */
    f = tmpfile();
    CHECK(f != NULL);
    if (f == NULL)
        return;
    stats_init(&empty);
    CHECK_EQ(flow_table_init(&an.tunnels, 0), 0);
    CHECK_EQ(report_gtpu(f, &empty, &an.tunnels), 0);
    CHECK_EQ(ftell(f), 0);
    flow_table_free(&an.tunnels);
    fclose(f);
}

void run_gtpu_tests(void)
{
    RUN_TEST(test_gtpu_gpdu_ipv4_tcp);
    RUN_TEST(test_gtpu_inner_ipv6_udp);
    RUN_TEST(test_gtpu_optional_fields);
    RUN_TEST(test_gtpu_one_extension);
    RUN_TEST(test_gtpu_extension_chain);
    RUN_TEST(test_gtpu_extension_length_zero);
    RUN_TEST(test_gtpu_extension_overrun);
    RUN_TEST(test_gtpu_length_vs_payload);
    RUN_TEST(test_gtpu_not_v1u);
    RUN_TEST(test_gtpu_echo);
    RUN_TEST(test_gtpu_signalling_messages);
    RUN_TEST(test_gtpu_inner_not_ip);
    RUN_TEST(test_gtpu_in_gtpu_not_decoded);
    RUN_TEST(test_gtpu_port_detection);
    RUN_TEST(test_gtpu_outer_ipv6_vlan);
    RUN_TEST(test_gtpu_every_prefix);
    RUN_TEST(test_gtpu_stats);
    RUN_TEST(test_tunnel_table);
    RUN_TEST(test_tunnels_csv);
    RUN_TEST(test_gtpu_report_text);
}
