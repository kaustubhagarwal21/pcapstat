/*
 * builder.c - byte-exact packet and pcap construction for tests.
 */
#include "builder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const uint8_t TEST_V4_A[4] = {10, 0, 0, 1};
const uint8_t TEST_V4_B[4] = {192, 168, 1, 20};
const uint8_t TEST_V6_A[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0x01};
const uint8_t TEST_V6_B[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0x02};

void bb_init(struct bytebuf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void bb_free(struct bytebuf *b)
{
    free(b->data);
    bb_init(b);
}

static void reserve(struct bytebuf *b, size_t extra)
{
    size_t want;

    if (extra > SIZE_MAX - b->len)
        abort();
    want = b->len + extra;
    if (want <= b->cap)
        return;
    if (b->cap == 0)
        b->cap = 64;
    while (b->cap < want)
        b->cap *= 2;
    b->data = realloc(b->data, b->cap);
    if (b->data == NULL) {
        fprintf(stderr, "builder: out of memory\n");
        abort();
    }
}

void bb_u8(struct bytebuf *b, unsigned v)
{
    reserve(b, 1);
    b->data[b->len++] = (uint8_t)v;
}

void bb_be16(struct bytebuf *b, unsigned v)
{
    bb_u8(b, (v >> 8) & 0xFF);
    bb_u8(b, v & 0xFF);
}

void bb_be32(struct bytebuf *b, uint32_t v)
{
    bb_be16(b, (unsigned)(v >> 16));
    bb_be16(b, (unsigned)(v & 0xFFFF));
}

void bb_u16(struct bytebuf *b, unsigned v, int big_endian)
{
    if (big_endian) {
        bb_be16(b, v);
    } else {
        bb_u8(b, v & 0xFF);
        bb_u8(b, (v >> 8) & 0xFF);
    }
}

void bb_u32(struct bytebuf *b, uint32_t v, int big_endian)
{
    if (big_endian) {
        bb_be32(b, v);
    } else {
        bb_u16(b, (unsigned)(v & 0xFFFF), 0);
        bb_u16(b, (unsigned)(v >> 16), 0);
    }
}

void bb_bytes(struct bytebuf *b, const void *p, size_t n)
{
    if (n == 0)
        return;
    reserve(b, n);
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

void bb_fill(struct bytebuf *b, unsigned v, size_t n)
{
    if (n == 0)
        return;
    reserve(b, n);
    memset(b->data + b->len, (int)(v & 0xFF), n);
    b->len += n;
}

void put_eth(struct bytebuf *b, unsigned ethertype)
{
    static const uint8_t dst[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    static const uint8_t src[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

    bb_bytes(b, dst, 6);
    bb_bytes(b, src, 6);
    bb_be16(b, ethertype);
}

void put_vlan(struct bytebuf *b, unsigned vid, unsigned next_ethertype)
{
    bb_be16(b, vid & 0x0FFF); /* priority 0, DEI 0 */
    bb_be16(b, next_ethertype);
}

void put_ipv4(struct bytebuf *b, unsigned proto, const uint8_t src[4],
              const uint8_t dst[4], size_t payload_len, unsigned opt_words,
              unsigned frag)
{
    size_t hlen = 20 + 4 * (size_t)opt_words;

    bb_u8(b, 0x40 | ((5 + opt_words) & 0x0F)); /* version 4, IHL */
    bb_u8(b, 0);                               /* DSCP/ECN */
    bb_be16(b, (unsigned)(hlen + payload_len)); /* total length */
    bb_be16(b, 0x1234);                        /* identification */
    bb_be16(b, frag);                          /* flags + fragment offset */
    bb_u8(b, 64);                              /* TTL */
    bb_u8(b, proto);
    bb_be16(b, 0);                             /* checksum (not checked) */
    bb_bytes(b, src, 4);
    bb_bytes(b, dst, 4);
    bb_fill(b, 0x01, 4 * (size_t)opt_words);   /* NOP options */
}

void put_ipv6(struct bytebuf *b, unsigned next, const uint8_t src[16],
              const uint8_t dst[16], size_t payload_len)
{
    bb_be32(b, 0x60000000u);             /* version 6, class 0, label 0 */
    bb_be16(b, (unsigned)payload_len);
    bb_u8(b, next);
    bb_u8(b, 64);                        /* hop limit */
    bb_bytes(b, src, 16);
    bb_bytes(b, dst, 16);
}

void put_tcp(struct bytebuf *b, unsigned sport, unsigned dport,
             unsigned flags)
{
    bb_be16(b, sport);
    bb_be16(b, dport);
    bb_be32(b, 1000);    /* sequence number */
    bb_be32(b, 2000);    /* acknowledgement number */
    bb_u8(b, 5 << 4);    /* data offset 5 words */
    bb_u8(b, flags);
    bb_be16(b, 65535);   /* window */
    bb_be16(b, 0);       /* checksum */
    bb_be16(b, 0);       /* urgent pointer */
}

void put_udp(struct bytebuf *b, unsigned sport, unsigned dport,
             size_t payload_len)
{
    bb_be16(b, sport);
    bb_be16(b, dport);
    bb_be16(b, (unsigned)(8 + payload_len));
    bb_be16(b, 0);
}

void put_icmp(struct bytebuf *b, unsigned type, unsigned code)
{
    bb_u8(b, type);
    bb_u8(b, code);
    bb_be16(b, 0);       /* checksum */
    bb_be16(b, 0x0042);  /* identifier */
    bb_be16(b, 1);       /* sequence */
}

void frame_v4_tcp(struct bytebuf *b, const uint8_t src[4],
                  const uint8_t dst[4], unsigned sport, unsigned dport,
                  unsigned flags, size_t payload)
{
    put_eth(b, 0x0800);
    put_ipv4(b, 6, src, dst, 20 + payload, 0, 0x4000 /* DF */);
    put_tcp(b, sport, dport, flags);
    bb_fill(b, 0xAB, payload);
}

void frame_v4_udp(struct bytebuf *b, const uint8_t src[4],
                  const uint8_t dst[4], unsigned sport, unsigned dport,
                  size_t payload)
{
    put_eth(b, 0x0800);
    put_ipv4(b, 17, src, dst, 8 + payload, 0, 0);
    put_udp(b, sport, dport, payload);
    bb_fill(b, 0xCD, payload);
}

void frame_v6_tcp(struct bytebuf *b, const uint8_t src[16],
                  const uint8_t dst[16], unsigned sport, unsigned dport,
                  unsigned flags, size_t payload)
{
    put_eth(b, 0x86DD);
    put_ipv6(b, 6, src, dst, 20 + payload);
    put_tcp(b, sport, dport, flags);
    bb_fill(b, 0xEF, payload);
}

void pcap_put_global(struct bytebuf *b, int big_endian, int nsec,
                     uint32_t snaplen, uint32_t linktype)
{
    /* The magic is written in the file's own byte order, which is exactly
     * how a reader learns that byte order. */
    bb_u32(b, nsec ? 0xA1B23C4Du : 0xA1B2C3D4u, big_endian);
    bb_u16(b, 2, big_endian);
    bb_u16(b, 4, big_endian);
    bb_u32(b, 0, big_endian);            /* thiszone */
    bb_u32(b, 0, big_endian);            /* sigfigs */
    bb_u32(b, snaplen, big_endian);
    bb_u32(b, linktype, big_endian);
}

void pcap_put_record(struct bytebuf *b, int big_endian, uint32_t sec,
                     uint32_t frac, const uint8_t *data, uint32_t caplen,
                     uint32_t wirelen)
{
    bb_u32(b, sec, big_endian);
    bb_u32(b, frac, big_endian);
    bb_u32(b, caplen, big_endian);
    bb_u32(b, wirelen, big_endian);
    bb_bytes(b, data, caplen);
}

int bb_write_file(const struct bytebuf *b, const char *path)
{
    FILE *f = fopen(path, "wb");
    int rc = 0;

    if (f == NULL)
        return -1;
    if (b->len > 0 && fwrite(b->data, 1, b->len, f) != b->len)
        rc = -1;
    if (fclose(f) != 0)
        rc = -1;
    return rc;
}
