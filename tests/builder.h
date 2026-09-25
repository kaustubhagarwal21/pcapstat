/*
 * builder.h - build packets and pcap files byte by byte, for tests and the
 * fuzzer. Every header is written field by field in network byte order, so
 * a test states exactly which bytes the decoder sees. Checksums are left 0:
 * the decoder does not verify them.
 */
#ifndef PCAPSTAT_BUILDER_H
#define PCAPSTAT_BUILDER_H

#include <stddef.h>
#include <stdint.h>

/* A growable byte buffer. Allocation failure aborts: this is test code. */
struct bytebuf {
    uint8_t *data;
    size_t len;
    size_t cap;
};

void bb_init(struct bytebuf *b);
void bb_free(struct bytebuf *b);
void bb_u8(struct bytebuf *b, unsigned v);
void bb_be16(struct bytebuf *b, unsigned v);
void bb_be32(struct bytebuf *b, uint32_t v);
void bb_u32(struct bytebuf *b, uint32_t v, int big_endian);
void bb_u16(struct bytebuf *b, unsigned v, int big_endian);
void bb_bytes(struct bytebuf *b, const void *p, size_t n);
void bb_fill(struct bytebuf *b, unsigned v, size_t n);

/* --- protocol headers ------------------------------------------------ */

/* 14-byte Ethernet header with fixed test MAC addresses. */
void put_eth(struct bytebuf *b, unsigned ethertype);
/* The 4 bytes after a VLAN TPID: tag control info, then next ethertype. */
void put_vlan(struct bytebuf *b, unsigned vid, unsigned next_ethertype);
/* IPv4 header with IHL = 5 + opt_words (options filled with NOP, 0x01).
 * total length = header + payload_len. frag is the raw flags+offset word. */
void put_ipv4(struct bytebuf *b, unsigned proto, const uint8_t src[4],
              const uint8_t dst[4], size_t payload_len, unsigned opt_words,
              unsigned frag);
void put_ipv6(struct bytebuf *b, unsigned next, const uint8_t src[16],
              const uint8_t dst[16], size_t payload_len);
/* 20-byte TCP header, data offset 5. */
void put_tcp(struct bytebuf *b, unsigned sport, unsigned dport,
             unsigned flags);
/* 8-byte UDP header; length = 8 + payload_len. */
void put_udp(struct bytebuf *b, unsigned sport, unsigned dport,
             size_t payload_len);
/* 8-byte ICMP/ICMPv6 echo-style header. */
void put_icmp(struct bytebuf *b, unsigned type, unsigned code);

/* --- whole frames ---------------------------------------------------- */

void frame_v4_tcp(struct bytebuf *b, const uint8_t src[4],
                  const uint8_t dst[4], unsigned sport, unsigned dport,
                  unsigned flags, size_t payload);
void frame_v4_udp(struct bytebuf *b, const uint8_t src[4],
                  const uint8_t dst[4], unsigned sport, unsigned dport,
                  size_t payload);
void frame_v6_tcp(struct bytebuf *b, const uint8_t src[16],
                  const uint8_t dst[16], unsigned sport, unsigned dport,
                  unsigned flags, size_t payload);

/* --- pcap files ------------------------------------------------------ */

void pcap_put_global(struct bytebuf *b, int big_endian, int nsec,
                     uint32_t snaplen, uint32_t linktype);
void pcap_put_record(struct bytebuf *b, int big_endian, uint32_t sec,
                     uint32_t frac, const uint8_t *data, uint32_t caplen,
                     uint32_t wirelen);

/* Write the buffer to a file. Returns 0 on success. */
int bb_write_file(const struct bytebuf *b, const char *path);

/* Well-known test addresses. */
extern const uint8_t TEST_V4_A[4], TEST_V4_B[4];
extern const uint8_t TEST_V6_A[16], TEST_V6_B[16];

#endif /* PCAPSTAT_BUILDER_H */
