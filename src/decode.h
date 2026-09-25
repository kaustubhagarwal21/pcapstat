/*
 * decode.h - bounds-checked decoding of one Ethernet frame.
 *
 * decode_frame() is a pure function: it reads only the bytes it is given,
 * keeps no state between calls, and never reads past `caplen`. Anything it
 * cannot decode is reported through packet_info.status instead of aborting,
 * so the caller can count it and move on.
 */
#ifndef PCAPSTAT_DECODE_H
#define PCAPSTAT_DECODE_H

#include <stddef.h>
#include <stdint.h>

#define DECODE_MAX_VLANS 2 /* 802.1Q, or 802.1ad Q-in-Q (outer + inner) */

#define ETHERTYPE_IPV4 0x0800u
#define ETHERTYPE_ARP  0x0806u
#define ETHERTYPE_VLAN 0x8100u /* 802.1Q customer tag */
#define ETHERTYPE_QINQ 0x88A8u /* 802.1ad service tag */
#define ETHERTYPE_QINQ_LEGACY 0x9100u /* pre-standard Q-in-Q tag */
#define ETHERTYPE_IPV6 0x86DDu

#define IPPROTO_NUM_ICMP   1u
#define IPPROTO_NUM_TCP    6u
#define IPPROTO_NUM_UDP   17u
#define IPPROTO_NUM_ICMPV6 58u

#define TCP_FIN 0x01u
#define TCP_SYN 0x02u
#define TCP_RST 0x04u
#define TCP_PSH 0x08u
#define TCP_ACK 0x10u
#define TCP_URG 0x20u
#define TCP_ECE 0x40u
#define TCP_CWR 0x80u

/* GTP-U, the GPRS Tunnelling Protocol for user data (3GPP TS 29.281). */
#define GTPU_PORT 2152u

/* First header byte: version (3 bits), PT, a spare bit, then E, S, PN. */
#define GTPU_FLAG_PT 0x10u /* protocol type: 1 = GTP, 0 = GTP' (charging) */
#define GTPU_FLAG_E  0x04u /* an extension header follows */
#define GTPU_FLAG_S  0x02u /* the sequence number field is meaningful */
#define GTPU_FLAG_PN 0x01u /* the N-PDU number field is meaningful */

#define GTPU_MSG_ECHO_REQUEST     1u
#define GTPU_MSG_ECHO_RESPONSE    2u
#define GTPU_MSG_ERROR_INDICATION 26u
#define GTPU_MSG_END_MARKER       254u
#define GTPU_MSG_GPDU             255u /* carries one user IP packet */

/* Real packets carry one or two extension headers. The bound keeps a
 * crafted chain from making the loop run long. */
#define GTPU_MAX_EXT_HEADERS 16u

/*
 * Why a frame could not be fully decoded. "Truncated" means the capture
 * stopped before a header ended (a small snapshot length, or a damaged
 * file); the packet itself may have been fine. "Malformed" means a header
 * field is impossible: it contradicts itself or the size of the frame.
 *
 * The same values describe the outer packet (packet_info.status) and a
 * GTP-U message with the user packet inside it (packet_info.gtp_status).
 * All the truncation values come first: decode_status_is_truncation()
 * tests that range.
 */
enum decode_status {
    DEC_OK = 0,

    DEC_TRUNC_ETHERNET,
    DEC_TRUNC_VLAN,
    DEC_TRUNC_IPV4,
    DEC_TRUNC_IPV6,
    DEC_TRUNC_IPV6_EXT,
    DEC_TRUNC_TCP,
    DEC_TRUNC_UDP,
    DEC_TRUNC_ICMP,
    DEC_TRUNC_GTPU,           /* inside the GTP-U header or its optional fields */
    DEC_TRUNC_GTPU_EXT,       /* inside a GTP-U extension header */
    DEC_TRUNC_GTPU_INNER,     /* before the first byte of a G-PDU's user packet */

    DEC_BAD_SHORT_FRAME,      /* whole frame shorter than a fixed-size header */
    DEC_BAD_VLAN_DEPTH,       /* more than DECODE_MAX_VLANS tags */
    DEC_BAD_IPV4_VERSION,     /* ethertype says IPv4, version nibble disagrees */
    DEC_BAD_IPV4_IHL,         /* header length below the 20-byte minimum */
    DEC_BAD_IPV4_TOTAL_LEN,   /* total length < header, or > frame */
    DEC_BAD_IPV6_VERSION,
    DEC_BAD_IPV6_PAYLOAD_LEN, /* payload length > frame */
    DEC_BAD_IPV6_EXT,         /* extension header overruns payload, or chain too long */
    DEC_BAD_L4_LEN,           /* IP payload too short for the L4 header */
    DEC_BAD_TCP_DOFF,         /* TCP data offset < 5 or beyond the IP payload */
    DEC_BAD_UDP_LEN,          /* UDP length < 8 or beyond the IP payload */
    DEC_BAD_GTPU_LEN,         /* GTP-U length > UDP payload, or too short for
                                 the optional fields the flags announce */
    DEC_BAD_GTPU_EXT_LEN,     /* extension header with length 0 */
    DEC_BAD_GTPU_EXT,         /* extension header overruns the message, or
                                 more than GTPU_MAX_EXT_HEADERS of them */
    DEC_BAD_GTPU_INNER,       /* G-PDU payload empty or not IPv4/IPv6 */
    DEC_BAD_GTPU_INNER_SHORT, /* G-PDU payload shorter than the fixed IPv4
                                 or IPv6 header it starts */

    DEC_STATUS_COUNT
};

enum frag_kind {
    FRAG_NONE = 0,  /* not fragmented */
    FRAG_FIRST,     /* offset 0, more fragments follow: carries the L4 header */
    FRAG_LATER      /* offset > 0: no L4 header, so it is not decoded */
};

struct packet_info {
    enum decode_status status;

    /* Which layers were decoded. has_l3 means the IP header was valid and
     * the addresses and protocol below can be trusted. */
    uint8_t has_l2;
    uint8_t has_l3;
    uint8_t has_l4;

    /* L2 */
    uint16_t ethertype;                 /* after any VLAN tags */
    uint8_t vlan_count;
    uint16_t vlan_ids[DECODE_MAX_VLANS]; /* 12-bit VLAN IDs, outermost first */

    /* L3 */
    uint8_t ip_version;                 /* 4 or 6 when has_l3 */
    uint8_t ip_proto;                   /* IPv4 protocol / IPv6 final next header;
                                           left 0 if the IPv6 extension chain
                                           is broken before its end */
    uint8_t src_addr[16];               /* IPv4 uses the first 4 bytes, rest 0 */
    uint8_t dst_addr[16];
    enum frag_kind frag;
    uint32_t frag_id;                   /* IPv4 identification or IPv6 fragment
                                           header ID; meaningful when fragmented */

    /* L4 (valid when has_l4) */
    uint16_t src_port;                  /* TCP/UDP only */
    uint16_t dst_port;
    uint8_t tcp_flags;                  /* TCP_* bits */
    uint8_t icmp_type;                  /* ICMP and ICMPv6 */
    uint8_t icmp_code;

    /* GTP-U. is_gtpu is set for a cleanly decoded, unfragmented UDP
     * datagram to or from port 2152 with at least 8 bytes of payload; the
     * GTP-U decoder then ran on that payload, and gtp_status says how far
     * it got. The fields above always describe the outer packet, and
     * pi->status is not changed by anything inside the tunnel. */
    uint8_t is_gtpu;
    enum decode_status gtp_status;      /* DEC_OK unless is_gtpu */
    uint8_t gtp_v1u;                    /* header read and it is GTPv1-U
                                           (version 1, PT 1); only then are
                                           the GTP fields below set */
    uint8_t gtp_flags;                  /* first header byte: version, PT,
                                           E, S, PN (GTPU_FLAG_*) */
    uint8_t gtp_msg_type;               /* GTPU_MSG_* */
    uint8_t gtp_msg_ok;                 /* the GTP-U headers (header,
                                           optional fields, extension
                                           headers) were read in full and
                                           are consistent. A G-PDU's user
                                           packet may still have failed:
                                           gtp_status then says why */
    uint16_t gtp_seq;                   /* valid when GTPU_FLAG_S is set */
    uint32_t teid;                      /* tunnel endpoint identifier */
    uint8_t gtp_ext_count;              /* extension headers walked */

    /* The user packet inside a G-PDU, decoded by the same IPv4/IPv6/L4
     * code as the outer packet. has_inner means its IP header was valid. */
    uint8_t has_inner;
    uint8_t inner_has_l4;
    uint8_t gtp_nested;                 /* the user packet is UDP port 2152
                                           again: counted, never decoded */
    uint8_t inner_version;              /* 4 or 6 */
    uint8_t inner_proto;                /* 0 if its IPv6 chain is broken */
    uint8_t inner_src[16];              /* IPv4 uses the first 4 bytes */
    uint8_t inner_dst[16];
    uint16_t inner_src_port;            /* TCP/UDP, when inner_has_l4 */
    uint16_t inner_dst_port;
};

/*
 * Decode one Ethernet frame. `caplen` is the number of bytes in `frame`;
 * `wirelen` is the frame's original length (pass caplen if unknown). The
 * difference lets the decoder tell snapshot-length truncation, which is
 * normal, from length fields that lie. Returns pi->status.
 */
enum decode_status decode_frame(const uint8_t *frame, size_t caplen,
                                size_t wirelen, struct packet_info *pi);

/* 1 if the packet has a decoded UDP header with port 2152 on either side
 * (whether or not it was decoded as GTP-U: a first IP fragment is not). */
int decode_is_gtpu_port(const struct packet_info *pi);

const char *decode_status_str(enum decode_status s);
int decode_status_is_truncation(enum decode_status s);

#endif /* PCAPSTAT_DECODE_H */
