/*
 * decode.c - Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP / ICMP / GTP-U
 * decoder.
 *
 * The central idea is the `span`: a view of the bytes that remain at the
 * current layer, carrying two lengths.
 *
 *   cap  - bytes that are really in the capture buffer. Only these may be
 *          read. Every read in this file is preceded by a check against cap.
 *   wire - bytes that the enclosing header says exist (for example the IPv4
 *          total length minus the IP header). It can be larger than cap when
 *          the capture used a snapshot length.
 *
 * The invariant cap <= wire always holds. When a header needs n bytes and
 * n > cap, comparing n with wire tells us why: if n <= wire the packet was
 * fine but the capture stopped early (truncated); if n > wire the packet's
 * own length fields are inconsistent (malformed). Declared lengths from the
 * packet can only ever shrink a span, never grow it, so a lying length field
 * cannot move a read outside the buffer.
 *
 * Every "is there room?" check goes through need(), including the ones for
 * fixed-size headers (Ethernet, VLAN tag, IPv4, IPv6). So a frame that was
 * captured in full (caplen == wire length) keeps cap == wire at every layer
 * and can never be reported as truncated: if it is too short for a header,
 * the frame itself is at fault, and that is malformed.
 *
 * GTP-U follows the same rules one level down: the UDP length bounds the
 * GTP-U message, the GTP-U length bounds what follows its header, and the
 * user IP packet inside a G-PDU is decoded by the same IPv4/IPv6 code as
 * the outer packet, inside that span.
 */
#include "decode.h"

#include <string.h>

#include "bytes.h"

#define ETH_HDR_LEN     14u
#define VLAN_TAG_LEN     4u
#define IPV4_MIN_HDR    20u
#define IPV6_HDR_LEN    40u
#define IPV6_FRAG_LEN    8u
#define TCP_MIN_HDR     20u
#define UDP_HDR_LEN      8u
#define ICMP_MIN_HDR     4u  /* type, code, checksum */
#define GTPU_HDR_LEN     8u  /* flags, type, length, TEID */
#define GTPU_OPT_LEN     4u  /* sequence number, N-PDU number, next type */

/* IPv6 extension headers we step over to find the upper-layer protocol. */
#define IP6_EXT_HOPOPTS   0u
#define IP6_EXT_ROUTING  43u
#define IP6_EXT_FRAGMENT 44u
#define IP6_EXT_DSTOPTS  60u

/* Real packets carry at most a handful of extension headers. The bound
 * keeps a crafted chain from making the loop run long. */
#define IPV6_MAX_EXT_HEADERS 8u

struct span {
    const uint8_t *p;
    size_t cap;
    size_t wire;
};

/* Is there room for n bytes? If not, say whether the capture or the packet
 * is to blame. */
static enum decode_status need(const struct span *s, size_t n,
                               enum decode_status truncated,
                               enum decode_status malformed)
{
    if (n <= s->cap)
        return DEC_OK;
    return n <= s->wire ? truncated : malformed;
}

/* Step over n bytes. Callers have already checked n <= s->cap, and since
 * cap <= wire, neither subtraction can wrap. */
static void advance(struct span *s, size_t n)
{
    s->p += n;
    s->cap -= n;
    s->wire -= n;
}

/* Limit the span to a length declared by a header. Callers have already
 * checked len <= s->wire, so this only ever shrinks the span. */
static void clip(struct span *s, size_t len)
{
    if (s->cap > len)
        s->cap = len; /* e.g. drop Ethernet padding after a short IP packet */
    s->wire = len;
}

static enum decode_status decode_l4(struct span *s, struct packet_info *pi)
{
    enum decode_status st;

    switch (pi->ip_proto) {
    case IPPROTO_NUM_TCP: {
        size_t hlen;

        st = need(s, TCP_MIN_HDR, DEC_TRUNC_TCP, DEC_BAD_L4_LEN);
        if (st != DEC_OK)
            return st;
        pi->src_port = load_be16(s->p);
        pi->dst_port = load_be16(s->p + 2);
        pi->tcp_flags = s->p[13];

        /* Data offset: header length in 32-bit words, including options. */
        hlen = (size_t)(s->p[12] >> 4) * 4;
        if (hlen < TCP_MIN_HDR || hlen > s->wire)
            return DEC_BAD_TCP_DOFF;
        if (hlen > s->cap)
            return DEC_TRUNC_TCP; /* options cut off by the snapshot length */
        pi->has_l4 = 1;
        return DEC_OK;
    }
    case IPPROTO_NUM_UDP: {
        size_t ulen;

        st = need(s, UDP_HDR_LEN, DEC_TRUNC_UDP, DEC_BAD_L4_LEN);
        if (st != DEC_OK)
            return st;
        pi->src_port = load_be16(s->p);
        pi->dst_port = load_be16(s->p + 2);

        /* The UDP length covers the whole datagram. In a first fragment the
         * IP payload holds only part of it, so the upper-bound check only
         * applies to unfragmented packets. */
        ulen = load_be16(s->p + 4);
        if (ulen < UDP_HDR_LEN || (pi->frag == FRAG_NONE && ulen > s->wire))
            return DEC_BAD_UDP_LEN;
        /* In an unfragmented packet the UDP length is the datagram's real
         * size, so from here on the span covers exactly the datagram. That
         * matters for GTP-U, the one UDP payload that is decoded. */
        if (pi->frag == FRAG_NONE)
            clip(s, ulen);
        pi->has_l4 = 1;
        return DEC_OK;
    }
    case IPPROTO_NUM_ICMP:
    case IPPROTO_NUM_ICMPV6:
        st = need(s, ICMP_MIN_HDR, DEC_TRUNC_ICMP, DEC_BAD_L4_LEN);
        if (st != DEC_OK)
            return st;
        pi->icmp_type = s->p[0];
        pi->icmp_code = s->p[1];
        pi->has_l4 = 1;
        return DEC_OK;
    default:
        /* Some other protocol (GRE, ESP, SCTP, ...): the IP layer is still
         * valid, so the packet counts as "other" rather than as an error. */
        return DEC_OK;
    }
}

static enum decode_status decode_ipv4(struct span *s, struct packet_info *pi)
{
    const uint8_t *ip;
    size_t hlen, total;
    unsigned frag_offset, more_frags;
    enum decode_status st;

    st = need(s, IPV4_MIN_HDR, DEC_TRUNC_IPV4, DEC_BAD_SHORT_FRAME);
    if (st != DEC_OK)
        return st;
    ip = s->p;
    if ((ip[0] >> 4) != 4)
        return DEC_BAD_IPV4_VERSION;

    hlen = (size_t)(ip[0] & 0x0F) * 4; /* IHL is in 32-bit words: 20..60 */
    if (hlen < IPV4_MIN_HDR)
        return DEC_BAD_IPV4_IHL;

    total = load_be16(ip + 2);
    /* A total length of 0 shows up in packets captured on the sending host
     * when the NIC does TCP segmentation offload (TSO): the stack hands the
     * NIC one large packet and the NIC fills in the real lengths of the
     * segments it cuts. Like Wireshark, assume the packet runs to the end of
     * the frame. The checks below still apply. */
    if (total == 0)
        total = s->wire;
    if (total < hlen || total > s->wire)
        return DEC_BAD_IPV4_TOTAL_LEN;
    if (hlen > s->cap)
        return DEC_TRUNC_IPV4; /* options cut off by the snapshot length */

    pi->ip_version = 4;
    pi->ip_proto = ip[9];
    memcpy(pi->src_addr, ip + 12, 4);
    memcpy(pi->dst_addr, ip + 16, 4);

    /* Flags (3 bits) and fragment offset (13 bits, in 8-byte units). The
     * identification field ties the fragments of one datagram together. */
    pi->frag_id = load_be16(ip + 4);
    frag_offset = load_be16(ip + 6) & 0x1FFFu;
    more_frags = load_be16(ip + 6) & 0x2000u;
    if (frag_offset != 0)
        pi->frag = FRAG_LATER;
    else if (more_frags)
        pi->frag = FRAG_FIRST;
    pi->has_l3 = 1;

    clip(s, total);
    advance(s, hlen);

    /* Only the first fragment starts with the L4 header. The bytes at the
     * start of a later fragment are the middle of the payload; reading them
     * as ports would invent a bogus flow. */
    if (pi->frag == FRAG_LATER)
        return DEC_OK;
    return decode_l4(s, pi);
}

static int is_ipv6_ext(unsigned next)
{
    return next == IP6_EXT_HOPOPTS || next == IP6_EXT_ROUTING ||
           next == IP6_EXT_FRAGMENT || next == IP6_EXT_DSTOPTS;
}

static enum decode_status decode_ipv6(struct span *s, struct packet_info *pi)
{
    const uint8_t *ip;
    size_t payload;
    unsigned next, hops = 0;
    enum decode_status st;

    st = need(s, IPV6_HDR_LEN, DEC_TRUNC_IPV6, DEC_BAD_SHORT_FRAME);
    if (st != DEC_OK)
        return st;
    ip = s->p;
    if ((ip[0] >> 4) != 6)
        return DEC_BAD_IPV6_VERSION;

    /* cap >= 40 was checked above and wire >= cap, so wire - 40 is safe.
     * (A payload length of 0 would mean a jumbogram, which is not
     * supported; it simply leaves no room for the L4 header.) */
    payload = load_be16(ip + 4);
    if (payload > s->wire - IPV6_HDR_LEN)
        return DEC_BAD_IPV6_PAYLOAD_LEN;

    pi->ip_version = 6;
    next = ip[6];
    memcpy(pi->src_addr, ip + 8, 16);
    memcpy(pi->dst_addr, ip + 24, 16);
    pi->has_l3 = 1;

    advance(s, IPV6_HDR_LEN);
    clip(s, payload);

    /* pi->ip_proto is only set once the chain has been walked to its end.
     * If the chain is broken, the transport protocol is unknown, and it
     * stays 0 rather than naming whichever extension header failed. */
    while (is_ipv6_ext(next)) {
        if (hops++ == IPV6_MAX_EXT_HEADERS)
            return DEC_BAD_IPV6_EXT;

        if (next == IP6_EXT_FRAGMENT) {
            unsigned off_flags;

            st = need(s, IPV6_FRAG_LEN, DEC_TRUNC_IPV6_EXT, DEC_BAD_IPV6_EXT);
            if (st != DEC_OK)
                return st;
            /* 13-bit offset in 8-byte units, 2 reserved bits, M flag, then
             * the 32-bit identification shared by all the fragments. */
            off_flags = load_be16(s->p + 2);
            pi->frag_id = load_be32(s->p + 4);
            if ((off_flags >> 3) != 0)
                pi->frag = FRAG_LATER;
            else if (off_flags & 1u)
                pi->frag = FRAG_FIRST;
            /* else: an "atomic fragment" (RFC 6946), not really fragmented */
            next = s->p[0];
            advance(s, IPV6_FRAG_LEN);
            if (pi->frag == FRAG_LATER) {
                pi->ip_proto = (uint8_t)next;
                return DEC_OK; /* no L4 header in this fragment */
            }
        } else {
            size_t len;

            /* Hop-by-hop, routing and destination options share a layout:
             * next header (1 byte), length in 8-byte units not counting the
             * first 8 (1 byte), then options. */
            st = need(s, 2, DEC_TRUNC_IPV6_EXT, DEC_BAD_IPV6_EXT);
            if (st != DEC_OK)
                return st;
            len = ((size_t)s->p[1] + 1) * 8;
            st = need(s, len, DEC_TRUNC_IPV6_EXT, DEC_BAD_IPV6_EXT);
            if (st != DEC_OK)
                return st;
            next = s->p[0];
            advance(s, len);
        }
    }

    pi->ip_proto = (uint8_t)next;
    return decode_l4(s, pi);
}

int decode_is_gtpu_port(const struct packet_info *pi)
{
    return pi->has_l4 && pi->ip_proto == IPPROTO_NUM_UDP &&
           (pi->src_port == GTPU_PORT || pi->dst_port == GTPU_PORT);
}

/*
 * The payload of a G-PDU (the "T-PDU") is one user IP packet. No ethertype
 * precedes it, so its version nibble says which IP version it is. It goes
 * through the same decoders as the outer packet, into a scratch
 * packet_info, and the fields that describe it are copied out.
 */
static enum decode_status decode_gtpu_inner(struct span *s,
                                            struct packet_info *pi)
{
    struct packet_info in;
    enum decode_status st;

    st = need(s, 1, DEC_TRUNC_GTPU_INNER, DEC_BAD_GTPU_INNER);
    if (st != DEC_OK)
        return st;
    memset(&in, 0, sizeof in);
    switch (s->p[0] >> 4) {
    case 4:
        st = decode_ipv4(s, &in);
        break;
    case 6:
        st = decode_ipv6(s, &in);
        break;
    default:
        return DEC_BAD_GTPU_INNER;
    }
    /* The IP decoders call a packet that is too short for their fixed
     * header a short frame. Here the frame is fine: the GTP-U length left
     * too little room for the user packet, so give it a reason that says
     * so. No other check in those decoders returns DEC_BAD_SHORT_FRAME. */
    if (st == DEC_BAD_SHORT_FRAME)
        st = DEC_BAD_GTPU_INNER_SHORT;

    /* Keep whatever was valid, even if decoding failed further in: an
     * inner packet with a good IP header and a bad TCP header still has
     * known addresses, as the outer packet would. */
    if (in.has_l3) {
        pi->has_inner = 1;
        pi->inner_version = in.ip_version;
        pi->inner_proto = in.ip_proto;
        memcpy(pi->inner_src, in.src_addr, sizeof pi->inner_src);
        memcpy(pi->inner_dst, in.dst_addr, sizeof pi->inner_dst);
    }
    if (in.has_l4) {
        pi->inner_has_l4 = 1;
        pi->inner_src_port = in.src_port;
        pi->inner_dst_port = in.dst_port;
        /* GTP-U inside GTP-U is only flagged. decode_l4() never calls
         * decode_gtpu(), so this cannot recurse however deep a crafted
         * packet nests. */
        pi->gtp_nested = (uint8_t)decode_is_gtpu_port(&in);
    }
    return st;
}

/*
 * GTPv1-U (3GPP TS 29.281 section 5.1). `s` covers the UDP payload, which
 * the caller checked is at least 8 bytes on the wire.
 *
 *   byte 0     version (3 bits) | PT | spare | E | S | PN
 *   byte 1     message type
 *   bytes 2-3  length: the bytes after these first 8 (optional fields,
 *              extension headers and payload)
 *   bytes 4-7  TEID, the tunnel endpoint identifier chosen by the receiver
 *
 * If any of E, S or PN is set, 4 more bytes follow: sequence number (2),
 * N-PDU number (1) and the type of the first extension header (1). Each
 * extension header (section 5.2) starts with its length in 4-byte units
 * and ends with the type of the next one; type 0 ends the chain.
 */
static enum decode_status decode_gtpu(struct span *s, struct packet_info *pi)
{
    unsigned flags, next = 0, hops = 0;
    size_t len;
    enum decode_status st;

    /* wire >= 8 is known, so only the capture can cut the header short. */
    st = need(s, GTPU_HDR_LEN, DEC_TRUNC_GTPU, DEC_BAD_GTPU_LEN);
    if (st != DEC_OK)
        return st;

    /* PT 0 is GTP' (charging data) and version 2 is GTP-C. Neither is
     * GTP-U, so the packet is counted but not decoded further. */
    flags = s->p[0];
    if ((flags >> 5) != 1 || !(flags & GTPU_FLAG_PT))
        return DEC_OK;
    pi->gtp_v1u = 1;
    pi->gtp_flags = (uint8_t)flags;
    pi->gtp_msg_type = s->p[1];
    len = load_be16(s->p + 2);
    pi->teid = load_be32(s->p + 4);

    /* The length may not claim more than the UDP datagram holds. Like
     * every length from the packet, it can only shrink the span. */
    if (len > s->wire - GTPU_HDR_LEN)
        return DEC_BAD_GTPU_LEN;
    advance(s, GTPU_HDR_LEN);
    clip(s, len);

    /* If the length is too small for the optional fields that the flags
     * announce, need() finds wire < 4 and reports it as malformed. */
    if (flags & (GTPU_FLAG_E | GTPU_FLAG_S | GTPU_FLAG_PN)) {
        st = need(s, GTPU_OPT_LEN, DEC_TRUNC_GTPU, DEC_BAD_GTPU_LEN);
        if (st != DEC_OK)
            return st;
        if (flags & GTPU_FLAG_S)
            pi->gtp_seq = load_be16(s->p);
        /* With E clear, the next-type byte "shall not be interpreted". */
        if (flags & GTPU_FLAG_E)
            next = s->p[3];
        advance(s, GTPU_OPT_LEN);
    }

    while (next != 0) {
        size_t elen;

        if (hops++ == GTPU_MAX_EXT_HEADERS)
            return DEC_BAD_GTPU_EXT;
        st = need(s, 1, DEC_TRUNC_GTPU_EXT, DEC_BAD_GTPU_EXT);
        if (st != DEC_OK)
            return st;
        /* The length counts the whole header, including this byte and the
         * next-type byte, so 0 is impossible, and accepting it would let
         * the walk stand still. */
        elen = (size_t)s->p[0] * 4;
        if (elen == 0)
            return DEC_BAD_GTPU_EXT_LEN;
        st = need(s, elen, DEC_TRUNC_GTPU_EXT, DEC_BAD_GTPU_EXT);
        if (st != DEC_OK)
            return st;
        next = s->p[elen - 1];
        advance(s, elen);
        pi->gtp_ext_count = (uint8_t)hops;
    }

    /* Every GTP-U header of the message has now been read and checked.
     * Whatever happens in the user packet below, the message itself (and
     * so the tunnel it belongs to) is known. */
    pi->gtp_msg_ok = 1;

    /* Echo, error indication, end marker and the other signalling messages
     * carry information elements, not user data. They are counted by type;
     * their contents are not decoded. */
    if (pi->gtp_msg_type != GTPU_MSG_GPDU)
        return DEC_OK;
    return decode_gtpu_inner(s, pi);
}

enum decode_status decode_frame(const uint8_t *frame, size_t caplen,
                                size_t wirelen, struct packet_info *pi)
{
    struct span s;
    unsigned type;

    memset(pi, 0, sizeof *pi);
    s.p = frame;
    s.cap = caplen;
    s.wire = wirelen > caplen ? wirelen : caplen; /* keep cap <= wire */

    pi->status = need(&s, ETH_HDR_LEN, DEC_TRUNC_ETHERNET, DEC_BAD_SHORT_FRAME);
    if (pi->status != DEC_OK)
        return pi->status;
    /* Bytes 0-5 destination MAC, 6-11 source MAC, 12-13 ethertype. */
    type = load_be16(s.p + 12);
    advance(&s, ETH_HDR_LEN);

    /* A VLAN tag sits where the ethertype was: the "ethertype" we just read
     * is really the tag protocol ID, followed by 2 bytes of tag control info
     * (priority, DEI, 12-bit VLAN ID) and then the real ethertype. */
    while (type == ETHERTYPE_VLAN || type == ETHERTYPE_QINQ ||
           type == ETHERTYPE_QINQ_LEGACY) {
        if (pi->vlan_count == DECODE_MAX_VLANS)
            return pi->status = DEC_BAD_VLAN_DEPTH;
        pi->status = need(&s, VLAN_TAG_LEN, DEC_TRUNC_VLAN, DEC_BAD_SHORT_FRAME);
        if (pi->status != DEC_OK)
            return pi->status;
        pi->vlan_ids[pi->vlan_count++] = load_be16(s.p) & 0x0FFFu;
        type = load_be16(s.p + 2);
        advance(&s, VLAN_TAG_LEN);
    }
    pi->ethertype = (uint16_t)type;
    pi->has_l2 = 1;

    switch (type) {
    case ETHERTYPE_IPV4:
        pi->status = decode_ipv4(&s, pi);
        break;
    case ETHERTYPE_IPV6:
        pi->status = decode_ipv6(&s, pi);
        break;
    default:
        pi->status = DEC_OK; /* ARP, LLDP, ...: valid, just not IP */
        break;
    }

    /* GTP-U rides on UDP, so it is decoded here, once the outer packet has
     * decoded cleanly. The IP decoders have stepped over the IP headers and
     * decode_l4() clipped the span to the UDP length, so `s` now covers
     * exactly the UDP datagram. A first IP fragment holds only part of the
     * datagram, so it is not decoded (there is no reassembly). */
    if (pi->status == DEC_OK && pi->frag == FRAG_NONE &&
        decode_is_gtpu_port(pi) && s.wire >= UDP_HDR_LEN + GTPU_HDR_LEN) {
        pi->is_gtpu = 1;
        advance(&s, UDP_HDR_LEN);
        pi->gtp_status = decode_gtpu(&s, pi);
    }
    return pi->status;
}

int decode_status_is_truncation(enum decode_status s)
{
    return s >= DEC_TRUNC_ETHERNET && s <= DEC_TRUNC_GTPU_INNER;
}

const char *decode_status_str(enum decode_status s)
{
    switch (s) {
    case DEC_OK:                   return "ok";
    case DEC_TRUNC_ETHERNET:       return "truncated Ethernet header";
    case DEC_TRUNC_VLAN:           return "truncated VLAN tag";
    case DEC_TRUNC_IPV4:           return "truncated IPv4 header";
    case DEC_TRUNC_IPV6:           return "truncated IPv6 header";
    case DEC_TRUNC_IPV6_EXT:       return "truncated IPv6 extension header";
    case DEC_TRUNC_TCP:            return "truncated TCP header";
    case DEC_TRUNC_UDP:            return "truncated UDP header";
    case DEC_TRUNC_ICMP:           return "truncated ICMP header";
    case DEC_TRUNC_GTPU:           return "truncated GTP-U header";
    case DEC_TRUNC_GTPU_EXT:       return "truncated GTP-U extension header";
    case DEC_TRUNC_GTPU_INNER:     return "G-PDU truncated before its IP packet";
    case DEC_BAD_SHORT_FRAME:      return "frame too short for its headers";
    case DEC_BAD_VLAN_DEPTH:       return "more than 2 VLAN tags";
    case DEC_BAD_IPV4_VERSION:     return "IPv4 ethertype with wrong IP version";
    case DEC_BAD_IPV4_IHL:         return "IPv4 header length < 20";
    case DEC_BAD_IPV4_TOTAL_LEN:   return "IPv4 total length invalid";
    case DEC_BAD_IPV6_VERSION:     return "IPv6 ethertype with wrong IP version";
    case DEC_BAD_IPV6_PAYLOAD_LEN: return "IPv6 payload length exceeds frame";
    case DEC_BAD_IPV6_EXT:         return "IPv6 extension header invalid";
    case DEC_BAD_L4_LEN:           return "IP payload too short for L4 header";
    case DEC_BAD_TCP_DOFF:         return "TCP data offset invalid";
    case DEC_BAD_UDP_LEN:          return "UDP length invalid";
    case DEC_BAD_GTPU_LEN:         return "GTP-U length invalid";
    case DEC_BAD_GTPU_EXT_LEN:     return "GTP-U extension header length 0";
    case DEC_BAD_GTPU_EXT:         return "GTP-U extension header invalid";
    case DEC_BAD_GTPU_INNER:       return "G-PDU payload not IPv4 or IPv6";
    case DEC_BAD_GTPU_INNER_SHORT: return "G-PDU payload too short for IP header";
    case DEC_STATUS_COUNT:         break;
    }
    return "unknown";
}
