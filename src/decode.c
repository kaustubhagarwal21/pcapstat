/*
 * decode.c - Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP / ICMP decoder.
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

    if (s->cap < IPV4_MIN_HDR)
        return DEC_TRUNC_IPV4;
    ip = s->p;
    if ((ip[0] >> 4) != 4)
        return DEC_BAD_IPV4_VERSION;

    hlen = (size_t)(ip[0] & 0x0F) * 4; /* IHL is in 32-bit words: 20..60 */
    if (hlen < IPV4_MIN_HDR)
        return DEC_BAD_IPV4_IHL;

    total = load_be16(ip + 2);
    if (total < hlen || total > s->wire)
        return DEC_BAD_IPV4_TOTAL_LEN;
    if (hlen > s->cap)
        return DEC_TRUNC_IPV4; /* options cut off by the snapshot length */

    pi->ip_version = 4;
    pi->ip_proto = ip[9];
    memcpy(pi->src_addr, ip + 12, 4);
    memcpy(pi->dst_addr, ip + 16, 4);

    /* Flags (3 bits) and fragment offset (13 bits, in 8-byte units). */
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

    if (s->cap < IPV6_HDR_LEN)
        return DEC_TRUNC_IPV6;
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

    while (is_ipv6_ext(next)) {
        pi->ip_proto = (uint8_t)next;
        if (hops++ == IPV6_MAX_EXT_HEADERS)
            return DEC_BAD_IPV6_EXT;

        if (next == IP6_EXT_FRAGMENT) {
            unsigned off_flags;

            st = need(s, IPV6_FRAG_LEN, DEC_TRUNC_IPV6_EXT, DEC_BAD_IPV6_EXT);
            if (st != DEC_OK)
                return st;
            /* 13-bit offset in 8-byte units, 2 reserved bits, M flag. */
            off_flags = load_be16(s->p + 2);
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

enum decode_status decode_frame(const uint8_t *frame, size_t caplen,
                                size_t wirelen, struct packet_info *pi)
{
    struct span s;
    unsigned type;

    memset(pi, 0, sizeof *pi);
    s.p = frame;
    s.cap = caplen;
    s.wire = wirelen > caplen ? wirelen : caplen; /* keep cap <= wire */

    if (s.cap < ETH_HDR_LEN)
        return pi->status = DEC_TRUNC_ETHERNET;
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
        if (s.cap < VLAN_TAG_LEN)
            return pi->status = DEC_TRUNC_VLAN;
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
    return pi->status;
}

int decode_status_is_truncation(enum decode_status s)
{
    return s >= DEC_TRUNC_ETHERNET && s <= DEC_TRUNC_ICMP;
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
    case DEC_STATUS_COUNT:         break;
    }
    return "unknown";
}
