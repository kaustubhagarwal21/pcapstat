#!/usr/bin/env python3
"""gen_pcap.py - deterministic generator of realistic mixed-traffic captures.

Writes a classic pcap file (little-endian, microsecond timestamps, Ethernet
link type) containing interleaved conversations:

  * TCP over IPv4 and IPv6: three-way handshake with MSS / window-scale /
    SACK-permitted options, request/response exchanges split into MSS-sized
    segments with delayed ACKs, and a FIN teardown
  * DNS-like UDP query/response pairs (IPv4 and IPv6)
  * UDP bulk streams; some IPv4 streams send datagrams larger than the MTU,
    which are split into IP fragments
  * ICMP and ICMPv6 echo request/reply
  * ARP request/reply (non-IP traffic)
  * about 8% of conversations on an 802.1Q VLAN, 2% double-tagged (802.1ad)

All IPv4 header, TCP, UDP, ICMP and ICMPv6 checksums are computed, so tools
such as Wireshark show the packets as valid. Addresses come from the
documentation ranges (10.0.0.0/16 clients, 198.51.100.0/24 and
203.0.113.0/24 servers, 2001:db8::/32 for IPv6).

The same arguments always produce a byte-identical file. Only the Python
standard library is used.

Example:
    python3 tools/gen_pcap.py --seed 17 --packets 400 --flows 30 \\
        --out samples/sample.pcap
"""

import argparse
import array
import heapq
import random
import struct
import sys

EPOCH = 1700000000          # capture start: 2023-11-14 22:13:20 UTC
PACKETS_PER_SEC = 2000      # conversations start over packets / this seconds

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10

ETH_IPV4, ETH_IPV6, ETH_ARP = 0x0800, 0x86DD, 0x0806
TPID_8021Q, TPID_8021AD = 0x8100, 0x88A8


# --- checksums -------------------------------------------------------------

def checksum(data):
    """RFC 1071 Internet checksum.

    Summing 16-bit words through array('H') is much faster than unpacking
    them one by one. array uses host byte order, so on little-endian hosts
    the words are byte-swapped first to get network-order words.
    """
    if len(data) & 1:
        data += b"\x00"
    words = array.array("H", data)
    if sys.byteorder == "little":
        words.byteswap()
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def l4_checksum(version, src, dst, proto, segment):
    """TCP/UDP/ICMPv6 checksum including the IPv4 or IPv6 pseudo-header."""
    if version == 4:
        pseudo = src + dst + struct.pack("!BBH", 0, proto, len(segment))
    else:
        pseudo = src + dst + struct.pack("!I3xB", len(segment), proto)
    return checksum(pseudo + segment)


# --- headers ---------------------------------------------------------------

def ipv4_packet(src, dst, proto, payload, ident, df=True, offset=0,
                more=False):
    flags = (0x4000 if df else 0) | (0x2000 if more else 0) | (offset // 8)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                      ident & 0xFFFF, flags, 64, proto, 0, src, dst)
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:] + payload


def ipv6_packet(src, dst, next_header, payload):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), next_header,
                       64, src, dst) + payload


def tcp_segment(version, src, dst, sport, dport, seq, ack, flags,
                payload=b"", options=b""):
    doff = (20 + len(options)) // 4
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF,
                      ack & 0xFFFFFFFF, doff << 4, flags, 502, 0, 0)
    seg += options + payload
    csum = l4_checksum(version, src, dst, 6, seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def udp_datagram(version, src, dst, sport, dport, payload):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = l4_checksum(version, src, dst, 17, seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def icmp_echo(version, src, dst, icmp_type, ident, seq, payload):
    msg = struct.pack("!BBHHH", icmp_type, 0, 0, ident, seq) + payload
    if version == 4:
        csum = checksum(msg)
    else:
        csum = l4_checksum(6, src, dst, 58, msg)
    return msg[:2] + struct.pack("!H", csum) + msg[4:]


# --- conversations ---------------------------------------------------------

class Endpoints:
    """Addresses, MACs and L2 tagging shared by one conversation."""

    def __init__(self, version, client, server, cmac, smac, tags):
        self.version = version
        self.client = client
        self.server = server
        self.cmac = cmac
        self.smac = smac
        self.tags = tags            # list of (tpid, vlan id), outermost first

    def frame(self, from_client, ethertype, l3):
        dst, src = (self.smac, self.cmac) if from_client else \
                   (self.cmac, self.smac)
        hdr = dst + src
        for tpid, vid in self.tags:
            hdr += struct.pack("!HH", tpid, vid)
        frame = hdr + struct.pack("!H", ethertype) + l3
        if len(frame) < 60:         # Ethernet minimum frame size (no FCS)
            frame += bytes(60 - len(frame))
        return frame

    def ip(self, from_client, proto, l4, ident=0):
        src, dst = (self.client, self.server) if from_client else \
                   (self.server, self.client)
        if self.version == 4:
            return self.frame(from_client, ETH_IPV4,
                              ipv4_packet(src, dst, proto, l4, ident))
        return self.frame(from_client, ETH_IPV6,
                          ipv6_packet(src, dst, proto, l4))

    def addrs(self, from_client):
        return (self.client, self.server) if from_client else \
               (self.server, self.client)


class Blob:
    """Deterministic pseudo-random payload bytes, sliced without copying
    per-byte random calls."""

    def __init__(self, rng, size=1 << 16):
        self.data = rng.getrandbits(size * 8).to_bytes(size, "little")
        self.rng = rng

    def take(self, n):
        start = self.rng.randrange(0, len(self.data) - n)
        return self.data[start:start + n]


def tcp_conversation(rng, blob, ep, sport, dport, budget):
    """Yield (gap_us, frame) for one TCP connection of about `budget`
    packets."""
    v = ep.version
    mss = 1460 if v == 4 else 1440
    rtt = rng.randint(2000, 80000)                  # microseconds
    cseq, sseq = rng.getrandbits(32), rng.getrandbits(32)
    ident = {True: rng.getrandbits(16), False: rng.getrandbits(16)}

    def pkt(from_client, seq, ack, flags, payload=b"", options=b""):
        src, dst = ep.addrs(from_client)
        sp, dp = (sport, dport) if from_client else (dport, sport)
        seg = tcp_segment(v, src, dst, sp, dp, seq, ack, flags, payload,
                          options)
        ident[from_client] += 1                     # IPv4 ID per direction
        return ep.ip(from_client, 6, seg, ident[from_client])

    syn_opts = (struct.pack("!BBH", 2, 4, mss) + b"\x01\x03\x03\x07"
                + b"\x01\x01\x04\x02")               # MSS, WS=7, SACK-perm
    yield 0, pkt(True, cseq, 0, TCP_SYN, options=syn_opts)
    yield rtt, pkt(False, sseq, cseq + 1, TCP_SYN | TCP_ACK, options=syn_opts)
    cseq += 1
    sseq += 1
    yield rng.randint(20, 200), pkt(True, cseq, sseq, TCP_ACK)

    def send(from_client, nbytes):
        """Send a message as MSS-sized segments; the receiver ACKs every
        second segment and the last one (delayed ACK)."""
        nonlocal cseq, sseq
        segs = 0
        while nbytes > 0:
            n = min(mss, nbytes)
            nbytes -= n
            flags = TCP_ACK | (TCP_PSH if nbytes == 0 else 0)
            if from_client:
                yield rng.randint(10, 300), pkt(True, cseq, sseq, flags,
                                                blob.take(n))
                cseq += n
            else:
                yield rng.randint(10, 300), pkt(False, sseq, cseq, flags,
                                                blob.take(n))
                sseq += n
            segs += 1
            if segs % 2 == 0 or nbytes == 0:
                if from_client:
                    yield rng.randint(50, 400), pkt(False, sseq, cseq, TCP_ACK)
                else:
                    yield rng.randint(50, 400), pkt(True, cseq, sseq, TCP_ACK)

    # Spread the packet budget over a few request/response exchanges. An
    # exchange costs 2 packets for the request and its ACK plus k response
    # segments and about k/2 ACKs, so a big budget becomes a big download
    # rather than thousands of exchanges.
    exchanges = max(1, min(rng.randint(1, 12), (budget - 6) // 4))
    per_exchange = max(3, (budget - 6) // exchanges)
    for x in range(exchanges):
        gap = rng.randint(200, 3000) if x == 0 else rng.randint(5000, 400000)
        segments = max(1, round((per_exchange - 2) / 1.5))
        response = (segments - 1) * mss + rng.randint(1, mss)
        g = gap
        for extra, frame in send(True, rng.randint(80, 900)):
            yield g + extra, frame
            g = 0
        g = rtt
        for extra, frame in send(False, response):
            yield g + extra, frame
            g = 0

    yield rng.randint(1000, 50000), pkt(True, cseq, sseq, TCP_FIN | TCP_ACK)
    yield rtt, pkt(False, sseq, cseq + 1, TCP_FIN | TCP_ACK)
    yield rng.randint(20, 200), pkt(True, cseq + 1, sseq + 1, TCP_ACK)


def dns_conversation(rng, blob, ep, sport, queries):
    v = ep.version
    for q in range(queries):
        src, dst = ep.addrs(True)
        query = udp_datagram(v, src, dst, sport, 53,
                             blob.take(rng.randint(28, 60)))
        yield (0 if q == 0 else rng.randint(1000, 200000)), \
            ep.ip(True, 17, query, rng.getrandbits(16))
        src, dst = ep.addrs(False)
        answer = udp_datagram(v, src, dst, 53, sport,
                              blob.take(rng.randint(60, 480)))
        yield rng.randint(3000, 60000), ep.ip(False, 17, answer,
                                              rng.getrandbits(16))


def udp_bulk_conversation(rng, blob, ep, sport, dport, budget, fragment):
    """A one-way stream (think video or QUIC download) with occasional
    feedback packets. With `fragment`, IPv4 datagrams exceed the MTU and are
    sent as fragments."""
    v = ep.version
    ident = rng.getrandbits(16)
    sent = 0
    while sent < budget:
        src, dst = ep.addrs(False)
        size = rng.randint(2400, 4000) if fragment else rng.randint(1000, 1350)
        dgram = udp_datagram(v, src, dst, dport, sport, blob.take(size))
        ident = (ident + 1) & 0xFFFF
        gap = rng.randint(200, 5000)
        if fragment and v == 4 and len(dgram) > 1480:
            off = 0
            while off < len(dgram):
                chunk = dgram[off:off + 1480]           # multiple of 8
                more = off + len(chunk) < len(dgram)
                l3 = ipv4_packet(src, dst, 17, chunk, ident, df=False,
                                 offset=off, more=more)
                yield gap, ep.frame(False, ETH_IPV4, l3)
                gap = rng.randint(5, 50)
                off += len(chunk)
                sent += 1
        else:
            yield gap, ep.ip(False, 17, dgram, ident)
            sent += 1
        if rng.random() < 0.1:                          # receiver feedback
            src, dst = ep.addrs(True)
            fb = udp_datagram(v, src, dst, sport, dport,
                              blob.take(rng.randint(30, 80)))
            yield rng.randint(100, 5000), ep.ip(True, 17, fb, ident)
            sent += 1


def ping_conversation(rng, ep, count):
    v = ep.version
    ident = rng.getrandbits(16)
    req_type, rep_type = (8, 0) if v == 4 else (128, 129)
    proto = 1 if v == 4 else 58
    pattern = bytes(range(56))
    for seq in range(1, count + 1):
        src, dst = ep.addrs(True)
        yield (0 if seq == 1 else rng.randint(900000, 1100000)), ep.ip(
            True, proto, icmp_echo(v, src, dst, req_type, ident, seq, pattern),
            ident + seq)
        src, dst = ep.addrs(False)
        yield rng.randint(1000, 60000), ep.ip(
            False, proto, icmp_echo(v, src, dst, rep_type, ident, seq,
                                    pattern), ident + seq)


def arp_conversation(rng, ep, client_ip, server_ip):
    req = struct.pack("!HHBBH6s4s6s4s", 1, ETH_IPV4, 6, 4, 1, ep.cmac,
                      client_ip, b"\x00" * 6, server_ip)
    rep = struct.pack("!HHBBH6s4s6s4s", 1, ETH_IPV4, 6, 4, 2, ep.smac,
                      server_ip, ep.cmac, client_ip)
    broadcast = Endpoints(4, None, None, ep.cmac, b"\xff" * 6, ep.tags)
    yield 0, broadcast.frame(True, ETH_ARP, req)
    yield rng.randint(50, 500), ep.frame(False, ETH_ARP, rep)


# --- scheduling ------------------------------------------------------------

def mac_for(kind, index):
    return bytes([0x02, kind, 0, (index >> 16) & 0xFF, (index >> 8) & 0xFF,
                  index & 0xFF])


KINDS = ["tcp", "dns", "bulk", "ping", "arp"]
KIND_WEIGHTS = [60, 20, 8, 9, 3]


def plan(rng, packets, flows):
    """Choose each conversation's kind and packet budget.

    DNS, ping and ARP conversations are short with fixed sizes. The packets
    left over are shared among the TCP and UDP-bulk conversations in
    proportion to Pareto(1.5) weights: a heavy tail of a few elephant flows
    and many mice, with budgets that add up to about `packets`.
    """
    kinds = rng.choices(KINDS, weights=KIND_WEIGHTS, k=flows)
    budgets = [0] * flows
    for i, kind in enumerate(kinds):
        if kind == "dns":
            budgets[i] = rng.randint(1, 4)          # query/response pairs
        elif kind == "ping":
            budgets[i] = rng.randint(1, 10)         # echo request/reply pairs
    fixed = sum(2 * b for b in budgets) + 2 * kinds.count("arp")
    elastic = [i for i, kind in enumerate(kinds) if kind in ("tcp", "bulk")]
    weights = [rng.paretovariate(1.5) for _ in elastic]
    remaining = max(8 * len(elastic), packets - fixed)
    total = sum(weights) or 1.0
    for i, w in zip(elastic, weights):
        budgets[i] = max(8, int(w / total * remaining))
    return kinds, budgets


def make_conversation(rng, blob, kind, budget, n_clients):
    """Pick endpoints for one conversation; return its frame generator."""
    ci = rng.randrange(n_clients)
    si = rng.randrange(508)
    v4_client = bytes([10, 0, ci // 250, ci % 250 + 1])
    v4_server = bytes([198, 51, 100, si + 1]) if si < 254 else \
        bytes([203, 0, 113, si - 253])
    v6_client = bytes.fromhex("20010db8000100000000000000000000")[:12] + \
        struct.pack("!I", ci + 1)
    v6_server = bytes.fromhex("20010db800ff00000000000000000000")[:12] + \
        struct.pack("!I", si + 1)

    r = rng.random()
    tags = []
    if r < 0.02:
        tags = [(TPID_8021AD, 1000), (TPID_8021Q, rng.choice([10, 20, 30]))]
    elif r < 0.10:
        tags = [(TPID_8021Q, rng.choice([10, 20, 100]))]

    def endpoints(version):
        if version == 4:
            return Endpoints(4, v4_client, v4_server, mac_for(1, ci),
                             mac_for(2, si), tags)
        return Endpoints(6, v6_client, v6_server, mac_for(1, ci),
                         mac_for(2, si), tags)

    sport = rng.randint(32768, 60999)
    if kind == "tcp":
        version = 6 if rng.random() < 0.25 else 4
        dport = rng.choices([443, 80, 22, 8080, 993],
                            weights=[70, 15, 5, 5, 5])[0]
        return tcp_conversation(rng, blob, endpoints(version), sport, dport,
                                budget)
    if kind == "dns":
        version = 6 if rng.random() < 0.25 else 4
        return dns_conversation(rng, blob, endpoints(version), sport, budget)
    if kind == "bulk":
        version = 6 if rng.random() < 0.3 else 4
        fragment = version == 4 and rng.random() < 0.3
        dport = rng.choice([443, 5004, 4500])
        return udp_bulk_conversation(rng, blob, endpoints(version), sport,
                                     dport, budget, fragment)
    if kind == "ping":
        version = 6 if rng.random() < 0.4 else 4
        return ping_conversation(rng, endpoints(version), budget)
    return arp_conversation(rng, endpoints(4), v4_client, v4_server)


def generate(args):
    rng = random.Random(args.seed)
    blob = Blob(rng)
    window_us = max(1_000_000, args.packets * 1_000_000 // PACKETS_PER_SEC)
    n_clients = max(4, min(60000, args.flows // 4))
    kinds, budgets = plan(rng, args.packets, args.flows)

    # Heap of (time_us, sequence, generator, frame): always emit the
    # earliest pending packet, so timestamps come out in order.
    heap = []
    seq = 0

    def start(kind, budget, at_us):
        nonlocal seq
        gen = make_conversation(rng, blob, kind, budget, n_clients)
        first = next(gen, None)
        if first is not None:
            heapq.heappush(heap, (at_us + first[0], seq, gen, first[1]))
            seq += 1

    for kind, budget in zip(kinds, budgets):
        start(kind, budget, rng.randrange(window_us))

    written = 0
    started = args.flows
    last_us = 0
    with open(args.out, "wb", buffering=1 << 20) as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        while written < args.packets:
            if not heap:
                # Budgets are estimates, so the planned conversations can run
                # out a little early. Top up with a batch of TCP
                # conversations over the next second rather than one at a
                # time, so the traffic density stays realistic.
                batch = max(1, args.flows // 100)
                each = max(8, (args.packets - written) // batch)
                for _ in range(batch):
                    start("tcp", each, last_us + rng.randrange(1_000_000))
                started += batch
                continue
            t, s, gen, frame = heapq.heappop(heap)
            last_us = t
            sec, usec = divmod(t, 1_000_000)
            out.write(struct.pack("<IIII", EPOCH + sec, usec, len(frame),
                                  len(frame)))
            out.write(frame)
            written += 1
            nxt = next(gen, None)
            if nxt is not None:
                heapq.heappush(heap, (t + nxt[0], s, gen, nxt[1]))
    return written, started


def main():
    p = argparse.ArgumentParser(
        description="Generate a deterministic mixed-traffic pcap file.")
    p.add_argument("--seed", type=int, default=1,
                   help="random seed (default 1)")
    p.add_argument("--packets", type=int, default=1000,
                   help="exact number of packets to write (default 1000)")
    p.add_argument("--flows", type=int, default=50,
                   help="number of conversations to plan (default 50); a "
                        "few more are added only if they all finish before "
                        "--packets is reached")
    p.add_argument("--out", required=True, help="output .pcap path")
    args = p.parse_args()
    if args.packets < 1 or args.flows < 1:
        p.error("--packets and --flows must be positive")
    written, convs = generate(args)
    print(f"wrote {written} packets from {convs} conversations to {args.out}")


if __name__ == "__main__":
    main()
