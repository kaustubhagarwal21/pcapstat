# pcapstat

`pcapstat` is a small command-line tool in C11 that reads classic libpcap
capture files (`.pcap`, as written by tcpdump and Wireshark). It decodes
Ethernet, 802.1Q / 802.1ad VLAN tags, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6.
It also decodes GTP-U, the tunnel that carries phones' IP packets between
LTE/5G base stations and the mobile core, including the user packet inside
each tunnel. It then reports per-protocol counts, decode problems, the
largest bidirectional flows and the largest GTP-U tunnels. It depends on
nothing but the C standard library.

The project is an exercise in the parts of network software where C is
unforgiving: parsing untrusted binary input, byte order, unaligned data,
length fields that lie, and integer overflow. The rule throughout is that no
length read from the file or the packet is trusted until it has been checked
against the bytes that are actually there. AddressSanitizer,
UndefinedBehaviorSanitizer and a mutation fuzzer check that rule, rather than
code review alone.

## Features

- Reads both pcap byte orders and both timestamp resolutions (microsecond
  magic `a1b2c3d4` and nanosecond magic `a1b23c4d`), independent of the host's
  byte order.
- Validates the global header (magic, version 2.4, link type) and every record
  (captured length capped at 262144 bytes). Truncated files are reported
  cleanly, and the statistics for the records before the damage are still
  printed.
- Decodes Ethernet, up to two VLAN tags, IPv4 (including options and
  fragments), IPv6 (skipping hop-by-hop, routing, destination-options and
  fragment extension headers), TCP (ports, flags), UDP (ports) and
  ICMP/ICMPv6 (type, code).
- Counts every packet it cannot fully decode by reason, and tells truncation
  (the capture stopped early) apart from malformation (a length field is
  impossible, or the frame is too short for its own headers). Nothing it
  fails to understand stops the run.
- Keeps bidirectional 5-tuple flows in an open-addressing hash table and
  prints the top N by bytes. Later IP fragments, which carry no ports, are
  matched to their datagram's flow. `--csv` writes every flow to a CSV file.
- Decodes GTP-U (GTPv1-U, 3GPP TS 29.281) on UDP port 2152: the header
  flags, the optional fields, the extension header chain and the message
  types. The IPv4 or IPv6 user packet inside a G-PDU, with its TCP, UDP or
  ICMP header, is decoded by the same bounds-checked code as the outer
  packet. Tunnels are kept in a second hash table keyed by (outer source,
  outer destination, TEID), and the top N by bytes are printed.
  `--tunnels-csv` writes every tunnel to a CSV file. See
  [GTP-U](#gtp-u-lte-s1-u-and-5g-n3).

## Build and run

Needs a C11 compiler and `make`. `python3` is needed only to regenerate the
sample and benchmark captures.

```sh
make                  # release build: build/pcapstat
make test             # 96 unit tests + 37 CLI checks
make asan             # the same tests under ASan + UBSan
make fuzz             # 200,000 fuzz iterations under ASan + UBSan
make bench            # build a 1,000,000-packet capture, then time pcapstat on it
```

```text
usage: pcapstat [-n N] [--csv FILE] [--tunnels-csv FILE] FILE.pcap

  -n N                show the top N flows and tunnels by bytes
                      (default 10, 0 hides the tables)
  --csv FILE          also write every flow to FILE as CSV
  --tunnels-csv FILE  also write every GTP-U tunnel to FILE as CSV
  -h, --help          show this help

exit status: 0 ok, 1 usage error, 2 input error
```

An input error covers a file that cannot be opened, is not a pcap file,
turns out to be truncated or corrupt part-way through, or a CSV file that
cannot be written. For a capture damaged part-way through, the summary for
the records before the damage is still printed. Naming the input file as a
CSV output, or the same file for both CSVs, is a usage error, so repeating
a name by mistake cannot overwrite the capture or the other CSV.

## Sample output

`samples/sample.pcap` is a 400-packet synthetic capture produced by
`tools/gen_pcap.py --seed 17 --packets 400 --flows 30` (`make sample`). It
contains:

- TCP handshakes, data and FIN teardowns;
- DNS-like UDP and a UDP stream whose datagrams are IP-fragmented;
- ICMP and ICMPv6 echo;
- VLAN-tagged frames and ARP.

All checksums are valid. This is the unedited output of
`./build/pcapstat samples/sample.pcap`:

```text
File:        samples/sample.pcap
Format:      pcap 2.4, little-endian, microsecond timestamps, snaplen 65535, Ethernet
Packets:     400
Bytes:       217253 on the wire, 217253 captured
First:       2023-11-14 22:13:20.060402 UTC
Last:        2023-11-14 22:13:22.993419 UTC
Duration:    2.933017 s (136.4 packets/s, 0.593 Mbit/s)

Network:     IPv4 369 (92.2%), IPv6 27 (6.8%), non-IP 4 (1.0%)
Transport:   TCP 325, UDP 57, ICMP 9, ICMPv6 5, other 0
VLAN:        47 tagged frames
Fragments:   3 first, 6 non-first (6 matched to their first fragment's ports)
Flows:       28
Problems:    0 truncated, 0 malformed (excluded from flows)

Top 10 of 28 flows by bytes (src = sender of the first packet seen):
  #  proto   src                    dst                     packets       bytes      duration  tcp flags
  1  TCP     10.0.0.5:38348         198.51.100.34:443           129      121443       0.579 s  FSPA
  2  TCP     10.0.0.6:53655         203.0.113.9:443              34       16123       1.095 s  FSPA
  3  UDP     198.51.100.8:4500      10.0.0.6:42363                9       10857       0.007 s  -
  4  UDP     203.0.113.124:443      10.0.0.2:37158                8        9710       0.014 s  -
  5  TCP     10.0.0.3:45033         203.0.113.126:443            34        9678       1.595 s  FSPA
  6  UDP     203.0.113.190:4500     10.0.0.4:52459                8        9596       0.019 s  -
  7  TCP     10.0.0.2:40834         203.0.113.80:443             16        6264       0.623 s  FSPA
  8  TCP     10.0.0.3:40596         198.51.100.211:443           14        5533       0.171 s  FSPA
  9  TCP     10.0.0.6:60851         203.0.113.57:443             18        4358       0.480 s  FSPA
 10  TCP     [2001:db8:1::4]:50731  [2001:db8:ff::6d]:443        10        2356       0.256 s  FSPA
```

Notes on reading it:

- TCP flags are the union over the whole flow, in bit order F S R P A U E C.
  `FSPA` means the flow saw FIN, SYN, PSH and ACK.
- Row 3 is a UDP stream whose datagrams were too big for the MTU, so each
  was sent as IP fragments. Only a first fragment carries the UDP header;
  the 6 later ones have no ports of their own. pcapstat matches them to
  their first fragment by (source, destination, protocol, IP ID) and gives
  them its ports, so all 9 packets count toward one flow. Without that
  matching, the stream would be split into a 3-packet flow and a port-less
  6-packet flow, and neither would rank as high.
- The CSV file (`--csv flows.csv`) has one row per flow, largest first:
  `src_addr,src_port,dst_addr,dst_port,protocol,ip_version,packets,bytes,first_ts,last_ts,duration_s,tcp_flags`,
  with timestamps as `seconds.nanoseconds`.

## GTP-U (LTE S1-U and 5G N3)

In a mobile network, a phone's IP packets do not cross the operator's
network as plain IP. The base station (an LTE eNodeB or a 5G gNodeB) wraps
each uplink packet in GTP-U, the GPRS Tunnelling Protocol for user data
(3GPP TS 29.281), and sends it over UDP port 2152 to the core network's
user-plane node: the SGW-U in LTE, the UPF in 5G. Downlink packets travel
the same way in the other direction. This link is called S1-U in LTE and N3
in 5G. Each GTP-U header carries a TEID (tunnel endpoint identifier) that
tells the receiver which bearer or PDU session, and so which phone, the
packet belongs to. A capture on that link therefore has two sets of
addresses: the outer ones (base station and core) and the inner ones (phone
and the server it talks to).

```text
Ethernet | IP base station -> core | UDP 2152 | GTP-U TEID | IP phone -> server | TCP/UDP/ICMP | data
         |<------------ outer packet: flows ------------->|<------------- user packet ------------->|
```

### What is decoded

- **Detection.** An unfragmented UDP datagram with port 2152 on either side
  and at least 8 bytes of payload is decoded as GTP-U. Either port is
  enough: an Echo Response goes back to the port the request came from, so
  only its source port is 2152.
- **Header.** Version and PT (protocol type), the E, S and PN flags, the
  message type, the length and the TEID. A header with a version other than
  1, or with PT 0 (GTP', used for charging data), is counted and not
  decoded further.
- **Optional fields and extension headers.** If any of E, S or PN is set, 4
  more bytes follow: sequence number, N-PDU number and the type of the
  first extension header. The extension header chain is walked: each
  header's length is in 4-byte units and must be at least 1, and the type
  of the next header is in its last byte. 5G traffic normally carries one,
  the PDU Session Container (type 0x85), which holds the QoS flow ID.
- **Message types.** A G-PDU (255) carries a user packet. Echo Request (1),
  Echo Response (2), Error Indication (26) and End Marker (254) are counted
  by type, and any other type as "other". Their information elements are
  not decoded. The type and the flags sit in the first 8 bytes, so the
  counts by type and option include messages that later turn out to be
  malformed (an echo request with S set but no room for the sequence
  number counts as an echo request, as "sequence number in", and as a
  problem).
- **The user packet.** Its first 4 bits select IPv4 or IPv6, and it goes
  through the same `decode_ipv4()` / `decode_ipv6()` functions as the outer
  packet. It gets the same checks (IHL, total length, extension headers,
  TCP data offset, UDP length), and its addresses, protocol and ports are
  kept in `struct packet_info` next to the outer ones.

### The same rules, one level down

- **Spans all the way down.** The UDP length bounds the GTP-U message. The
  GTP-U length counts the bytes after the first 8; it must fit in the UDP
  payload, and it then bounds the extension headers and the user packet,
  whose own lengths must fit in what is left. Each length can only shrink
  the span. A GTP-U length larger than the UDP payload is **malformed**
  even in a cut-short capture, because the UDP length that proves it is in
  the captured bytes. A consistent message cut by the snapshot length is
  **truncated**. A complete frame's GTP-U message is never called
  truncated; a unit test sweep and a fuzzer invariant check this.
- **The outer packet is not affected.** `pi->status` and the outer flow
  table are exactly what they were before GTP-U decoding existed. A problem
  inside the tunnel is recorded in a separate `pi->gtp_status`, using the
  same list of reasons, and counted in the GTP-U part of the summary. A
  G-PDU with a broken extension header still counts in its outer UDP flow,
  because the outer headers are fine.
- **Two layers inside the tunnel.** Once the GTP-U headers (header,
  optional fields, extension headers) have been read in full,
  `pi->gtp_msg_ok` is set. Anything that goes wrong after that point is in
  the user packet. The summary counts the two kinds of problem on separate
  lines, because only the first kind keeps a G-PDU out of its tunnel (see
  [Tunnels](#tunnels)). A user packet whose GTP-U length leaves less room
  than an IP header has its own reason ("G-PDU payload too short for IP
  header"), rather than the outer decoder's "frame too short for its
  headers": the frame is fine.
- **Zero-length extension headers.** A length of 0 would describe a header
  too short to hold even its own length byte, and accepting it would let
  the walk stand still. It has its own malformation reason. The chain is
  also capped at 16 headers, so a crafted chain cannot make the loop run
  long.
- **No recursion.** GTP-U is decoded in `decode_frame()`, after the outer
  packet. The user packet goes through `decode_ipv4()` / `decode_ipv6()`
  and then `decode_l4()`, and none of them calls the GTP-U decoder. So a
  GTP-U packet inside a tunnel is flagged and counted but never decoded,
  however deeply a crafted packet nests.
- **Fragments.** A GTP-U datagram split into IP fragments is counted but
  not decoded, since there is no reassembly: its first fragment holds only
  part of the message.

### Tunnels

A G-PDU whose GTP-U headers decoded in full is also added to a second hash
table, keyed by (outer source, outer destination, TEID), with its full
length on the wire. The state of the user packet inside does not matter.
The key does not depend on it, and the tunnel carried those bytes whether
or not the capture kept them. GTP-U captures are often taken headers-only,
with a small snapshot length that cuts most user packets short, and the
tunnel table must not lose those G-PDUs. The same goes for a malformed user
packet: its tunnel still carried it, just as the outer flow still counts a
G-PDU whose GTP-U header is broken. A G-PDU whose GTP-U headers are broken
or cut short is left out, because then the message itself could not be
checked. The summary's two GTP-U "Problems" lines count these two cases
separately.

Unlike a flow key, a tunnel key is
not put in canonical order. The TEID is chosen by the node that receives
the packets, so the uplink and the downlink of one session use different
TEIDs, and two nodes can pick the same value independently. Each direction
is therefore its own tunnel. The tunnel table uses the same `flow_table`
code, with the TEID added to the key (it is 0 in ordinary flows), so it
shares the hashing, probing, growth and top-N code and their tests. Adding
the TEID did not make a table slot bigger: with the single-byte fields
moved up next to the key, it fits in what used to be padding, and a slot is
still 88 bytes.

The report shows the top N tunnels by bytes. `--tunnels-csv FILE` writes
every tunnel, largest first:
`teid,src_addr,dst_addr,ip_version,packets,bytes,first_ts,last_ts,duration_s`.

### Sample

`samples/gtpu_sample.pcap` is a 300-packet capture produced by
`tools/gen_pcap.py --seed 2 --packets 300 --flows 6 --gtp-fraction 0.9`
(`make sample`):

- two LTE eNodeBs and two 5G gNodeBs talk to one core node, one of them
  over IPv6 on VLAN 300;
- each phone session has its own uplink and downlink TEIDs and carries TCP,
  DNS-like UDP, a UDP stream or ping, over IPv4 or IPv6;
- 5G sessions carry a PDU Session Container, and some LTE sessions use
  sequence numbers;
- every base station exchanges echo requests with the core, and one
  session ends with an End Marker, as after a handover.

The rest is ordinary traffic. This is the unedited output of
`./build/pcapstat -n 5 samples/gtpu_sample.pcap`:

```text
File:        samples/gtpu_sample.pcap
Format:      pcap 2.4, little-endian, microsecond timestamps, snaplen 65535, Ethernet
Packets:     300
Bytes:       212520 on the wire, 212520 captured
First:       2023-11-14 22:13:20.153165 UTC
Last:        2023-11-14 22:13:21.426574 UTC
Duration:    1.273409 s (235.6 packets/s, 1.335 Mbit/s)

Network:     IPv4 272 (90.7%), IPv6 28 (9.3%), non-IP 0 (0.0%)
Transport:   TCP 43, UDP 253, ICMP 4, ICMPv6 0, other 0
VLAN:        15 tagged frames
Fragments:   0 first, 0 non-first (0 matched to their first fragment's ports)
Flows:       14
Problems:    0 truncated, 0 malformed (excluded from flows)

Top 5 of 14 flows by bytes (src = sender of the first packet seen):
  #  proto   src                    dst                    packets       bytes      duration  tcp flags
  1  UDP     172.16.1.21:2152       172.16.0.1:2152            191      190121       0.471 s  -
  2  UDP     172.16.1.12:2152       172.16.0.1:2152             17        5873       0.687 s  -
  3  TCP     [2001:db8:1::4]:60406  [2001:db8:ff::96]:22        13        4659       0.114 s  FSPA
  4  UDP     172.16.1.11:2152       172.16.0.1:2152             14        3190       0.670 s  -
  5  TCP     10.0.0.2:41157         198.51.100.182:80           10        2205       0.160 s  FSPA

GTP-U:       249 packets on UDP port 2152
  Messages:  G-PDU 230, echo request 9, echo response 9, error indication 0, end marker 1, other 0
  Options:   sequence number in 35, extension headers in 199
  Inner IP:  IPv4 123, IPv6 107; TCP 112, UDP 108, ICMP 4, ICMPv6 6, other 0
  Tunnels:   20 (20 distinct TEIDs)
  Skipped:   0 GTP' or other version, 0 GTP-U in GTP-U, 0 fragmented datagrams on port 2152
  Problems:  0 truncated, 0 malformed in GTP-U headers (not added to tunnels)
             0 truncated, 0 malformed in user packets (still added to tunnels)

Top 5 of 20 GTP-U tunnels by bytes (one direction each; the receiver chose the TEID):
  #  teid        src          dst           packets       bytes      duration
  1  0xa15a3dfb  172.16.0.1   172.16.1.21        77       97558       0.223 s
  2  0x01a02600  172.16.0.1   172.16.1.21        61       84169       0.127 s
  3  0xb9e1ee87  172.16.1.21  172.16.0.1         34        4847       0.162 s
  4  0x3fd446f9  172.16.0.1   172.16.1.12         8        3400       0.626 s
  5  0x30c218e1  172.16.1.12  172.16.0.1          9        2473       0.687 s
```

Notes on reading it:

- The flow table sees only the transport. Its row 1 is the 8 tunnels
  between the gNodeB at 172.16.1.21 and the core, 191 packets in all,
  merged into one UDP flow. The tunnel table splits that traffic by TEID.
  Rows 1 and 2 are downlink tunnels (core to base station) and row 3 is an
  uplink tunnel with far fewer bytes, which is what a download looks like.
- The counts add up: the 230 G-PDUs carry 123 IPv4 and 107 IPv6 user
  packets, and 112 TCP + 108 UDP + 4 ICMP + 6 ICMPv6 = 230.
- The generator gives every session its own uplink and downlink TEID, so
  the 20 tunnels are the two directions of 10 sessions.
- Cut the same capture to its first 96 bytes per packet (what
  `editcap -s 96` does), and 113 of the 230 user packets end inside their
  IPv4, IPv6 or TCP header. The second "Problems" line then reads "113
  truncated, 0 malformed in user packets (still added to tunnels)". The
  tunnel table and the tunnels CSV are byte for byte the same as for the
  full capture: 20 tunnels, all 230 G-PDUs, and the same bytes in each.

## Design

```text
 pcap_reader  --record-->  decode  --packet_info-->  stats  (global and GTP-U counters)
 (file/memory)             (pure)                 \-> flow   (flows and GTP-U tunnels:
                                                        |     hash tables, top-N)
                                                        |
                                           report: summary, tables, CSVs
```

| File | Role |
|---|---|
| `src/pcap_reader.{c,h}` | Global header and record parsing from a file, an open stream or a memory buffer |
| `src/decode.{c,h}` | Pure, bounds-checked frame decoder, including GTP-U and the user packet inside it, producing a `struct packet_info` |
| `src/flow.{c,h}` | Bidirectional flow key, directional tunnel key, open-addressing hash table, top-N selection |
| `src/frag.{c,h}` | Direct-mapped cache that gives later IP fragments their datagram's ports |
| `src/stats.{c,h}` | Capture-wide counters, including decode problems by reason and the GTP-U counters |
| `src/analyze.{c,h}` | The read → decode → count loop, shared by the CLI, the tests and the fuzzer |
| `src/report.{c,h}`, `src/addr.{c,h}` | Text output, CSVs, RFC 5952 IPv6 formatting |
| `src/bytes.h`, `src/hash.h` | Explicit big/little-endian loads from byte buffers; FNV-1a |
| `src/main.c` | Argument parsing and exit codes |

### Reading the file

- **Byte order without swapping.** The first 4 bytes are always read as a
  little-endian integer. `a1b2c3d4` means a little-endian file and
  `d4c3b2a1` means a big-endian file; the same holds for the nanosecond magic.
  All later fields are then read in the file's byte order with explicit
  byte loads, so the host's byte order never matters.
- **Every length is checked before it sizes a read.** `caplen` above 262144
  (libpcap's own limit) is rejected before any bytes are read, so a corrupt
  record header cannot cause a huge read or allocation. The record buffer is
  allocated once. An `origlen` smaller than `caplen` is impossible (a frame
  cannot be shorter on the wire than the bytes saved of it), so it is raised
  to `caplen`; otherwise the wire-byte totals could come out smaller than
  the captured-byte totals.
- **Truncation is reported, not tolerated silently.** Zero bytes at a record
  boundary is a clean end of file. 1–15 bytes of a record header, or fewer
  data bytes than `caplen`, is reported as a truncated file. Errors are
  sticky, so the reader never resynchronises on garbage.
- **Overflow-safe arithmetic.** Timestamps are computed in 64 bits:
  `(2^32-1) * 10^9 + (2^32-1) * 1000` still fits. The memory reader compares
  `n > len - pos` rather than computing `pos + n`.
- **One code path, two sources.** The reader works on a `FILE *` (a path,
  or an already-open stream) or on a memory buffer. The CLI uses files, the
  tests use both, and the fuzzer reads every mutated file both ways and
  requires identical results.

### Bounds-checked decoding

The decoder walks the frame with a `span`: a pointer plus two lengths.

- `cap` is the number of bytes actually present in the capture buffer. Only
  these are ever read.
- `wire` is the number of bytes the enclosing header says exist, for example
  the IPv4 total length minus the header length.

The invariant is `cap <= wire`. When a header needs `n` bytes and `n > cap`,
comparing `n` with `wire` says why: if `n <= wire`, the packet was fine but
the capture stopped early (**truncated**, which is normal with a small
snapshot length). If `n > wire`, the packet's own length fields are
inconsistent (**malformed**). A length field from the packet can only ever
*shrink* a span, never grow it, so a lying length cannot move a read outside
the buffer. Ethernet padding is dropped the same way: a 46-byte IP packet in
a 60-byte frame is limited to 46 bytes.

Every header check goes through the same `need()` function, including the
checks for fixed-size headers (Ethernet, VLAN tag, IPv4, IPv6). For a frame
captured in full (`caplen == origlen`), `cap == wire` then holds at every
layer, so such a frame can never be reported as truncated. A complete
30-byte frame that ends inside its IPv4 header is **malformed** ("frame too
short for its headers"). The same 30 bytes cut from a 1514-byte frame by a
snapshot length are **truncated**. A unit test and a fuzzer invariant both
check this.

Other rules:

- Multi-byte fields are read with byte loads (`load_be16`, `load_be32`), never
  by casting the buffer to a struct pointer. Packet data is unaligned (the IP
  header starts at offset 14), and a cast would also break strict aliasing.
- IPv4: IHL must be ≥ 5. Options are skipped using IHL, and the total length
  must be between the header length and the frame length. A total length of
  0 is what packets captured on a sender using TCP segmentation offload look
  like (the NIC fills in the lengths later). Like Wireshark, pcapstat then
  assumes the packet runs to the end of the frame.
- IPv4 and IPv6 fragments: only the first fragment (offset 0) carries the L4
  header. Later fragments are counted, but their first bytes are not read as
  ports.
- IPv6: extension headers are walked in a loop capped at 8 headers, and each
  one's length is checked against both `cap` and `wire`. The payload length
  must fit in the frame. If the chain is broken, the transport protocol is
  unknown: the packet counts as IPv6 and as malformed or truncated, but not
  under any transport protocol.
- TCP: the data offset must be ≥ 5 and within the IP payload. UDP: the length
  must be ≥ 8 and, unless the packet is a fragment, within the IP payload.
- Unknown ethertypes and IP protocols are valid input: they are counted as
  "non-IP" or "other", not as errors.

Every non-OK result has its own `enum decode_status` value, so the summary can
say, for example, "TCP data offset invalid: 3".

### Flows

- **Normalisation.** A flow key holds two endpoints (address, port) plus the
  IP version and protocol. The endpoints are stored in sorted order (by
  address, then port), so `A:p -> B:q` and `B:q -> A:p` build the same key.
  The flow separately records which endpoint sent the first packet seen,
  so the output can show it as `src`.
- **Hash table.** Open addressing with linear probing over one flat array,
  indexed by 64-bit FNV-1a (`hash & (capacity - 1)`, with capacity a power of
  two). The key is hashed field by field rather than as raw struct bytes, so
  padding can never affect the hash. The table doubles when the load factor
  would pass 0.7. Each slot caches its hash, so growing re-places entries
  without re-hashing keys. The size arithmetic is checked for overflow before
  doubling.
- **Accounting.** Each flow keeps packets, bytes (original wire length), first
  and last timestamp (true min and max, because merged captures can be out
  of order) and the OR of all TCP flags seen. Only cleanly decoded packets
  join a flow; truncated and malformed packets appear only in the global
  counters.
- **Fragments.** Only the first fragment of a datagram carries the TCP/UDP
  header. All fragments share (IP version, source, destination, protocol,
  identification), so a first fragment's ports are stored under that key
  and a later fragment with the same key borrows them. The store is a
  direct-mapped cache of 4,096 slots (176 KiB): each key has exactly one
  slot and a new entry overwrites the old one. Memory is fixed no matter how
  many fragments a capture holds, and nothing needs evicting. A collision,
  or a later fragment that arrives before its first fragment, leaves that
  fragment port-less, as it would be without the cache.
- **Top-N.** A size-N min-heap keyed on rank: a flow only has to beat the
  heap's root to get in, so selection costs O(F log N) for F flows. The N
  winners are then sorted. Ties are broken by packets, then start time, then
  key, so the output is fully deterministic.
- **Tunnels.** GTP-U tunnels live in a second table of the same kind, with
  keys that keep their direction (see [Tunnels](#tunnels)).

## Testing

`make test` runs 96 unit tests (43,857 individual checks) and 37 CLI checks.
The tests use a small assert framework in `tests/test.h` with no external
dependencies. `tests/builder.c` builds frames and pcap files byte by byte, so
each test states exactly what the decoder sees. The tests cover:

- **pcap reader:** all four magic/endianness combinations, bad magic, pcapng
  rejection, bad version and link type, every truncated global-header length
  0–23, a truncated record header and record body, oversized `caplen`
  (262145 and 0xFFFFFFFF), exactly 262144 bytes, `origlen < caplen`, empty
  captures, and file and stream I/O.
- **Decoder:** IPv4/IPv6 with TCP (ports, flags), UDP, ICMP and ICMPv6.
  Single, double and triple VLAN tags. IPv4 options at every IHL from 6 to
  15. First and non-first fragments for IPv4, and IPv6 with hop-by-hop plus
  fragment headers, including the fragment IDs. Destination-options plus
  routing headers, the extension chain limit, and extension headers that
  overrun. Malformed input: IHL < 5, bad total length, TCP data offset < 5
  or too large, UDP length, an IPv6 payload length larger than the frame,
  and complete frames that end inside the Ethernet, VLAN, IPv4 or IPv6
  header. Snapshot-length truncation, which is not an error, IPv4 total
  length 0 (TSO), Ethernet padding, and non-IP frames.
- **Prefix sweep:** every prefix of several frames is decoded from a heap
  buffer of exactly that length, both as a snapped capture (which must come
  out OK or truncated) and as a complete frame (which must never come out
  truncated).
- **Flows:** normalisation, bidirectional merging, distinct 5-tuples,
  out-of-order timestamps, growth to 20,000 flows (with the load-factor and
  power-of-two invariants checked, and every flow found again), iteration,
  top-N ordering and tie-breaks, and top-N checked against a full sort of
  3,000 random flows. The fragment cache: matching, a later fragment before
  its first, different IDs and peers, and 1,000 datagrams in flight with no
  wrong match.
- **Output:** exact CSV text, RFC 5952 IPv6 formatting cases (including
  IPv4-mapped addresses), TCP flag strings, and end-to-end pipelines with
  exact counters: a mixed capture, fragments joining their flow, complete
  short frames counted as malformed, and a broken IPv6 chain counted under
  no transport protocol.
- **GTP-U** (`tests/test_gtpu.c`, 23 tests):
  - G-PDUs with IPv4/TCP and with IPv6/UDP inside, and IPv6 transport on a
    VLAN.
  - The S, PN and E flags, including a non-zero next-type byte with E
    clear, which must be ignored.
  - One extension header, and a chain of two whose first header is 2 units
    long, so a decoder that took the length as bytes would fail.
  - Malformed chains: an extension length of 0, a header that overruns the
    message, and a chain that promises another header after the message
    ends. 16 headers are accepted and a 17th is refused.
  - A GTP-U length larger than the UDP payload (malformed, even when the
    capture was cut short), against a consistent message cut at each layer
    (truncated). Also a length too short for the optional fields.
  - Versions 0, 2 and 7, and PT 0 (GTP'), counted as not GTPv1-U.
  - Echo request and response, error indication, end marker and an
    unknown type.
  - A payload that is not IP, an empty G-PDU, and IPv4 and IPv6 user
    packets too short for their own header, which get the GTP-U reason and
    not the outer "frame too short for its headers".
  - `gtp_msg_ok` at each stage: set when the user packet is cut short at
    three points or is malformed, and clear when the capture ends inside
    the first 8 bytes, the GTP-U length is too large, or an extension
    header is cut short or has length 0.
  - GTP-U inside GTP-U, flagged and not decoded.
  - Port 2152 as the source only and as the destination only; also a
    7-byte payload, TCP on port 2152 and a first IP fragment, none of
    which is decoded as GTP-U.
  - Two prefix sweeps. First, every prefix of a message as the complete
    payload of a UDP datagram: never truncated, and never OK unless whole.
    Second, every snapshot-length cut of the full frame: never blamed on
    the packet.
  - A 15-frame capture that checks every GTP-U counter and the tunnel table
    (direction, a TEID reused by another node, top-N). It also checks that
    a G-PDU with a broken GTP-U header still counts in its outer flow.
  - A 9-frame headers-only capture. G-PDUs whose user packet was cut by
    the snapshot length (inside its TCP, IPv4 or IPv6 header, or right
    after the GTP-U header) or is malformed still join their tunnels, with
    their full wire length. A tunnel whose only packet was cut short is
    still listed. A G-PDU cut inside an extension header does not join its
    tunnel, and the two "Problems" lines count each case on its side.
  - The exact tunnels CSV text and the GTP-U summary text.
- **CLI** (`tests/cli_test.sh`): exit codes for `--help`, usage errors, a
  missing file, a non-pcap file, a truncated capture (partial stats plus exit
  2), an unwritable CSV path, and `--csv` naming the input file (refused,
  input untouched). It also checks the CSV header and that the CSV has one
  row per flow. With the GTP-U sample, it checks the GTP-U section, the
  tunnel table, the tunnels CSV header and one row per tunnel, and that
  `-n 0` hides both tables. It also checks that a capture without GTP-U
  has no GTP-U section, and that `--tunnels-csv` is refused when it names
  the input file or the `--csv` file.

**Sanitizers.** `make asan` builds the same tests and the CLI with
`-fsanitize=address,undefined -fno-sanitize-recover=all`, so any UB report
fails the run, and runs the unit and CLI suites again. LeakSanitizer is on,
so leaks fail too.

**Fuzzing.** `fuzz/fuzz_decode.c` is a deterministic mutation fuzzer using a
seeded xorshift64 PRNG, so a given iteration count and seed always replay the
same inputs. Each random draw is its own statement: C leaves the evaluation
order of function arguments unspecified, so `f(rng(), rng())` would replay
differently under gcc and clang. With that rule, both compilers produce the
same fuzz report, number for number. Each iteration does the following:

- It takes one of 18 valid seed frames and applies 1–4 mutations: bit flips,
  random bytes, boundary values written at header offsets (0, 5, 20, 0xFFFF,
  ethertypes, ...), nibble rewrites (IP version, IHL, TCP data offset),
  truncation and extension. Five of the seeds are GTP-U:
  - a plain G-PDU;
  - one with S, E and a PDU Session Container;
  - one over IPv6 on a VLAN with a chain of two extension headers;
  - an echo request;
  - GTP-U inside GTP-U.
- Half the time, a GTP-U seed first gets a change aimed at the fields that
  steer the GTP-U parse: a flag bit (version, PT, E, S, PN), a boundary or
  off-by-a-few value in the length, a next-type byte that starts a chain,
  or an extension length of 0, 1, 2, 3 or 255.
- It decodes the result from a heap buffer of *exactly* the mutated length,
  so ASan reports a read even one byte past the end, and then runs it
  through the same accounting as the tool (fragment cache, counters, flow
  and tunnel tables).
- It decodes the same bytes a second time with 64 random bytes after them,
  and every field of the two results must match: the decoder may not look
  past `caplen`. ASan catches an over-read of the exact-size buffer; this
  check would also catch one in a build without sanitizers.
- It checks invariants on every result. For example: no L4 fields without a
  valid L3 header, and no ports read in non-first fragments. A frame whose
  captured length equals its wire length is never classified as truncated,
  and neither is the GTP-U message inside it. GTP-U fields are never set
  outside a clean, unfragmented UDP port 2152 datagram, and a clean G-PDU
  always has an inner packet. `gtp_msg_ok` is set exactly when the reason
  for stopping, if any, is not a GTP-U header problem, and no user packet
  is decoded without it.
- It formats one random IPv6 address (half its groups zero, sometimes
  IPv4-mapped) and compares the text with the C library's `inet_ntop()`.

Every fourth iteration it also builds a small pcap file from mutated frames,
corrupts record lengths (`caplen` and `origlen`) and random file bytes, and
cuts the file at a random point. It then reads the file twice in lockstep:
from memory, and through `fread()` from a `tmpfile()`. Both readers must
return the same records and the same final status. At the end, the summary,
the GTP-U section, both top-N tables and both CSVs are written for the whole
fuzzed flow and tunnel tables, and each CSV must have exactly one row per
entry. The fuzzer also counts, on its own, the G-PDUs whose GTP-U headers
decoded in full, and the tunnel table must hold exactly that many packets.

`make fuzz` (200,000 iterations, seed 1) reached:

- all 20 outcomes of the outer decoder;
- inside GTP-U, all 8 GTP-U problem reasons (5 in the GTP-U headers, 3
  about a G-PDU's payload), and 12 of the 13 that the user packet's IP and
  transport headers can have (not "truncated IPv6 extension header");
- 7 of the reader's format-error paths.

pcapng detection is not reached by random mutation; a unit test covers it
instead. Excerpt:

```text
decoder: 200000 mutated frames
  ok                                     140387
  truncated Ethernet header              7001
  ...                                    (all 19 problem reasons reached)
  frame too short for its headers        16264
  ...
  UDP length invalid                     3363
GTP-U: 33547 of those frames decoded as GTP-U, 14837 with a valid inner packet
  ok                                     20180
  truncated IPv4 header                  439
  ...                                    (12 user-packet reasons reached)
  truncated GTP-U header                 567
  truncated GTP-U extension header       146
  G-PDU truncated before its IP packet   28
  ...
  GTP-U length invalid                   5127
  GTP-U extension header length 0        325
  GTP-U extension header invalid         1051
  G-PDU payload not IPv4 or IPv6         1372
  G-PDU payload too short for IP header  369
reader: 50000 mutated pcap files (each read from memory and through stdio), 70604 records decoded
  end of file                            28691
  ...
  corrupt record: captured length exceeds 262144 bytes 5310
addresses: 200000 IPv6 addresses checked against inet_ntop
flow table: 29633 flows, 11533 later fragments matched; tunnel table: 4168 tunnels
tunnels: 31579 G-PDUs with complete GTP-U headers, all in the tunnel table
reports: summary, GTP-U section, top 100 flow and top 100 tunnel tables, 29633-row and 4168-row CSVs written
result: no crashes, no sanitizer reports, all invariants held
```

A longer run, `make fuzz FUZZ_ITERS=1000000`, also passes: 1,000,000
mutated frames (168,400 of them decoded as GTP-U), 250,000 mutated files
(354,460 records) and 1,000,000 addresses, with a byte-identical report
from gcc 13.3.0 and clang 17.0.6.

Five checks that the fuzzer finds real bugs, each on a scratch copy:

- With the `hlen > cap` check in `decode_ipv4` deleted, `make fuzz` failed
  with an ASan `heap-buffer-overflow` report in `decode_l4`.
- With the IPv4 fixed-header check changed back to the old
  `if (cap < 20) return DEC_TRUNC_IPV4`, it failed at iteration 23:
  "complete frame classified as truncated".
- With the bounds check before a GTP-U extension header's next-type byte
  deleted, it failed with an ASan `heap-buffer-overflow` report in
  `decode_gtpu`.
- With the check that the GTP-U length fits in the UDP payload deleted, it
  failed at iteration 104: "complete frame's GTP-U message classified as
  truncated". No memory was read wrongly. The lying length only raised the
  `wire` bound and never `cap`, so the cap/wire invariant was the only
  thing that could notice.
- With the tunnel rule changed back to an earlier version, which added a
  G-PDU to its tunnel only if its user packet also decoded cleanly
  (`gtp_status == DEC_OK` instead of `gtp_msg_ok` in `analysis_account`),
  the run failed its end-of-run check: "tunnel table packets differ from
  G-PDUs with complete headers". The headers-only unit test fails too.

**Compilers.** Locally (WSL2, Ubuntu 24.04), `make`, `make test`,
`make asan` and `make fuzz FUZZ_ITERS=1000000` all pass with gcc 13.3.0 and
with clang 17.0.6 (`make CC=/usr/lib/llvm-17/bin/clang ...`). CI runs `make`, `make test`,
`make asan` and `make fuzz FUZZ_ITERS=50000` with both compilers on
`ubuntu-latest`.

## Benchmarks

`./build/pcapstat -n 5` on three generated 1,000,000-packet captures: one
of ordinary traffic, one mostly GTP-U and one half GTP-U. Each got one
warm-up run, then 5 timed runs. The files sat on WSL's own ext4 file system
and were in the page cache, so this measures parsing, decoding and
counting, not the disk. Each run was started by a small C helper that
forks, `exec`s pcapstat with stdout sent to `/dev/null`, and waits with
`wait4()`. Wall time comes from `CLOCK_MONOTONIC` around the whole process;
peak RSS is `ru_maxrss`. The first two tables come from one session.

| | |
|---|---|
| Build | `make` (gcc 13.3.0, `-std=c11 -O2`) |
| Machine | Intel Core i9-13900HX laptop (`lscpu`: 32 logical CPUs), Windows 11 host with 15.7 GiB RAM; WSL2 VM with 7.6 GiB, kernel 5.15.167.4-microsoft-standard-WSL2, Ubuntu 24.04.3 LTS. Host CPU load was 2% before the runs |

Ordinary traffic:

| | |
|---|---|
| Capture | `python3 tools/gen_pcap.py --seed 1 --packets 1000000 --flows 20000 --out ~/bench_1m.pcap` (generated in 10.2 s): 789,683,198 bytes, SHA-256 `c8143d00…2e57412`, 510 s of traffic, 19,584 flows, no GTP-U |
| Wall time | median **0.171 s** over 5 runs (range 0.167–0.173 s) |
| Throughput at the median | **5.87 million packets/s**; 4,632 MB/s of capture file (file size ÷ wall time) |
| Peak RSS | **5.7–5.9 MiB** (5,824–6,004 KiB; the same helper reports 1,352 KiB for `/bin/true`) |
| With `--csv` (19,584 rows) | median 0.184 s (range 0.177–0.185 s), 5.44 million packets/s |

GTP-U traffic:

| | |
|---|---|
| Capture | `python3 tools/gen_pcap.py --seed 1 --packets 1000000 --flows 2000 --gtp-fraction 0.9 --out ~/bench_gtp_1m.pcap` (generated in 19.6 s): 705,568,084 bytes, SHA-256 `c49c3df5…b0fdd5f`, 508 s of traffic; 887,506 GTP-U packets, 880,230 of them G-PDUs whose user packet is decoded too; 71,469 tunnels and 1,976 outer flows |
| Wall time | median **0.224 s** over 5 runs (range 0.220–0.230 s) |
| Throughput at the median | **4.46 million packets/s**; 3,146 MB/s of capture file |
| Peak RSS | **18.3–18.4 MiB** (18,688–18,808 KiB). The tunnel table has grown to 131,072 slots of 88 bytes (11 MiB) |
| With `--tunnels-csv` (71,469 rows) | median 0.272 s (range 0.268–0.274 s), 3.68 million packets/s |

Half GTP-U traffic, measured later for v0.2.0 in a separate session. In
that session the two captures above had medians of 0.168 s (range
0.166–0.172 s) and 0.228 s (range 0.220–0.235 s). Both are within
run-to-run noise of the figures above, so those were kept.

| | |
|---|---|
| Capture | `python3 tools/gen_pcap.py --seed 1 --packets 1000000 --flows 20000 --gtp-fraction 0.5 --out ~/bench_gtp50_1m.pcap` (generated in 12.6 s): 680,441,006 bytes, SHA-256 `a34c8154…7dfc078`, 510 s of traffic; 493,113 GTP-U packets, 489,007 of them G-PDUs; 39,747 tunnels and 19,634 outer flows |
| Wall time | median **0.202 s** over 5 runs (range 0.196–0.205 s) |
| Throughput at the median | **4.94 million packets/s**; 3,364 MB/s of capture file |
| Peak RSS | **12.2–12.3 MiB** (12,500–12,636 KiB). The tunnel table has 65,536 slots of 88 bytes (5.5 MiB) |
| With `--tunnels-csv` (39,747 rows) | median 0.231 s (range 0.228–0.242 s), 4.33 million packets/s |

pcapstat is single-threaded, so these figures are for one core.

**What GTP-U support costs on traffic without GTP-U.** In the session of
the first two tables, the last commit before GTP-U and the commit that
added it were each run 25 times, interleaved, on the first capture. The
medians were 0.157 s and 0.169 s, so GTP-U support made it about 8%
slower. Five variants each undid or worked around one part of the change:

- the TEID left out of the flow hash;
- the GTP-U dispatch removed from the decoder;
- the GTP-U counters removed;
- the old flow slot layout;
- `packet_info` cleared in two parts instead of one. At 128 bytes it is
  past the 80 bytes up to which GCC clears with vector stores; above that,
  GCC uses `rep stos`.

Each variant won back 1% or less, so no single cause has been found.

To reproduce the runs:

```sh
python3 tools/gen_pcap.py --seed 1 --packets 1000000 --flows 20000 --out ~/bench_1m.pcap
python3 tools/gen_pcap.py --seed 1 --packets 1000000 --flows 2000 --gtp-fraction 0.9 --out ~/bench_gtp_1m.pcap
python3 tools/gen_pcap.py --seed 1 --packets 1000000 --flows 20000 --gtp-fraction 0.5 --out ~/bench_gtp50_1m.pcap
make
./build/pcapstat -n 5 ~/bench_1m.pcap > /dev/null          # warm-up
for i in 1 2 3 4 5; do /usr/bin/time -f '%e s %M KiB' ./build/pcapstat -n 5 ~/bench_1m.pcap > /dev/null; done
```

(`/usr/bin/time` rounds to 10 ms; the figures above used the finer
`CLOCK_MONOTONIC` helper described above.)

`make bench` generates the capture (if missing) and times one run. By
default the file is written to `bench/`. On WSL, keep it on the Linux file
system, as in `make bench BENCH_PCAP=$HOME/bench_1m.pcap`. A path under
`/mnt/c` is read through WSL's 9P bridge to Windows NTFS, so the timing
would include that bridge and not just the parser.

## Limitations

- Classic pcap only. pcapng is detected and rejected with a hint
  (`editcap -F pcap in.pcapng out.pcap`).
- Ethernet link type only (`DLT_EN10MB`). Linux cooked capture, raw IP and
  802.11 are rejected with a clear error.
- No IP fragment reassembly and no TCP stream reassembly. A non-first
  fragment joins its datagram's flow only if the first fragment was seen
  earlier and still holds its slot in the 4,096-slot cache. Otherwise it
  forms a port-less flow for its address pair.
- Checksums are not verified.
- An IPv4 total length of 0 is read as TCP segmentation offload ("to the end
  of the frame"), not as an error, so a corrupt 0 in a normal packet is not
  flagged.
- The `--csv` and `--tunnels-csv` guards compare file names, so
  `--csv ./cap.pcap cap.pcap` is not caught. Catching every spelling would
  need POSIX `stat()`.
- IPv6 jumbograms are not supported. AH/ESP and other headers are not walked
  and count as "other" protocols.
- At most two VLAN tags. A third is reported as a decode problem.
- GTP-U only, recognised on UDP port 2152 only. Nothing that sets tunnels
  up is decoded: not GTP-C (GTPv2-C on port 2123, the LTE control plane),
  not PFCP (N4, the 5G core's control of the UPF), and not S1AP or NGAP
  (the base station's signalling). So a tunnel cannot be tied to a
  subscriber or a session; it is just (source, destination, TEID).
- The information elements of echo, error indication and other signalling
  messages are not decoded, nor are extension header contents (for
  example the QoS flow ID in a PDU Session Container).
- No reassembly inside tunnels either. A GTP-U datagram split into IP
  fragments is counted, not decoded; a user packet that is itself an IP
  fragment is decoded as a fragment and not reassembled; and GTP-U inside
  GTP-U is counted, not decoded.
- User packets are decoded but not grouped into flows of their own: the
  tables show outer flows and tunnels, not the phones' conversations.
- The flow table grows without eviction (about 88 bytes per slot), so memory
  grows with the number of distinct flows. FNV-1a is not keyed, so traffic
  crafted to collide could slow the table down. A long-running monitor would
  need idle-flow eviction and a keyed hash such as SipHash.
- Single-threaded.

## Project layout

```text
src/            the tool (C11, libc only)
tests/          unit tests, test framework, packet/pcap builder, CLI tests
fuzz/           mutation fuzzer
tools/          gen_pcap.py: deterministic mixed-traffic capture generator,
                optionally with GTP-U traffic (--gtp-fraction)
samples/        sample.pcap (400 packets, from gen_pcap.py --seed 17) and
                gtpu_sample.pcap (300 packets, --seed 2 --gtp-fraction 0.9)
.github/        CI: gcc and clang; build, tests, sanitizers, fuzzing
```

## License

MIT. See [LICENSE](LICENSE).
