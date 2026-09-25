# pcapstat

`pcapstat` is a small command-line tool in C11 that reads classic libpcap
capture files (`.pcap`, as written by tcpdump and Wireshark). It decodes
Ethernet, 802.1Q / 802.1ad VLAN tags, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6,
then reports per-protocol counts, decode problems and the largest
bidirectional flows. It depends on nothing but the C standard library.

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
  impossible). Nothing it fails to understand stops the run.
- Keeps bidirectional 5-tuple flows in an open-addressing hash table and
  prints the top N by bytes. `--csv` writes every flow to a CSV file.

## Build and run

Needs a C11 compiler and `make`. `python3` is needed only to regenerate the
sample and benchmark captures.

```sh
make                  # release build: build/pcapstat
make test             # 61 unit tests + 22 CLI checks
make asan             # the same tests under ASan + UBSan
make fuzz             # 200,000 fuzz iterations under ASan + UBSan
make bench            # build a 1,000,000-packet capture, then time pcapstat on it
```

```text
usage: pcapstat [-n N] [--csv FILE] FILE.pcap

  -n N        show the top N flows by bytes (default 10, 0 hides the table)
  --csv FILE  also write every flow to FILE as CSV
  -h, --help  show this help

exit status: 0 ok, 1 usage error, 2 input error
```

An input error covers a file that cannot be opened, is not a pcap file,
turns out to be truncated or corrupt part-way through, or a CSV file that
cannot be written. For a capture damaged part-way through, the summary for
the records before the damage is still printed.

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
Fragments:   3 first, 6 non-first (not L4-decoded)
Flows:       29
Problems:    0 truncated, 0 malformed (excluded from flows)

Top 10 of 29 flows by bytes (src = sender of the first packet seen):
  #  proto   src                 dst                  packets       bytes      duration  tcp flags
  1  TCP     10.0.0.5:38348      198.51.100.34:443        129      121443       0.579 s  FSPA
  2  TCP     10.0.0.6:53655      203.0.113.9:443           34       16123       1.095 s  FSPA
  3  UDP     203.0.113.124:443   10.0.0.2:37158             8        9710       0.014 s  -
  4  TCP     10.0.0.3:45033      203.0.113.126:443         34        9678       1.595 s  FSPA
  5  UDP     203.0.113.190:4500  10.0.0.4:52459             8        9596       0.019 s  -
  6  UDP     198.51.100.8:0      10.0.0.6:0                 6        6315       0.007 s  -
  7  TCP     10.0.0.2:40834      203.0.113.80:443          16        6264       0.623 s  FSPA
  8  TCP     10.0.0.3:40596      198.51.100.211:443        14        5533       0.171 s  FSPA
  9  UDP     198.51.100.8:4500   10.0.0.6:42363             3        4542       0.007 s  -
 10  TCP     10.0.0.6:60851      203.0.113.57:443          18        4358       0.480 s  FSPA
```

Notes on reading it:

- TCP flags are the union over the whole flow, in bit order F S R P A U E C.
  `FSPA` means the flow saw FIN, SYN, PSH and ACK.
- Row 6 is the non-first IP fragments of the stream in row 9. They carry no
  UDP header, so they have no ports. pcapstat does not reassemble fragments,
  so they form their own port-less flow (see [Limitations](#limitations)).
- The CSV file (`--csv flows.csv`) has one row per flow, largest first:
  `src_addr,src_port,dst_addr,dst_port,protocol,ip_version,packets,bytes,first_ts,last_ts,duration_s,tcp_flags`,
  with timestamps as `seconds.nanoseconds`.

## Design

```text
 pcap_reader  --record-->  decode  --packet_info-->  stats  (global counters)
 (file/memory)             (pure)                 \-> flow   (hash table, top-N)
                                                        |
                                           report: summary, table, CSV
```

| File | Role |
|---|---|
| `src/pcap_reader.{c,h}` | Global header and record parsing from a file or a memory buffer |
| `src/decode.{c,h}` | Pure, bounds-checked frame decoder producing a `struct packet_info` |
| `src/flow.{c,h}` | Bidirectional flow key, open-addressing hash table, top-N selection |
| `src/stats.{c,h}` | Capture-wide counters, including decode problems by reason |
| `src/analyze.{c,h}` | The read → decode → count loop, shared by the CLI and the tests |
| `src/report.{c,h}`, `src/addr.{c,h}` | Text output, CSV, RFC 5952 IPv6 formatting |
| `src/bytes.h` | Explicit big/little-endian loads from byte buffers |
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
  allocated once.
- **Truncation is reported, not tolerated silently.** Zero bytes at a record
  boundary is a clean end of file. 1–15 bytes of a record header, or fewer
  data bytes than `caplen`, is reported as a truncated file. Errors are
  sticky, so the reader never resynchronises on garbage.
- **Overflow-safe arithmetic.** Timestamps are computed in 64 bits:
  `(2^32-1) * 10^9 + (2^32-1) * 1000` still fits. The memory reader compares
  `n > len - pos` rather than computing `pos + n`.
- **One code path, two sources.** The reader works on a `FILE *` or on a
  memory buffer. The tests and the fuzzer use memory; the CLI uses files.

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

Other rules:

- Multi-byte fields are read with byte loads (`load_be16`, `load_be32`), never
  by casting the buffer to a struct pointer. Packet data is unaligned (the IP
  header starts at offset 14), and a cast would also break strict aliasing.
- IPv4: IHL must be ≥ 5. Options are skipped using IHL, and the total length
  must be between the header length and the frame length.
- IPv4 and IPv6 fragments: only the first fragment (offset 0) carries the L4
  header. Later fragments are counted, but their first bytes are not read as
  ports.
- IPv6: extension headers are walked in a loop capped at 8 headers, and each
  one's length is checked against both `cap` and `wire`. The payload length
  must fit in the frame.
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
- **Top-N.** A size-N min-heap keyed on rank: a flow only has to beat the
  heap's root to get in, so selection costs O(F log N) for F flows. The N
  winners are then sorted. Ties are broken by packets, then start time, then
  key, so the output is fully deterministic.

## Testing

`make test` runs 61 unit tests (41,844 individual checks) and 22 CLI checks.
The tests use a small assert framework in `tests/test.h` with no external
dependencies. `tests/builder.c` builds frames and pcap files byte by byte, so
each test states exactly what the decoder sees. The tests cover:

- **pcap reader:** all four magic/endianness combinations, bad magic, pcapng
  rejection, bad version and link type, every truncated global-header length
  0–23, a truncated record header and record body, oversized `caplen`
  (262145 and 0xFFFFFFFF), exactly 262144 bytes, empty captures, and file
  I/O.
- **Decoder:** IPv4/IPv6 with TCP (ports, flags), UDP, ICMP and ICMPv6.
  Single, double and triple VLAN tags. IPv4 options at every IHL from 6 to
  15. First and non-first fragments for IPv4, and IPv6 with hop-by-hop plus
  fragment headers. Destination-options plus routing headers, the extension
  chain limit, and extension headers that overrun. Malformed input: IHL < 5,
  bad total length, TCP data offset < 5 or too large, UDP length, and an IPv6
  payload length larger than the frame. Snapshot-length truncation, which is
  not an error, Ethernet padding, and non-IP frames.
- **Prefix sweep:** every prefix of several frames is decoded from a heap
  buffer of exactly that length, both as a snapped capture and as a complete
  frame.
- **Flows:** normalisation, bidirectional merging, distinct 5-tuples,
  out-of-order timestamps, growth to 20,000 flows (with the load-factor and
  power-of-two invariants checked, and every flow found again), iteration,
  top-N ordering and tie-breaks, and top-N checked against a full sort of
  3,000 random flows.
- **Output:** exact CSV text, RFC 5952 IPv6 formatting cases, TCP flag
  strings, and an end-to-end pipeline over a mixed capture with exact
  counters.
- **CLI** (`tests/cli_test.sh`): exit codes for `--help`, usage errors, a
  missing file, a non-pcap file, a truncated capture (partial stats plus exit
  2) and an unwritable CSV path. It also checks the CSV header and that the
  CSV has one row per flow.

**Sanitizers.** `make asan` builds the same tests and the CLI with
`-fsanitize=address,undefined -fno-sanitize-recover=all`, so any UB report
fails the run, and runs the unit and CLI suites again. LeakSanitizer is on,
so leaks fail too.

**Fuzzing.** `fuzz/fuzz_decode.c` is a deterministic mutation fuzzer using a
seeded xorshift64 PRNG, so a given iteration count and seed always replay the
same inputs. Each iteration does the following:

- It takes one of 12 valid seed frames and applies 1–4 mutations: bit flips,
  random bytes, boundary values written at header offsets (0, 5, 20, 0xFFFF,
  ethertypes, ...), nibble rewrites (IP version, IHL, TCP data offset),
  truncation and extension.
- It decodes the result from a heap buffer of *exactly* the mutated length,
  so ASan reports a read even one byte past the end.
- It checks invariants on every result, for example that no L4 fields are
  set without a valid L3 header, and that no ports are read in non-first
  fragments.

Every fourth iteration it also builds a small pcap file from mutated frames,
corrupts record lengths (`caplen` and `origlen`) and random file bytes, cuts
the file at a random point, and runs it through the reader, decoder, stats
and flow table.

`make fuzz` (200,000 iterations, seed 1) reached all 19 decoder outcomes and
7 of the reader's format-error paths. pcapng detection is not reached by
random mutation; a unit test covers it instead.

```text
decoder: 200000 mutated frames
  ok                                     139861
  truncated Ethernet header              15089
  ...                                    (all 18 problem reasons reached)
  UDP length invalid                     2122
reader: 50000 mutated pcap files, 70938 records decoded
  end of file                            28740
  corrupt record: captured length exceeds 262144 bytes 5148
  ...
result: no crashes, no sanitizer reports, all invariants held
```

To check that the fuzzer can find real bugs, the `hlen > cap` check in
`decode_ipv4` was deleted from a scratch copy. `make fuzz` then failed with
an ASan `heap-buffer-overflow` report in `decode_l4`.

## Benchmarks

Measured by running `./build/pcapstat -n 5` on a generated 1,000,000-packet
capture. There was one warm-up run, then 10 timed runs; the file was in the
page cache, so this measures parsing and counting, not the disk.

| | |
|---|---|
| Capture | `python3 tools/gen_pcap.py --seed 1 --packets 1000000 --flows 20000` → 789,683,198 bytes, 19,939 flows, 510 s of traffic (generated in 9.1 s) |
| Machine | Intel Core i9-13900HX, WSL2 (kernel 5.15.167.4), Ubuntu 24.04, gcc 13.3.0, `-O2` |
| Wall time | median **0.162 s** (min 0.157 s, max 0.172 s) |
| Throughput | about **6.2 million packets/s**, 4.9 GB/s of capture file |
| Peak memory | about 5.8 MB max RSS |
| With `--csv` of all 19,939 flows | 0.17 s |

`make bench` generates the capture (if missing) and times one run. By
default the file is written to `bench/`. On WSL, keep it on the Linux file
system, as in `make bench BENCH_PCAP=$HOME/bench_1m.pcap`: reading the same
file from `/mnt/c` (Windows NTFS through WSL's 9P bridge) took 74–78 s. Only
about 0.5 s of that was user CPU; the rest was waiting on I/O.

## Limitations

- Classic pcap only. pcapng is detected and rejected with a hint
  (`editcap -F pcap in.pcapng out.pcap`).
- Ethernet link type only (`DLT_EN10MB`). Linux cooked capture, raw IP and
  802.11 are rejected with a clear error.
- No IP fragment reassembly and no TCP stream reassembly. Non-first
  fragments are counted, and form a port-less flow for their address pair.
- Checksums are not verified.
- IPv6 jumbograms are not supported. AH/ESP and other headers are not walked
  and count as "other" protocols.
- At most two VLAN tags. A third is reported as a decode problem.
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
tools/          gen_pcap.py: deterministic mixed-traffic capture generator
samples/        sample.pcap (400 packets, from gen_pcap.py --seed 17)
.github/        CI: gcc and clang; build, tests, sanitizers, fuzzing
```

## License

MIT. See [LICENSE](LICENSE).
