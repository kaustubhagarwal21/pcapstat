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
  impossible, or the frame is too short for its own headers). Nothing it
  fails to understand stops the run.
- Keeps bidirectional 5-tuple flows in an open-addressing hash table and
  prints the top N by bytes. Later IP fragments, which carry no ports, are
  matched to their datagram's flow. `--csv` writes every flow to a CSV file.

## Build and run

Needs a C11 compiler and `make`. `python3` is needed only to regenerate the
sample and benchmark captures.

```sh
make                  # release build: build/pcapstat
make test             # 73 unit tests + 24 CLI checks
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
the records before the damage is still printed. Giving the input file's name
as the `--csv` output is a usage error, so repeating the name by mistake
cannot overwrite the capture.

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

## Design

```text
 pcap_reader  --record-->  decode  --packet_info-->  stats  (global counters)
 (file/memory)             (pure)                 \-> flow   (hash table, top-N)
                                                        |
                                           report: summary, table, CSV
```

| File | Role |
|---|---|
| `src/pcap_reader.{c,h}` | Global header and record parsing from a file, an open stream or a memory buffer |
| `src/decode.{c,h}` | Pure, bounds-checked frame decoder producing a `struct packet_info` |
| `src/flow.{c,h}` | Bidirectional flow key, open-addressing hash table, top-N selection |
| `src/frag.{c,h}` | Direct-mapped cache that gives later IP fragments their datagram's ports |
| `src/stats.{c,h}` | Capture-wide counters, including decode problems by reason |
| `src/analyze.{c,h}` | The read → decode → count loop, shared by the CLI, the tests and the fuzzer |
| `src/report.{c,h}`, `src/addr.{c,h}` | Text output, CSV, RFC 5952 IPv6 formatting |
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

## Testing

`make test` runs 73 unit tests (42,257 individual checks) and 24 CLI checks.
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
- **CLI** (`tests/cli_test.sh`): exit codes for `--help`, usage errors, a
  missing file, a non-pcap file, a truncated capture (partial stats plus exit
  2), an unwritable CSV path, and `--csv` naming the input file (refused,
  input untouched). It also checks the CSV header and that the CSV has one
  row per flow.

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

- It takes one of 13 valid seed frames and applies 1–4 mutations: bit flips,
  random bytes, boundary values written at header offsets (0, 5, 20, 0xFFFF,
  ethertypes, ...), nibble rewrites (IP version, IHL, TCP data offset),
  truncation and extension.
- It decodes the result from a heap buffer of *exactly* the mutated length,
  so ASan reports a read even one byte past the end, and then runs it
  through the same accounting as the tool (fragment cache, counters, flow
  table).
- It checks invariants on every result. For example: no L4 fields without a
  valid L3 header, no ports read in non-first fragments, and a frame whose
  captured length equals its wire length never classified as truncated.
- It formats one random IPv6 address (half its groups zero, sometimes
  IPv4-mapped) and compares the text with the C library's `inet_ntop()`.

Every fourth iteration it also builds a small pcap file from mutated frames,
corrupts record lengths (`caplen` and `origlen`) and random file bytes, and
cuts the file at a random point. It then reads the file twice in lockstep:
from memory, and through `fread()` from a `tmpfile()`. Both readers must
return the same records and the same final status. At the end, the summary,
top-N table and CSV are written for the whole fuzzed flow table, and the CSV
must have exactly one row per flow.

`make fuzz` (200,000 iterations, seed 1) reached all 20 decoder outcomes and
7 of the reader's format-error paths. pcapng detection is not reached by
random mutation; a unit test covers it instead. Excerpt:

```text
decoder: 200000 mutated frames
  ok                                     139927
  truncated Ethernet header              7558
  ...                                    (all 19 problem reasons reached)
  frame too short for its headers        17585
  ...
  UDP length invalid                     2070
reader: 50000 mutated pcap files (each read from memory and through stdio), 70429 records decoded
  end of file                            28822
  ...
  corrupt record: captured length exceeds 262144 bytes 5215
addresses: 200000 IPv6 addresses checked against inet_ntop
flow table: 30815 flows, 14550 later fragments matched
reports: summary, top 100 table and 30815-row CSV written
result: no crashes, no sanitizer reports, all invariants held
```

A longer run, `make fuzz FUZZ_ITERS=1000000`, also passes: 1,000,000
mutated frames, 250,000 mutated files (353,901 records) and 1,000,000
addresses, with a byte-identical report from gcc 13.3.0 and clang 17.0.6.

Two checks that the fuzzer finds real bugs, each on a scratch copy:

- With the `hlen > cap` check in `decode_ipv4` deleted, `make fuzz` failed
  with an ASan `heap-buffer-overflow` report in `decode_l4`.
- With the IPv4 fixed-header check changed back to the old
  `if (cap < 20) return DEC_TRUNC_IPV4`, it failed at iteration 23:
  "complete frame classified as truncated".

**Compilers.** Locally (WSL2, Ubuntu 24.04), `make`, `make test`,
`make asan` and `make fuzz FUZZ_ITERS=1000000` all pass with gcc 13.3.0 and
with clang 17.0.6 (`make CC=/usr/lib/llvm-17/bin/clang ...`). CI runs `make`, `make test`,
`make asan` and `make fuzz FUZZ_ITERS=50000` with both compilers on
`ubuntu-latest`.

## Benchmarks

`./build/pcapstat -n 5` on a generated 1,000,000-packet capture: one warm-up
run, then 5 timed runs. The file sat on WSL's own ext4 file system and was
in the page cache, so this measures parsing, decoding and counting, not the
disk. Each run was started by a small C helper that forks, `exec`s pcapstat
with stdout sent to `/dev/null`, and waits with `wait4()`. Wall time comes
from `CLOCK_MONOTONIC` around the whole process; peak RSS is `ru_maxrss`.

| | |
|---|---|
| Capture | `python3 tools/gen_pcap.py --seed 1 --packets 1000000 --flows 20000 --out ~/bench_1m.pcap` (generated in 9.1 s): 789,683,198 bytes, SHA-256 `c8143d00…2e57412`, 510 s of traffic, 19,584 flows |
| Build | `make` (gcc 13.3.0, `-std=c11 -O2`) |
| Machine | Intel Core i9-13900HX laptop (`lscpu`: 32 logical CPUs), Windows 11 host with 15.7 GiB RAM; WSL2 VM with 7.6 GiB, kernel 5.15.167.4-microsoft-standard-WSL2, Ubuntu 24.04.3 LTS. Host CPU load was 5% before the runs |
| Wall time | median **0.165 s** over 5 runs (range 0.155–0.246 s) |
| Throughput at the median | **6.05 million packets/s**; 4,780 MB/s of capture file (file size ÷ wall time) |
| Peak RSS | **5.8–5.9 MiB** (5,908–6,036 KiB; the same helper reports 1,348 KiB for `/bin/true`) |
| With `--csv` (19,584 rows) | median 0.174 s (range 0.171–0.199 s), 5.74 million packets/s |

pcapstat is single-threaded, so these figures are for one core.

To reproduce the runs:

```sh
python3 tools/gen_pcap.py --seed 1 --packets 1000000 --flows 20000 --out ~/bench_1m.pcap
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
- The `--csv` guard compares file names, so `--csv ./cap.pcap cap.pcap` is
  not caught. Catching every spelling would need POSIX `stat()`.
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
