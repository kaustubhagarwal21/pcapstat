/*
 * fuzz_decode.c - deterministic mutation fuzzer for the frame decoder, the
 * pcap reader and the output code.
 *
 *   fuzz_decode [ITERATIONS [SEED]]      (defaults: 200000, 1)
 *
 * Built with -fsanitize=address,undefined. Each iteration takes a valid seed
 * frame, applies a few random mutations (bit flips, random bytes, "length
 * field" values such as 0, 5, 0xFFFF, truncation, extension) and decodes it
 * from a heap buffer of exactly the mutated length, so AddressSanitizer
 * catches a read even one byte past the end. The result goes through the
 * same accounting as the real tool (fragment cache, counters, flow table).
 *
 * Every fourth iteration also builds a small pcap file from mutated frames,
 * corrupts its record headers (caplen in particular) and file bytes, and
 * reads it twice in lockstep: from memory, and through stdio from a
 * tmpfile(). Both must return the same records and the same final status.
 *
 * Each iteration also formats one random IPv6 address and compares it with
 * the C library's inet_ntop() (POSIX, used here only as a reference). At
 * the end, the summary, top-N table and CSV are written for the fuzzed
 * flow table.
 *
 * The same ITERATIONS and SEED always replay the same inputs, so any
 * failure is reproducible. On a crash, sanitizer report or broken invariant
 * the process exits non-zero.
 */
#define _POSIX_C_SOURCE 200112L /* inet_ntop */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "addr.h"
#include "analyze.h"
#include "builder.h"
#include "decode.h"
#include "pcap_reader.h"
#include "report.h"

#define MAX_FRAME 2048
#define MAX_SEEDS 16
#define MAX_RECORDS 4

static uint64_t rng_state;

/* xorshift64 (Marsaglia 2003): tiny, fast, and fully determined by the
 * seed. Statistical quality is plenty for choosing mutations. */
static uint64_t rng(void)
{
    uint64_t x = rng_state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static size_t rng_below(size_t n)
{
    return n ? (size_t)(rng() % n) : 0;
}

/* Values that tend to sit on boundaries of length checks: zero, the IPv4
 * and TCP minimum header sizes (5 words, 20 bytes), maxima, sign-bit
 * values; plus ethertypes, so mutations can add or remove VLAN tags and
 * switch between IPv4 and IPv6. */
static const uint16_t interesting16[] = {
    0x0000, 0x0001, 0x0004, 0x0005, 0x0008, 0x000F, 0x0014, 0x0028,
    0x003C, 0x0040, 0x007F, 0x0080, 0x00FF, 0x0100, 0x05DC, 0x7FFF,
    0x8000, 0xFFFE, 0xFFFF,
    0x0800, 0x86DD, 0x8100, 0x88A8, 0x9100
};

static const uint32_t interesting32[] = {
    0u, 1u, 13u, 14u, 15u, 16u, 54u, 60u, 1514u, 65535u, 65536u,
    PCAP_MAX_CAPLEN - 1u, PCAP_MAX_CAPLEN, PCAP_MAX_CAPLEN + 1u,
    0x7FFFFFFFu, 0x80000000u, 0xFFFFFFF0u, 0xFFFFFFFFu
};

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

/*
 * Every random draw below is a separate statement. C leaves the order in
 * which function arguments, and the operands of most operators, are
 * evaluated unspecified, so something like `buf[rng_below(n)] ^= 1u <<
 * rng_below(8)` or `f(rng(), rng())` draws the same numbers in a different
 * order under gcc and clang, and the same seed would replay different
 * inputs.
 */

/* Flip one random bit of buf[0..len). */
static void flip_random_bit(uint8_t *buf, size_t len)
{
    size_t at;
    unsigned bit;

    if (len == 0)
        return;
    at = rng_below(len);
    bit = (unsigned)rng_below(8);
    buf[at] ^= (uint8_t)(1u << bit);
}

static void mutate(uint8_t *buf, size_t *len, size_t max)
{
    unsigned rounds = 1 + (unsigned)rng_below(4);

    while (rounds--) {
        switch (rng_below(6)) {
        case 0: /* flip one bit */
            flip_random_bit(buf, *len);
            break;
        case 1: /* overwrite one byte */
            if (*len > 0) {
                size_t at = rng_below(*len);

                buf[at] = (uint8_t)rng();
            }
            break;
        case 2: /* a boundary value in the first 96 bytes, where every
                 * length field of every header we decode lives */
            if (*len >= 2) {
                size_t off = rng_below((*len < 96 ? *len : 96) - 1);
                uint16_t v = interesting16[rng_below(COUNT_OF(interesting16))];

                buf[off] = (uint8_t)(v >> 8);
                buf[off + 1] = (uint8_t)v;
            }
            break;
        case 3: /* rewrite a nibble: IP version, IHL, TCP data offset */
            if (*len > 0) {
                size_t off = rng_below(*len < 96 ? *len : 96);
                unsigned nib = (unsigned)rng_below(16);

                if (rng() & 1)
                    buf[off] = (uint8_t)((buf[off] & 0x0F) | (nib << 4));
                else
                    buf[off] = (uint8_t)((buf[off] & 0xF0) | nib);
            }
            break;
        case 4: /* truncate */
            *len = rng_below(*len + 1);
            break;
        default: { /* append random bytes */
            size_t add = rng_below(64);

            if (add > max - *len)
                add = max - *len;
            while (add--)
                buf[(*len)++] = (uint8_t)rng();
            break;
        }
        }
    }
}

static void fail(const char *what, unsigned long long iter)
{
    fprintf(stderr, "fuzz_decode: invariant violated at iteration %llu: %s\n",
            iter, what);
    exit(1);
}

/* Properties that must hold for any input whatsoever. `complete` is set
 * when the frame was captured in full (caplen == wire length). */
static void check_invariants(const struct packet_info *pi,
                             enum decode_status st, int complete,
                             unsigned long long iter)
{
    if (st != pi->status)
        fail("return value != pi->status", iter);
    if ((unsigned)st >= DEC_STATUS_COUNT)
        fail("status out of range", iter);
    if (pi->vlan_count > DECODE_MAX_VLANS)
        fail("too many VLAN tags recorded", iter);
    if (pi->has_l4 && !pi->has_l3)
        fail("L4 decoded without L3", iter);
    if (pi->has_l3 && !pi->has_l2)
        fail("L3 decoded without L2", iter);
    if (pi->has_l3 && pi->ip_version != 4 && pi->ip_version != 6)
        fail("bad ip_version with has_l3", iter);
    if (pi->frag == FRAG_LATER && pi->has_l4)
        fail("L4 decoded in a non-first fragment", iter);
    if (st == DEC_OK && pi->has_l2 == 0)
        fail("DEC_OK without L2", iter);
    /* A frame that was not cut by the capture cannot be "truncated": if it
     * is too short for its headers, the frame itself is malformed. */
    if (complete && decode_status_is_truncation(st))
        fail("complete frame classified as truncated", iter);
}

/* Decode from an exact-size heap copy so ASan sees any over-read. */
static enum decode_status decode_exact(const uint8_t *data, size_t len,
                                       size_t wirelen, struct packet_info *pi)
{
    uint8_t *exact = malloc(len ? len : 1);
    enum decode_status st;

    if (exact == NULL) {
        fprintf(stderr, "fuzz_decode: out of memory\n");
        exit(1);
    }
    if (len > 0)
        memcpy(exact, data, len);
    st = decode_frame(exact, len, wirelen, pi);
    free(exact);
    return st;
}

static size_t build_seeds(struct bytebuf *seeds)
{
    size_t n = 0;
    struct bytebuf *b;

    b = &seeds[n++];
    frame_v4_tcp(b, TEST_V4_A, TEST_V4_B, 40000, 443, TCP_SYN, 0);

    b = &seeds[n++];                     /* IPv4 options + TCP payload */
    put_eth(b, ETHERTYPE_IPV4);
    put_ipv4(b, IPPROTO_NUM_TCP, TEST_V4_A, TEST_V4_B, 40, 3, 0x4000);
    put_tcp(b, 443, 40000, TCP_PSH | TCP_ACK);
    bb_fill(b, 0x42, 20);

    b = &seeds[n++];
    frame_v4_udp(b, TEST_V4_A, TEST_V4_B, 5353, 53, 40);

    b = &seeds[n++];                     /* ICMP echo */
    put_eth(b, ETHERTYPE_IPV4);
    put_ipv4(b, IPPROTO_NUM_ICMP, TEST_V4_A, TEST_V4_B, 8 + 16, 0, 0);
    put_icmp(b, 8, 0);
    bb_fill(b, 0x61, 16);

    b = &seeds[n++];
    frame_v6_tcp(b, TEST_V6_A, TEST_V6_B, 443, 50000, TCP_ACK, 32);

    b = &seeds[n++];                     /* IPv6 hop-by-hop + fragment + UDP */
    put_eth(b, ETHERTYPE_IPV6);
    put_ipv6(b, 0, TEST_V6_A, TEST_V6_B, 8 + 8 + 8 + 8);
    bb_u8(b, 44); bb_u8(b, 0); bb_u8(b, 1); bb_u8(b, 4); bb_fill(b, 0, 4);
    bb_u8(b, IPPROTO_NUM_UDP); bb_u8(b, 0); bb_be16(b, 1); bb_be32(b, 7);
    put_udp(b, 1000, 2000, 100);
    bb_fill(b, 0, 8);

    b = &seeds[n++];                     /* IPv6 dst-opts + routing + TCP */
    put_eth(b, ETHERTYPE_IPV6);
    put_ipv6(b, 60, TEST_V6_A, TEST_V6_B, 16 + 8 + 20);
    bb_u8(b, 43); bb_u8(b, 1); bb_fill(b, 0, 14);
    bb_u8(b, IPPROTO_NUM_TCP); bb_u8(b, 0); bb_fill(b, 0, 6);
    put_tcp(b, 80, 60000, TCP_FIN | TCP_ACK);

    b = &seeds[n++];                     /* ICMPv6 */
    put_eth(b, ETHERTYPE_IPV6);
    put_ipv6(b, IPPROTO_NUM_ICMPV6, TEST_V6_A, TEST_V6_B, 8);
    put_icmp(b, 128, 0);

    b = &seeds[n++];                     /* Q-in-Q + IPv4 UDP */
    put_eth(b, ETHERTYPE_QINQ);
    put_vlan(b, 300, ETHERTYPE_VLAN);
    put_vlan(b, 30, ETHERTYPE_IPV4);
    put_ipv4(b, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 8 + 12, 0, 0);
    put_udp(b, 4789, 4789, 12);
    bb_fill(b, 0, 12);

    b = &seeds[n++];                     /* single VLAN + IPv6 UDP */
    put_eth(b, ETHERTYPE_VLAN);
    put_vlan(b, 7, ETHERTYPE_IPV6);
    put_ipv6(b, IPPROTO_NUM_UDP, TEST_V6_A, TEST_V6_B, 8 + 4);
    put_udp(b, 546, 547, 4);
    bb_fill(b, 0, 4);

    b = &seeds[n++];                     /* IPv4 first fragment (MF set) */
    put_eth(b, ETHERTYPE_IPV4);
    put_ipv4(b, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 24, 0, 0x2000);
    put_udp(b, 4500, 4500, 200);
    bb_fill(b, 0x33, 16);

    b = &seeds[n++];                     /* IPv4 non-first fragment */
    put_eth(b, ETHERTYPE_IPV4);
    put_ipv4(b, IPPROTO_NUM_UDP, TEST_V4_A, TEST_V4_B, 24, 0, 185);
    bb_fill(b, 0x33, 24);

    b = &seeds[n++];                     /* ARP */
    put_eth(b, ETHERTYPE_ARP);
    bb_fill(b, 0, 28);
    return n;
}

struct totals {
    unsigned long long frames;
    unsigned long long by_status[DEC_STATUS_COUNT];
    unsigned long long files;
    unsigned long long file_records;
    unsigned long long file_outcome[PCAP_ERR_BAD_CAPLEN + 1];
    unsigned long long stream_files;
    unsigned long long addrs;
};

/* Decode one record, check it, and account it like the real tool does. */
static void process_record(const struct pcap_record *rec, struct analysis *an,
                           unsigned long long iter)
{
    struct packet_info pi;
    enum decode_status ds;

    if (rec->wirelen < rec->caplen)
        fail("record wire length below captured length", iter);
    ds = decode_exact(rec->data, rec->caplen, rec->wirelen, &pi);
    check_invariants(&pi, ds, rec->wirelen == rec->caplen, iter);
    if (analysis_account(an, &pi, rec->caplen, rec->wirelen, rec->ts_ns) != 0)
        fail("flow table out of memory", iter);
}

/* Build a small pcap file from mutated frames, corrupt it, and read it from
 * memory and, in lockstep, through stdio. */
static void fuzz_reader(const struct bytebuf *seeds, size_t nseeds,
                        struct analysis *an, struct totals *tot,
                        unsigned long long iter)
{
    struct bytebuf file;
    size_t rec_hdr_at[MAX_RECORDS];
    size_t nrec = rng_below(MAX_RECORDS + 1), k;
    int be = (int)(rng() & 1), nsec = (int)(rng() & 1);
    uint8_t frame[MAX_FRAME + 64];
    uint8_t *exact;
    struct pcap_reader mr, fr;
    struct pcap_record mrec, frec;
    enum pcap_status ms, fs;
    FILE *tmp;

    bb_init(&file);
    pcap_put_global(&file, be, nsec, 65535, 1);
    for (k = 0; k < nrec; k++) {
        const struct bytebuf *s = &seeds[rng_below(nseeds)];
        size_t len = s->len;
        uint32_t wire, sec, frac;

        memcpy(frame, s->data, len);
        if (rng() & 1)
            mutate(frame, &len, sizeof frame);
        wire = (uint32_t)len + ((rng() & 3) == 0 ? (uint32_t)rng_below(1500) : 0);
        sec = (uint32_t)rng();
        frac = (uint32_t)rng();
        rec_hdr_at[k] = file.len;
        pcap_put_record(&file, be, sec, frac, frame, (uint32_t)len, wire);
    }

    /* Corrupt a record length field (caplen or origlen), in file order. */
    if (nrec > 0 && (rng() & 1)) {
        size_t rec_no = rng_below(nrec);
        size_t at = rec_hdr_at[rec_no] + 8 + 4 * rng_below(2);
        uint32_t v = interesting32[rng_below(COUNT_OF(interesting32))];

        file.data[at + 0] = (uint8_t)(be ? v >> 24 : v);
        file.data[at + 1] = (uint8_t)(be ? v >> 16 : v >> 8);
        file.data[at + 2] = (uint8_t)(be ? v >> 8 : v >> 16);
        file.data[at + 3] = (uint8_t)(be ? v : v >> 24);
    }
    /* Random damage anywhere, including the global header. */
    if ((rng() & 3) == 0)
        flip_random_bit(file.data, file.len);
    /* Cut the file at a random point. */
    if ((rng() & 3) == 0)
        file.len = rng_below(file.len + 1);

    exact = malloc(file.len ? file.len : 1);
    if (exact == NULL)
        exit(1);
    if (file.len > 0)
        memcpy(exact, file.data, file.len);

    /* The same bytes as a real file, read through fread(). */
    tmp = tmpfile();
    if (tmp == NULL || fwrite(exact, 1, file.len, tmp) != file.len ||
        fflush(tmp) != 0) {
        fprintf(stderr, "fuzz_decode: cannot write temporary file\n");
        exit(1);
    }
    rewind(tmp);

    tot->files++;
    ms = pcap_open_mem(&mr, exact, file.len);
    fs = pcap_open_stream(&fr, tmp); /* fr now owns tmp */
    if (ms != fs)
        fail("memory and stream readers disagree on the global header", iter);
    if (ms == PCAP_OK) {
        for (;;) {
            ms = pcap_next(&mr, &mrec);
            fs = pcap_next(&fr, &frec);
            if (ms != fs)
                fail("memory and stream readers disagree on a record", iter);
            if (ms != PCAP_OK)
                break;
            if (mrec.caplen != frec.caplen || mrec.wirelen != frec.wirelen ||
                mrec.ts_ns != frec.ts_ns ||
                memcmp(mrec.data, frec.data, mrec.caplen) != 0)
                fail("memory and stream readers returned different records",
                     iter);

            /* The record must lie entirely inside the input buffer (memory
             * input returns records in place). caplen is checked first so
             * that file.len - caplen cannot wrap. */
            if (mrec.caplen > PCAP_MAX_CAPLEN || mrec.caplen > file.len ||
                (size_t)(mrec.data - exact) > file.len - mrec.caplen)
                fail("record outside the input buffer", iter);
            process_record(&mrec, an, iter);
            tot->file_records++;
        }
    }
    if (mr.records != fr.records)
        fail("memory and stream readers returned different counts", iter);
    tot->stream_files++;
    if ((unsigned)ms <= PCAP_ERR_BAD_CAPLEN)
        tot->file_outcome[ms]++;
    pcap_close(&mr);
    pcap_close(&fr);
    free(exact);
    bb_free(&file);
}

/* Format a random IPv6 address and compare with inet_ntop(). Half the
 * groups are zero so that "::" compression is exercised hard. */
static void fuzz_addr(struct totals *tot, unsigned long long iter)
{
    uint8_t a[16];
    char mine[ADDR_STR_LEN], ref[INET6_ADDRSTRLEN];
    int g, compat;

    for (g = 0; g < 8; g++) {
        unsigned v;

        switch (rng_below(4)) {
        case 0:
        case 1:  v = 0; break;
        case 2:  v = (unsigned)rng_below(16); break;
        default: v = (unsigned)(rng() & 0xFFFF); break;
        }
        a[2 * g] = (uint8_t)(v >> 8);
        a[2 * g + 1] = (uint8_t)v;
    }
    if (rng_below(16) == 0) {           /* IPv4-mapped, ::ffff:a.b.c.d */
        memset(a, 0, 10);
        a[10] = a[11] = 0xff;
    }
    addr_format(6, a, mine, sizeof mine);
    if (inet_ntop(AF_INET6, a, ref, sizeof ref) == NULL)
        fail("inet_ntop failed", iter);

    /* glibc also prints the deprecated IPv4-compatible form (96 zero bits,
     * then a non-zero group) as ::a.b.c.d. RFC 5952 does not ask for that,
     * and pcapstat prints it in hex, so those addresses are skipped. */
    compat = a[12] != 0 || a[13] != 0;
    for (g = 0; g < 12 && compat; g++)
        compat = a[g] == 0;
    if (!compat && strcmp(mine, ref) != 0) {
        fprintf(stderr, "fuzz_decode: addr_format gave \"%s\", inet_ntop "
                        "gave \"%s\"\n", mine, ref);
        fail("IPv6 text form differs from inet_ntop", iter);
    }
    tot->addrs++;
}

/* Write the summary, the top-N table and the CSV for whatever the fuzzed
 * inputs left in the flow table, and check the CSV's shape. */
static void fuzz_reports(const struct analysis *an)
{
    struct pcap_file_info info;
    const struct flow **top;
    size_t n = an->flows.count < 100 ? an->flows.count : 100;
    unsigned long long lines = 0;
    FILE *f = tmpfile();
    int c;

    if (f == NULL)
        fail("cannot create temporary file for reports", 0);
    memset(&info, 0, sizeof info);
    info.version_major = 2;
    info.version_minor = 4;
    report_summary(f, "fuzz", &info, &an->stats, an->flows.count);
    top = malloc((n ? n : 1) * sizeof *top);
    if (top == NULL)
        exit(1);
    n = flow_table_top_n(&an->flows, n, top);
    report_top_flows(f, top, n, an->flows.count);
    free(top);
    if (ferror(f))
        fail("report write failed", 0);
    fclose(f);

    f = tmpfile();
    if (f == NULL)
        fail("cannot create temporary file for CSV", 0);
    if (report_csv(f, &an->flows) != 0)
        fail("CSV write failed", 0);
    rewind(f);
    while ((c = getc(f)) != EOF)
        lines += c == '\n';
    fclose(f);
    if (lines != (unsigned long long)an->flows.count + 1)
        fail("CSV does not have one row per flow plus a header", 0);
    printf("reports: summary, top %zu table and %zu-row CSV written\n", n,
           an->flows.count);
}

int main(int argc, char **argv)
{
    unsigned long long iterations = 200000, seed = 1, i;
    struct bytebuf seeds[MAX_SEEDS];
    size_t nseeds, k;
    struct analysis an;
    struct totals tot;
    uint8_t work[MAX_FRAME + 64];

    if (argc > 1)
        iterations = strtoull(argv[1], NULL, 10);
    if (argc > 2)
        seed = strtoull(argv[2], NULL, 10);
    /* xorshift must not start at 0 (it would stay 0 forever). */
    rng_state = seed * 0x9E3779B97F4A7C15ull + 1;
    if (rng_state == 0)
        rng_state = 1;

    for (k = 0; k < MAX_SEEDS; k++)
        bb_init(&seeds[k]);
    nseeds = build_seeds(seeds);
    memset(&tot, 0, sizeof tot);
    if (analysis_init(&an) != 0)
        return 1;

    for (i = 0; i < iterations; i++) {
        const struct bytebuf *s = &seeds[rng_below(nseeds)];
        size_t len = s->len;
        size_t wirelen;
        struct packet_info pi;
        enum decode_status ds;

        memcpy(work, s->data, len);
        mutate(work, &len, sizeof work);
        /* Half the time claim the frame was longer on the wire, as with a
         * snapshot length, to exercise the truncated-vs-malformed logic. */
        wirelen = (rng() & 1) ? len : len + rng_below(3000);

        ds = decode_exact(work, len, wirelen, &pi);
        check_invariants(&pi, ds, wirelen == len, i);
        tot.frames++;
        tot.by_status[ds]++;
        if (analysis_account(&an, &pi, (uint32_t)len, (uint32_t)wirelen,
                             i) != 0)
            fail("flow table out of memory", i);

        if ((i & 3) == 0)
            fuzz_reader(seeds, nseeds, &an, &tot, i);
        fuzz_addr(&tot, i);
    }

    printf("fuzz_decode: %llu iterations, seed %llu\n", iterations, seed);
    printf("decoder: %llu mutated frames\n", tot.frames);
    for (k = 0; k < DEC_STATUS_COUNT; k++) {
        if (tot.by_status[k] > 0)
            printf("  %-38s %llu\n",
                   decode_status_str((enum decode_status)k),
                   tot.by_status[k]);
    }
    printf("reader: %llu mutated pcap files (each read from memory and "
           "through stdio), %llu records decoded\n",
           tot.files, tot.file_records);
    for (k = 0; k <= PCAP_ERR_BAD_CAPLEN; k++) {
        if (tot.file_outcome[k] > 0)
            printf("  %-38s %llu\n", pcap_status_str((enum pcap_status)k),
                   tot.file_outcome[k]);
    }
    printf("addresses: %llu IPv6 addresses checked against inet_ntop\n",
           tot.addrs);
    printf("flow table: %zu flows, %llu later fragments matched\n",
           an.flows.count, (unsigned long long)an.stats.frag_matched);
    fuzz_reports(&an);
    printf("result: no crashes, no sanitizer reports, all invariants held\n");

    analysis_free(&an);
    for (k = 0; k < nseeds; k++)
        bb_free(&seeds[k]);
    return 0;
}
