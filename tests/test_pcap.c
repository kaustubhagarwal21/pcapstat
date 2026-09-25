/*
 * test_pcap.c - pcap file reader tests.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "builder.h"
#include "pcap_reader.h"
#include "test.h"

static const uint8_t payload8[8] = {1, 2, 3, 4, 5, 6, 7, 8};

/* A one-record capture in the given byte order and timestamp resolution;
 * checks that the record comes back intact with the right timestamp. */
static void check_variant(int big_endian, int nsec)
{
    struct bytebuf b;
    struct pcap_reader r;
    struct pcap_record rec;

    bb_init(&b);
    pcap_put_global(&b, big_endian, nsec, 65535, 1);
    pcap_put_record(&b, big_endian, 1700000000u, 123456u, payload8, 8, 60);

    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_OK);
    CHECK_EQ(r.info.big_endian, big_endian);
    CHECK_EQ(r.info.nsec, nsec);
    CHECK_EQ(r.info.snaplen, 65535);
    CHECK_EQ(r.info.linktype, 1);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_OK);
    CHECK_EQ(rec.caplen, 8);
    CHECK_EQ(rec.wirelen, 60);
    CHECK(memcmp(rec.data, payload8, 8) == 0);
    /* 123456 is microseconds or nanoseconds depending on the magic. */
    CHECK_EQ(rec.ts_ns, 1700000000ull * 1000000000ull +
                            (nsec ? 123456ull : 123456000ull));
    CHECK_EQ(pcap_next(&r, &rec), PCAP_EOF);
    pcap_close(&r);
    bb_free(&b);
}

static void test_magic_le_usec(void) { check_variant(0, 0); }
static void test_magic_be_usec(void) { check_variant(1, 0); }
static void test_magic_le_nsec(void) { check_variant(0, 1); }
static void test_magic_be_nsec(void) { check_variant(1, 1); }

static void test_bad_magic(void)
{
    uint8_t hdr[24];
    struct pcap_reader r;

    memset(hdr, 0x55, sizeof hdr);
    CHECK_EQ(pcap_open_mem(&r, hdr, sizeof hdr), PCAP_ERR_BAD_MAGIC);
    /* A short file that is not pcap should say "bad magic", not "short". */
    CHECK_EQ(pcap_open_mem(&r, hdr, 6), PCAP_ERR_BAD_MAGIC);
}

static void test_pcapng_rejected(void)
{
    static const uint8_t shb[24] = {0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0, 0, 0,
                                    0x4D, 0x3C, 0x2B, 0x1A};
    struct pcap_reader r;

    CHECK_EQ(pcap_open_mem(&r, shb, sizeof shb), PCAP_ERR_PCAPNG);
}

static void test_bad_version_and_linktype(void)
{
    struct bytebuf b;
    struct pcap_reader r;

    bb_init(&b);
    pcap_put_global(&b, 0, 0, 65535, 1);
    b.data[4] = 1; /* version 1.4 */
    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_ERR_BAD_VERSION);
    bb_free(&b);

    pcap_put_global(&b, 0, 0, 65535, 101); /* LINKTYPE_RAW */
    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_ERR_BAD_LINKTYPE);
    bb_free(&b);

    /* Upper bits of the link-type field are FCS metadata, not the type. */
    pcap_put_global(&b, 1, 0, 65535, 0x14000001u);
    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_OK);
    CHECK_EQ(r.info.linktype, 1);
    bb_free(&b);
}

static void test_truncated_global_header(void)
{
    struct bytebuf b;
    struct pcap_reader r;
    size_t cut;

    bb_init(&b);
    pcap_put_global(&b, 0, 0, 65535, 1);
    /* Every length short of 24 must fail cleanly, including 0. */
    for (cut = 0; cut < PCAP_GLOBAL_HDR_LEN; cut++)
        CHECK_EQ(pcap_open_mem(&r, cut ? b.data : NULL, cut),
                 PCAP_ERR_SHORT_HEADER);
    bb_free(&b);
}

static void test_truncated_record_header(void)
{
    struct bytebuf b;
    struct pcap_reader r;
    struct pcap_record rec;

    bb_init(&b);
    pcap_put_global(&b, 0, 0, 65535, 1);
    pcap_put_record(&b, 0, 1, 0, payload8, 8, 8);
    bb_fill(&b, 0, 7); /* 7 of the next record header's 16 bytes */

    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_OK);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_OK);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_ERR_TRUNC_RECORD_HDR);
    CHECK_EQ(r.records, 1);
    bb_free(&b);
}

static void test_truncated_record_data(void)
{
    struct bytebuf b;
    struct pcap_reader r;
    struct pcap_record rec;

    bb_init(&b);
    pcap_put_global(&b, 0, 0, 65535, 1);
    pcap_put_record(&b, 0, 1, 0, payload8, 8, 8);
    /* Header promises 60 bytes, only 30 follow. */
    bb_u32(&b, 2, 0);
    bb_u32(&b, 0, 0);
    bb_u32(&b, 60, 0);
    bb_u32(&b, 60, 0);
    bb_fill(&b, 0xEE, 30);

    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_OK);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_OK);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_ERR_TRUNC_RECORD);
    /* Errors are sticky: the reader does not resynchronise on garbage. */
    CHECK_EQ(pcap_next(&r, &rec), PCAP_ERR_TRUNC_RECORD);
    bb_free(&b);
}

static void test_oversized_caplen(void)
{
    struct bytebuf b;
    struct pcap_reader r;
    struct pcap_record rec;

    bb_init(&b);
    pcap_put_global(&b, 1, 0, 65535, 1);
    bb_u32(&b, 1, 1);
    bb_u32(&b, 0, 1);
    bb_u32(&b, PCAP_MAX_CAPLEN + 1, 1);
    bb_u32(&b, PCAP_MAX_CAPLEN + 1, 1);

    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_OK);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_ERR_BAD_CAPLEN);
    bb_free(&b);

    /* A 0xFFFFFFFF caplen must be rejected, not wrap any size arithmetic. */
    pcap_put_global(&b, 0, 0, 65535, 1);
    bb_u32(&b, 1, 0);
    bb_u32(&b, 0, 0);
    bb_u32(&b, 0xFFFFFFFFu, 0);
    bb_u32(&b, 0xFFFFFFFFu, 0);
    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_OK);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_ERR_BAD_CAPLEN);
    bb_free(&b);
}

static void test_max_caplen_accepted(void)
{
    struct bytebuf b;
    struct pcap_reader r;
    struct pcap_record rec;
    uint8_t *big = calloc(PCAP_MAX_CAPLEN, 1);

    CHECK(big != NULL);
    if (big == NULL)
        return;
    bb_init(&b);
    pcap_put_global(&b, 0, 0, PCAP_MAX_CAPLEN, 1);
    pcap_put_record(&b, 0, 1, 0, big, PCAP_MAX_CAPLEN, PCAP_MAX_CAPLEN);
    pcap_put_record(&b, 0, 2, 0, big, 0, 0); /* empty record is legal */

    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_OK);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_OK);
    CHECK_EQ(rec.caplen, PCAP_MAX_CAPLEN);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_OK);
    CHECK_EQ(rec.caplen, 0);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_EOF);
    bb_free(&b);
    free(big);
}

static void test_empty_capture(void)
{
    struct bytebuf b;
    struct pcap_reader r;
    struct pcap_record rec;

    bb_init(&b);
    pcap_put_global(&b, 0, 1, 262144, 1);
    CHECK_EQ(pcap_open_mem(&r, b.data, b.len), PCAP_OK);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_EOF);
    CHECK_EQ(r.records, 0);
    bb_free(&b);
}

static void tmp_path(char *buf, size_t len, const char *name)
{
    snprintf(buf, len, "%s/%s", test_tmpdir, name);
}

static void test_file_reader(void)
{
    struct bytebuf b, frame;
    struct pcap_reader r;
    struct pcap_record rec;
    char path[512];
    uint32_t i;

    bb_init(&b);
    bb_init(&frame);
    frame_v4_udp(&frame, TEST_V4_A, TEST_V4_B, 5353, 53, 20);
    pcap_put_global(&b, 1, 1, 65535, 1);
    for (i = 0; i < 100; i++)
        pcap_put_record(&b, 1, 1000 + i, i, frame.data, (uint32_t)frame.len,
                        (uint32_t)frame.len);
    tmp_path(path, sizeof path, "test_file_reader.pcap");
    CHECK_EQ(bb_write_file(&b, path), 0);

    CHECK_EQ(pcap_open_file(&r, path), PCAP_OK);
    for (i = 0; i < 100; i++) {
        CHECK_EQ(pcap_next(&r, &rec), PCAP_OK);
        CHECK_EQ(rec.caplen, frame.len);
        CHECK_EQ(rec.ts_ns, (1000ull + i) * 1000000000ull + i);
    }
    CHECK(memcmp(rec.data, frame.data, frame.len) == 0);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_EOF);
    CHECK_EQ(r.records, 100);
    pcap_close(&r);

    /* The same file cut in the middle of the last record. */
    b.len -= 10;
    CHECK_EQ(bb_write_file(&b, path), 0);
    CHECK_EQ(pcap_open_file(&r, path), PCAP_OK);
    for (i = 0; i < 99; i++)
        CHECK_EQ(pcap_next(&r, &rec), PCAP_OK);
    CHECK_EQ(pcap_next(&r, &rec), PCAP_ERR_TRUNC_RECORD);
    pcap_close(&r);
    remove(path);
    bb_free(&b);
    bb_free(&frame);
}

static void test_file_errors(void)
{
    struct pcap_reader r;
    struct bytebuf b;
    char path[512];

    CHECK_EQ(pcap_open_file(&r, "/nonexistent/dir/none.pcap"), PCAP_ERR_OPEN);
    CHECK(r.sys_errno != 0);
    pcap_close(&r); /* safe after a failed open */

    bb_init(&b);
    pcap_put_global(&b, 0, 0, 65535, 1);
    b.len = 10; /* valid magic, then the file ends */
    tmp_path(path, sizeof path, "test_short.pcap");
    CHECK_EQ(bb_write_file(&b, path), 0);
    CHECK_EQ(pcap_open_file(&r, path), PCAP_ERR_SHORT_HEADER);
    remove(path);
    bb_free(&b);
}

void run_pcap_tests(void)
{
    RUN_TEST(test_magic_le_usec);
    RUN_TEST(test_magic_be_usec);
    RUN_TEST(test_magic_le_nsec);
    RUN_TEST(test_magic_be_nsec);
    RUN_TEST(test_bad_magic);
    RUN_TEST(test_pcapng_rejected);
    RUN_TEST(test_bad_version_and_linktype);
    RUN_TEST(test_truncated_global_header);
    RUN_TEST(test_truncated_record_header);
    RUN_TEST(test_truncated_record_data);
    RUN_TEST(test_oversized_caplen);
    RUN_TEST(test_max_caplen_accepted);
    RUN_TEST(test_empty_capture);
    RUN_TEST(test_file_reader);
    RUN_TEST(test_file_errors);
}
