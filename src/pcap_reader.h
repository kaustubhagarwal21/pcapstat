/*
 * pcap_reader.h - reader for classic libpcap capture files (.pcap).
 *
 * File layout (all integers in the byte order announced by the magic number):
 *
 *   global header, 24 bytes:
 *     magic(4) version_major(2) version_minor(2) thiszone(4) sigfigs(4)
 *     snaplen(4) linktype(4)
 *   then zero or more records:
 *     ts_sec(4) ts_frac(4) caplen(4) origlen(4) followed by caplen bytes
 *
 * ts_frac is microseconds or nanoseconds depending on the magic number.
 * caplen is how many bytes were saved; origlen is the frame's length on the
 * wire (larger than caplen when the capture used a snapshot length).
 */
#ifndef PCAPSTAT_PCAP_READER_H
#define PCAPSTAT_PCAP_READER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PCAP_GLOBAL_HDR_LEN 24u
#define PCAP_RECORD_HDR_LEN 16u

/* Largest record we accept. libpcap uses the same limit (262144) for most
 * link types; anything bigger is a corrupt length field, and refusing it
 * bounds the record buffer. */
#define PCAP_MAX_CAPLEN 262144u

#define PCAP_LINKTYPE_ETHERNET 1u /* DLT_EN10MB / LINKTYPE_ETHERNET */

enum pcap_status {
    PCAP_OK = 0,
    PCAP_EOF,                  /* clean end of file on a record boundary */
    PCAP_ERR_OPEN,             /* fopen failed; see pcap_reader.sys_errno */
    PCAP_ERR_IO,               /* read error from the operating system */
    PCAP_ERR_NOMEM,
    PCAP_ERR_SHORT_HEADER,     /* input ends inside the 24-byte global header */
    PCAP_ERR_BAD_MAGIC,
    PCAP_ERR_PCAPNG,           /* a pcapng file, which is a different format */
    PCAP_ERR_BAD_VERSION,
    PCAP_ERR_BAD_LINKTYPE,
    PCAP_ERR_TRUNC_RECORD_HDR, /* input ends inside a 16-byte record header */
    PCAP_ERR_TRUNC_RECORD,     /* input ends inside a record's packet bytes */
    PCAP_ERR_BAD_CAPLEN        /* caplen larger than PCAP_MAX_CAPLEN */
};

/* What the global header told us about the file. */
struct pcap_file_info {
    int big_endian;          /* 1 if the file's integers are big-endian */
    int nsec;                /* 1 if ts_frac is nanoseconds, 0 if microseconds */
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t snaplen;
    uint32_t linktype;
};

/* One packet record. `data` points at `caplen` bytes that stay valid only
 * until the next call to pcap_next() or pcap_close(). */
struct pcap_record {
    uint64_t ts_ns;          /* capture time, nanoseconds since the Unix epoch */
    uint32_t caplen;         /* bytes present in data */
    uint32_t wirelen;        /* original length of the frame on the wire */
    const uint8_t *data;
};

struct pcap_reader {
    FILE *fp;                /* file input, or NULL for memory input */
    const uint8_t *mem;      /* memory input */
    size_t mem_len;
    size_t mem_pos;
    uint8_t *buf;            /* file input: holds the current record */
    struct pcap_file_info info;
    uint64_t records;        /* records returned so far */
    enum pcap_status error;  /* first error seen; sticky */
    int sys_errno;           /* errno captured when fopen/fread fails */
};

/* Parse and validate a 24-byte global header. `len` is how many bytes are
 * available at `hdr`. Pure function: used by the reader and by the tests. */
enum pcap_status pcap_parse_global_header(const uint8_t *hdr, size_t len,
                                          struct pcap_file_info *info);

/* Parse and validate a 16-byte record header (everything except `data`). */
enum pcap_status pcap_parse_record_header(const struct pcap_file_info *info,
                                          const uint8_t *hdr,
                                          struct pcap_record *rec);

/* Open a capture file and validate its global header. On failure the reader
 * holds no resources, but calling pcap_close() is still safe. */
enum pcap_status pcap_open_file(struct pcap_reader *r, const char *path);

/* Read a capture that is already in memory. `data` must outlive the reader.
 * Records are returned in place, without copying. */
enum pcap_status pcap_open_mem(struct pcap_reader *r, const uint8_t *data,
                               size_t len);

/* Fetch the next record. Returns PCAP_OK, PCAP_EOF, or an error. Once an
 * error has been returned, every later call returns the same error. */
enum pcap_status pcap_next(struct pcap_reader *r, struct pcap_record *rec);

void pcap_close(struct pcap_reader *r);

const char *pcap_status_str(enum pcap_status s);

#endif /* PCAPSTAT_PCAP_READER_H */
