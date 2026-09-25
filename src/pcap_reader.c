/*
 * pcap_reader.c - classic pcap file reader with strict validation.
 *
 * Every length that comes from the file is checked before it is used to size
 * a read, so a corrupt or hostile file can end the read early but can never
 * make us read past the input or allocate an attacker-chosen amount.
 */
#include "pcap_reader.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "bytes.h"

/* The magic number is the first 4 bytes of the file, written in the byte
 * order of the machine that wrote it. We always read it as little-endian:
 * if we get the documented value the file is little-endian, and if we get
 * the byte-reversed value the file is big-endian. This way the host's own
 * byte order never matters. */
#define MAGIC_USEC          0xA1B2C3D4u
#define MAGIC_NSEC          0xA1B23C4Du
#define MAGIC_USEC_SWAPPED  0xD4C3B2A1u
#define MAGIC_NSEC_SWAPPED  0x4D3CB2A1u
#define MAGIC_PCAPNG        0x0A0D0D0Au /* pcapng Section Header Block type */

/* The link-type field's top bits may carry FCS-length metadata; like
 * libpcap's LT_LINKTYPE() we keep only the low 26 bits as the link type. */
#define LINKTYPE_MASK 0x03FFFFFFu

/* stdio buffer for file input: large sequential reads, few syscalls. */
#define READ_BUFFER_SIZE (1u << 20)

static uint32_t rd32(const uint8_t *p, int big_endian)
{
    return big_endian ? load_be32(p) : load_le32(p);
}

static uint16_t rd16(const uint8_t *p, int big_endian)
{
    return big_endian ? load_be16(p) : load_le16(p);
}

enum pcap_status pcap_parse_global_header(const uint8_t *hdr, size_t len,
                                          struct pcap_file_info *info)
{
    uint32_t magic;

    memset(info, 0, sizeof *info);
    if (len < 4)
        return PCAP_ERR_SHORT_HEADER;

    magic = load_le32(hdr);
    switch (magic) {
    case MAGIC_USEC:         info->big_endian = 0; info->nsec = 0; break;
    case MAGIC_NSEC:         info->big_endian = 0; info->nsec = 1; break;
    case MAGIC_USEC_SWAPPED: info->big_endian = 1; info->nsec = 0; break;
    case MAGIC_NSEC_SWAPPED: info->big_endian = 1; info->nsec = 1; break;
    case MAGIC_PCAPNG:       return PCAP_ERR_PCAPNG;
    default:                 return PCAP_ERR_BAD_MAGIC;
    }

    /* Check the magic first so a non-pcap file gets the more useful
     * "bad magic" message even when it is also short. */
    if (len < PCAP_GLOBAL_HDR_LEN)
        return PCAP_ERR_SHORT_HEADER;

    info->version_major = rd16(hdr + 4, info->big_endian);
    info->version_minor = rd16(hdr + 6, info->big_endian);
    /* hdr + 8: thiszone and hdr + 12: sigfigs are always 0 in practice and
     * are not needed: timestamps are already UTC. */
    info->snaplen = rd32(hdr + 16, info->big_endian);
    info->linktype = rd32(hdr + 20, info->big_endian) & LINKTYPE_MASK;

    if (info->version_major != 2 || info->version_minor != 4)
        return PCAP_ERR_BAD_VERSION;
    if (info->linktype != PCAP_LINKTYPE_ETHERNET)
        return PCAP_ERR_BAD_LINKTYPE;
    return PCAP_OK;
}

enum pcap_status pcap_parse_record_header(const struct pcap_file_info *info,
                                          const uint8_t *hdr,
                                          struct pcap_record *rec)
{
    int be = info->big_endian;
    uint32_t sec = rd32(hdr, be);
    uint32_t frac = rd32(hdr + 4, be);
    uint64_t frac_ns;

    rec->caplen = rd32(hdr + 8, be);
    rec->wirelen = rd32(hdr + 12, be);
    rec->data = NULL;

    /* caplen sizes the next read, so it is the one field that must be
     * validated before we trust it. We deliberately do not also require
     * caplen <= snaplen: real tools sometimes write a snaplen smaller than
     * the records, and libpcap tolerates that too. The hard cap is enough to
     * keep reads bounded. */
    if (rec->caplen > PCAP_MAX_CAPLEN)
        return PCAP_ERR_BAD_CAPLEN;

    /* Done in 64-bit arithmetic: sec * 1e9 needs up to 63 bits, and
     * frac * 1000 would overflow 32 bits for a corrupt microsecond value.
     * The worst case, (2^32 - 1) * 1e9 + (2^32 - 1) * 1000, still fits in a
     * uint64_t. Out-of-range fractions are kept as-is rather than rejected. */
    frac_ns = info->nsec ? (uint64_t)frac : (uint64_t)frac * 1000u;
    rec->ts_ns = (uint64_t)sec * 1000000000u + frac_ns;
    return PCAP_OK;
}

static void reader_reset(struct pcap_reader *r)
{
    memset(r, 0, sizeof *r);
    r->error = PCAP_OK;
}

/*
 * Return a pointer to the next n bytes of input, or NULL if fewer than n
 * bytes remain; *got then says how many were available (0 means a clean end
 * of input). File input is copied into r->buf; memory input is returned in
 * place. Callers never ask for more than PCAP_MAX_CAPLEN bytes, the size of
 * r->buf.
 */
static const uint8_t *take(struct pcap_reader *r, size_t n, size_t *got)
{
    if (r->fp != NULL) {
        *got = fread(r->buf, 1, n, r->fp);
        return *got == n ? r->buf : NULL;
    } else {
        /* mem_pos never exceeds mem_len, so this subtraction cannot wrap,
         * and comparing n with what is left avoids computing mem_pos + n,
         * which could overflow. */
        size_t left = r->mem_len - r->mem_pos;
        const uint8_t *p;

        if (n > left) {
            *got = left;
            r->mem_pos = r->mem_len;
            return NULL;
        }
        p = r->mem + r->mem_pos;
        *got = n;
        r->mem_pos += n;
        return p;
    }
}

/* A short read is either end-of-file or an I/O error; only stdio knows. */
static enum pcap_status short_read_status(struct pcap_reader *r,
                                          enum pcap_status at_eof)
{
    if (r->fp != NULL && ferror(r->fp)) {
        r->sys_errno = errno;
        return PCAP_ERR_IO;
    }
    return at_eof;
}

static enum pcap_status read_global_header(struct pcap_reader *r)
{
    size_t got;
    const uint8_t *hdr = take(r, PCAP_GLOBAL_HDR_LEN, &got);
    enum pcap_status st;

    if (hdr == NULL) {
        st = short_read_status(r, PCAP_ERR_SHORT_HEADER);
        if (st == PCAP_ERR_SHORT_HEADER && got >= 4) {
            /* Report "not a pcap file" in preference to "too short". The
             * bytes we did get are in r->buf (file) or r->mem (memory). */
            const uint8_t *partial = r->fp != NULL ? r->buf : r->mem;
            struct pcap_file_info tmp;
            st = pcap_parse_global_header(partial, got, &tmp);
        }
        return st;
    }
    return pcap_parse_global_header(hdr, PCAP_GLOBAL_HDR_LEN, &r->info);
}

enum pcap_status pcap_open_file(struct pcap_reader *r, const char *path)
{
    enum pcap_status st;

    reader_reset(r);
    r->fp = fopen(path, "rb");
    if (r->fp == NULL) {
        r->sys_errno = errno;
        return r->error = PCAP_ERR_OPEN;
    }
    /* A bigger stdio buffer turns millions of small fread() calls into a
     * few large read() syscalls. Failure here is harmless, so it is ignored. */
    (void)setvbuf(r->fp, NULL, _IOFBF, READ_BUFFER_SIZE);

    r->buf = malloc(PCAP_MAX_CAPLEN);
    if (r->buf == NULL) {
        st = PCAP_ERR_NOMEM;
    } else {
        st = read_global_header(r);
    }
    if (st != PCAP_OK) {
        int saved_errno = r->sys_errno;
        pcap_close(r);
        r->sys_errno = saved_errno;
        r->error = st;
    }
    return st;
}

enum pcap_status pcap_open_mem(struct pcap_reader *r, const uint8_t *data,
                               size_t len)
{
    enum pcap_status st;

    reader_reset(r);
    r->mem = data;
    r->mem_len = len;
    st = read_global_header(r);
    if (st != PCAP_OK)
        r->error = st;
    return st;
}

enum pcap_status pcap_next(struct pcap_reader *r, struct pcap_record *rec)
{
    size_t got;
    const uint8_t *p;
    enum pcap_status st;

    if (r->error != PCAP_OK)
        return r->error;

    p = take(r, PCAP_RECORD_HDR_LEN, &got);
    if (p == NULL) {
        /* Zero bytes means the file ended exactly between records. Anything
         * in between 0 and 16 is a header cut off mid-way. */
        st = short_read_status(r, got == 0 ? PCAP_EOF
                                           : PCAP_ERR_TRUNC_RECORD_HDR);
        return r->error = st;
    }

    st = pcap_parse_record_header(&r->info, p, rec);
    if (st != PCAP_OK)
        return r->error = st;

    /* caplen <= PCAP_MAX_CAPLEN was just checked, so the read fits r->buf. */
    p = take(r, rec->caplen, &got);
    if (p == NULL)
        return r->error = short_read_status(r, PCAP_ERR_TRUNC_RECORD);

    rec->data = p;
    r->records++;
    return PCAP_OK;
}

void pcap_close(struct pcap_reader *r)
{
    if (r->fp != NULL)
        fclose(r->fp); /* read-only stream: nothing to flush, nothing lost */
    free(r->buf);
    reader_reset(r);
}

const char *pcap_status_str(enum pcap_status s)
{
    switch (s) {
    case PCAP_OK:                   return "ok";
    case PCAP_EOF:                  return "end of file";
    case PCAP_ERR_OPEN:             return "cannot open file";
    case PCAP_ERR_IO:               return "read error";
    case PCAP_ERR_NOMEM:            return "out of memory";
    case PCAP_ERR_SHORT_HEADER:     return "file too short for a pcap global header";
    case PCAP_ERR_BAD_MAGIC:        return "not a pcap file (unknown magic number)";
    case PCAP_ERR_PCAPNG:           return "pcapng files are not supported (convert with: editcap -F pcap in.pcapng out.pcap)";
    case PCAP_ERR_BAD_VERSION:      return "unsupported pcap version (expected 2.4)";
    case PCAP_ERR_BAD_LINKTYPE:     return "unsupported link type (only Ethernet, linktype 1, is supported)";
    case PCAP_ERR_TRUNC_RECORD_HDR: return "truncated file: record header cut short";
    case PCAP_ERR_TRUNC_RECORD:     return "truncated file: packet data cut short";
    case PCAP_ERR_BAD_CAPLEN:       return "corrupt record: captured length exceeds 262144 bytes";
    }
    return "unknown error";
}
