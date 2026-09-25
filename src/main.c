/*
 * main.c - pcapstat command-line interface.
 *
 *   pcapstat FILE.pcap
 *
 * First stage: validate the capture and count its records.
 * Exit status: 0 success, 1 usage error, 2 input error.
 */
#include <stdio.h>
#include <string.h>

#include "pcap_reader.h"

int main(int argc, char **argv)
{
    struct pcap_reader r;
    struct pcap_record rec;
    enum pcap_status st;
    unsigned long long wire_bytes = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: pcapstat FILE.pcap\n");
        return 1;
    }

    st = pcap_open_file(&r, argv[1]);
    if (st != PCAP_OK) {
        if (st == PCAP_ERR_OPEN || st == PCAP_ERR_IO)
            fprintf(stderr, "pcapstat: %s: %s: %s\n", argv[1],
                    pcap_status_str(st), strerror(r.sys_errno));
        else
            fprintf(stderr, "pcapstat: %s: %s\n", argv[1],
                    pcap_status_str(st));
        return 2;
    }

    while ((st = pcap_next(&r, &rec)) == PCAP_OK)
        wire_bytes += rec.wirelen;

    printf("File:     %s\n", argv[1]);
    printf("Format:   pcap %u.%u, %s-endian, %s timestamps, snaplen %lu\n",
           (unsigned)r.info.version_major, (unsigned)r.info.version_minor,
           r.info.big_endian ? "big" : "little",
           r.info.nsec ? "nanosecond" : "microsecond",
           (unsigned long)r.info.snaplen);
    printf("Records:  %llu\n", (unsigned long long)r.records);
    printf("Bytes:    %llu on the wire\n", wire_bytes);

    if (st != PCAP_EOF) {
        fprintf(stderr, "pcapstat: %s: %s after %llu records\n", argv[1],
                pcap_status_str(st), (unsigned long long)r.records);
        pcap_close(&r);
        return 2;
    }
    pcap_close(&r);
    return 0;
}
