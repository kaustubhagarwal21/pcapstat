/*
 * main.c - pcapstat command-line interface.
 *
 *   pcapstat FILE.pcap
 *
 * Second stage: decode every record and count the results by decode status
 * and IP version.
 * Exit status: 0 success, 1 usage error, 2 input error.
 */
#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "pcap_reader.h"

int main(int argc, char **argv)
{
    struct pcap_reader r;
    struct pcap_record rec;
    struct packet_info pi;
    enum pcap_status st;
    unsigned long long by_status[DEC_STATUS_COUNT] = {0};
    unsigned long long ipv4 = 0, ipv6 = 0, l4 = 0;
    unsigned i;

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

    while ((st = pcap_next(&r, &rec)) == PCAP_OK) {
        decode_frame(rec.data, rec.caplen, rec.wirelen, &pi);
        by_status[pi.status]++;
        if (pi.has_l3 && pi.ip_version == 4)
            ipv4++;
        else if (pi.has_l3)
            ipv6++;
        if (pi.has_l4)
            l4++;
    }

    printf("File:     %s\n", argv[1]);
    printf("Records:  %llu\n", (unsigned long long)r.records);
    printf("IPv4 %llu, IPv6 %llu, L4 decoded %llu\n", ipv4, ipv6, l4);
    for (i = 0; i < DEC_STATUS_COUNT; i++) {
        if (by_status[i] > 0)
            printf("  %-40s %llu\n",
                   decode_status_str((enum decode_status)i), by_status[i]);
    }

    if (st != PCAP_EOF) {
        fprintf(stderr, "pcapstat: %s: %s after %llu records\n", argv[1],
                pcap_status_str(st), (unsigned long long)r.records);
        pcap_close(&r);
        return 2;
    }
    pcap_close(&r);
    return 0;
}
