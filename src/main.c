/*
 * main.c - pcapstat command-line interface.
 *
 *   pcapstat [-n N] [--csv FILE] FILE.pcap
 *
 * Exit status: 0 success, 1 usage error, 2 input error (unreadable, not a
 * pcap file, truncated, or a CSV write failure). When a capture turns out to
 * be truncated part-way, the statistics for the records before the damage
 * are still printed, followed by exit status 2.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analyze.h"
#include "report.h"

#define EXIT_OK    0
#define EXIT_USAGE 1
#define EXIT_INPUT 2

#define DEFAULT_TOP_N 10u
#define MAX_TOP_N 1000000u

static void usage(FILE *out)
{
    fprintf(out,
            "usage: pcapstat [-n N] [--csv FILE] FILE.pcap\n"
            "\n"
            "Summarise a classic libpcap capture (Ethernet link type):\n"
            "packet counts per protocol, decode problems, and the largest\n"
            "bidirectional flows.\n"
            "\n"
            "  -n N        show the top N flows by bytes (default %u, 0 hides\n"
            "              the table)\n"
            "  --csv FILE  also write every flow to FILE as CSV\n"
            "  -h, --help  show this help\n"
            "\n"
            "exit status: 0 ok, 1 usage error, 2 input error\n",
            DEFAULT_TOP_N);
}

/* Parse a non-negative decimal count. strtoul alone is too forgiving: it
 * accepts leading spaces, a sign ("-1" becomes a huge value) and trailing
 * junk, so check that the text is digits only first. */
static int parse_count(const char *text, size_t *out)
{
    const char *p;
    unsigned long v;

    if (*text == '\0')
        return 0;
    for (p = text; *p; p++) {
        if (*p < '0' || *p > '9')
            return 0;
    }
    errno = 0;
    v = strtoul(text, NULL, 10);
    if (errno == ERANGE || v > MAX_TOP_N)
        return 0;
    *out = (size_t)v;
    return 1;
}

static int write_csv(const char *path, const struct flow_table *flows)
{
    FILE *f = fopen(path, "w");
    int rc;

    if (f == NULL) {
        fprintf(stderr, "pcapstat: %s: %s\n", path, strerror(errno));
        return -1;
    }
    rc = report_csv(f, flows);
    /* fclose flushes buffered output, so a full disk may only show up here. */
    if (fclose(f) != 0)
        rc = -1;
    if (rc != 0)
        fprintf(stderr, "pcapstat: %s: failed to write CSV\n", path);
    return rc;
}

int main(int argc, char **argv)
{
    size_t top_n = DEFAULT_TOP_N, n;
    const char *csv_path = NULL, *pcap_path = NULL;
    struct pcap_reader reader;
    struct analysis an;
    enum pcap_status st;
    const struct flow **top = NULL;
    int status = EXIT_OK, i;

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            usage(stdout);
            return EXIT_OK;
        } else if (strcmp(arg, "-n") == 0) {
            if (i + 1 >= argc || !parse_count(argv[i + 1], &top_n)) {
                fprintf(stderr, "pcapstat: -n needs a number from 0 to %u\n",
                        MAX_TOP_N);
                return EXIT_USAGE;
            }
            i++;
        } else if (strcmp(arg, "--csv") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "pcapstat: --csv needs a file name\n");
                return EXIT_USAGE;
            }
            csv_path = argv[++i];
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "pcapstat: unknown option '%s'\n", arg);
            usage(stderr);
            return EXIT_USAGE;
        } else if (pcap_path != NULL) {
            fprintf(stderr, "pcapstat: only one input file is supported\n");
            return EXIT_USAGE;
        } else {
            pcap_path = arg;
        }
    }
    if (pcap_path == NULL) {
        usage(stderr);
        return EXIT_USAGE;
    }

    st = pcap_open_file(&reader, pcap_path);
    if (st != PCAP_OK) {
        if (st == PCAP_ERR_OPEN || st == PCAP_ERR_IO)
            fprintf(stderr, "pcapstat: %s: %s: %s\n", pcap_path,
                    pcap_status_str(st), strerror(reader.sys_errno));
        else
            fprintf(stderr, "pcapstat: %s: %s\n", pcap_path,
                    pcap_status_str(st));
        return EXIT_INPUT;
    }

    if (analysis_init(&an) != 0) {
        fprintf(stderr, "pcapstat: out of memory\n");
        pcap_close(&reader);
        return EXIT_INPUT;
    }

    st = analysis_run(&an, &reader);
    if (st != PCAP_EOF) {
        /* Report the damage, but still print what was read before it. */
        fprintf(stderr, "pcapstat: %s: %s after %llu records; statistics "
                        "below cover those records only\n",
                pcap_path, pcap_status_str(st),
                (unsigned long long)reader.records);
        status = EXIT_INPUT;
    }

    report_summary(stdout, pcap_path, &reader.info, &an.stats,
                   an.flows.count);

    n = top_n < an.flows.count ? top_n : an.flows.count;
    if (n > 0) {
        top = malloc(n * sizeof *top); /* n <= MAX_TOP_N: cannot overflow */
        if (top == NULL) {
            fprintf(stderr, "pcapstat: out of memory\n");
            status = EXIT_INPUT;
        } else {
            n = flow_table_top_n(&an.flows, n, top);
            report_top_flows(stdout, top, n, an.flows.count);
        }
    }

    if (csv_path != NULL && write_csv(csv_path, &an.flows) != 0)
        status = EXIT_INPUT;

    if (fflush(stdout) != 0)
        status = EXIT_INPUT;

    free(top);
    analysis_free(&an);
    pcap_close(&reader);
    return status;
}
