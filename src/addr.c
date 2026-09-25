/*
 * addr.c - IPv4 dotted-quad and RFC 5952 IPv6 formatting.
 */
#include "addr.h"

#include <stdio.h>

#include "bytes.h"

/* ::ffff:0:0/96, the IPv4-mapped prefix: 80 zero bits, then 16 one bits. */
static int is_v4_mapped(const uint8_t *a)
{
    int i;

    for (i = 0; i < 10; i++) {
        if (a[i] != 0)
            return 0;
    }
    return a[10] == 0xff && a[11] == 0xff;
}

static void format_ipv6(const uint8_t *a, char *buf, size_t len)
{
    unsigned groups[8];
    int best_start = -1, best_len = 0, i;
    char tmp[ADDR_STR_LEN];
    size_t pos = 0;

    /* RFC 5952 section 5: an IPv4-mapped address shows its embedded IPv4
     * address in dotted-quad form, e.g. ::ffff:192.0.2.1. */
    if (is_v4_mapped(a)) {
        snprintf(buf, len, "::ffff:%u.%u.%u.%u", a[12], a[13], a[14], a[15]);
        return;
    }

    for (i = 0; i < 8; i++)
        groups[i] = load_be16(a + 2 * i);

    /* Find the longest run of zero groups; on a tie the first run wins. */
    for (i = 0; i < 8;) {
        int j = i;

        if (groups[i] != 0) {
            i++;
            continue;
        }
        while (j < 8 && groups[j] == 0)
            j++;
        if (j - i > best_len) {
            best_start = i;
            best_len = j - i;
        }
        i = j;
    }
    if (best_len < 2)
        best_start = -1; /* RFC 5952: a single zero group is not shortened */

    /* The longest output, 8 groups of 4 hex digits and 7 colons, is 39
     * characters, so tmp can never overflow; each snprintf is still told
     * the space left. */
    for (i = 0; i < 8; i++) {
        if (i == best_start) {
            pos += (size_t)snprintf(tmp + pos, sizeof tmp - pos, "::");
            i += best_len - 1;
            continue;
        }
        /* The "::" already separates the run from the next group. */
        if (i > 0 && !(best_start >= 0 && i == best_start + best_len))
            pos += (size_t)snprintf(tmp + pos, sizeof tmp - pos, ":");
        pos += (size_t)snprintf(tmp + pos, sizeof tmp - pos, "%x", groups[i]);
    }
    tmp[pos] = '\0';
    snprintf(buf, len, "%s", tmp);
}

void addr_format(int ip_version, const uint8_t *addr, char *buf, size_t len)
{
    if (len == 0)
        return;
    if (ip_version == 4)
        snprintf(buf, len, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    else if (ip_version == 6)
        format_ipv6(addr, buf, len);
    else
        snprintf(buf, len, "?");
}
