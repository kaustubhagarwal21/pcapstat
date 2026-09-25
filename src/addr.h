/*
 * addr.h - text formatting of IP addresses.
 *
 * Implemented here rather than with inet_ntop() so the program depends only
 * on the C standard library.
 */
#ifndef PCAPSTAT_ADDR_H
#define PCAPSTAT_ADDR_H

#include <stddef.h>
#include <stdint.h>

/* Enough for the longest IPv6 text form plus the terminator (same value as
 * POSIX INET6_ADDRSTRLEN). */
#define ADDR_STR_LEN 46

/* Format a 4-byte IPv4 address (ip_version 4) or a 16-byte IPv6 address
 * (ip_version 6) into buf. IPv6 follows RFC 5952: lowercase hex, no leading
 * zeros, the longest run of two or more zero groups shown as "::" (the first
 * one on a tie), and IPv4-mapped addresses as ::ffff:a.b.c.d. The output is
 * always NUL-terminated if len > 0. */
void addr_format(int ip_version, const uint8_t *addr, char *buf, size_t len);

#endif /* PCAPSTAT_ADDR_H */
