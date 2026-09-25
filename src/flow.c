/*
 * flow.c - open-addressing flow table and top-N selection.
 */
#include "flow.h"

#include <stdlib.h>
#include <string.h>

#include "hash.h"

#define MIN_CAPACITY 16u

/* Grow when count / capacity would exceed 7/10. Linear probing slows down
 * sharply as the table fills; 0.7 is a common trade-off between memory and
 * probe length. */
#define LOAD_NUM 7u
#define LOAD_DEN 10u

/* Hash the key field by field instead of hashing the struct's bytes, so the
 * result never depends on padding bytes, whose values C leaves unspecified. */
static uint64_t key_hash(const struct flow_key *k)
{
    uint8_t head[6];
    uint64_t h;

    head[0] = k->ip_version;
    head[1] = k->proto;
    head[2] = (uint8_t)(k->port_a >> 8);
    head[3] = (uint8_t)k->port_a;
    head[4] = (uint8_t)(k->port_b >> 8);
    head[5] = (uint8_t)k->port_b;
    h = fnv1a(FNV64_OFFSET, head, sizeof head);
    h = fnv1a(h, k->addr_a, sizeof k->addr_a);
    return fnv1a(h, k->addr_b, sizeof k->addr_b);
}

static int key_equal(const struct flow_key *a, const struct flow_key *b)
{
    return a->ip_version == b->ip_version && a->proto == b->proto &&
           a->port_a == b->port_a && a->port_b == b->port_b &&
           memcmp(a->addr_a, b->addr_a, sizeof a->addr_a) == 0 &&
           memcmp(a->addr_b, b->addr_b, sizeof a->addr_b) == 0;
}

/* Total order on keys, used only as the last tie-breaker for top-N. */
static int key_cmp(const struct flow_key *a, const struct flow_key *b)
{
    int c;

    if (a->ip_version != b->ip_version)
        return a->ip_version < b->ip_version ? -1 : 1;
    if (a->proto != b->proto)
        return a->proto < b->proto ? -1 : 1;
    if ((c = memcmp(a->addr_a, b->addr_a, sizeof a->addr_a)) != 0)
        return c;
    if (a->port_a != b->port_a)
        return a->port_a < b->port_a ? -1 : 1;
    if ((c = memcmp(a->addr_b, b->addr_b, sizeof a->addr_b)) != 0)
        return c;
    if (a->port_b != b->port_b)
        return a->port_b < b->port_b ? -1 : 1;
    return 0;
}

int flow_key_from_packet(const struct packet_info *pi, struct flow_key *key,
                         int *reversed)
{
    int cmp;

    if (!pi->has_l3)
        return 0;

    memset(key, 0, sizeof *key);
    key->ip_version = pi->ip_version;
    key->proto = pi->ip_proto;

    /* Order the endpoints by (address, port). The addresses are compared as
     * 16-byte arrays; IPv4 addresses have 12 zero bytes after them in both,
     * so that is the same as comparing the 4 real bytes. */
    cmp = memcmp(pi->src_addr, pi->dst_addr, sizeof pi->src_addr);
    if (cmp == 0)
        cmp = (pi->src_port > pi->dst_port) - (pi->src_port < pi->dst_port);

    *reversed = cmp > 0;
    if (!*reversed) {
        memcpy(key->addr_a, pi->src_addr, sizeof key->addr_a);
        memcpy(key->addr_b, pi->dst_addr, sizeof key->addr_b);
        key->port_a = pi->src_port;
        key->port_b = pi->dst_port;
    } else {
        memcpy(key->addr_a, pi->dst_addr, sizeof key->addr_a);
        memcpy(key->addr_b, pi->src_addr, sizeof key->addr_b);
        key->port_a = pi->dst_port;
        key->port_b = pi->src_port;
    }
    return 1;
}

int flow_table_init(struct flow_table *t, size_t capacity_hint)
{
    size_t cap = MIN_CAPACITY;

    /* Round up to a power of two so that `hash & (capacity - 1)` picks a
     * slot; that is cheaper than `%` and uses the hash's low bits. */
    while (cap < capacity_hint && cap <= SIZE_MAX / 2 / sizeof(struct flow))
        cap *= 2;

    t->count = 0;
    t->capacity = cap;
    t->slots = calloc(cap, sizeof *t->slots); /* calloc checks n * size */
    if (t->slots == NULL) {
        t->capacity = 0;
        return -1;
    }
    return 0;
}

void flow_table_free(struct flow_table *t)
{
    free(t->slots);
    t->slots = NULL;
    t->capacity = 0;
    t->count = 0;
}

/* Place an existing flow into a fresh table during growth. No equality
 * checks are needed: every key is already unique. */
static void place(struct flow *slots, size_t mask, const struct flow *f)
{
    size_t i = (size_t)f->hash & mask;

    while (slots[i].in_use)
        i = (i + 1) & mask;
    slots[i] = *f;
}

static int grow(struct flow_table *t)
{
    struct flow *bigger;
    size_t new_cap, i;

    if (t->capacity > SIZE_MAX / 2 / sizeof(struct flow))
        return -1; /* doubling would overflow the allocation size */
    new_cap = t->capacity * 2;
    bigger = calloc(new_cap, sizeof *bigger);
    if (bigger == NULL)
        return -1;
    for (i = 0; i < t->capacity; i++) {
        if (t->slots[i].in_use)
            place(bigger, new_cap - 1, &t->slots[i]);
    }
    free(t->slots);
    t->slots = bigger;
    t->capacity = new_cap;
    return 0;
}

const struct flow *flow_table_find(const struct flow_table *t,
                                   const struct flow_key *key)
{
    size_t mask, i;

    if (t->capacity == 0)
        return NULL;
    mask = t->capacity - 1;
    /* The load-factor limit guarantees an empty slot exists, so the probe
     * loop always terminates. */
    for (i = (size_t)key_hash(key) & mask; t->slots[i].in_use;
         i = (i + 1) & mask) {
        if (key_equal(&t->slots[i].key, key))
            return &t->slots[i];
    }
    return NULL;
}

struct flow *flow_table_find_or_insert(struct flow_table *t,
                                       const struct flow_key *key,
                                       int *inserted)
{
    uint64_t h = key_hash(key);
    size_t mask, i;

    *inserted = 0;
    if (t->capacity == 0)
        return NULL;

    /* Grow before probing, so the slot we find is in the final array.
     * count < capacity <= SIZE_MAX / sizeof(struct flow), and a flow is far
     * bigger than 10 bytes, so (count + 1) * 10 cannot overflow. */
    if ((t->count + 1) * LOAD_DEN > t->capacity * LOAD_NUM) {
        if (grow(t) != 0)
            return NULL;
    }

    mask = t->capacity - 1;
    for (i = (size_t)h & mask; t->slots[i].in_use; i = (i + 1) & mask) {
        if (t->slots[i].hash == h && key_equal(&t->slots[i].key, key))
            return &t->slots[i];
    }

    /* Not found: i is the first empty slot on the probe path. */
    memset(&t->slots[i], 0, sizeof t->slots[i]);
    t->slots[i].key = *key;
    t->slots[i].hash = h;
    t->slots[i].in_use = 1;
    t->count++;
    *inserted = 1;
    return &t->slots[i];
}

int flow_table_add_packet(struct flow_table *t, const struct packet_info *pi,
                          uint32_t wire_len, uint64_t ts_ns)
{
    struct flow_key key;
    struct flow *f;
    int reversed, inserted;

    if (!flow_key_from_packet(pi, &key, &reversed))
        return 0;
    f = flow_table_find_or_insert(t, &key, &inserted);
    if (f == NULL)
        return -1;

    if (inserted) {
        f->first_ts_ns = ts_ns;
        f->last_ts_ns = ts_ns;
        f->first_from_b = (uint8_t)reversed;
    }
    /* Capture files are usually in time order but not always (merged
     * captures, clock steps), so keep a true min and max. */
    if (ts_ns < f->first_ts_ns) {
        f->first_ts_ns = ts_ns;
        f->first_from_b = (uint8_t)reversed;
    }
    if (ts_ns > f->last_ts_ns)
        f->last_ts_ns = ts_ns;

    f->packets++;
    f->bytes += wire_len;
    if (pi->ip_proto == IPPROTO_NUM_TCP && pi->has_l4)
        f->tcp_flags |= pi->tcp_flags;
    return 0;
}

const struct flow *flow_table_next(const struct flow_table *t, size_t *pos)
{
    while (*pos < t->capacity) {
        const struct flow *f = &t->slots[(*pos)++];
        if (f->in_use)
            return f;
    }
    return NULL;
}

/* Negative if `a` ranks above `b` (should be listed first). */
static int rank_cmp(const struct flow *a, const struct flow *b)
{
    if (a->bytes != b->bytes)
        return a->bytes > b->bytes ? -1 : 1;
    if (a->packets != b->packets)
        return a->packets > b->packets ? -1 : 1;
    if (a->first_ts_ns != b->first_ts_ns)
        return a->first_ts_ns < b->first_ts_ns ? -1 : 1;
    return key_cmp(&a->key, &b->key);
}

static int rank_cmp_qsort(const void *pa, const void *pb)
{
    const struct flow *a = *(const struct flow *const *)pa;
    const struct flow *b = *(const struct flow *const *)pb;
    return rank_cmp(a, b);
}

/*
 * Min-heap keyed on rank: heap[0] is the lowest-ranked flow we are keeping,
 * so a new flow only has to beat heap[0] to get in. "Lower" in heap terms
 * means ranks below, i.e. rank_cmp(x, y) > 0.
 */
static void sift_down(const struct flow **heap, size_t n, size_t i)
{
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, low = i;
        const struct flow *tmp;

        if (l < n && rank_cmp(heap[l], heap[low]) > 0)
            low = l;
        if (r < n && rank_cmp(heap[r], heap[low]) > 0)
            low = r;
        if (low == i)
            return;
        tmp = heap[i];
        heap[i] = heap[low];
        heap[low] = tmp;
        i = low;
    }
}

static void sift_up(const struct flow **heap, size_t i)
{
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        const struct flow *tmp;

        if (rank_cmp(heap[i], heap[parent]) <= 0)
            return;
        tmp = heap[i];
        heap[i] = heap[parent];
        heap[parent] = tmp;
        i = parent;
    }
}

size_t flow_table_top_n(const struct flow_table *t, size_t n,
                        const struct flow **out)
{
    size_t kept = 0, pos = 0;
    const struct flow *f;

    if (n == 0)
        return 0;
    while ((f = flow_table_next(t, &pos)) != NULL) {
        if (kept < n) {
            out[kept] = f;
            sift_up(out, kept++);
        } else if (rank_cmp(f, out[0]) < 0) {
            out[0] = f; /* beats the weakest flow kept so far */
            sift_down(out, kept, 0);
        }
    }
    /* The heap holds the right flows in heap order; sort them for output. */
    qsort(out, kept, sizeof *out, rank_cmp_qsort);
    return kept;
}
