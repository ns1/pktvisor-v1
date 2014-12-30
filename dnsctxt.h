/*
 * Copyright 2015 NSONE, Inc.
 */

#ifndef DNSCTXT_H
#define DNSCTXT_H

#include "uthash.h"

// max length of domain name. 253 is the max according to standard,
// can make it smaller if we truncate and save memory
#define MAX_DNAME_LEN 253

// accumulator hash table keyed by ip address (in int form)
// or other 32 bit key
struct int32_table {
    uint32_t ip;
    uint64_t count;
    UT_hash_handle hh;
};

// accumulator hash table keyed by string
struct str_table {
    char key[MAX_DNAME_LEN];
    uint64_t count;
    UT_hash_handle hh;
};

// context structure that gets passed to dns processing function
struct dnsctxt {
    struct int32_table *source_table = NULL;
    struct int32_table *dest_table = NULL;
    struct str_table *query_name_table = NULL;
};

void dnsctxt_init(struct dnsctxt *ctxt) {
    ctxt->source_table = NULL;
    ctxt->dest_table = NULL;
    ctxt->query_name_table = NULL;
}

void dnsctxt_free(struct dnsctxt *ctxt) {
    HASH_CLEAR(hh, ctxt->source_table);
    HASH_CLEAR(hh, ctxt->dest_table);
    HASH_CLEAR(hh, ctxt->query_name_table);
}

void dnsctxt_count_ip(int32_table *table, uint32_t);
void dnsctxt_count_name(str_table *table, char *name);

#endif /* DNSCTXT_H */
