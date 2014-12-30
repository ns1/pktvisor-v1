/*
 * Copyright 2015 NSONE, Inc.
 */

#ifndef DNSCTXT_H
#define DNSCTXT_H

#include "uthash.h"

// max length of domain name. 253 is the max according to standard,
// can make it smaller if we truncate and save memory
#define MAX_DNAME_LEN 253

// max LRU table size
#define MAX_LRU_SIZE 500

// accumulator hash table keyed by ip address (in int form)
// or other 32 bit key
struct int32_entry {
    uint32_t key;
    uint64_t count;
    UT_hash_handle hh;
};

// accumulator hash table keyed by string
struct str_entry {
    char key[MAX_DNAME_LEN];
    uint64_t count;
    UT_hash_handle hh;
};

// context structure that gets passed to dns processing function
struct dnsctxt {
    struct int32_entry *source_table;
    struct int32_entry *dest_table;
    struct str_entry *query_name_table;
};

void dnsctxt_init(struct dnsctxt *ctxt) {
    ctxt->source_table = NULL;
    ctxt->dest_table = NULL;
    ctxt->query_name_table = NULL;
}

void dnsctxt_free(struct dnsctxt *ctxt) {
    struct int32_entry *entry, *tmp_entry;
    struct str_entry *sentry, *tmp_sentry;

    HASH_ITER(hh, ctxt->source_table, entry, tmp_entry) {
        HASH_DELETE(hh, ctxt->source_table, entry);
        free(entry);
    }
    HASH_ITER(hh, ctxt->dest_table, entry, tmp_entry) {
        HASH_DELETE(hh, ctxt->dest_table, entry);
        free(entry);
    }
    HASH_ITER(hh, ctxt->query_name_table, sentry, tmp_sentry) {
        HASH_DELETE(hh, ctxt->query_name_table, sentry);
        free(sentry);
    }
}

void dnsctxt_count_ip(struct int32_entry *table, uint32_t key);
void dnsctxt_count_name(struct str_entry *table, char *name);

#endif /* DNSCTXT_H */
