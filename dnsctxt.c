/*
 * Copyright 2015 NSONE, Inc.
 */

#include <stdio.h>
#include <arpa/inet.h>

#include "dnsctxt.h"

// uthash LRU: https://gist.github.com/jehiah/900846

void dnsctxt_init(struct dnsctxt *ctxt) {
    ctxt->source_table = NULL;
    ctxt->dest_table = NULL;
    ctxt->query_name_table = NULL;

    ctxt->query_count = 0;
    ctxt->reply_count = 0;
    ctxt->malformed_count = 0;
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

int _sort_ip_by_count(void *a, void *b) {
    struct int32_entry *left = (struct int32_entry *)a;
    struct int32_entry *right = (struct int32_entry *)b;
    if (left->count == right->count)
        return 0;
    else if (left->count > right->count)
        return -1;
    else
        return 1;
}

void _print_table_ip(struct int32_entry *table) {
    struct int32_entry *entry, *tmp_entry;
    char ip[INET_ADDRSTRLEN];
    unsigned int i = 0;

    HASH_SORT(table, _sort_ip_by_count);
    HASH_ITER(hh, table, entry, tmp_entry) {
        inet_ntop(AF_INET, &entry->key, ip, sizeof(ip));
        printf("%16s: %lu\n", ip, entry->count);
        if (++i > MAX_SUMMARY_SIZE)
            break;
    }
}

void dnsctxt_table_summary(struct dnsctxt *ctxt) {

    printf("Sources\n");
    _print_table_ip(ctxt->source_table);

}

struct int32_entry *lru_get_int(struct int32_entry **table, uint32_t key)
{
    struct int32_entry *entry;
    if (!*table)
        return NULL;
    HASH_FIND(hh, *table, &key, sizeof(uint32_t), entry);
    if (entry) {
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh, *table, entry);
        HASH_ADD(hh, *table, key, sizeof(uint32_t), entry);
        return entry;
    }
    return NULL;
}

void lru_add_int(struct int32_entry **table, uint32_t key)
{
    struct int32_entry *entry, *tmp_entry;
    entry = malloc(sizeof(struct int32_entry));
    entry->key = key;
    entry->count = 1;
    HASH_ADD(hh, *table, key, sizeof(uint32_t), entry);

    // prune the cache
    if (HASH_COUNT(*table) >= MAX_LRU_SIZE) {
        HASH_ITER(hh, *table, entry, tmp_entry) {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
            HASH_DELETE(hh, *table, entry);
            free(entry);
            break;
        }
    }
}

void dnsctxt_count_ip(struct int32_entry **table, uint32_t key) {

    struct int32_entry *entry = lru_get_int(table, key);
    if (entry) {
        entry->count++;
        return;
    }
    lru_add_int(table, key);

}

void dnsctxt_count_name(struct str_entry **table, char *name) {

}
