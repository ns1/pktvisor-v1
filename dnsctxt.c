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
    ctxt->malformed_table = NULL;
    ctxt->query_name2_table = NULL;
    ctxt->query_name3_table = NULL;
    ctxt->nxdomain_table = NULL;
    ctxt->refused_table = NULL;

    ctxt->seen = 0;
    ctxt->incoming = 0;

    ctxt->cnt_query = 0;
    ctxt->cnt_reply = 0;

    ctxt->cnt_status_noerror = 0;
    ctxt->cnt_status_srvfail = 0;
    ctxt->cnt_status_nxdomain = 0;
    ctxt->cnt_status_refused = 0;

    ctxt->cnt_malformed = 0;
    ctxt->cnt_edns = 0;

}

void dnsctxt_free(struct dnsctxt *ctxt) {
    struct int32_entry *entry, *tmp_entry;
    struct str_entry *sentry, *tmp_sentry;

    // XXX make this a macro
    HASH_ITER(hh, ctxt->source_table, entry, tmp_entry) {
        HASH_DELETE(hh, ctxt->source_table, entry);
        free(entry);
    }
    HASH_ITER(hh, ctxt->dest_table, entry, tmp_entry) {
        HASH_DELETE(hh, ctxt->dest_table, entry);
        free(entry);
    }
    HASH_ITER(hh, ctxt->malformed_table, entry, tmp_entry) {
        HASH_DELETE(hh, ctxt->malformed_table, entry);
        free(entry);
    }
    HASH_ITER(hh, ctxt->query_name2_table, sentry, tmp_sentry) {
        HASH_DELETE(hh, ctxt->query_name2_table, sentry);
        free(sentry);
    }
    HASH_ITER(hh, ctxt->query_name3_table, sentry, tmp_sentry) {
        HASH_DELETE(hh, ctxt->query_name3_table, sentry);
        free(sentry);
    }
    HASH_ITER(hh, ctxt->nxdomain_table, sentry, tmp_sentry) {
        HASH_DELETE(hh, ctxt->nxdomain_table, sentry);
        free(sentry);
    }
    HASH_ITER(hh, ctxt->refused_table, sentry, tmp_sentry) {
        HASH_DELETE(hh, ctxt->refused_table, sentry);
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

// XXX could be macro from ip version
int _sort_str_by_count(void *a, void *b) {
    struct str_entry *left = (struct str_entry *)a;
    struct str_entry *right = (struct str_entry *)b;
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
        printf("%16s %lu\n", ip, entry->count);
        if (++i > MAX_SUMMARY_SIZE)
            break;
    }
}

void _print_table_str(struct str_entry *table) {
    struct str_entry *entry, *tmp_entry;
    unsigned int i = 0;

    HASH_SORT(table, _sort_str_by_count);
    HASH_ITER(hh, table, entry, tmp_entry) {
        printf("%20s %lu\n", entry->key, entry->count);
        if (++i > MAX_SUMMARY_SIZE)
            break;
    }
}

void dnsctxt_table_summary(struct dnsctxt *ctxt) {

    printf("\nSources IPs\n");
    _print_table_ip(ctxt->source_table);
    printf("\nDestinations IPs\n");
    _print_table_ip(ctxt->dest_table);
    printf("\nMalformed Query Source IPs\n");
    _print_table_ip(ctxt->malformed_table);
    printf("\nQueried Names (2)\n");
    _print_table_str(ctxt->query_name2_table);
    printf("\nQueried Names (3)\n");
    _print_table_str(ctxt->query_name3_table);
    printf("\nNXDOMAIN Names\n");
    _print_table_str(ctxt->nxdomain_table);
    printf("\nREFUSED Names\n");
    _print_table_str(ctxt->refused_table);

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

struct str_entry *lru_get_str(struct str_entry **table, char *key)
{
    struct str_entry *entry;
    if (!*table)
        return NULL;
    HASH_FIND_STR(*table, key, entry);
    if (entry) {
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh, *table, entry);
        HASH_ADD_STR(*table, key, entry);
        return entry;
    }
    return NULL;
}

void lru_add_str(struct str_entry **table, char *key)
{
    struct str_entry *entry, *tmp_entry;
    entry = malloc(sizeof(struct str_entry));
    strncpy(entry->key, key, MAX_DNAME_LEN);
    entry->count = 1;
    HASH_ADD_STR(*table, key, entry);

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

    struct str_entry *entry = lru_get_str(table, name);
    if (entry) {
        entry->count++;
        return;
    }
    lru_add_str(table, name);

}
