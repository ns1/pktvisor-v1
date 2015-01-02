/*
 * netsniff-ng - the packet sniffing beast
 * Copyrit 2014 NSONE, Inc.
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <linux/if_packet.h>

#include <ldns/ldns.h>

#include "proto.h"
#include "protos.h"
#include "lookup.h"
#include "pkt_buff.h"
#include "dnsctxt.h"


void print_dns(struct pkt_buff *pkt, void *ctxt)
{
    size_t   len = pkt_len(pkt);
    uint8_t *ptr = pkt_pull(pkt, len);

    ldns_pkt *dns_pkt = NULL;
    ldns_status status;

    if (!len)
        return;

    status = ldns_wire2pkt(&dns_pkt, ptr, len);
    if (status != LDNS_STATUS_OK) {
        tprintf(" [ DNS: MALFORMED DNS PACKET ]\n");
        return;
    }

    // XXX this is very verbose, make something more useful
    char *pkt_str = ldns_pkt2str(dns_pkt);

    tprintf(" [ DNS %s ]\n", pkt_str);

    free(pkt_str);
    ldns_pkt_free(dns_pkt);

}

void process_dns(struct pkt_buff *pkt, void *ctxt)
{
    size_t   len = pkt_len(pkt);
    uint8_t *ptr = pkt_pull(pkt, len);

    ldns_pkt *dns_pkt = NULL;
    ldns_status status;

    struct dnsctxt *dns_ctxt = (struct dnsctxt *)ctxt;

    if (!len)
        return;

    dns_ctxt->seen++;

    if (pkt->pkttype == PACKET_HOST) {
        dns_ctxt->incoming++;
    }

    // table counters

    // source by ip
    dnsctxt_count_ip(&dns_ctxt->source_table, *pkt->src_addr);

    if (pkt->pkttype != PACKET_HOST) {
        // outgoing: we don't do a full DNS wire decode, just
        // look for DNS status code
        // XXX
        return;
    }

    status = ldns_wire2pkt(&dns_pkt, ptr, len);
    if (status != LDNS_STATUS_OK) {
        dns_ctxt->malformed_count++;
        return;
    }

    // XXX check query/reply flag, do appropriate counter
    dns_ctxt->query_count++;

    char *pkt_str = ldns_pkt2str(dns_pkt);

    free(pkt_str);
    ldns_pkt_free(dns_pkt);

}

static void print_dns_less(struct pkt_buff *pkt, void *ctxt)
{
    print_dns(pkt, ctxt);
}

struct protocol dns_ops = {
    // XXX this key is hard coded in proto_udp.c
    .key = 0x01,
    .print_full = print_dns,
    .print_less = print_dns_less,
    .visit = process_dns
};
