/*
 * netsniff-ng - the packet sniffing beast
 * Copyrit 2014 NSONE, Inc.
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "protos.h"
#include "lookup.h"
#include "pkt_buff.h"
#include "ldns/ldns.h"

void print_dns(struct pkt_buff *pkt)
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

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port, dest_port;

    ldns_pkt *dns_pkt = NULL;
    ldns_status status;

    if (!len)
        return;

    inet_ntop(AF_INET, pkt->src_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, pkt->dest_addr, dst_ip, sizeof(dst_ip));
    src_port = ntohs(*pkt->udp_src_port);
    dest_port = ntohs(*pkt->udp_dest_port);

    status = ldns_wire2pkt(&dns_pkt, ptr, len);
    if (status != LDNS_STATUS_OK) {
        // XXX malformed counter
        return;
    }

    char *pkt_str = ldns_pkt2str(dns_pkt);

    free(pkt_str);
    ldns_pkt_free(dns_pkt);

    // NEED TO RESET pkt data for potential print_dns run
    pkt->data -= len;

}

static void print_dns_less(struct pkt_buff *pkt)
{
    print_dns(pkt);
}

struct protocol dns_ops = {
    // XXX this key is hard coded in proto_udp.c
    .key = 0x01,
    .print_full = print_dns,
    .print_less = print_dns_less,
    .visit = process_dns
};
