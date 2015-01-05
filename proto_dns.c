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

// dnstop
struct _rfc1035_header {
    unsigned short id;
    unsigned int qr:1;
    unsigned int opcode:4;
    unsigned int aa:1;
    unsigned int tc:1;
    unsigned int rd:1;
    unsigned int ra:1;
    unsigned int rcode:4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

void process_dns(struct pkt_buff *pkt, void *ctxt)
{
    size_t   len = pkt_len(pkt);
    uint8_t *ptr = NULL;

    // for simple DNS header decode
    unsigned short us;
    struct _rfc1035_header qh;

    // for full DNS wire decode by ldns
    ldns_pkt *dns_pkt = NULL;
    char *q_name = NULL;
    ldns_status status;

    struct dnsctxt *dns_ctxt = (struct dnsctxt *)ctxt;

    // basic counts
    dns_ctxt->seen++;

    if (pkt->pkttype == PACKET_HOST) {
        // incoming packet
        dns_ctxt->incoming++;
    }

    // sanity check total len
    if (!len || len < sizeof(qh)) {
        dns_ctxt->cnt_malformed++;
        return;
    }

    // do a simple header decode first
    memcpy(&us, pkt->data + 0, 2);
    qh.id = ntohs(us);
    memcpy(&us, pkt->data + 2, 2);
    us = ntohs(us);
    qh.qr = (us >> 15) & 0x01;
    qh.opcode = (us >> 11) & 0x0F;
    qh.aa = (us >> 10) & 0x01;
    qh.tc = (us >> 9) & 0x01;
    qh.rd = (us >> 8) & 0x01;
    qh.ra = (us >> 7) & 0x01;
    qh.rcode = us & 0x0F;
    memcpy(&us, pkt->data + 4, 2);
    qh.qdcount = ntohs(us);
    memcpy(&us, pkt->data + 6, 2);
    qh.ancount = ntohs(us);
    memcpy(&us, pkt->data + 8, 2);
    qh.nscount = ntohs(us);
    memcpy(&us, pkt->data + 10, 2);
    qh.arcount = ntohs(us);

    // table counters

    // XXX if we can, limit source and udp src only to incoming (PACKET_HOST)
    // and dest only to outgoing. problem is, this doesn't seem to be working
    // for pcap dumps -- they all show up as PACKET_HOST

    // source by ip
    dnsctxt_count_ip(&dns_ctxt->source_table, *pkt->src_addr);
    // incoming: store source udp port
    dnsctxt_count_int(&dns_ctxt->src_port_table, ntohs(*pkt->udp_src_port));
    // store dest by ip
    dnsctxt_count_ip(&dns_ctxt->dest_table, *pkt->dest_addr);

    // Query/Reply flags
    if (qh.qr == 1) {
        dns_ctxt->cnt_reply++;
    }
    else {
        dns_ctxt->cnt_query++;
    }
    // result code
    switch (qh.rcode) {
    case LDNS_RCODE_NOERROR:
        dns_ctxt->cnt_status_noerror++;
        break;
    case LDNS_RCODE_NXDOMAIN:
        dns_ctxt->cnt_status_nxdomain++;
        break;
    case LDNS_RCODE_REFUSED:
        dns_ctxt->cnt_status_refused++;
        break;
    case LDNS_RCODE_SERVFAIL:
        dns_ctxt->cnt_status_srvfail++;
        break;
    }

    // XXX if we want to, we can branch here on incoming vs. outgong
    // packets to not have to fully decode outgoing

    // incoming query: ldns will decode the full udp packet buffer
    ptr = pkt_pull(pkt, len);
    status = ldns_wire2pkt(&dns_pkt, ptr, len);
    if (status != LDNS_STATUS_OK) {
        dns_ctxt->cnt_malformed++;
        // only add to malformed table if this is an incoming query,
        // because the authoritative server may echo back an invalid
        // query part with REFUSED
        if (pkt->pkttype == PACKET_HOST)
            dnsctxt_count_ip(&dns_ctxt->malformed_table, *pkt->src_addr);
        return;
    }

    q_name = ldns_rdf2str(ldns_rr_owner(ldns_rr_list_rr(
                                            ldns_pkt_question(dns_pkt), 0)));
    if (q_name) {

        // lowercase
        char *p = q_name;
        for ( ; *p; ++p) *p = tolower(*p);
        // chop terminating .
        q_name[strlen(q_name)-1] = 0;

        // break this out to labels of len 2 and 3
        // assumes terminating ".", which ldns always gives us in q_name
        char *part = q_name + strlen(q_name) - 1;
        // zip to TLD .
        while (part > q_name && *part != '.')
            part--;
        part--;
        // zip to zone, or q_name begin
        while (part > q_name && *part != '.')
            part--;
        // if not q_name begin, start after .
        if (part == q_name) {
            dnsctxt_count_name(&dns_ctxt->query_name2_table, part);
        }
        else {
            dnsctxt_count_name(&dns_ctxt->query_name2_table, part+1);
            // may be go one more label length
            part--;
            while (part > q_name && *part != '.')
                part--;
            if (part == q_name)
                dnsctxt_count_name(&dns_ctxt->query_name3_table, part);
            else
                // anything longer gets squished into this domain
                dnsctxt_count_name(&dns_ctxt->query_name3_table, part+1);
        }

        // if this was a query reply and it wasn't NOERROR, track NXDOMAIN
        // and REFUSED counts
        if (qh.qr && qh.rcode != LDNS_RCODE_NOERROR) {
            switch (qh.rcode) {
            case LDNS_RCODE_NXDOMAIN:
                dnsctxt_count_name(&dns_ctxt->nxdomain_table, q_name);
                break;
            case LDNS_RCODE_REFUSED:
                dnsctxt_count_name(&dns_ctxt->refused_table, q_name);
                break;
            }
        }

        free(q_name);
    }

    if (ldns_pkt_edns(dns_pkt)) {
        dns_ctxt->cnt_edns++;
    }

    ldns_pkt_free(dns_pkt);

}

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
        // backout the data so it dumps as hex
        pkt->data -= len;
        return;
    }

    // XXX this is very verbose, make something more useful
    char *pkt_str = ldns_pkt2str(dns_pkt);

    tprintf(" [ DNS %s ]\n", pkt_str);

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
