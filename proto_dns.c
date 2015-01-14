/*
 * DNS protocol dissector
 * Copyrit 2015 NSONE, Inc.
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <linux/if_packet.h>
#include <string.h>

#include "proto.h"
#include "protos.h"
#include "lookup.h"
#include "pkt_buff.h"
#include "dnsctxt.h"
#include "dns.h"

void process_dns(struct pkt_buff *pkt, void *ctxt)
{
    size_t   len = pkt_len(pkt);
    uint8_t *ptr = pkt_pull(pkt, len);
    char qname[DNS_D_MAXNAME+1];
    struct dns_rr rr;

    // XXX figure out how to make this dns_packet on stack using dns_p_init and pointing directly to
    // data in ptr
    int error = 0;
    struct dns_packet *dns_pkt = dns_p_make(len, &error);
    if (error) {
        if (dns_pkt)
            free(dns_pkt);
        fprintf(stderr, "dns_p_make fail: %s", strerror(error));
        return;
    }
    memcpy(dns_pkt->data, ptr, len);
    dns_pkt->end = len;

    struct dns_rr_i *I = dns_rr_i_new(dns_pkt, .section = DNS_S_QUESTION);

    struct dnsctxt *dns_ctxt = (struct dnsctxt *)ctxt;

    // basic counts
    dns_ctxt->seen++;

    if (pkt->pkttype == PACKET_HOST) {
        // incoming packet
        dns_ctxt->incoming++;
    }

    // sanity check total len
    if (!len || len < sizeof(struct dns_header)) {
        dns_ctxt->cnt_malformed++;
        return;
    }

    // table counters

    // XXX if we can, limit source and udp src only to incoming (PACKET_HOST)
    // and dest only to outgoing. problem is, this doesn't seem to be working
    // for pcap dumps -- they all show up as PACKET_HOST

    // source by ip
    if (pkt->pkttype != PACKET_OUTGOING) {
        dnsctxt_count_ip(&dns_ctxt->source_table, *pkt->src_addr);
        // incoming: store source udp port
        dnsctxt_count_int(&dns_ctxt->src_port_table, ntohs(*pkt->udp_src_port));
        if (dns_header(dns_pkt)->qr == 1) {
            // shouldn't see reply on incoming
            dns_ctxt->cnt_malformed++;
            dnsctxt_count_ip(&dns_ctxt->malformed_table, *pkt->src_addr);
        }
    }
    else {
        // store dest by ip
        dnsctxt_count_ip(&dns_ctxt->dest_table, *pkt->dest_addr);
    }

    // Query/Reply flags
    if (dns_header(dns_pkt)->qr == 1) {
        dns_ctxt->cnt_reply++;
    }
    else {
        dns_ctxt->cnt_query++;
    }
    // result code
    switch (dns_header(dns_pkt)->rcode) {
    case DNS_RC_NOERROR:
        dns_ctxt->cnt_status_noerror++;
        break;
    case DNS_RC_NXDOMAIN:
        dns_ctxt->cnt_status_nxdomain++;
        break;
    case DNS_RC_REFUSED:
        dns_ctxt->cnt_status_refused++;
        break;
    case DNS_RC_SERVFAIL:
        dns_ctxt->cnt_status_srvfail++;
        break;
    }

    // XXX if we want to, we can branch here on incoming vs. outgong
    // packets to not have to fully decode outgoing. however, we can't
    // capture query names of NXDOMAIN, REFUSED, etc that way

    // XXX detect malformed DNS packet here?
    if (dns_rr_grep(&rr, 1, I, dns_pkt, &error)) {
        if (!dns_d_expand((unsigned char *)qname, DNS_D_MAXNAME, rr.dn.p, dns_pkt, &error) && !error)
            goto finalize;
    }

    // lowercase
    char *p = qname;
    for ( ; *p; ++p) *p = tolower(*p);
    // chop terminating .
    qname[strlen(qname)-1] = 0;

    // break this out to labels of len 2 and 3
    // assumes terminating ".", which ldns always gives us in qname
    char *part = qname + strlen(qname) - 1;
    // zip to TLD .
    while (part > qname && *part != '.')
        part--;
    part--;
    // zip to zone, or qname begin
    while (part > qname && *part != '.')
        part--;
    // if not qname begin, start after .
    if (part == qname) {
        dnsctxt_count_name(&dns_ctxt->query_name2_table, part);
    }
    else {
        dnsctxt_count_name(&dns_ctxt->query_name2_table, part+1);
        // may be go one more label length
        part--;
        while (part > qname && *part != '.')
            part--;
        if (part == qname)
            dnsctxt_count_name(&dns_ctxt->query_name3_table, part);
        else
            // anything longer gets squished into this domain
            dnsctxt_count_name(&dns_ctxt->query_name3_table, part+1);
    }

    // if this was a query reply and it wasn't NOERROR, track NXDOMAIN
    // and REFUSED counts
    if (dns_header(dns_pkt)->qr == 1 && dns_header(dns_pkt)->rcode != DNS_RC_NOERROR) {
        switch (dns_header(dns_pkt)->rcode) {
        case DNS_RC_NXDOMAIN:
            dnsctxt_count_name(&dns_ctxt->nxdomain_table, qname);
            break;
        case DNS_RC_REFUSED:
            dnsctxt_count_name(&dns_ctxt->refused_table, qname);
            break;
        }
    }

    // XXX look for OPT, edns, client subnet
finalize:
    free(dns_pkt);

}

void print_dns_packet(struct dns_packet *P) {

    enum dns_section section;
    struct dns_rr rr;
    int error;
    char qname[DNS_D_MAXNAME+1];

    struct dns_rr_i *I = dns_rr_i_new(P, .section = 0);

    tprintf(" [ DNS Header ");
    tprintf(" qr: %s(%d),", (dns_header(P)->qr)? "RESPONSE" : "QUERY", dns_header(P)->qr);
    tprintf(" opcode: %s(%d),", dns_stropcode(dns_header(P)->opcode), dns_header(P)->opcode);
    tprintf(" aa: %s(%d),", (dns_header(P)->aa)? "AUTHORITATIVE" : "NON-AUTHORITATIVE", dns_header(P)->aa);
    tprintf(" tc: %s(%d),", (dns_header(P)->tc)? "TRUNCATED" : "NOT-TRUNCATED", dns_header(P)->tc);
    tprintf(" rd: %s(%d),", (dns_header(P)->rd)? "RECURSION-DESIRED" : "RECURSION-NOT-DESIRED", dns_header(P)->rd);
    tprintf(" ra: %s(%d),", (dns_header(P)->ra)? "RECURSION-ALLOWED" : "RECURSION-NOT-ALLOWED", dns_header(P)->ra);
    tprintf(" rcode: %s(%d) ]\n", dns_strrcode(dns_header(P)->rcode), dns_header(P)->rcode);

    section	= 0;

    while (dns_rr_grep(&rr, 1, I, P, &error)) {
        if (section != rr.section)
            tprintf(" [ DNS Section %s:%d ]\n", dns_strsection(rr.section), dns_p_count(P, rr.section));

        if (rr.section == DNS_S_QUESTION) {
            if (dns_d_expand((unsigned char *)qname, DNS_D_MAXNAME, rr.dn.p, P, &error) && !error)
                tprintf(" [ DNS Question: %s ]\n", qname);
        }

        section	= rr.section;
    }

}

void print_dns(struct pkt_buff *pkt, void *ctxt)
{
    size_t   len = pkt_len(pkt);
    uint8_t *ptr = pkt_pull(pkt, len);

    // XXX figure out how to make this dns_packet on stack using dns_p_init
    int err;
    struct dns_packet *dns_pkt = dns_p_make(len, &err);
    if (err) {
        if (dns_pkt)
            free(dns_pkt);
        fprintf(stderr, "dns_p_make fail: %d", err);
        return;
    }
    memcpy(dns_pkt->data, ptr, len);
    dns_pkt->end = len;
    print_dns_packet(dns_pkt);
    free(dns_pkt);

    // set len back so we get hex dump
    pkt->data -= len;

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
