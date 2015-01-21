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

// max length of the packet that we parse as a DNS packet.
// unless EDNS is in use, this should be 512. and even if EDNS is in
// use, if it's a Query, it should still be < 512. if EDNS is in use
// then technically a Reply may be larger than 512, but we don't care
// much about the contents of the data in the replies
// NOTE however that incoming traffic can sometimes be large Reply traffic
// during DNS amplication attacks
#define MAX_DNS_PKT_LEN 512

bool cidr_match(uint32_t addr, uint32_t net, uint8_t bits) {
  if (bits == 0) {
    // C99 6.5.7 (3): u32 << 32 is undefined behaviour
    return true;
  }
  return !((addr ^ net) & htonl(0xFFFFFFFFu << (32 - bits)));
}

void process_dns(struct pkt_buff *pkt, void *ctxt)
{
    size_t   len = pkt_len(pkt);
    int error;
    char qname[DNS_D_MAXNAME+1];
    struct dns_rr rr;
    int incoming = 1;

    struct dns_packet *dns_pkt = dns_p_new(MAX_DNS_PKT_LEN);
    struct dns_rr_i *I = dns_rr_i_new(dns_pkt, .section = DNS_S_QUESTION);
    struct dnsctxt *dns_ctxt = (struct dnsctxt *)ctxt;

    // basic counts
    dns_ctxt->seen++;

    // decide whether this is incoming or outgoing, based on our local network
    incoming = cidr_match(*pkt->dest_addr, dns_ctxt->local_net, dns_ctxt->local_bits);

    if (incoming) {
        // incoming packet
        dns_ctxt->incoming++;
    }

    // sanity check len is not 0 and is at least dns_header size
    if (!len || len < sizeof(struct dns_header)) {
        dns_ctxt->cnt_malformed++;
        if (incoming)
            dnsctxt_count_ip(&dns_ctxt->malformed_table, *pkt->src_addr);
        return;
    }

    // XXX this isn't really "zero copy" then, since the way the dns lib is setup, we have to copy
    // the pkt data into the dns_packet buffer. but, it's on the stack at least. if we
    // rework the lib a bit, could use a (optional?) pointer instead of in structure buf
    // copy at most MAX_DNS_PK_LEN bytes
    size_t dns_len = (len < MAX_DNS_PKT_LEN) ? len : MAX_DNS_PKT_LEN;
    memcpy(dns_pkt->data, pkt->data, dns_len);
    dns_pkt->end = dns_len;

    // table counters

    // if this is an incoming packet...
    if (incoming) {
        // source by ip
        dnsctxt_count_ip(&dns_ctxt->source_table, *pkt->src_addr);
        // incoming: store source udp port
        dnsctxt_count_int(&dns_ctxt->src_port_table, ntohs(*pkt->udp_src_port));
        if (dns_header(dns_pkt)->qr == 1) {
            // shouldn't see reply on incoming
            dns_ctxt->cnt_malformed++;
            dnsctxt_count_ip(&dns_ctxt->malformed_table, *pkt->src_addr);
        }
    }
    // otherwise, outgoing packet...
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

    // track result code outgoing for replies
    if (!incoming && dns_header(dns_pkt)->qr == 1) {
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
    }

    // XXX detect malformed DNS packet here?
    if (dns_rr_grep(&rr, 1, I, dns_pkt, &error)) {
        if (!dns_d_expand((unsigned char *)qname, DNS_D_MAXNAME, rr.dn.p, dns_pkt, &error) && !error)
            goto skip_q_name;
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

    if (incoming) {
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
    }

    // if this was a query reply and it wasn't NOERROR, track NXDOMAIN
    // and REFUSED counts
    if (!incoming && dns_header(dns_pkt)->qr == 1 && dns_header(dns_pkt)->rcode != DNS_RC_NOERROR) {
        switch (dns_header(dns_pkt)->rcode) {
        case DNS_RC_NXDOMAIN:
            dnsctxt_count_name(&dns_ctxt->nxdomain_table, qname);
            break;
        case DNS_RC_REFUSED:
            dnsctxt_count_name(&dns_ctxt->refused_table, qname);
            break;
        }
    }

skip_q_name:
    // XXX look for OPT, edns, client subnet
    return;

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
                tprintf(" [ DNS Question: %s %s ]\n", qname, dns_strtype(rr.type));
        }

        section	= rr.section;
    }

}

void print_dns(struct pkt_buff *pkt, void *ctxt)
{
    struct dns_packet *dns_pkt = dns_p_new(2048);
    size_t len = pkt_len(pkt);

    if (len > 2048) {
        tprintf(" [ DNS Malformed (too big: %lu) ]\n", len);
        return;
    }

    memcpy(dns_pkt->data, pkt->data, len);
    dns_pkt->end = len;
    print_dns_packet(dns_pkt);
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
