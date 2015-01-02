/*
 * netsniff-ng - the packet sniffing beast
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
#include "dissector_eth.h"

struct udphdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
} __packed;

static void udp(struct pkt_buff *pkt, void *ctxt)
{
	struct udphdr *udp = (struct udphdr *) pkt_pull(pkt, sizeof(*udp));
	ssize_t len;
	uint16_t src, dest;
	char *src_name, *dest_name;

	if (udp == NULL)
		return;

    pkt->udp_src_port = &udp->source;
    pkt->udp_dest_port = &udp->dest;

	len = ntohs(udp->len) - sizeof(*udp);
	src = ntohs(udp->source);
	dest = ntohs(udp->dest);

	src_name = lookup_port_udp(src);
	dest_name = lookup_port_udp(dest);

	tprintf(" [ UDP ");
	tprintf("Port (%u", src);
	if (src_name)
		tprintf(" (%s%s%s)", colorize_start(bold), src_name,
			colorize_end());
	tprintf(" => %u", dest);
	if (dest_name)
		tprintf(" (%s%s%s)", colorize_start(bold), dest_name,
			colorize_end());
	tprintf("), ");
	if(len > pkt_len(pkt) || len < 0){
		tprintf("Len (%u) %s, ", ntohs(udp->len),
			colorize_start_full(black, red)
			"invalid" colorize_end());
	}
	tprintf("Len (%u Bytes, %zd Bytes Data), ", ntohs(udp->len), len);
	tprintf("CSum (0x%.4x)", ntohs(udp->check));
    tprintf(" ]\n");
    pkt_set_proto(pkt, &eth_lay7, 0x01);
}

static void udp_less(struct pkt_buff *pkt, void *ctxt)
{
    struct udphdr *udp = (struct udphdr *) pkt_pull(pkt, sizeof(*udp));
    uint16_t src, dest;
    char *src_name, *dest_name;

    if (udp == NULL)
        return;

    src = ntohs(udp->source);
    dest = ntohs(udp->dest);

    src_name = lookup_port_udp(src);
    dest_name = lookup_port_udp(dest);

    tprintf(" UDP %u", src);
    if(src_name)
        tprintf("(%s%s%s)", colorize_start(bold), src_name,
            colorize_end());
    tprintf("/%u", dest);
    if (dest_name)
        tprintf("(%s%s%s)", colorize_start(bold), dest_name,
            colorize_end());
}

static void udp_visit(struct pkt_buff *pkt, void *ctxt)
{
	struct udphdr *udp = (struct udphdr *) pkt_pull(pkt, sizeof(*udp));
	uint16_t src, dest;
	char *src_name, *dest_name;

	if (udp == NULL)
		return;

	src = ntohs(udp->source);
	dest = ntohs(udp->dest);

	src_name = lookup_port_udp(src);
    dest_name = lookup_port_udp(dest);

    // XXX this key is hard coded in proto_dns.c. currently this will ALWAYS
    // process UDP traffic as DNS, so it assumes an appropriate bpf filter
    // has already been setup to just capture DNS. to fix this, we'd need to
    // pass some sort of context with commandline options or similar.
    pkt_set_proto(pkt, &eth_lay7, 0x01);

}

struct protocol udp_ops = {
	.key = 0x11,
	.print_full = udp,
    .print_less = udp_less,
    .visit = udp_visit,
};
