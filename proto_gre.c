/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "protos.h"
#include "lookup.h"
#include "dissector_eth.h"
#include "pkt_buff.h"
#include "built_in.h"

struct grehdr {
    uint16_t gre_flags;
    uint16_t gre_proto;
    /*
    uint16_t gre_checksum;
    uint16_t gre_reserved;
    uint32_t gre_key;
    uint32_t gre_sequence;
    */
} __packed;

static void gre(struct pkt_buff *pkt)
{

    char *type;
    struct grehdr *gre = (struct grehdr *) pkt_pull(pkt, sizeof(*gre));

    if (gre == NULL)
		return;

    tprintf(" [ GRE ");
    tprintf("Proto (0x%.4x", ntohs(gre->gre_proto));
    type = lookup_ether_type(ntohs(gre->gre_proto));
    if (type)
        tprintf(", %s%s%s", colorize_start(bold), type, colorize_end());

    tprintf(") Len (%u) ]\n", pkt_len(pkt));

    pkt_set_proto(pkt, &eth_lay2, ntohs(gre->gre_proto));

}

static void gre_visit(struct pkt_buff *pkt, void *ctxt)
{
    struct grehdr *gre = (struct grehdr *) pkt_pull(pkt, sizeof(*gre));

    if (gre == NULL)
        return;

    pkt_set_proto(pkt, &eth_lay2, ntohs(gre->gre_proto));
}

struct protocol gre_ops = {
    .key = 0x2f,
    .print_full = gre,
    .print_less = gre,
    .visit = gre_visit,
};
