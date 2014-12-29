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


static void dns(struct pkt_buff *pkt)
{

        tprintf(" [ DNS ] ");
}

static void dns_less(struct pkt_buff *pkt)
{
}

struct protocol dns_ops = {
        // XXX key?
        .key = 0x0,
        .print_full = dns,
        .print_less = dns_less,
};
