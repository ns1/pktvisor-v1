/*
 * netsniff-ng - the packet sniffing beast
 * Copyright (C) 2009, 2010 Daniel Borkmann
 * Copyright (C) 2012 Christoph Jaeger <christoph@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#ifndef PROTO_H
#define PROTO_H

#include <ctype.h>
#include <stdint.h>

#include "tprintf.h"

struct pkt_buff;

struct protocol {
	/* Needs to be filled out by user */
	unsigned int key;
    void (*print_full)(struct pkt_buff *pkt, void *ctxt);
    void (*print_less)(struct pkt_buff *pkt, void *ctxt);
    void (*visit)(struct pkt_buff *pkt, void *ctxt);
	/* Used by program logic */
    struct protocol *next;
    void (*process)   (struct pkt_buff *pkt, void *ctxt);
};

extern void empty(struct pkt_buff *pkt);
extern void hex(struct pkt_buff *pkt);
extern void ascii(struct pkt_buff *pkt);
extern void hex_ascii(struct pkt_buff *pkt);

#endif /* PROTO_H */
