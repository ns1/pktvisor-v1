/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_H
#define DISSECTOR_H

#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <libnl3/netlink/msg.h>

#include "ring.h"
#include "tprintf.h"
#include "linktype.h"

#define PRINT_NORM		0
#define PRINT_LESS		1
#define PRINT_HEX		2
#define PRINT_ASCII		3
#define PRINT_HEX_ASCII		4
#define PRINT_NONE		5

extern char *if_indextoname(unsigned ifindex, char *ifname);

static const char * const packet_types[256] = {
	[PACKET_HOST]		=	"<",  /* Incoming */
	[PACKET_BROADCAST]	=	"B",  /* Broadcast */
	[PACKET_MULTICAST]	=	"M",  /* Multicast */
	[PACKET_OTHERHOST]	=	"P",  /* Promisc */
	[PACKET_OUTGOING]	=	">",  /* Outgoing */
	[PACKET_USER]		=	">U", /* To Userspace */
	[PACKET_KERNEL]		=	">K", /* To Kernelspace */
};

static inline const char *__show_ts_source(uint32_t status)
{
	if (status & TP_STATUS_TS_RAW_HARDWARE)
		return "(raw hw ts)";
	else if (status & TP_STATUS_TS_SYS_HARDWARE)
		return "(sys hw ts)";
	else if (status & TP_STATUS_TS_SOFTWARE)
		return "(sw ts)";
	else
		return "";
}

static inline void __show_frame_hdr(uint8_t *packet, size_t len, int linktype,
				    struct sockaddr_ll *s_ll, void *raw_hdr,
				    int mode, bool v3)
{
	char tmp[IFNAMSIZ];
	union tpacket_uhdr hdr;
	uint8_t pkttype = s_ll->sll_pkttype;
	bool is_nl;

	if (mode == PRINT_NONE)
		return;

	/*
	 * If we're capturing on nlmon0, all packets will have sll_pkttype set
	 * to PACKET_OUTGOING, but we actually want PACKET_USER/PACKET_KERNEL as
	 * it originally was set in the kernel. Thus, use nlmsghdr->nlmsg_pid to
	 * restore the type.
	 */
	is_nl = (linktype == LINKTYPE_NETLINK && len >= sizeof(struct nlmsghdr));
	if (is_nl && pkttype == PACKET_OUTGOING) {
		struct nlmsghdr *hdr = (struct nlmsghdr *) packet;
		pkttype = hdr->nlmsg_pid == 0 ? PACKET_KERNEL : PACKET_USER;
	}

	hdr.raw = raw_hdr;
	switch (mode) {
	case PRINT_LESS:
		tprintf("%s %s %u",
			packet_types[pkttype] ? : "?",
			if_indextoname(s_ll->sll_ifindex, tmp) ? : "?",
			tpacket_uhdr(hdr, tp_len, v3));
		break;
	default:
		tprintf("%s %s %u %us.%uns %s\n",
			packet_types[pkttype] ? : "?",
			if_indextoname(s_ll->sll_ifindex, tmp) ? : "?",
			tpacket_uhdr(hdr, tp_len, v3),
			tpacket_uhdr(hdr, tp_sec, v3),
			tpacket_uhdr(hdr, tp_nsec, v3),
			v3 ? "" : __show_ts_source(hdr.h2->tp_status));
		break;
	}
}

static inline void show_frame_hdr(uint8_t *packet, size_t len, int linktype,
				  struct frame_map *hdr, int mode)
{
	__show_frame_hdr(packet, len, linktype, &hdr->s_ll, &hdr->tp_h, mode, false);
}

extern void dissector_init_all(int fnttype);
extern void dissector_entry_point(uint8_t *packet, size_t len, int linktype, int mode, void *ctxt);
extern void dissector_cleanup_all(void);
extern int dissector_set_print_type(void *ptr, int type);

#endif /* DISSECTOR_H */
