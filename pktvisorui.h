/*
 * Copyright 2015 NSONE, Inc.
 */

#ifndef PKTVISORUI_H
#define PKTVISORUI_H

#include "dnsctxt.h"

void pktvisor_ui_init(int interval);
void pktvisor_ui(struct dnsctxt *dns_ctxt);
void pktvisor_ui_shutdown();
void pktvisor_ui_waitforkey(struct dnsctxt *dns_ctxt);

#endif
