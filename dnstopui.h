/*
 * Copyright 2015 NSONE, Inc.
 */

#ifndef DNSTOPUI_H
#define DNSTOPUI_H

#include "dnsctxt.h"

void dnstop_ui_init(int interval);
void dnstop_ui(struct dnsctxt *dns_ctxt);
void dnstop_ui_shutdown();

#endif
