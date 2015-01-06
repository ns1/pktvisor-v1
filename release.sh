#!/bin/sh
make clean
make PREFIX=/opt/dnstop-ng CONFIG_TOOLS="dnstop-ng bpfc" CCACHE=ccache ETCDIR=/opt/dnstop-ng/etc
make PREFIX=/opt/dnstop-ng CONFIG_TOOLS="dnstop-ng bpfc" CCACHE=ccache ETCDIR=/opt/dnstop-ng/etc install
