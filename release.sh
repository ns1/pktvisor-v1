#!/bin/sh
make clean
make PREFIX=/opt/pktvisor CONFIG_TOOLS="pktvisor bpfc" CCACHE=ccache ETCDIR=/opt/pktvisor/etc
make PREFIX=/opt/pktvisor CONFIG_TOOLS="pktvisor bpfc" CCACHE=ccache ETCDIR=/opt/pktvisor/etc install
