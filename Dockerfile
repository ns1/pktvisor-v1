FROM ubuntu:14.04

RUN apt-get update \
    && apt-get install -q -y software-properties-common \
    && add-apt-repository ppa:maxmind/ppa \
    && apt-get update \
    && apt-get install -q -y build-essential dh-autoreconf dh-make debhelper devscripts fakeroot lintian pbuilder libncurses5-dev pkg-config bison flex libnl-genl-3-dev libpcap-dev libmaxminddb-dev libcli-dev libgeoip-dev libnacl-dev libnet1-dev zlib1g-dev libnetfilter-conntrack-dev liburcu-dev \
    && rm -rf /var/lib/apt/lists/* /var/lib/apt /var/cache/apt

USER root
RUN mkdir /builder
WORKDIR /builder
