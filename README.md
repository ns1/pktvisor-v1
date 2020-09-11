pktvisor - DNS protocol analyzer
================================
> This project is in [deprecated status](https://github.com/ns1/community/blob/master/project_status/DEPRECATED.md). See https://github.com/ns1/pktvisor

This project is a fork and reorganization of netsniff-ng, available at
http://netsniff-ng.org/

It adds a DNS protocol analyzer, which can generate various statistics about
real time traffic streams. It's intended use is to be run on authoritative DNS
servers to diagnose incoming and outgoing DNS traffic.

Like netsniff-ng, it can capture to a pcap. It also includes an ncurses based
UI that provides a top-like interface to live DNS traffic statistics, including
traffic by source/destination IP, DNS query label, result codes, source ports,
Geo and ASN.

Building via Docker (Compose)
-------------------

You'll need Docker and Docker Compose installed for this.  This is useful for simple cross compliation or in CI environments.

To use the Docker to build the pktvisor binary do the following:

```
$ cd pktvisor
$ docker-compose build
$ docker-compose run --rm builder ./configure
$ docker-compose run --rm builder make
```

After the `builder` container exists you can also create a release build (a Debian package) as follows:

```
$ docker-compose run --rm release
```

After building, you can even run pktvisor in a Docker:

```
$ docker-compose run --rm pktvisor <options>
```

Contributions
---
Pull Requests and issues are welcome. See the [NS1 Contribution Guidelines](https://github.com/ns1/community) for more information.
