#!/bin/bash
set -e
mkdir -p /opt/dpi-lab/pcap
exec /usr/bin/tcpdump -i any -nn -s 0 \
'(tcp port 2083 or tcp port 2097 or tcp port 443 or udp port 53 or tcp port 53)' \
-G 3600 -W 168 \
-w /opt/dpi-lab/pcap/lab-%Y%m%d-%H%M%S.pcap
