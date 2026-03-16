#!/bin/bash
set -e
mkdir -p /opt/dpi-lab/pcap
exec /usr/bin/tcpdump -i any -nn -s 0 \
'((host 195.188.181.130) and (tcp port 2083 or tcp port 2097 or tcp port 443 or udp port 53 or tcp port 53))' \
-C 50 -W 10 \
-w /opt/dpi-lab/pcap/lab_clients_only.pcap
