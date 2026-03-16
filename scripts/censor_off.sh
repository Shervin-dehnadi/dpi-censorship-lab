#!/bin/bash
set -e

IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

sudo iptables -D INPUT -p tcp --dport 2083 -j DPI_SIM 2>/dev/null || true
sudo iptables -D INPUT -p tcp --dport 2097 -j DPI_SIM 2>/dev/null || true
sudo iptables -D INPUT -p tcp --dport 443  -j DPI_SIM 2>/dev/null || true
sudo iptables -F DPI_SIM 2>/dev/null || true
sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true

echo "CENSOR OFF on $IFACE"
