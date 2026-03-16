#!/bin/bash
set -e

IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

sudo iptables -N DPI_SIM 2>/dev/null || true
sudo iptables -F DPI_SIM

for p in 2083 2097 443; do
  sudo iptables -C INPUT -p tcp --dport $p -j DPI_SIM 2>/dev/null || sudo iptables -I INPUT -p tcp --dport $p -j DPI_SIM
done

# 2083: drop ~30% of new connections
sudo iptables -A DPI_SIM -p tcp --dport 2083 -m conntrack --ctstate NEW -m statistic --mode random --probability 0.30 -j DROP

# 2097: reset ~20% of new connections
sudo iptables -A DPI_SIM -p tcp --dport 2097 -m conntrack --ctstate NEW -m statistic --mode random --probability 0.20 -j REJECT --reject-with tcp-reset

# 443: mild global impairment while censor is ON
sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true
sudo tc qdisc add dev "$IFACE" root netem delay 60ms 15ms loss 2% reorder 1% 20%
echo "CENSOR ON on $IFACE"
