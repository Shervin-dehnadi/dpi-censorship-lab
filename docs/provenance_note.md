# Provenance note

## Lab objective
The dataset was generated in a controlled VPS-based censorship lab designed to study whether VPN traffic can be detected and disrupted using DPI-relevant transport, timing, TLS, DNS, and behavioural features.

## Infrastructure
- VPS IP: `69.169.97.176`
- VPN software: Xray/VLESS
- Inbound 1: port `443`, `vless-reality`, flow `xtls-rprx-vision`, server names `apple.com` / `www.apple.com`
- Inbound 2: port `2097`, `vless-tcp-tls`, TLS certificate bound to `test.ourbluesky.co.uk`
- Inbound 3: port `2083`, `vless-tcp-no-tls`
- Packet capture: `tcpdump`
- DPI telemetry: `Suricata` (`flow`, `alert`, `dns`, `tls`, `stats`)
- Feature extraction: `extract_features_full.py`

## Simulated DPI / censorship environment
The lab does not claim to re-implement the internal firmware of a state censor. Instead, it simulates the observable network effects of DPI-driven censorship.

Two operating modes were used:

### Censorship OFF
Traffic passes normally. This produces uncensored baseline traffic.

### Censorship ON
A controlled enforcement policy is applied on the VPS using Linux firewall and traffic-control mechanisms:
- new TCP connections on `2083` are probabilistically dropped
- new TCP connections on `2097` are probabilistically reset using TCP RST
- network quality impairment is introduced using `tc netem` with delay, loss, and reordering

These actions simulate outcomes commonly associated with censorship:
- connection timeout
- connection reset
- degraded throughput
- increased latency
- partial or failed handshake

## Data sources
The dataset is derived from:
1. raw PCAP files collected with `tcpdump`
2. Suricata `eve.json` telemetry
3. local IP-to-ASN / ISP mapping
4. the active Xray configuration

## Label definition
`label_success = 1` when a session meets the configured success condition:
- for `443` REALITY: first server payload observed within the expected time window, sufficient downstream bytes transferred, and no reset observed
- for `2097` TLS: TLS metadata observed, handshake completed within the time window, sufficient downstream bytes transferred, and no reset observed
- for `2083` no-TLS: session duration exceeded the minimum threshold, sufficient downstream bytes transferred, and no reset observed

Otherwise `label_success = 0`.

## Reproducibility
The dataset is reproducible because the same VPS configuration, scripts, service files, capture logic, and feature-extraction pipeline can be executed again on a clean VPS.
