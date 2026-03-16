# DPI Censorship Lab

This repository contains the scripts, configs, and documentation used to generate a VPS-based DPI censorship dataset for Xray/VLESS traffic.

## Main components
- `scripts/` capture, censorship simulation, and feature extraction
- `services/` systemd service files
- `config/` Xray, Suricata, rules, and IP mapping
- `docs/` provenance, reproducibility, sanity checks
- `output-samples/` sample dataset outputs

## Xray inbounds
- `443`: VLESS REALITY (`xtls-rprx-vision`)
- `2097`: VLESS TCP TLS
- `2083`: VLESS TCP no-TLS

## Dataset generation
Traffic is captured with `tcpdump`, observed with Suricata, and transformed into a feature-complete CSV using `scripts/extract_features_full.py`.

## Censorship simulation
The lab supports:
- baseline mode (`censor_off.sh`)
- censorship simulation mode (`censor_on.sh`)

The censorship layer simulates:
- packet drop
- TCP reset
- delay/loss/reordering

These produce measurable censorship effects such as timeout, reset, degraded throughput, and partial handshakes.
