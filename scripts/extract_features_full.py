#!/usr/bin/env python3
import json
import math
import hashlib
from pathlib import Path
from collections import defaultdict
from datetime import datetime, UTC

import pandas as pd
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Raw

PCAP_DIR = Path("/opt/dpi-lab/pcap")
EVE_PATH = Path("/var/log/suricata/eve.json")
OUT_CSV = Path("/opt/dpi-lab/output/dpi_lab_dataset_full.csv")
PROFILE_MAP = Path("/opt/dpi-lab/cache/ip_profile_map.json")

SERVICE_PORTS = {2083, 2097, 443}
SERVER_BUILD = "xray-core 1.8.24"

PORT_META = {
    2083: {
        "protocol_label": "vless-tcp-no-tls",
        "flow": "not_applicable",
        "sni_bucket": "not_applicable",
        "cdn_vendor": "not_applicable",
        "dest_bucket": "not_applicable",
    },
    2097: {
        "protocol_label": "vless-tcp-tls",
        "flow": "not_applicable",
        "sni_bucket": "ourbluesky_front",
        "cdn_vendor": "Origin",
        "dest_bucket": "ourbluesky_front",
    },
    443: {
        "protocol_label": "vless-reality",
        "flow": "xtls-rprx-vision",
        "sni_bucket": "apple_front",
        "cdn_vendor": "Apple",
        "dest_bucket": "apple_front",
    },
}

def sha12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]

def tod_bucket(ts: datetime) -> str:
    h = ts.hour
    if 5 <= h < 12:
        return "morning"
    if 12 <= h < 17:
        return "noon"
    if 17 <= h < 22:
        return "evening"
    return "midnight"

def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = defaultdict(int)
    for x in b:
        counts[x] += 1
    n = len(b)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 4)

def ascii_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for x in b if 32 <= x <= 126)
    return round(ok / len(b), 4)

def norm_key(src_ip, src_port, dst_ip, dst_port, proto):
    if dst_port in SERVICE_PORTS:
        return (src_ip, src_port, dst_port, proto)
    if src_port in SERVICE_PORTS:
        return (dst_ip, dst_port, src_port, proto)
    return None

def packet_dir(sport, dport):
    if dport in SERVICE_PORTS:
        return "up"
    if sport in SERVICE_PORTS:
        return "down"
    return None

def bucket_dns_name(q: str):
    if not q:
        return "not_observed"
    q = q.lower()
    if "apple" in q:
        return "apple_front"
    if "ourbluesky" in q:
        return "ourbluesky_front"
    return "other_dns"

if PROFILE_MAP.exists():
    profiles = json.loads(PROFILE_MAP.read_text())
else:
    profiles = {}

def ip_profile(ip):
    return profiles.get(ip, {
        "src_asn": "UNKNOWN",
        "src_cc": "UNKNOWN",
        "src_isp": "UNKNOWN",
        "prob_cgnat": False
    })

eve_meta = defaultdict(lambda: {
    "alpn_negotiated": "not_observed",
    "tls_version": "not_observed",
    "cipher_chosen": "not_observed",
    "ja3": "not_observed",
    "ja4": "not_observed",
    "utls_inferred": "not_observed",
    "alpn_offered_set_hash": "not_observed",
    "tls_alert_desc": "not_observed",
    "signature_based_match": 0,
})

dns_by_src = {}

if EVE_PATH.exists():
    with EVE_PATH.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            et = rec.get("event_type")
            src_ip = rec.get("src_ip")
            dst_ip = rec.get("dest_ip")
            src_port = rec.get("src_port", 0)
            dst_port = rec.get("dest_port", 0)
            proto = rec.get("proto", "TCP")
            key = norm_key(src_ip, src_port, dst_ip, dst_port, proto)

            if et == "alert" and key:
                eve_meta[key]["signature_based_match"] = 1

            if et == "tls" and key:
                tls = rec.get("tls", {})
                ja3 = tls.get("ja3")
                if isinstance(ja3, dict):
                    ja3 = ja3.get("hash", "not_observed")

                ja4 = tls.get("ja4", "not_observed")
                alpn = tls.get("alpn", "not_observed")
                version = tls.get("version", "not_observed")
                cipher = tls.get("cipher", "not_observed")

                eve_meta[key]["alpn_negotiated"] = alpn if alpn else "not_observed"
                eve_meta[key]["tls_version"] = version if version else "not_observed"
                eve_meta[key]["cipher_chosen"] = cipher if cipher else "not_observed"
                eve_meta[key]["ja3"] = ja3 if ja3 else "not_observed"
                eve_meta[key]["ja4"] = ja4 if ja4 else "not_observed"
                eve_meta[key]["utls_inferred"] = "chrome" if ja3 not in ("not_observed", "", None) else "not_observed"
                eve_meta[key]["alpn_offered_set_hash"] = sha12(alpn) if alpn not in ("not_observed", "", None) else "not_observed"

            if et == "dns":
                dns = rec.get("dns", {})
                q = dns.get("rrname", dns.get("query", ""))
                dns_by_src[src_ip] = {
                    "dns_qname_bucket": bucket_dns_name(q),
                    "dns_rcode": dns.get("rcode", "not_observed"),
                    "dns_ttl_s": dns.get("ttl", "not_observed"),
                }

sessions = {}

for pcap in sorted(PCAP_DIR.glob("*.pcap")):
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            ts = float(pkt.time)

            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                continue

            l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
            if l4 is None:
                continue

            src_ip = ip.src
            dst_ip = ip.dst
            src_port = int(getattr(l4, "sport", 0))
            dst_port = int(getattr(l4, "dport", 0))
            proto = "TCP" if pkt.haslayer(TCP) else "UDP"

            key = norm_key(src_ip, src_port, dst_ip, dst_port, proto)
            if not key:
                continue

            direction = packet_dir(src_port, dst_port)
            if direction is None:
                continue

            if key not in sessions:
                sessions[key] = {
                    "src_ip": src_ip,
                    "first_ts": ts,
                    "last_ts": ts,
                    "sizes": [],
                    "iats": [],
                    "prev_ts": None,
                    "bytes_up": 0,
                    "bytes_down": 0,
                    "payload_sample": bytearray(),
                    "payload_bytes": 0,
                    "header_bytes": 0,
                    "first_server_payload_ts": None,
                    "tcp_rst_seen": False,
                    "syn_count": 0,
                    "retransmissions": 0,
                    "seq_seen": set(),
                    "ttl_sum": 0.0,
                    "ttl_n": 0,
                    "fragmentation_seen": False,
                }

            s = sessions[key]
            s["last_ts"] = ts

            plen = len(bytes(pkt))
            s["sizes"].append(plen)

            if s["prev_ts"] is not None:
                s["iats"].append((ts - s["prev_ts"]) * 1000.0)
            s["prev_ts"] = ts

            if pkt.haslayer(IP):
                ttl = pkt[IP].ttl
                s["ttl_sum"] += ttl
                s["ttl_n"] += 1
                if pkt[IP].flags.MF or pkt[IP].frag > 0:
                    s["fragmentation_seen"] = True

            payload_len = 0
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                payload_len = len(payload)
                if len(s["payload_sample"]) < 512:
                    need = 512 - len(s["payload_sample"])
                    s["payload_sample"].extend(payload[:need])

            if pkt.haslayer(TCP):
                ip_h = pkt[IP].ihl * 4 if pkt.haslayer(IP) else 40
                tcp_h = pkt[TCP].dataofs * 4
                hdr = ip_h + tcp_h
                flags = pkt[TCP].flags

                if "R" in str(flags):
                    s["tcp_rst_seen"] = True

                if direction == "up" and pkt[TCP].flags & 0x02 and not (pkt[TCP].flags & 0x10):
                    s["syn_count"] += 1

                seq_sig = (direction, int(pkt[TCP].seq), payload_len)
                if seq_sig in s["seq_seen"] and payload_len > 0:
                    s["retransmissions"] += 1
                else:
                    s["seq_seen"].add(seq_sig)
            else:
                ip_h = pkt[IP].ihl * 4 if pkt.haslayer(IP) else 40
                hdr = ip_h + 8

            s["header_bytes"] += hdr
            s["payload_bytes"] += payload_len

            if direction == "up":
                s["bytes_up"] += plen
            else:
                s["bytes_down"] += plen
                if payload_len > 0 and s["first_server_payload_ts"] is None:
                    s["first_server_payload_ts"] = ts

rows = []

for key, s in sessions.items():
    src_ip, src_port, service_port, proto = key
    ts0 = datetime.fromtimestamp(s["first_ts"], UTC)
    prof = ip_profile(src_ip)
    meta = PORT_META[service_port]
    em = eve_meta[key]

    sizes = s["sizes"]
    iats = s["iats"]

    pkt_mean = round(sum(sizes) / len(sizes), 3) if sizes else 0.0
    pkt_std = round(pd.Series(sizes).std(ddof=0), 3) if len(sizes) > 1 else 0.0
    pkt_p95 = round(pd.Series(sizes).quantile(0.95), 3) if sizes else 0.0
    iat_mean = round(sum(iats) / len(iats), 3) if iats else 0.0
    iat_std = round(pd.Series(iats).std(ddof=0), 3) if len(iats) > 1 else 0.0

    dur_s = round(s["last_ts"] - s["first_ts"], 3)
    flow_ms = round(dur_s * 1000.0, 3)

    first_server_payload_ms = None
    if s["first_server_payload_ts"] is not None:
        first_server_payload_ms = round((s["first_server_payload_ts"] - s["first_ts"]) * 1000.0, 3)

    tt_handshake_ms = first_server_payload_ms if first_server_payload_ms is not None else None
    ttfb_ms = first_server_payload_ms if first_server_payload_ms is not None else None
    throughput_kbps = round((s["bytes_down"] * 8 / 1000.0) / max(dur_s, 0.001), 3) if dur_s > 0 else 0.0

    if service_port == 443:
        label_success = int(
            s["first_server_payload_ts"] is not None and
            tt_handshake_ms is not None and tt_handshake_ms <= 5000 and
            s["bytes_down"] >= 32768 and
            not s["tcp_rst_seen"]
        )
    elif service_port == 2097:
        label_success = int(
            em["tls_version"] != "not_observed" and
            tt_handshake_ms is not None and tt_handshake_ms <= 5000 and
            s["bytes_down"] >= 32768 and
            not s["tcp_rst_seen"]
        )
    else:
        label_success = int(
            dur_s > 1.0 and
            s["bytes_down"] >= 16384 and
            not s["tcp_rst_seen"]
        )

    syn_retries = max(0, s["syn_count"] - 1)

    if label_success:
        protocol_state_tracking = "complete" if dur_s > 2 else "partial"
        censor_action = "allow"
    else:
        protocol_state_tracking = "reset" if s["tcp_rst_seen"] else ("timeout" if syn_retries > 0 else "partial")
        censor_action = "tcp_reset" if s["tcp_rst_seen"] else ("drop" if syn_retries > 0 else "throttle")

    if dur_s > 60 and s["bytes_down"] > 500000:
        connection_pattern_bucket = "bulk_transfer"
    elif dur_s > 5:
        connection_pattern_bucket = "interactive"
    else:
        connection_pattern_bucket = "short_burst"

    payload = bytes(s["payload_sample"])

    bins = [
        round(sum(1 for b in payload if 0 <= b <= 31) / max(len(payload), 1), 4),
        round(sum(1 for b in payload if 32 <= b <= 63) / max(len(payload), 1), 4),
        round(sum(1 for b in payload if 64 <= b <= 95) / max(len(payload), 1), 4),
        round(sum(1 for b in payload if 96 <= b <= 127) / max(len(payload), 1), 4),
        round(sum(1 for b in payload if 128 <= b <= 159) / max(len(payload), 1), 4),
        round(sum(1 for b in payload if 160 <= b <= 191) / max(len(payload), 1), 4),
        round(sum(1 for b in payload if 192 <= b <= 223) / max(len(payload), 1), 4),
        round(sum(1 for b in payload if 224 <= b <= 255) / max(len(payload), 1), 4),
    ]

    dns = dns_by_src.get(src_ip, {
        "dns_qname_bucket": "not_observed",
        "dns_rcode": "not_observed",
        "dns_ttl_s": "not_observed"
    })

    rows.append({
        "session_id": sha12(f"{key}-{s['first_ts']}-{s['last_ts']}"),
        "timestamp_utc": ts0.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tod_bucket": tod_bucket(ts0),
        "dow": ts0.weekday(),
        "src_asn": prof["src_asn"],
        "src_cc": prof["src_cc"],
        "src_isp": prof["src_isp"],
        "ip_version": "ipv4" if ":" not in src_ip else "ipv6",
        "prob_cgnat": prof["prob_cgnat"],
        "port": service_port,
        "protocol_label": meta["protocol_label"],
        "flow": meta["flow"],
        "allowInsecure": False,
        "server_build": SERVER_BUILD,
        "alpn_negotiated": em["alpn_negotiated"] if service_port == 2097 else "not_applicable",
        "tls_version": em["tls_version"] if service_port == 2097 else "not_applicable",
        "cipher_chosen": em["cipher_chosen"] if service_port == 2097 else "not_applicable",
        "ja3": em["ja3"] if service_port == 2097 else "not_applicable",
        "ja4": em["ja4"] if service_port == 2097 else "not_applicable",
        "utls_inferred": em["utls_inferred"] if service_port == 2097 else "not_applicable",
        "alpn_offered_set_hash": em["alpn_offered_set_hash"] if service_port == 2097 else "not_applicable",
        "sni_bucket": meta["sni_bucket"],
        "cdn_vendor": meta["cdn_vendor"],
        "dest_bucket": meta["dest_bucket"],
        "tcp_rst_seen": s["tcp_rst_seen"],
        "syn_retries": syn_retries,
        "tls_alert_desc": em["tls_alert_desc"] if service_port == 2097 else "not_applicable",
        "retransmissions": s["retransmissions"],
        "tt_handshake_ms": tt_handshake_ms,
        "ttfb_ms": ttfb_ms,
        "throughput_kbps": throughput_kbps,
        "session_duration_s": dur_s,
        "bytes_up": s["bytes_up"],
        "bytes_down": s["bytes_down"],
        "signature_based_match": em["signature_based_match"],
        "protocol_state_tracking": protocol_state_tracking,
        "heuristic_behavior_score": round(min(1.0, (syn_retries * 0.15) + (0.35 if s["tcp_rst_seen"] else 0) + (0.10 if s["retransmissions"] > 0 else 0)), 4),
        "packet_size_mean": pkt_mean,
        "packet_size_std": pkt_std,
        "packet_size_p95": pkt_p95,
        "interarrival_mean_ms": iat_mean,
        "interarrival_std_ms": iat_std,
        "flow_duration_ms": flow_ms,
        "byte_entropy": entropy(payload),
        "ascii_ratio_initial32": ascii_ratio(payload[:32]),
        "byte_freq_bin_00_31": bins[0],
        "byte_freq_bin_32_63": bins[1],
        "byte_freq_bin_64_95": bins[2],
        "byte_freq_bin_96_127": bins[3],
        "byte_freq_bin_128_159": bins[4],
        "byte_freq_bin_160_191": bins[5],
        "byte_freq_bin_192_223": bins[6],
        "byte_freq_bin_224_255": bins[7],
        "connection_pattern_bucket": connection_pattern_bucket,
        "payload_to_header_ratio": round(s["payload_bytes"] / max(s["header_bytes"], 1), 4),
        "dns_qname_bucket": dns["dns_qname_bucket"],
        "dns_rcode": dns["dns_rcode"],
        "dns_ttl_s": dns["dns_ttl_s"],
        "ttl_mean": round(s["ttl_sum"] / s["ttl_n"], 3) if s["ttl_n"] else None,
        "fragmentation_seen": s["fragmentation_seen"],
        "label_success": label_success,
    })

df = pd.DataFrame(rows).sort_values("timestamp_utc").reset_index(drop=True)

bucket_seen = {}
sni_seen = {}
port_seen = {}
ja3_seen = {}
ema_seen = {}

hist_bucket = []
hist_sni = []
hist_port = []
hist_ja3 = []
ema_tp = []

for _, r in df.iterrows():
    bkey = (r["sni_bucket"], r["port"], r["ja3"])
    n, ok = bucket_seen.get(bkey, (0, 0))
    hist_bucket.append(round(ok / n, 4) if n else None)
    bucket_seen[bkey] = (n + 1, ok + int(r["label_success"]))

    n, ok = sni_seen.get(r["sni_bucket"], (0, 0))
    hist_sni.append(round(ok / n, 4) if n else None)
    sni_seen[r["sni_bucket"]] = (n + 1, ok + int(r["label_success"]))

    n, ok = port_seen.get(r["port"], (0, 0))
    hist_port.append(round(ok / n, 4) if n else None)
    port_seen[r["port"]] = (n + 1, ok + int(r["label_success"]))

    n, ok = ja3_seen.get(r["ja3"], (0, 0))
    hist_ja3.append(round(ok / n, 4) if n else None)
    ja3_seen[r["ja3"]] = (n + 1, ok + int(r["label_success"]))

    ekey = r["port"]
    prev = ema_seen.get(ekey, float(r["throughput_kbps"]))
    cur = round(0.2 * float(r["throughput_kbps"]) + 0.8 * float(prev), 3)
    ema_seen[ekey] = cur
    ema_tp.append(cur)

df["hist_success_rate_by_bucket"] = hist_bucket
df["hist_success_rate_by_sni"] = hist_sni
df["hist_success_rate_by_port"] = hist_port
df["hist_success_rate_by_ja3"] = hist_ja3

df["ratio_handshake_totaldelay"] = df.apply(
    lambda x: round(float(x["tt_handshake_ms"]) / float(x["ttfb_ms"]), 4)
    if pd.notna(x["tt_handshake_ms"]) and pd.notna(x["ttfb_ms"]) and float(x["ttfb_ms"]) > 0
    else None,
    axis=1
)

df["ema_throughput_kbps_24h"] = ema_tp
df["onehot_morning"] = (df["tod_bucket"] == "morning").astype(int)
df["onehot_noon"] = (df["tod_bucket"] == "noon").astype(int)
df["onehot_evening"] = (df["tod_bucket"] == "evening").astype(int)
df["onehot_midnight"] = (df["tod_bucket"] == "midnight").astype(int)

OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(OUT_CSV, index=False)
print(f"Wrote {OUT_CSV} with {len(df)} rows and {len(df.columns)} columns")
