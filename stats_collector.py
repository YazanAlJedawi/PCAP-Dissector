
import pyshark
from collections import defaultdict, Counter
import sys

def activate_stats_collection(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "ttl": [], "protocols": Counter()})
    protocol_count = Counter()
    tcp_flags = Counter()

    print("\n[+] Starting network statistics and fingerprinting...\n")

    for pkt in cap:
        try:
            if hasattr(pkt, 'ip'):
                src = pkt.ip.src
                ip_stats[src]["packets"] += 1
                ip_stats[src]["bytes"] += int(pkt.length)
                if hasattr(pkt.ip, 'ttl'):
                    ip_stats[src]["ttl"].append(int(pkt.ip.ttl))

            if hasattr(pkt, 'highest_layer'):
                protocol_count[pkt.highest_layer] += 1

            if hasattr(pkt, 'tcp'):
                flags = pkt.tcp.flags_str.lower()
                for f in flags:
                    if f in ['s', 'f', 'r']:  
                        tcp_flags[f.upper()] += 1

        except Exception:
            continue

    cap.close()

    print("[Protocol Usage]")
    for proto, count in protocol_count.most_common():
        print(f"  {proto:<10}: {count} packets")

    print("\n[Top Talkers by Packets Sent]")
    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]['packets'], reverse=True)
    for ip, stats in sorted_ips[:10]:
        avg_ttl = sum(stats['ttl']) / len(stats['ttl']) if stats['ttl'] else 0
        os_guess = "Linux" if avg_ttl >= 64 else ("Windows" if avg_ttl >= 32 else "Unknown")
        print(f"  {ip:<15} Packets: {stats['packets']:<5} Bytes: {stats['bytes']:<7} Avg TTL: {avg_ttl:.1f} ({os_guess})")

    print("\n[TCP Flag Summary]")
    for flag, count in tcp_flags.items():
        print(f"  {flag}: {count} packets")

