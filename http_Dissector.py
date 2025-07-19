import pyshark
import csv
import os
import sys


SUSPICIOUS_AGENTS = ["sqlmap", "curl", "nmap", "python-requests", "wget"]
INTERESTING_PATHS = ["/admin", "/login", "/upload"]
MALWARE_MIME_TYPES = ["application/zip", "application/x-msdownload", "application/pdf", "application/x-executable"]

def activate_http_analysis(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="http")

    rows = []  

    print("\n[+] Starting HTTP traffic analysis...\n")
    for pkt in cap:
        try:
            if 'HTTP' in pkt:
                http = pkt.http
                row = {
                    "src_ip": pkt.ip.src if hasattr(pkt, 'ip') else "",
                    "dst_ip": pkt.ip.dst if hasattr(pkt, 'ip') else "",
                    "type": "", "method": "", "url": "", "agent": "",
                    "status": "", "content_type": "", "content_length": "", "flags": []
                }

                if hasattr(http, 'request_method'):
                    method = http.request_method
                    host = http.host if hasattr(http, 'host') else ""
                    uri = http.request_uri if hasattr(http, 'request_uri') else ""
                    agent = http.user_agent if hasattr(http, 'user_agent') else ""

                    url = f"http://{host}{uri}"
                    print(f"[REQUEST] {method} {url}")
                    print(f"          From {row['src_ip']} → {row['dst_ip']}")
                    print(f"          Agent: {agent}")

                    row.update({"type": "request", "method": method, "url": url, "agent": agent})

                    if any(x in uri.lower() for x in INTERESTING_PATHS):
                        print("          [!] Interesting path detected!")
                        row["flags"].append("interesting-path")
                    if any(a in agent.lower() for a in SUSPICIOUS_AGENTS):
                        print("          [!] Suspicious user-agent!")
                        row["flags"].append("suspicious-agent")


                elif hasattr(http, 'response_code'):
                    status = http.response_code
                    ctype = http.content_type if hasattr(http, 'content_type') else "?"
                    clen = http.content_length if hasattr(http, 'content_length') else "?"
                    print(f"[RESPONSE] From {row['src_ip']} → {row['dst_ip']} | Status: {status} | Type: {ctype} | Size: {clen} bytes")

                    row.update({"type": "response", "status": status, "content_type": ctype, "content_length": clen})

                    if ctype in MALWARE_MIME_TYPES:
                        print("          [!] Potential file download detected!")
                        row["flags"].append("file-download")

                if row["type"]:
                    row["flags"] = ", ".join(row["flags"])
                    rows.append(row)

        except Exception as e:
            print(f"[!] Error parsing packet: {e}")

    cap.close()

    
    output_file = "http_report.csv"
    print(f"\n[+] Writing organized HTTP analysis report to {output_file}")
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["src_ip", "dst_ip", "type", "method", "url", "agent", "status", "content_type", "content_length", "flags"])
        writer.writeheader()
        writer.writerows(rows)
