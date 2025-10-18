"""
Run Demo
--------
Runs parsers + classifier to showcase CIA classification results.
"""

from parser.snort import parse_snort_file
from parser.wireshark import parse_wireshark_file

def run_demo():
    print("=== PyLogGuard v2 Demo ===")

    print("\n[1] Parsing Snort logs...")
    snort_results = parse_snort_file("demo/sample_logs/snort_sample.log")
    for r in snort_results:
        print(f"→ {r['event_type']} [{r['cia_category']}] from {r['src']} -> {r['dst']}")

    print("\n[2] Parsing Wireshark logs...")
    ws_results = parse_wireshark_file("demo/sample_logs/wireshark_sample.txt")
    for r in ws_results:
        print(f"→ {r['event_type']} [{r['cia_category']}]")

if __name__ == "__main__":
    run_demo()