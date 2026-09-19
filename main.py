"""Command line entry point."""

import csv
import os
import sys
import time

from scanner.dkim import evaluate_dkim
from scanner.dmarc import evaluate_dmarc
from scanner.report import build_report
from scanner.spf import evaluate_spf


def scan(domain):
    """Run all checks on one domain and return a flat result row."""
    spf = evaluate_spf(domain)
    dmarc = evaluate_dmarc(domain)
    dkim = evaluate_dkim(domain)

    return {
        "domain": domain,
        "spf_status": spf["status"],
        "spf_policy": spf["policy"] or "",
        "spf_record": spf["record"],
        "dmarc_status": dmarc["status"],
        "dmarc_policy": dmarc["policy"] or "",
        "dmarc_subdomain": dmarc["subdomain_policy"] or "",
        "dmarc_pct": dmarc["pct"],
        "dmarc_reporting": "yes" if dmarc["reporting"] else "no",
        "dmarc_rua_domain": dmarc["rua_domain"],
        "dmarc_record": dmarc["record"],
        "dkim_status": dkim["status"],
        "dkim_selectors": ", ".join(s for s, _ in dkim["selectors"]),
        "spf_detail": spf["detail"],
        "dmarc_detail": dmarc["detail"],
        "dkim_detail": dkim["detail"],
    }


def print_single(row):
    print(f"\nDomain: {row['domain']}")

    print(f"\nSPF:    {row['spf_status'].upper()}")
    print(f"        {row['spf_detail']}")

    print(f"\nDMARC:  {row['dmarc_status'].upper()}")
    print(f"        {row['dmarc_detail']}")

    print(f"\nDKIM:   {row['dkim_status'].upper()}")
    print(f"        {row['dkim_detail']}")


def run_batch(path, want_report=False):
    with open(path, encoding="utf-8") as f:
        # Skip blank lines and anything starting with #
        domains = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    print(f"Scanning {len(domains)} domains\n")
    print(f"{'DOMAIN':<35} {'SPF':<10} {'DMARC':<10} {'DKIM':<10} {'REPORTS':<8}")
    print("-" * 78)

    rows = []
    for domain in domains:
        row = scan(domain)
        rows.append(row)

        print(
            f"{row['domain']:<35} "
            f"{row['spf_status']:<10} "
            f"{row['dmarc_status']:<10} "
            f"{row['dkim_status']:<10} "
            f"{row['dmarc_reporting']:<8}"
        )

        if want_report:
            os.makedirs("reports", exist_ok=True)
            build_report(row, f"reports/{domain}.pdf")

        # Be polite to DNS servers.
        time.sleep(0.3)

    os.makedirs("results", exist_ok=True)
    out = "results/scan.csv"

    # Raw records are kept out of the CSV to keep it readable.
    fields = [k for k in rows[0] if not k.endswith("_record")]

    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved to {out}")

    if want_report:
        print("Reports in reports/")


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain|file.txt> [--report]")
        return

    target = sys.argv[1]
    want_report = "--report" in sys.argv

    if target.endswith(".txt"):
        run_batch(target, want_report)
    else:
        row = scan(target)
        print_single(row)

        if want_report:
            os.makedirs("reports", exist_ok=True)
            path = f"reports/{target}.pdf"
            build_report(row, path)
            print(f"\nReport: {path}")


if __name__ == "__main__":
    main()