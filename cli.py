import argparse
import sys
from scanner import run_scan
from config import load_config

def main():
    parser = argparse.ArgumentParser(
        prog="rshade",
        description="Passive recon via Shodan for pentest initial sweep",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target CIDR range or file path containing IPs (one per line)\nExamples: 192.168.1.0/24 or targets.txt"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save report as markdown file (e.g. report.md)"
    )
    parser.add_argument(
        "-j", "--json",
        dest="json_output",
        help="Save raw results as JSON (e.g. output.json)"
    )
    parser.add_argument(
        "--min-cvss",
        type=float,
        default=0.0,
        metavar="SCORE",
        help="Only show vulnerabilities with CVSS >= this value (e.g. 7.0)"
    )
    parser.add_argument(
        "--ports",
        help="Filter output to specific ports, comma-separated (e.g. 22,80,443)"
    )
    parser.add_argument(
        "--flag-defaults",
        action="store_true",
        help="Highlight hosts with default credential banners"
    )
    parser.add_argument(
        "--diff",
        metavar="PREV_JSON",
        help="Compare current scan against a previous JSON output"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary totals only, no per-host detail"
    )
    parser.add_argument(
        "--api-key",
        help="Shodan API key (overrides config file / env var)"
    )

    args = parser.parse_args()

    port_filter = None
    if args.ports:
        try:
            port_filter = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print("[!] Invalid --ports value. Use comma-separated integers.")
            sys.exit(1)

    config = load_config(api_key_override=args.api_key)

    run_scan(
        target=args.target,
        output_md=args.output,
        output_json=args.json_output,
        min_cvss=args.min_cvss,
        port_filter=port_filter,
        flag_defaults=args.flag_defaults,
        diff_file=args.diff,
        summary_only=args.summary,
        config=config,
    )

if __name__ == "__main__":
    main()