import ipaddress
import json
import os
import sys
from typing import Optional

from config import Config
from shodan_client import ShodanClient
from enrichment import parse_host, diff_results
from output import (
    print_header, print_host, print_summary,
    print_diff, print_top_vulns, save_markdown, save_json
)


def resolve_targets(target: str) -> list:
    """Expand CIDR or read IPs from file."""
    ips = []

    if os.path.isfile(target):
        with open(target) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        ips.extend(str(ip) for ip in net.hosts())
                    except ValueError:
                        ips.append(line)
    else:
        try:
            net = ipaddress.ip_network(target, strict=False)
            ips = [str(ip) for ip in net.hosts()]
        except ValueError:
            # Single IP
            ips = [target]

    return ips


def run_scan(
    target: str,
    output_md: Optional[str],
    output_json: Optional[str],
    min_cvss: float,
    port_filter: Optional[list],
    flag_defaults: bool,
    diff_file: Optional[str],
    summary_only: bool,
    top_vulns: int,
    config: Config,
):
    ips = resolve_targets(target)

    if not ips:
        print("[!] No valid IPs resolved from target.")
        sys.exit(1)

    print_header(target, len(ips))

    client = ShodanClient(config.api_key)

    hosts = []
    not_found = []

    for ip in ips:
        raw = client.host(ip)
        if raw is None:
            not_found.append(ip)
            continue

        host = parse_host(raw, min_cvss=min_cvss, port_filter=port_filter, flag_defaults=flag_defaults)

        # Skip hosts with no matching ports if filter is active
        if port_filter and not host["ports"]:
            not_found.append(ip)
            continue

        hosts.append(host)
        print_host(host, summary_only=summary_only)

    # Sort: most critical first
    hosts.sort(key=lambda h: h["max_cvss"], reverse=True)

    print_summary(hosts, not_found)

    if top_vulns > 0:
        print_top_vulns(hosts, top_vulns)

    # Diff
    if diff_file:
        if not os.path.isfile(diff_file):
            print(f"[!] Diff file not found: {diff_file}")
        else:
            with open(diff_file) as f:
                previous = json.load(f)
            delta = diff_results(hosts, previous)
            print_diff(delta)

    if output_md:
        save_markdown(hosts, target, output_md)

    if output_json:
        save_json(hosts, output_json)