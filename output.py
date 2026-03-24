import json
from datetime import datetime
from enrichment import severity_label

# ANSI colors
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
G  = "\033[92m"   # green
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DIM= "\033[2m"
BOLD="\033[1m"
RST= "\033[0m"

SEP = f"{DIM}{'─' * 72}{RST}"


def cvss_color(cvss: float) -> str:
    if cvss >= 9.0:
        return R
    elif cvss >= 7.0:
        return Y
    elif cvss >= 4.0:
        return "\033[33m"
    return G


def print_header(target: str, total_ips: int):
    print()
    print(f"{BOLD}{C}  rshade{RST} : passive recon via Shodan")
    print(f"  Target : {W}{target}{RST}")
    print(f"  Hosts  : {W}{total_ips}{RST}")
    print(f"  Time   : {DIM}{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}{RST}")
    print(f"\n{SEP}")


def print_host(host: dict, summary_only: bool = False):
    ip       = host["ip"]
    ports    = host["ports"]
    vulns    = host["vulns"]
    flags    = host["flags"]
    max_cvss = host["max_cvss"]
    org      = host["org"]
    country  = host["country"]

    vuln_str = ""
    if vulns:
        cc = cvss_color(max_cvss)
        vuln_str = f"  {cc}▲ {len(vulns)} CVE{'s' if len(vulns) > 1 else ''} (max {max_cvss}){RST}"
    else:
        vuln_str = f"  {DIM}▲ 0 CVEs{RST}"

    flag_str = ""
    if flags:
        flag_str = f"  {Y}⚑ {flags[0]}{RST}"
        if len(flags) > 1:
            flag_str += f" {DIM}+{len(flags)-1} more{RST}"

    port_str = f"{DIM}■{RST} {len(ports)} port{'s' if len(ports) != 1 else ''}"

    print(f"  {G}[+]{RST} {BOLD}{ip:<18}{RST} {port_str}{vuln_str}{flag_str}")

    if summary_only:
        return

    # Per-host detail
    print(f"      {DIM}org:{RST} {org}  {DIM}country:{RST} {country}")

    if host.get("os"):
        print(f"      {DIM}os:{RST} {host['os']}")

    if host.get("hostnames"):
        print(f"      {DIM}hostnames:{RST} {', '.join(host['hostnames'][:3])}")

    if ports:
        port_labels = []
        for p in ports:
            from enrichment import INTERESTING_PORTS, HIGH_RISK_PORTS
            label = INTERESTING_PORTS.get(p, "")
            if p in HIGH_RISK_PORTS:
                port_labels.append(f"{Y}{p}{RST}")
            elif label:
                port_labels.append(f"{C}{p}{RST}")
            else:
                port_labels.append(str(p))
        print(f"      {DIM}ports:{RST} {', '.join(port_labels)}")

    if vulns:
        print(f"      {DIM}vulns:{RST}")
        for v in vulns[:5]:  # cap at 5 in terminal
            cc = cvss_color(v["cvss"])
            label = severity_label(v["cvss"])
            summary = v["summary"][:80] + "..." if len(v["summary"]) > 80 else v["summary"]
            print(f"        {cc}{v['id']:<18} [{label:<8}] CVSS {v['cvss']}{RST}")
            if summary:
                print(f"        {DIM}{summary}{RST}")
        if len(vulns) > 5:
            print(f"        {DIM}... and {len(vulns) - 5} more (see JSON/markdown output){RST}")

    if flags:
        for f in flags:
            print(f"      {Y}⚑  {f}{RST}")

    print()


def print_summary(hosts: list, not_found: list):
    total        = len(hosts) + len(not_found)
    found        = len(hosts)
    with_vulns   = sum(1 for h in hosts if h["vulns"])
    flagged      = sum(1 for h in hosts if h["flags"])
    critical     = sum(1 for h in hosts if h["max_cvss"] >= 9.0)
    high         = sum(1 for h in hosts if 7.0 <= h["max_cvss"] < 9.0)

    print(SEP)
    print(f"\n  {BOLD}Summary{RST}")
    print(f"  {'Total IPs':<20} {total}")
    print(f"  {'Indexed by Shodan':<20} {G}{found}{RST}")
    print(f"  {'Not found':<20} {DIM}{len(not_found)}{RST}")
    print(f"  {'With CVEs':<20} {Y}{with_vulns}{RST}")
    print(f"  {'Critical (≥9.0)':<20} {R}{critical}{RST}")
    print(f"  {'High (7.0–8.9)':<20} {Y}{high}{RST}")
    print(f"  {'Flagged':<20} {Y}{flagged}{RST}")
    print()


def print_diff(diff: dict):
    print(f"\n{BOLD}  Diff vs previous scan{RST}")
    print(SEP)

    if diff["new_hosts"]:
        print(f"  {G}New hosts:{RST} {', '.join(diff['new_hosts'])}")
    if diff["gone_hosts"]:
        print(f"  {DIM}Gone hosts:{RST} {', '.join(diff['gone_hosts'])}")

    for ch in diff["changed"]:
        print(f"\n  {C}{ch['ip']}{RST}")
        if ch["new_ports"]:
            print(f"    {G}+ ports:{RST} {', '.join(map(str, ch['new_ports']))}")
        if ch["closed_ports"]:
            print(f"    {R}- ports:{RST} {', '.join(map(str, ch['closed_ports']))}")
        if ch["new_vulns"]:
            print(f"    {Y}+ CVEs:{RST}  {', '.join(ch['new_vulns'])}")

    if not diff["new_hosts"] and not diff["gone_hosts"] and not diff["changed"]:
        print(f"  {DIM}No changes detected.{RST}")
    print()


def save_markdown(hosts: list, target: str, output_path: str):
    lines = []
    lines.append(f"# rshade: {target}")
    lines.append(f"*Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*\n")
    lines.append(f"**Hosts found:** {len(hosts)}\n")

    for h in hosts:
        lines.append(f"---\n## {h['ip']}")
        lines.append(f"- **Org:** {h['org']}")
        lines.append(f"- **Country:** {h['country']}")
        if h.get("os"):
            lines.append(f"- **OS:** {h['os']}")
        if h.get("hostnames"):
            lines.append(f"- **Hostnames:** {', '.join(h['hostnames'])}")
        lines.append(f"- **Ports:** {', '.join(map(str, h['ports']))}")
        lines.append(f"- **Last Shodan scan:** {h['last_update']}")

        if h["vulns"]:
            lines.append(f"\n### Vulnerabilities")
            lines.append("| CVE | CVSS | Severity | Summary |")
            lines.append("|-----|------|----------|---------|")
            for v in h["vulns"]:
                summary = v["summary"][:100].replace("|", "\\|") if v["summary"] else ""
                lines.append(f"| {v['id']} | {v['cvss']} | {severity_label(v['cvss'])} | {summary} |")

        if h["flags"]:
            lines.append(f"\n### Flags")
            for f in h["flags"]:
                lines.append(f"- ⚑ {f}")

        lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    print(f"  {G}[✓]{RST} Markdown report saved → {output_path}")


def save_json(hosts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump(hosts, f, indent=2)
    print(f"  {G}[✓]{RST} JSON saved → {output_path}")


def print_top_vulns(hosts: list, n: int):
    from collections import defaultdict
 
    # Aggregate CVEs across all hosts
    cve_map = defaultdict(lambda: {"count": 0, "cvss": 0.0, "summary": ""})
 
    for host in hosts:
        for v in host["vulns"]:
            cve_id = v["id"]
            cve_map[cve_id]["count"] += 1
            cve_map[cve_id]["cvss"] = max(cve_map[cve_id]["cvss"], v["cvss"])
            if not cve_map[cve_id]["summary"]:
                cve_map[cve_id]["summary"] = v["summary"]
 
    if not cve_map:
        print(f"\n  {DIM}No CVEs found across scanned hosts.{RST}")
        return
 
    # Sort by count desc, then CVSS desc
    ranked = sorted(cve_map.items(), key=lambda x: (x[1]["count"], x[1]["cvss"]), reverse=True)[:n]
 
    print(f"\n{BOLD}  Top {n} Vulnerabilities{RST}")
    print(SEP)
    print(f"  {'CVE':<20} {'Hosts':>6}  {'CVSS':>6}  {'Severity':<10} Summary")
    print(f"  {DIM}{'─'*20} {'─'*6}  {'─'*6}  {'─'*10} {'─'*40}{RST}")
 
    for cve_id, data in ranked:
        cc = cvss_color(data["cvss"])
        label = severity_label(data["cvss"])
        summary = data["summary"][:50] + "..." if len(data["summary"]) > 50 else data["summary"]
        hosts_str = f"{data['count']} host{'s' if data['count'] != 1 else ''}"
        print(f"  {cc}{cve_id:<20}{RST} {Y}{hosts_str:>6}{RST}  {cc}{data['cvss']:>6}{RST}  {cc}{label:<10}{RST} {DIM}{summary}{RST}")
 
    print()