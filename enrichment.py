from typing import Optional

# Banners / strings commonly associated with default credentials or exposed admin panels
DEFAULT_CRED_SIGNATURES = [
    "default password",
    "admin:admin",
    "admin:password",
    "username: admin",
    "Authorization: Basic",
    "Cisco IOS",
    "RouterOS",
    "MikroTik",
    "DVWA",
    "phpMyAdmin",
    "Tomcat",
    "JBoss",
    "WebLogic",
    "Jenkins",
    "Kibana",
    "Grafana",
    "Netgear",
    "D-Link",
    "TP-Link",
    "ZyXEL",
]

INTERESTING_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    102:  "Siemens S7",
    110:  "POP3",
    143:  "IMAP",
    161:  "SNMP",
    443:  "HTTPS",
    445:  "SMB",
    502:  "Modbus",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker (unauthenticated)",
    3306: "MySQL",
    3389: "RDP",
    4840: "OPC-UA",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
    47808:"BACnet",
}

HIGH_RISK_PORTS = {23, 445, 2375, 5900, 6379, 9200, 27017, 502, 102, 47808}


def parse_host(raw: dict, min_cvss: float = 0.0, port_filter: list = None, flag_defaults: bool = False) -> dict:
    ip = raw.get("ip_str", "")
    ports = []
    banners = []

    for service in raw.get("data", []):
        port = service.get("port")
        banner = service.get("data", "")
        if port:
            ports.append(port)
        if banner:
            banners.append(banner)

    if port_filter:
        ports = [p for p in ports if p in port_filter]

    # CVE parsing
    vulns = []
    raw_vulns = raw.get("vulns", {})
    for cve_id, vuln_data in raw_vulns.items():
        cvss = vuln_data.get("cvss", 0.0)
        if cvss is None:
            cvss = 0.0
        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            cvss = 0.0
        if cvss >= min_cvss:
            vulns.append({
                "id": cve_id,
                "cvss": cvss,
                "summary": vuln_data.get("summary", ""),
            })

    vulns.sort(key=lambda v: v["cvss"], reverse=True)

    flags = []

    for port in ports:
        if port in HIGH_RISK_PORTS:
            label = INTERESTING_PORTS.get(port, str(port))
            flags.append(f"port {port} ({label})")

    if flag_defaults:
        combined_banners = " ".join(banners).lower()
        for sig in DEFAULT_CRED_SIGNATURES:
            if sig.lower() in combined_banners:
                flags.append(f"default creds signature: '{sig}'")
                break  # one flag is enough

    # Scan timestamp
    last_update = raw.get("last_update", "unknown")

    max_cvss = vulns[0]["cvss"] if vulns else 0.0

    return {
        "ip": ip,
        "org": raw.get("org", "unknown"),
        "country": raw.get("country_name", "unknown"),
        "ports": sorted(set(ports)),
        "vulns": vulns,
        "max_cvss": max_cvss,
        "flags": flags,
        "last_update": last_update,
        "os": raw.get("os", None),
        "hostnames": raw.get("hostnames", []),
    }


def severity_label(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    elif cvss >= 7.0:
        return "HIGH"
    elif cvss >= 4.0:
        return "MEDIUM"
    elif cvss > 0:
        return "LOW"
    return "NONE"


def diff_results(current: list, previous: list) -> dict:
    prev_map = {h["ip"]: h for h in previous}
    curr_map = {h["ip"]: h for h in current}

    new_hosts = [ip for ip in curr_map if ip not in prev_map]
    gone_hosts = [ip for ip in prev_map if ip not in curr_map]

    changed = []
    for ip in curr_map:
        if ip in prev_map:
            curr = curr_map[ip]
            prev = prev_map[ip]
            new_ports = set(curr["ports"]) - set(prev["ports"])
            closed_ports = set(prev["ports"]) - set(curr["ports"])
            new_vulns = set(v["id"] for v in curr["vulns"]) - set(v["id"] for v in prev["vulns"])
            if new_ports or closed_ports or new_vulns:
                changed.append({
                    "ip": ip,
                    "new_ports": sorted(new_ports),
                    "closed_ports": sorted(closed_ports),
                    "new_vulns": sorted(new_vulns),
                })

    return {
        "new_hosts": new_hosts,
        "gone_hosts": gone_hosts,
        "changed": changed,
    }