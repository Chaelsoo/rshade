# rshade

Passive recon tool for pentest initial sweeps via Shodan. Zero active traffic to the target.

## Install

```bash
pip install .
```

## API Key

Set your Shodan API key via any of these:

```bash
export SHODAN_API_KEY=your_key
# or
mkdir -p ~/.rshade && echo "api_key=your_key" > ~/.rshade/config
# or
rshade -t ... --api-key your_key
```

## Usage

```bash
# Scan a CIDR range
rshade -t 192.168.1.0/24

# Scan from file, save report
rshade -t targets.txt -o report.md -j results.json

# Only show vulns CVSS >= 7.0
rshade -t 10.0.0.0/24 --min-cvss 7.0

# Filter to specific ports only
rshade -t 10.0.0.0/24 --ports 22,80,443,3389

# Flag default credential banners
rshade -t 10.0.0.0/24 --flag-defaults

# Summary only (no per-host detail)
rshade -t 10.0.0.0/24 --summary

# Diff against previous scan
rshade -t 10.0.0.0/24 -j new.json --diff old.json
```

## Output

Terminal output is color-coded:
- Red: Critical CVEs (CVSS ≥ 9.0)
- Yellow: High CVEs / flagged ports
- Green: Host found, clean
- Flag: Interesting service or default cred signature detected

Markdown report includes full CVE table per host.
JSON output can be used as input for `--diff` on subsequent scans.

## Notes

- Shodan data may be weeks/months old — treat as intel, not ground truth
- Works best with Shodan Member+ (required for vuln data)
- `/30` and `/29` ranges work well; large `/16` ranges will burn API credits fast