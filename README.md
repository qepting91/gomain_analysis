# gomain_analysis

A powerful, fast, and comprehensive Go-based Cyber Threat Intelligence (CTI) OSINT tool for domain analysis and reporting. 

Unlike traditional scripts, `gomain_analysis` aggregates live infrastructure data, historical records, and web presence into fully structured **Raw JSON feeds** for SIEM ingestion, alongside easily digestible, presentation-ready **PDF Reports**.

## Features

- **Infrastructure & DNS**: Resolves A, AAAA, MX records, and performs Reverse DNS lookups.
- **Passive Subdomain Enumeration**: Integrates `projectdiscovery/subfinder` to stealthily scrape hundreds of subdomains from APIs without alerting the target.
- **SSL/TLS Certificate Inspection**: Dual-layer hybrid approach. Instantly pulls the live certificate chain via direct TLS handshake, with a secondary fallback to Certificate Transparency (CT) logs (`crt.sh`).
- **Threat Intelligence & Reputation**: Connects to the **VirusTotal API** to check the domain and resolved IPs for malicious, phishing, or C2 tags.
- **Credential Breach Checks**: Automatically validates extracted employee/target emails against the **HaveIBeenPwned API** to reveal brute-force or credential stuffing vectors.
- **IP Geolocation**: Uses MaxMind's GeoIP2 database for accurate target mapping.
- **Web Content Analysis**: Extracts titles, emails, phone numbers, technologies, exposed forms, internal/external links, and social media presence.
- **Historical Data**: Retrieves archived snapshots and proactively triggers active captures via the Wayback Machine.
- **Google Dorking**: Automatically generates targeted dork queries for the domain.
- **WHOIS Lookups**: Fetches registrar and ownership information.
- **Dual Reporting Engine**: Outputs a cleanly formatted, executive-style PDF summary and a fully structured `_raw.json` file for automation and graphing (Neo4j, Maltego, Splunk).

---

## Prerequisites

### 1. Go Runtime
Ensure you have Go 1.23+ installed.

### 2. MaxMind GeoLite2 Database
This tool requires the free MaxMind GeoLite2-City database for IP geolocation.

1. Download the `GeoLite2-City.mmdb` database. You can get it directly from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) or via a free CDN mirror:
   ```bash
   wget https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz
   gunzip GeoLite2-City.mmdb.gz
   ```
2. Place the decompressed `GeoLite2-City.mmdb` file in the `assets/` directory at the root of this project:
   ```text
   gomain_analysis/
   ├── assets/
   │   └── GeoLite2-City.mmdb
   ```
*(Note: If the database is missing, the tool will gracefully skip geolocation and continue the rest of the analysis).*

---

## Installation & Build

Clone the repository and build the binary:

```bash
git clone https://github.com/qepting91/gomain_analysis.git
cd gomain_analysis
go build -o gomain_analysis ./cmd/
```

Alternatively, you can run the tool via Docker:
```bash
docker build -t gomain_analysis .
docker run --rm -v $(pwd)/assets:/app/assets gomain_analysis analyze --domain example.com
```

---

## Usage

Run the `analyze` command and provide the target domain:

```bash
# Using the built binary
./gomain_analysis analyze --domain samtechautomated.com

# Or running directly via Go
go run ./cmd/ analyze --domain samtechautomated.com
```

### API Key Configuration (Optional)
To unlock the passive advanced Threat Intelligence capabilities (VirusTotal and HaveIBeenPwned), simply export your API keys in your terminal environment before running the tool. If you do not have these keys, the tool will gracefully skip these checks while `subfinder` and the rest of the OSINT modules continue.

```bash
export VT_API_KEY="your_virustotal_api_key_here"
export HIBP_API_KEY="your_haveibeenpwned_api_key_here"

./gomain_analysis analyze --domain samtechautomated.com
```

### Outputs

Upon successful execution, the tool will generate two files in your current directory:

1. **`{domain}_report.pdf`**: A professional, paginated PDF report with tables, structured data, and click-able links. Ideal for sharing with stakeholders or including in penetration test reports.
2. **`{domain}_raw.json`**: A machine-readable JSON structure containing all findings, perfect for programmatic ingestion into SIEMs or threat intelligence platforms.

---

## Project Structure

```text
gomain_analysis/
├── cmd/                 # CLI entrypoint (main.go)
├── internal/
│   ├── config/          # Configurations and GeoLite2 initialization
│   ├── crt/             # Hybrid Live TLS & CT Log inspection
│   ├── dns/             # DNS and Reverse DNS operations
│   ├── dork/            # Automated Google dork query generation
│   ├── fetcher/         # HTTP content retrieval
│   ├── geolocation/     # IP location parsing
│   ├── parser/          # HTML parsing and extraction
│   ├── report/          # PDF and JSON generation engines
│   ├── wayback/         # Wayback Machine integration
│   └── whois/           # WHOIS lookups
├── queries/
│   └── queries.txt      # List of dork templates
└── assets/              # Place GeoLite2-City.mmdb here
```

## Development & CI/CD

This project uses **GitHub Actions** for continuous integration. Every push and pull request goes through a strict 4-stage pipeline:
1. **Linting**: `golangci-lint` with 15 active linters enforcing code quality.
2. **Testing**: `go test` with race condition detection and code coverage.
3. **Security**: `govulncheck` and `gosec` for vulnerability scanning.
4. **Build**: Verification of successful cross-platform compilation.
