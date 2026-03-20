# gomain_analysis

A powerful, fast, and comprehensive Go-based Cyber Threat Intelligence (CTI) OSINT tool for **passive domain reconnaissance** and reporting.

Designed with **operational security (OPSEC)** in mind, `gomain_analysis` performs 100% passive intelligence gathering without alerting the target. It aggregates infrastructure data, threat intelligence, security posture, and hidden attack surface into fully structured **Raw JSON feeds** for SIEM ingestion, alongside executive-style **PDF Reports**.

**Key Differentiator:** Most modules require **zero API keys** and utilize free, open-source intelligence from authoritative databases (RIPE NCC, Abuse.ch, Certificate Transparency logs) – making this tool accessible for penetration testers, bug bounty hunters, red teams, and security researchers worldwide.

## Features

### 🎯 Core Intelligence Modules

- **Infrastructure & DNS**: Resolves A, AAAA, MX records, and performs Reverse DNS lookups.
- **ASN & IP Range Enumeration** ⭐ NEW: Maps the target's entire Autonomous System Number (ASN) and all associated IP ranges, revealing complete infrastructure footprint via HackerTarget, RIPE NCC, and Team Cymru (**no API key required**).
- **Passive Subdomain Enumeration with Fallbacks**: Multi-layered approach using `subfinder` → Certificate Transparency logs (crt.sh) → VirusTotal API → Amass. Ensures subdomain discovery even if primary tools are unavailable.
- **SSL/TLS Certificate Inspection**: Dual-layer hybrid approach. Instantly pulls the live certificate chain via direct TLS handshake, with a secondary fallback to Certificate Transparency (CT) logs (`crt.sh`).
- **IP Geolocation**: Uses MaxMind's GeoIP2 database for accurate target mapping.
- **WHOIS Lookups**: Fetches registrar and ownership information.

### 🛡️ Security Posture Assessment

- **Security Headers Analysis** ⭐ NEW: Automated vulnerability detection via HTTP security header analysis. Identifies missing HSTS, weak CSP, clickjacking risks, information disclosure, and CORS misconfigurations. Generates security scores (0-100) and actionable remediation steps (**no API key required**).
- **Passive Endpoint Discovery** ⭐ NEW: Discovers hidden directories, admin panels, and APIs by analyzing `robots.txt`, `sitemap.xml`, `security.txt` (RFC 9116), and well-known URIs (RFC 8615) (**no API key required**).
- **JavaScript Analysis & Secret Extraction** ⭐ NEW: Deep analysis of JavaScript files to extract hidden API endpoints, hardcoded secrets (AWS keys, JWTs, Stripe keys, GitHub tokens), and third-party dependencies. Identifies source map exposure and potential credential leaks (**no API key required**).

### ⚠️ Threat Intelligence & Detection

- **Abuse.ch Threat Feeds** ⭐ NEW: Real-time checks against 4 authoritative malware databases: URLhaus (malicious URLs), ThreatFox (IOCs/C2 servers), SSL Blacklist (malicious certificates), and Feodo Tracker (banking trojan/botnet C2s). Provides threat scoring and severity classification (**no API key required**).
- **VirusTotal Integration** (optional): Checks domains and IPs for malicious/phishing/C2 tags (requires free API key).
- **HaveIBeenPwned Integration** (optional): Validates extracted emails against breach databases (requires free API key).

### 🌐 Web & Historical Analysis

- **Web Content Analysis**: Extracts titles, emails, phone numbers, technologies, exposed forms, internal/external links, and social media presence.
- **Historical Data**: Retrieves archived snapshots via the Wayback Machine.
- **Google Dorking**: Automatically generates targeted dork queries for the domain.

### 📊 Reporting

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

**Most modules require zero API keys!** The following modules work completely free without any authentication:
- ✅ ASN/IP range enumeration (HackerTarget, RIPE NCC, Team Cymru)
- ✅ Abuse.ch threat feeds (URLhaus, ThreatFox, SSL Blacklist, Feodo Tracker)
- ✅ Certificate Transparency logs (crt.sh)
- ✅ Security headers analysis
- ✅ Passive discovery (robots.txt, sitemap.xml, security.txt)
- ✅ JavaScript analysis & secret extraction

**Optional API keys** (for enhanced capabilities):

```bash
# Optional: VirusTotal for reputation checks (free tier: 500 requests/day)
export VT_API_KEY="your_virustotal_api_key_here"

# Optional: HaveIBeenPwned for credential breach checks (free tier available)
export HIBP_API_KEY="your_haveibeenpwned_api_key_here"

./gomain_analysis analyze --domain example.com
```

**If you don't provide API keys**, the tool will:
- Use Certificate Transparency logs instead of VirusTotal for subdomain enumeration
- Use free Abuse.ch feeds for threat intelligence
- Skip HaveIBeenPwned checks (all other modules continue normally)

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
│   ├── asn/             # ⭐ ASN & IP range enumeration (HackerTarget, RIPE, Cymru)
│   ├── breach/          # HaveIBeenPwned credential breach checks
│   ├── config/          # Configurations and GeoLite2 initialization
│   ├── crt/             # Hybrid Live TLS & CT Log inspection
│   ├── discovery/       # ⭐ Passive discovery (robots.txt, sitemap.xml, security.txt)
│   ├── dns/             # DNS and Reverse DNS operations
│   ├── dork/            # Automated Google dork query generation
│   ├── fetcher/         # HTTP content retrieval
│   ├── geolocation/     # IP location parsing
│   ├── jsanalysis/      # ⭐ JavaScript analysis & secret extraction
│   ├── parser/          # HTML parsing and extraction
│   ├── report/          # PDF and JSON generation engines
│   ├── reputation/      # VirusTotal reputation checks
│   ├── security/        # ⭐ Security headers analysis & vulnerability detection
│   ├── subfinder/       # Subdomain enumeration with multi-source fallbacks
│   ├── threatfeed/      # ⭐ Abuse.ch threat intelligence (URLhaus, ThreatFox, etc.)
│   ├── wayback/         # Wayback Machine integration
│   └── whois/           # WHOIS lookups
├── docs/
│   ├── OPSEC_OSINT_MODULES.md              # ⭐ Implementation guide for new modules
│   └── SUBDOMAIN_ENUMERATION_CTI_PLAYBOOK.md  # ⭐ Fallback strategy documentation
├── queries/
│   └── queries.txt      # List of dork templates
└── assets/              # Place GeoLite2-City.mmdb here
```

⭐ = New OPSEC-focused passive reconnaissance modules

## OPSEC & Operational Security

This tool is designed for **100% passive reconnaissance** with zero attribution risk:

✅ **No Active Scanning**: No port scans, no DNS brute-forcing, no active probing
✅ **No Target Interaction**: All queries to third-party databases (RIPE, Abuse.ch, CT logs)
✅ **Zero Attribution**: Target's SOC/IDS will NOT detect reconnaissance activities
✅ **Graceful Degradation**: If primary tools fail, automatic fallback to alternative methods
✅ **Rate Limiting**: Built-in politeness delays to avoid abuse detection

**Recommended for:**
- Red team operations
- Bug bounty reconnaissance
- Penetration testing (pre-engagement phase)
- Threat intelligence gathering
- Security research
- Vendor risk assessment

**Read the full OPSEC guide:** [docs/OPSEC_OSINT_MODULES.md](docs/OPSEC_OSINT_MODULES.md)

---

## Documentation

### 📚 Comprehensive Guides

1. **[OPSEC_OSINT_MODULES.md](docs/OPSEC_OSINT_MODULES.md)** (19KB)
   - Implementation guide for all 5 new passive reconnaissance modules
   - CTI analyst use cases and real-world scenarios
   - Integration examples and code snippets
   - Zero-attribution workflows
   - Threat scoring methodologies

2. **[SUBDOMAIN_ENUMERATION_CTI_PLAYBOOK.md](docs/SUBDOMAIN_ENUMERATION_CTI_PLAYBOOK.md)** (13KB)
   - Defense-in-depth subdomain enumeration strategy
   - Fallback mechanisms (Subfinder → crt.sh → VirusTotal → Amass)
   - OPSEC considerations for passive subdomain discovery
   - Data source comparison and selection criteria

---

## Example Output

### Sample Security Findings

```
🎯 Target: example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 INFRASTRUCTURE ANALYSIS
  • DNS Records: 4 A records, 2 MX records
  • ASN: AS15169 (Google LLC)
  • IP Ranges: 35 prefixes discovered (8,960 total IPs)
  • Geolocation: Mountain View, CA, US

🛡️ SECURITY POSTURE
  • Security Score: 68/100 (Grade: D)
  ⚠️ Missing: HSTS, CSP, X-Frame-Options
  ⚠️ Information Disclosure: Server: Apache/2.4.41

⚠️ THREAT INTELLIGENCE
  • Abuse.ch ThreatScore: 0/100 (CLEAN)
  • VirusTotal: 0 malicious detections
  • No IOCs found in ThreatFox/URLhaus

🔍 ATTACK SURFACE
  • Subdomains: 247 discovered (crt.sh fallback)
  • robots.txt: 12 disallowed paths
    - /admin/ ⚠️
    - /api/v2/internal/ ⚠️
    - /backup/ ⚠️
  • API Endpoints: 8 extracted from JavaScript
  • Secrets: 🚨 1 AWS key found in main.js

📄 Reports Generated:
  ✓ example.com_report.pdf (detailed analysis)
  ✓ example.com_raw.json (SIEM-ready)
```

---

## Development & CI/CD

This project uses **GitHub Actions** for continuous integration. Every push and pull request goes through a strict 4-stage pipeline:
1. **Linting**: `golangci-lint` with 15 active linters enforcing code quality.
2. **Testing**: `go test` with race condition detection and code coverage.
3. **Security**: `govulncheck` and `gosec` for vulnerability scanning.
4. **Build**: Verification of successful cross-platform compilation.

---

## Contributing

Contributions are welcome! Areas of interest:
- Additional passive reconnaissance modules
- Enhanced OPSEC/attribution-safe techniques
- New threat intelligence sources (no API keys preferred)
- Improved reporting formats
- Additional export formats (CSV, GraphML for Maltego, etc.)

Please ensure all contributions maintain the **zero-attribution** and **passive-only** philosophy of this tool.

---

## License

MIT License - See LICENSE file for details

---

## Disclaimer

This tool is intended for **authorized security testing and research only**. Users are responsible for complying with all applicable laws and obtaining proper authorization before scanning targets. The authors assume no liability for misuse or damage caused by this program.

**Ethical Use Guidelines:**
- ✅ Bug bounty programs (within scope)
- ✅ Authorized penetration tests
- ✅ Your own infrastructure
- ✅ Educational/research purposes with permission
- ❌ Unauthorized scanning of third-party systems
- ❌ Malicious reconnaissance

---

## Acknowledgments

This tool leverages the following open-source projects and free services:
- [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder)
- [OWASP Amass](https://github.com/owasp-amass/amass)
- [Abuse.ch Threat Feeds](https://abuse.ch) (URLhaus, ThreatFox, SSL Blacklist, Feodo Tracker)
- [Certificate Transparency](https://crt.sh) by Sectigo
- [RIPE NCC](https://stat.ripe.net) for ASN/BGP data
- [Team Cymru](https://www.team-cymru.com) for IP-to-ASN mapping
- [HackerTarget](https://hackertarget.com) for free reconnaissance APIs
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

Special thanks to the CTI and OSINT communities for their invaluable research and tool development.
