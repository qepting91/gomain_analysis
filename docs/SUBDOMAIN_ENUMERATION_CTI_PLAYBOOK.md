# Subdomain Enumeration: CTI Analyst Playbook

## Executive Summary
This document outlines the **multi-layered passive subdomain enumeration strategy** implemented in `gomain_analysis` to ensure operational resilience during threat intelligence collection operations.

## The Problem: Single Point of Failure
Relying on a single tool (subfinder) creates operational risk:
- **Dependency failures** (missing binaries, API rate limits)
- **Detection & attribution** (repeated queries to the same data sources)
- **Incomplete coverage** (different tools have access to different data sources)

## Solution: Defense-in-Depth Enumeration Strategy

### Tier 1: Subfinder (Primary Method)
**Data Sources:** 55+ including Certificate Transparency, DNS aggregators, search engines
**Attribution Risk:** Low (distributed queries)
**Coverage:** Excellent
**Speed:** Fast (parallelized)

**When it fails:** Missing binary, dependency issues, API exhaustion

---

### Tier 2: Certificate Transparency Logs (crt.sh)
**Data Sources:** All public CT logs (Google, Cloudflare, DigiCert, etc.)
**Attribution Risk:** None (public historical data)
**Coverage:** Good (only HTTPS-enabled subdomains)
**Speed:** Moderate

**Advantages:**
- ✅ Zero dependencies (direct HTTPS API call)
- ✅ 100% passive (no DNS queries to target)
- ✅ Historical data (subdomains from expired certificates)
- ✅ No authentication required

**Limitations:**
- ❌ Misses non-HTTPS subdomains
- ❌ Misses internal/private subdomains
- ❌ May include decommissioned subdomains

**CTI Use Case:** Ideal for **initial reconnaissance** and **infrastructure mapping** without alerting SOC/IDS

---

### Tier 3: VirusTotal API
**Data Sources:** VT's passive DNS database (crawler submissions, sandboxes, partnerships)
**Attribution Risk:** Low (VT aggregates from many sources)
**Coverage:** Excellent (includes malicious/suspicious subdomains)
**Speed:** Fast

**Advantages:**
- ✅ Already integrated for reputation checks (reuse API key)
- ✅ Includes subdomains from malware C2 analysis
- ✅ Historical passive DNS data
- ✅ Threat context included

**Limitations:**
- ❌ Requires API key (free tier: 500 requests/day)
- ❌ Rate limited

**CTI Use Case:** **Threat hunting** and **adversary infrastructure discovery**. VT's dataset includes domains seen in malware samples, giving insight into attacker-controlled infrastructure.

---

### Tier 4: Amass (OWASP)
**Data Sources:** 55+ APIs, DNS brute-forcing (passive mode disables this)
**Attribution Risk:** Low in passive mode
**Coverage:** Best-in-class
**Speed:** Slow (comprehensive data collection)

**Advantages:**
- ✅ Industry standard
- ✅ Most comprehensive results
- ✅ Supports multiple API integrations
- ✅ Active community and updates

**Limitations:**
- ❌ Requires installation
- ❌ Slower than other methods
- ❌ More complex configuration

**CTI Use Case:** **Deep-dive investigations** where thoroughness outweighs speed

---

## Implementation Logic Flow

```
┌─────────────────────────────────────────┐
│ START: EnumerateWithFallback(domain)    │
└───────────────┬─────────────────────────┘
                │
                ▼
     ┌──────────────────────┐
     │  Try Subfinder       │◄──── PRIMARY METHOD
     └──────┬───────────────┘
            │
            ├─── SUCCESS? ──► Return results
            │                 (10-1000+ subdomains)
            ▼
         FAILURE
            │
            ▼
     ┌──────────────────────┐
     │  Try crt.sh API      │◄──── FALLBACK 1 (Zero Dependencies)
     └──────┬───────────────┘
            │
            ├─── SUCCESS? ──► Return results
            │                 (5-500 subdomains)
            ▼
         FAILURE
            │
            ▼
     ┌──────────────────────┐
     │ Check VT_API_KEY?    │
     └──────┬───────────────┘
            │
            ├─── KEY EXISTS?
            │        │
            │        ▼
            │ ┌──────────────────────┐
            │ │  Try VirusTotal API  │◄──── FALLBACK 2 (Threat Context)
            │ └──────┬───────────────┘
            │        │
            │        ├─── SUCCESS? ──► Return results
            │        │                 (10-200 subdomains)
            │        ▼
            │     FAILURE
            │        │
            └────────┤
                     ▼
            ┌──────────────────────┐
            │  Check for Amass?    │
            └──────┬───────────────┘
                   │
                   ├─── INSTALLED?
                   │        │
                   │        ▼
                   │ ┌──────────────────────┐
                   │ │ Try Amass (passive)  │◄──── FALLBACK 3 (Comprehensive)
                   │ └──────┬───────────────┘
                   │        │
                   │        ├─── SUCCESS? ──► Return results
                   │        │                 (50-2000+ subdomains)
                   │        ▼
                   │     FAILURE
                   │        │
                   └────────┤
                            ▼
                  ┌──────────────────────┐
                  │ Return empty array   │
                  │ (Graceful degradation)│
                  └──────────────────────┘
```

---

## Operational Security (OPSEC) Considerations

### Attribution & Detection Risk Matrix

| Method       | Target Detection Risk | Source Attribution | Footprint           |
|--------------|----------------------|-------------------|---------------------|
| Subfinder    | **None** (passive)   | Low               | API queries to 3rd parties |
| crt.sh       | **None** (public logs)| None              | Single HTTPS request |
| VirusTotal   | **None** (API query) | Medium (API key)  | Logged by VT        |
| Amass        | **None** (passive mode)| Low             | Multiple API queries |

**Key Takeaway:** All methods are passive and safe for **non-attributed reconnaissance**. The target organization will NOT see these queries in their DNS logs or IDS.

### When to Use Each Method

#### Pre-Attack Intelligence Gathering
- **Start with:** crt.sh (fastest, zero attribution)
- **Expand with:** Subfinder or Amass (comprehensive coverage)
- **Enrich with:** VirusTotal (threat context on discovered infrastructure)

#### Incident Response / Threat Hunting
- **Start with:** VirusTotal (check for known malicious subdomains)
- **Expand with:** Subfinder/Amass (find all current infrastructure)
- **Historical analysis:** crt.sh (find decommissioned but historically-associated subdomains)

#### Red Team Operations
- **Primary:** Subfinder (fast, comprehensive)
- **Fallback:** crt.sh (if stealth is critical and you need zero API attribution)
- **Avoid:** Methods requiring API keys tied to your organization

---

## API Key Configuration

To unlock all fallback methods, export these environment variables:

```bash
# Required for VirusTotal fallback + reputation checks
export VT_API_KEY="your_virustotal_api_key"

# Optional: Amass can use these for extended coverage
export CENSYS_API_ID="your_censys_id"
export CENSYS_SECRET="your_censys_secret"
export SHODAN_API_KEY="your_shodan_key"
export SECURITYTRAILS_API_KEY="your_securitytrails_key"
```

**Free Tier Limits:**
- VirusTotal: 500 requests/day
- SecurityTrails: 50 requests/month
- Shodan: 100 results/month

---

## Data Quality & Deduplication

### Expected Result Ranges (for typical corporate domain)

| Method       | Typical Results | Quality Notes                          |
|--------------|-----------------|----------------------------------------|
| Subfinder    | 100-1000+       | High quality, minimal false positives  |
| crt.sh       | 50-500          | Historical data, may include expired   |
| VirusTotal   | 20-200          | High quality + threat-tagged domains   |
| Amass        | 200-2000+       | Most comprehensive, some noise         |

### False Positive Handling
The tool automatically:
- ✅ Deduplicates results across data sources
- ✅ Removes wildcard indicators (`*.example.com` → `example.com`)
- ✅ Validates that results belong to target domain
- ✅ Converts to lowercase for consistency

---

## Testing the Fallback System

### Simulate Subfinder Failure
```bash
# Temporarily rename subfinder to test fallback
mv $(which subfinder) $(which subfinder).bak

# Run tool - should automatically fall back to crt.sh
./gomain_analysis analyze --domain example.com

# Restore
mv $(which subfinder).bak $(which subfinder)
```

### Test Individual Methods
```bash
# Test crt.sh
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Test VirusTotal
curl -H "x-apikey: YOUR_KEY" \
  "https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=40"

# Test Amass
amass enum -passive -d example.com -silent
```

---

## Threat Intelligence Best Practices

### Data Freshness
- **Certificate Transparency:** Updated in real-time as certificates are issued
- **VirusTotal:** Updated continuously from global telemetry
- **Subfinder APIs:** Varies by source (most update hourly/daily)

### Correlation & Enrichment
After subdomain discovery, cross-reference with:
1. **WHOIS data** (ownership changes, recent registrations)
2. **DNS records** (unusual records, misconfigurations)
3. **SSL certificate metadata** (wildcards, self-signed, expired)
4. **Reputation databases** (known malicious IPs/domains)
5. **Passive DNS** (historical IP mappings)

### Operational Workflow
```
1. Passive Subdomain Enum → 2. DNS Resolution → 3. Port Scanning → 4. Service Fingerprinting
        (This Tool)              (dnsx)            (nmap/masscan)     (httpx/nuclei)
```

---

## Threat Actor Perspective: Why Subdomains Matter

### Attack Surface Expansion
- Forgotten dev/staging environments (often less secure)
- Legacy applications (unpatched, EOL software)
- Third-party integrations (supply chain risks)
- Employee-facing portals (credential harvesting targets)

### Real-World Example
**Target:** `bigcorp.com`
**Subdomain Found:** `old-jenkins.bigcorp.com`
**Result:** Unauthenticated Jenkins instance with hardcoded AWS credentials in build scripts

### Defensive Monitoring
Use this tool's output to:
- ✅ Inventory your external attack surface
- ✅ Identify shadow IT and rogue subdomains
- ✅ Detect typosquatting and phishing domains
- ✅ Monitor for newly-issued certificates (threat hunting)

---

## Troubleshooting

### "All subdomain enumeration methods exhausted"
**Causes:**
1. Domain is very new (not indexed yet)
2. Domain has no subdomains
3. All external services are temporarily down
4. Network connectivity issues

**Verify:**
```bash
# Manual crt.sh check
curl -I https://crt.sh

# DNS resolution working?
nslookup example.com

# API keys valid?
echo $VT_API_KEY
```

### Rate Limiting / 429 Errors
**VirusTotal:** Wait 24 hours or upgrade to paid tier
**crt.sh:** Rarely rate-limits, but if so, wait 1 hour
**Subfinder:** Rotates across many APIs to avoid this

---

## References & Further Reading

- [OWASP Amass Documentation](https://github.com/owasp-amass/amass)
- [Certificate Transparency RFC 6962](https://tools.ietf.org/html/rfc6962)
- [VirusTotal API v3 Docs](https://developers.virustotal.com/reference/overview)
- [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder)
- [MITRE ATT&CK: T1590.005 - Gather Victim Network Information: IP Addresses](https://attack.mitre.org/techniques/T1590/005/)

---

**Document Version:** 1.0
**Last Updated:** 2026-03-20
**Maintained By:** CTI Team
