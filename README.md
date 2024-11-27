# gomain_analysis

A powerful Go-based OSINT tool for comprehensive domain analysis and reporting.

## Features

- IP Geolocation using MaxMind's GeoIP2 database
- Web content extraction and analysis
- WHOIS information lookup
- DNS record analysis (A, MX records)
- Reverse DNS lookups
- Historical data via Wayback Machine
- Certificate transparency logs via crt.sh
- Automated PDF report generation

gomain_analysis/
├── cmd/                    # Command line interface
├── internal/
│   ├── config/            # Configuration management
│   ├── crt.sh/            # Certificate transparency checks
│   ├── dns/               # DNS operations
│   ├── geolocation/       # IP geolocation
│   ├── parser/            # HTML parsing
│   ├── report/            # PDF report generation
│   ├── wayback/           # Wayback Machine integration
│   └── whois/             # WHOIS lookups

## Dependencies
github.com/PuerkitoBio/goquery - HTML parsing
github.com/domainr/whois - WHOIS lookups
github.com/e-zk/go-crtsh - Certificate transparency
github.com/go-pdf/fpdf - PDF generation
github.com/oschwald/geoip2-golang - IP geolocation
github.com/seekr-osint/wayback-machine-golang - Wayback Machine integration
github.com/urfave/cli/v2 - CLI interface
## Prerequisites

Download GeoLite2-City.mmdb database from MaxMind
Place the database file in your project's asset directory

## Note
this is a rewrite and improvement upon the github.com/qepting/domain_analysis tool.

The following will be used for the Python to GO transformation:

### Python Tool Mapping & Go Alternatives

#### 1. `GeoLiteCity.dat` (IP Geolocation)
- **Python Tool**: `pygeoip`
- **Go Alternative**: Use [MaxMind's GeoIP2 Go library](https://github.com/oschwald/geoip2-golang).
  - **Note**: This library will allow us to use the `.mmdb` version of the GeoLite database. You’ll need to download the latest version (`GeoLite2-City.mmdb`) and use the `geoip2-golang` library for IP lookups.

#### 2. **Fetching Web Content** (`requests`, `urllib`)
- **Python Tool**: `requests`, `urllib`
- **Go Alternative**: Use Go's built-in `net/http` package for making HTTP requests.
  - **Reproduction**: `http.Get(url)` can be used for fetching content. This is very straightforward to replicate in Go using `net/http`.

#### 3. **HTML Parsing** (`BeautifulSoup`)
- **Python Tool**: `BeautifulSoup` from `bs4`
- **Go Alternative**: Use [PuerkitoBio's `goquery`](https://github.com/PuerkitoBio/goquery), which is similar in functionality to BeautifulSoup.
  - **Reproduction**: `goquery` provides functions to parse HTML and traverse/manipulate the document, making it a close match to `BeautifulSoup`.

#### 4. **WHOIS Lookup** (`whois`)
- **Python Tool**: `whois`
- **Go Alternative**: Use [domainr/whois](https://github.com/domainr/whois) or [likexian/whois-go](https://github.com/likexian/whois-go).
  - **Reproduction**: These libraries allow performing WHOIS lookups on domains, similar to the Python `whois` package.

#### 5. **DNS Resolution** (`dns.resolver`)
- **Python Tool**: `dnspython` library (`dns.resolver`)
- **Go Alternative**: Use Go’s built-in `net` package or a DNS library like [miekg/dns](https://github.com/miekg/dns).
  - **Reproduction**: The `net` package has `LookupHost` and `LookupMX` functions to get A and MX records, respectively. For more complex DNS queries, the `miekg/dns` library can be used.

#### 6. **Reverse DNS Lookup** (`dns.reversename`)
- **Python Tool**: `dnspython` library (`dns.reversename`)
- **Go Alternative**: Use Go's built-in `net` package, specifically `net.LookupAddr`.
  - **Reproduction**: `net.LookupAddr(ip)` can be used to perform reverse DNS lookups, similar to the Python implementation.

#### 7. **Wayback Machine Integration** (`wayback` library)
- **Python Tool**: `wayback` Python package for fetching Wayback Machine snapshots.
- **Go Alternative**: No direct equivalent, but you can use simple HTTP GET requests to the Wayback Machine API.
  - **Reproduction**: Write a function in Go to perform requests to the Wayback Machine API (`http://archive.org/wayback/available?url={URL}`) and parse the response. JSON parsing is straightforward in Go using the `encoding/json` package.

#### 8. **Google Dorking (`oxdork`)**
- **Python Tool**: `subprocess.run` to execute `oxdork` for Google dorking.
- **Go Alternative**: Execute commands using Go's `os/exec` package.
  - **Reproduction**: You can still execute external tools using `os/exec`. Alternatively, consider using a built-in library or writing Go code to simulate `oxdork` functionality (e.g., using the `net/http` package to craft Google queries).

#### 9. **PDF Generation** (`reportlab`)
- **Python Tool**: `reportlab` for creating PDF reports.
- **Go Alternative**: Use [jung-kurt/gofpdf](https://github.com/jung-kurt/gofpdf) (archived, but still useful) or [go-pdf/fpdf](https://github.com/go-pdf/fpdf) for PDF generation.
  - **Reproduction**: The `gofpdf` package provides methods to create and customize PDF documents similarly to ReportLab. You can use it to generate headers, paragraphs, and tables.

### Final Module Mapping Overview
Here's the updated modular overview including Go alternatives:

1. **`config/geolite.go`**:
   - **Python**: `pygeoip`
   - **Go**: Use `geoip2-golang` with MaxMind `.mmdb` files.

2. **`fetcher/web_fetcher.go`**:
   - **Python**: `requests`, `urllib`
   - **Go**: Use `net/http`.

3. **`parser/html_parser.go`**:
   - **Python**: `BeautifulSoup`
   - **Go**: Use `goquery`.

4. **`whois/whois_lookup.go`**:
   - **Python**: `whois`
   - **Go**: Use `likexian/whois-go`.

5. **`dns/dns_resolver.go` & `reverse_dns.go`**:
   - **Python**: `dnspython`
   - **Go**: Use `net` package (`LookupHost`, `LookupMX`, `LookupAddr`) or `miekg/dns` for advanced features.

6. **`geolocation/geo_lookup.go`**:
   - **Python**: `pygeoip`
   - **Go**: Use `geoip2-golang`.

7. **`wayback/wayback_fetcher.go`**:
   - **Python**: `wayback`
   - **Go**: Implement using `net/http` to interact with the Wayback Machine API.

8. **`dork/dork.go`**:
   - **Python**: Execute `oxdork` using `subprocess`.
   - **Go**: Use `os/exec` to execute `Google Dorking` or write equivalent dorking functions in Go.

9. **`report/pdf_generator.go`**:
   - **Python**: `reportlab`
   - **Go**: Use `go-pdf/fpdf`.

## Generated Report Contents
The tool generates a comprehensive PDF report including:

- WHOIS Information
- Geolocation Data
- Extracted Links
- DNS Records
- MX Records
- Reverse DNS Information
- Historical Wayback Machine Snapshots
- Project Structure

