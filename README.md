```markdown
# Bug Bounty Comprehensive Toolkit v2.1.0

**Educational Purpose Only**  
Created by Psycho ([@the_psycho_of_hackers](https://instagram.com/the_psycho_of_hackers))

A powerful, all-in-one reconnaissance and vulnerability scanning toolkit designed for bug bounty hunters, penetration testers, and cybersecurity students. This tool automates the process of gathering information, discovering assets, and identifying common security flaws in web applications and network services.

> ⚠️ **DISCLAIMER**: This tool is for educational purposes and authorized testing only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The author assumes no liability for misuse.

---

## Table of Contents
- [Features](#features)
  - [Reconnaissance](#-reconnaissance)
  - [Web Application Scanning](#-web-application-scanning)
  - [Vulnerability Assessment](#-vulnerability-assessment)
  - [Additional Modules](#-additional-modules)
  - [Reporting](#-reporting)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Install from Source](#install-from-source)
  - [Using a Virtual Environment](#using-a-virtual-environment-recommended)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Command-Line Options](#command-line-options)
  - [Module Control](#module-control)
  - [API Keys Configuration](#api-keys-configuration)
  - [Examples](#examples)
    - [Full Reconnaissance](#1-full-reconnaissance-on-a-domain)
    - [Quick Web Vulnerability Scan](#2-quick-web-vulnerability-scan)
    - [Subdomain Focus](#3-subdomain-takeover-potential)
    - [Custom Wordlist](#4-using-custom-wordlist-for-directory-bruteforce)
- [Output and Reports](#output-and-reports)
  - [Text Report](#text-report)
  - [HTML Report](#html-report)
- [Dependencies](#dependencies)
- [Tips and Best Practices](#tips-and-best-practices)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## Features

### 🔍 Reconnaissance

#### Passive Subdomain Enumeration
The toolkit aggregates subdomains from multiple public sources without directly querying the target, reducing the risk of detection. Sources include:
- **Certificate Transparency logs** (crt.sh) – Extracts subdomains from SSL/TLS certificates.
- **AlienVault OTX** – Uses the Open Threat Exchange API to fetch passive DNS data.
- **VirusTotal** – If an API key is provided, retrieves subdomains from VirusTotal's passive DNS dataset.
- **SecurityTrails** – Requires an API key; provides comprehensive historical DNS data.
- **ThreatMiner** – Public API for passive DNS and threat intelligence.
- **Bufferover.run** – DNS dumpster service that returns related domains and subdomains.

This multi-source approach ensures broad coverage and helps discover hidden or forgotten subdomains.

#### Active Subdomain Bruteforce
The toolkit performs DNS resolution on a list of common subdomain names. It supports:
- **Custom wordlists** – Users can provide their own wordlist via the `--wordlist` option.
- **Threading** – Configurable thread count for faster brute-forcing.
- **Progress bar** – When `tqdm` is installed, a progress bar shows the scan status.
- **Built-in wordlist** – If no custom wordlist is provided, a default list of common subdomains (e.g., `www`, `mail`, `api`, `admin`) is used.

#### DNS Analysis
The toolkit queries various DNS record types and performs advanced checks:
- **Standard Records** – Retrieves A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, and SRV records.
- **Zone Transfer Attempt** – Tries to perform a DNS zone transfer from each discovered name server to detect misconfigurations.
- **Wildcard Detection** – Checks if the domain uses wildcard DNS by resolving a random subdomain; if it resolves, a wildcard is likely present.

#### Cloud Provider Detection
Identifies if the target is hosted behind a cloud provider or CDN by:
- **IP Range Matching** – Compares the resolved IP address against known CIDR blocks of Cloudflare, AWS, Google Cloud, Akamai, Fastly, and others.
- **Header Analysis** – Examines HTTP response headers (e.g., `Server`, `CF-Ray`, `X-Amz-Cf-Id`) for clues about the infrastructure.

#### SSL/TLS Certificate Analysis
- Extracts certificate details: subject, issuer, validity period, serial number, subject alternative names.
- Checks for weak ciphers by examining the negotiated cipher suite during the TLS handshake.

### 🌐 Web Application Scanning

#### Directory & File Bruteforce
Discovers hidden directories and files by requesting common paths with various extensions. Features:
- **Custom wordlist support** – Users can supply their own wordlist.
- **Extension fuzzing** – Tries multiple extensions (`.php`, `.asp`, `.jsp`, `.json`, etc.) for each base path.
- **Status code filtering** – Reports URLs with HTTP status codes 200, 301, 302, 403, 401, and 500 as potentially interesting.

#### Endpoint Discovery
Scans for sensitive files and API endpoints that are often overlooked, such as:
- Configuration files: `.env`, `config.json`, `web.config`
- Backup files: `backup.zip`, `database.sql`
- Log files: `access.log`, `error.log`
- API documentation: `swagger.json`, `api-docs`, `graphql`
- Version control exposure: `.git/HEAD`, `.svn/entries`

#### 403 Bypass Testing
When a directory returns a 403 Forbidden status, the toolkit attempts various bypass techniques:
- Path manipulation: adding trailing slashes, URL-encoded characters, double slashes, etc.
- Header injection: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, `Referer` spoofing.
- HTTP method switching (if supported by the server).

#### Technology Fingerprinting
Identifies the technologies powering the web application by analyzing:
- HTTP response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`)
- HTML content patterns (e.g., `wp-content` for WordPress, `csrf-token` for Laravel)
- Cookies (`PHPSESSID`, `JSESSIONID`, etc.)
- Common framework signatures (React, Angular, Vue, Django, Flask, etc.)

### 🔬 Vulnerability Assessment

#### SQL Injection (SQLi)
Tests URL parameters with common SQLi payloads (e.g., `'`, `' OR '1'='1`, `' UNION SELECT 1--`). Detects potential vulnerabilities by looking for database error messages in the response.

#### Cross-Site Scripting (XSS)
Injects reflective XSS payloads (e.g., `<script>alert('XSS')</script>`, `<img src=x onerror=alert(1)>`) into parameters and checks if the payload appears unencoded in the response.

#### CORS Misconfiguration
Checks if the target allows cross-origin requests from arbitrary origins (`Access-Control-Allow-Origin: *`) or if it reflects the `Origin` header with `Access-Control-Allow-Credentials: true`, which can lead to data theft.

#### Open Redirect
Attempts to redirect users to an external domain by injecting payloads into common redirect parameters (`redirect`, `url`, `next`, `return`). A vulnerability is flagged if the response includes a `Location` header pointing to the attacker's domain.

#### Local File Inclusion (LFI)
Tests parameters with path traversal payloads (e.g., `../../../../etc/passwd`) and looks for signs of successful inclusion (e.g., `root:x:0:0` in the response).

#### Server-Side Template Injection (SSTI)
Injects template syntax from various engines (Jinja2, Twig, Freemarker, etc.) into parameters. If the expression is evaluated (e.g., `{{7*7}}` returning `49`), a vulnerability is reported.

#### Security Header Analysis
Checks for the presence of important security headers:
- `X-Frame-Options` – prevents clickjacking
- `X-Content-Type-Options` – stops MIME type sniffing
- `Strict-Transport-Security` – enforces HTTPS
- `Content-Security-Policy` – mitigates XSS and data injection
- `X-XSS-Protection` – enables browser XSS filters
- `Referrer-Policy` – controls referrer information leakage
- `Permissions-Policy` – restricts browser features

Missing headers are reported as potential weaknesses.

#### Weak SSL/TLS Ciphers
During SSL analysis, the toolkit checks the negotiated cipher suite against a list of known weak ciphers (RC4, DES, MD5, EXPORT, NULL). If a weak cipher is accepted, it's flagged.

### 📦 Additional Modules

#### Wayback Machine Integration
Fetches historical URLs from the Internet Archive's Wayback Machine for the target domain. This can reveal old endpoints, backup files, or parameters that are no longer linked but still accessible.

#### GitHub Dorking
Requires a GitHub API key. Searches GitHub for code containing the target domain along with sensitive keywords (e.g., `api_key`, `password`, `secret`, `token`, `aws_access_key`). Results include repository names, file paths, and direct links to the findings.

#### Port Scanning
- **Nmap Integration** – If `python-nmap` is installed and Nmap is available on the system, it performs a SYN scan (`-sS`) on common ports with service version detection (`-sV`). Results include port, protocol, service name, product, version, and extra info.
- **Socket Fallback** – If Nmap is not available, a simple TCP connect scan using Python sockets is performed. This is slower and does not provide version information but still identifies open ports.

### 📊 Reporting

#### Text Report
A plain-text summary of all findings, organized by category. Includes counts of discovered items and details for each. Saved as `bugbounty_report_<target>_<timestamp>.txt`.

#### HTML Report
A styled HTML report with tables, color-coded vulnerabilities, and collapsible sections (if Jinja2 is installed). Provides an interactive way to review results. Saved as `bugbounty_report_<target>_<timestamp>.html`.

---

## Installation

### Prerequisites
- **Python 3.6+** – The toolkit is written in Python and requires version 3.6 or higher.
- **pip** – Python package manager.
- **Nmap (optional)** – For advanced port scanning with version detection. Install via your system package manager (e.g., `apt install nmap`, `brew install nmap`).

### Install from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/psycho/bugbounty-toolkit.git
   cd bugbounty-toolkit
   ```
2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Install the toolkit as a package for system-wide access:
   ```bash
   pip install .
   ```
   This creates a console script `bugbounty-toolkit` that you can run from anywhere.

### Using a Virtual Environment (Recommended)
Isolate dependencies to avoid conflicts with other projects:
```bash
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python bugbounty_toolkit.py -d example.com
```

---

## Usage

### Basic Usage
The simplest way to run a scan is to provide a domain:
```bash
python bugbounty_toolkit.py -d example.com
```
This will run all modules (subdomain enumeration, port scanning, DNS analysis, SSL analysis, directory bruteforce, endpoint discovery, vulnerability scanning, technology detection, cloud detection, Wayback Machine fetch, and GitHub dorking if an API key is provided). Results are saved to both text and HTML reports.

If you have a full URL (including protocol), use `-u`:
```bash
python bugbounty_toolkit.py -u https://example.com
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-d DOMAIN, --domain DOMAIN` | Target domain (e.g., example.com) |
| `-u URL, --url URL`           | Target URL (e.g., https://example.com) |
| `-o OUTPUT, --output OUTPUT`  | File to append raw findings (optional) |
| `-t THREADS, --threads THREADS` | Number of threads for concurrent tasks (default: 10) |
| `--timeout TIMEOUT`           | HTTP request timeout in seconds (default: 10) |
| `--user-agent USER_AGENT`     | Custom User-Agent string for HTTP requests |
| `--wordlist WORDLIST`         | Path to a custom wordlist for directory/subdomain brute force |
| `--api-keys API_KEYS`         | JSON file containing API keys (see [API Keys Configuration](#api-keys-configuration)) |

### Module Control
You can selectively enable or disable specific modules using the following flags:

| Flag | Description |
|------|-------------|
| `--no-subdomain` | Disable subdomain enumeration (both passive and active) |
| `--no-ports`     | Disable port scanning |
| `--no-dns`       | Disable DNS analysis |
| `--no-ssl`       | Disable SSL/TLS analysis |
| `--no-directories` | Disable directory/file bruteforce |
| `--no-endpoints` | Disable endpoint discovery |
| `--no-vulnerabilities` | Disable vulnerability scanning (SQLi, XSS, etc.) |
| `--no-technology` | Disable technology fingerprinting |
| `--no-cloud`     | Disable cloud provider detection |
| `--no-wayback`   | Disable Wayback Machine historical URL fetch |
| `--no-github`    | Disable GitHub dorking |

Example: Run only subdomain enumeration and DNS analysis:
```bash
python bugbounty_toolkit.py -d example.com --no-ports --no-ssl --no-directories --no-endpoints --no-vulnerabilities --no-technology --no-cloud --no-wayback --no-github
```
Or more concisely, use the `--no-*` flags for the modules you want to skip.

### API Keys Configuration
To use certain features (VirusTotal, SecurityTrails, GitHub dorking), you need to provide API keys. Create a JSON file (e.g., `keys.json`) with the following structure:
```json
{
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "securitytrails": "YOUR_SECURITYTRAILS_API_KEY",
    "github": "YOUR_GITHUB_TOKEN"
}
```
Then pass the file via `--api-keys`:
```bash
python bugbounty_toolkit.py -d example.com --api-keys keys.json
```

- **VirusTotal API Key**: Get one from [VirusTotal](https://www.virustotal.com/) (free tier available).
- **SecurityTrails API Key**: Sign up at [SecurityTrails](https://securitytrails.com/) for a free API key.
- **GitHub Token**: Generate a personal access token from [GitHub Settings](https://github.com/settings/tokens) with `repo` scope (for public repositories, `public_repo` is sufficient).

If a key is missing, the corresponding module will be skipped with a warning.

### Examples

#### 1. Full Reconnaissance on a Domain
```bash
python bugbounty_toolkit.py -d target.com -o full_scan.txt
```
- Enumerates subdomains passively and actively.
- Scans open ports (if Nmap available, with version detection).
- Analyzes DNS records and attempts zone transfer.
- Checks SSL certificate and weak ciphers.
- Bruteforces directories and discovers endpoints.
- Runs vulnerability checks (SQLi, XSS, etc.).
- Detects cloud provider and technologies.
- Fetches historical URLs from Wayback Machine.
- Searches GitHub for leaks (if API key provided).
- Generates both text and HTML reports.

#### 2. Quick Web Vulnerability Scan
```bash
python bugbounty_toolkit.py -u https://target.com --no-subdomain --no-ports --no-dns
```
Skips infrastructure discovery and focuses on web application vulnerabilities.

#### 3. Subdomain Takeover Potential
```bash
python bugbounty_toolkit.py -d target.com --no-directories --no-vulnerabilities
```
Focuses on subdomain enumeration and DNS record analysis, which are essential for identifying subdomain takeover opportunities.

#### 4. Using Custom Wordlist for Directory Bruteforce
```bash
python bugbounty_toolkit.py -u https://target.com --wordlist ./my_dirs.txt
```
Uses a custom wordlist for directory brute-forcing. The wordlist should contain one entry per line (e.g., `admin`, `backup`, `uploads`). The toolkit will automatically append common extensions.

---

## Output and Reports

### Text Report
The text report (`bugbounty_report_<target>_<timestamp>.txt`) contains:
- Scan metadata (target, date, duration)
- Executive summary with counts
- Detailed lists of subdomains, open ports, directories, endpoints, vulnerabilities, DNS records, technologies, SSL info, cloud provider, Wayback URLs, and GitHub leaks.
- Security recommendations.

### HTML Report
The HTML report (`bugbounty_report_<target>_<timestamp>.html`) is generated only if Jinja2 is installed. It features:
- A clean, responsive layout.
- Tables for structured data (subdomains, ports, directories, etc.).
- Color-coded vulnerability blocks (red for critical, orange for warnings, green for informational).
- Links to Wayback Machine URLs and GitHub leak pages.
- Expandable sections for long lists.
- The ability to print or save as PDF.

Both reports are saved in the current working directory.

---

## Dependencies

| Package | Purpose | Required? | Installation Command |
|---------|---------|-----------|----------------------|
| `requests` | HTTP requests | Yes | `pip install requests` |
| `beautifulsoup4` | HTML parsing | Yes | `pip install beautifulsoup4` |
| `urllib3` | HTTP library (used by requests) | Yes (indirect) | (installed with requests) |
| `dnspython` | DNS record queries and zone transfers | No* | `pip install dnspython` |
| `python-nmap` | Advanced port scanning | No* | `pip install python-nmap` (requires Nmap system binary) |
| `tqdm` | Progress bars | No* | `pip install tqdm` |
| `jinja2` | HTML report generation | No* | `pip install jinja2` |

*Optional but recommended for full functionality.

To install all optional dependencies at once:
```bash
pip install -r requirements.txt
```
The `requirements.txt` file includes all of the above.

---

## Tips and Best Practices

1. **Start with passive reconnaissance** – Use the `--no-active` (if implemented) or disable active subdomain brute force initially to avoid triggering alerts. Then run a full scan once you have a list of subdomains.
2. **Use API keys** – They significantly improve passive subdomain enumeration and enable GitHub dorking.
3. **Customize wordlists** – Tailor directory and subdomain wordlists to the target's technology stack. For example, if the target uses ASP.NET, include `.aspx` extensions and `web.config`.
4. **Adjust thread count** – High thread counts may cause rate limiting or connection errors. Start with 10 and increase gradually.
5. **Review the HTML report** – It provides a structured overview and helps prioritize findings.
6. **Always obtain authorization** – Unauthorized scanning is illegal and unethical.
7. **Combine with other tools** – Use this toolkit as a first pass, then manually verify findings with tools like Burp Suite or manual testing.

---

## Contributing

Contributions are welcome! If you'd like to add features, fix bugs, or improve documentation:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Make your changes.
4. Commit and push (`git commit -m 'Add some feature'`, `git push origin feature/YourFeature`).
5. Open a pull request.

Please ensure your code follows PEP 8 style guidelines and includes appropriate comments.

---

## License

This project is licensed under the **Educational Use Only** license. Redistribution and commercial use are prohibited without explicit permission. See the `LICENSE` file for details.

---

## Contact

For questions, suggestions, or collaboration, reach out via Instagram: [@the_psycho_of_hackers](https://instagram.com/the_psycho_of_hackers)

---

**Happy Hunting!** 🕵️‍♂️🔒
```
