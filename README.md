```markdown
# Bug Bounty Comprehensive Toolkit v2.1.0

**Educational Purpose Only**  
Created by Psycho ([@the_psycho_of_hackers](https://instagram.com/the_psycho_of_hackers))

A powerful, all-in-one reconnaissance and vulnerability scanning toolkit designed for bug bounty hunters, penetration testers, and cybersecurity students. This tool automates the process of gathering information, discovering assets, and identifying common security flaws in web applications and network services.

> ⚠️ **DISCLAIMER**: This tool is for educational purposes and authorized testing only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The author assumes no liability for misuse.

---

## Features

### 🔍 Reconnaissance
- **Passive Subdomain Enumeration** – Leverages multiple sources: crt.sh, AlienVault OTX, VirusTotal, SecurityTrails, ThreatMiner, Bufferover.run.
- **Active Subdomain Bruteforce** – DNS resolution with custom wordlists and threading.
- **DNS Analysis** – Retrieves A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV records; attempts zone transfer; detects wildcard DNS.
- **Cloud Provider Detection** – Identifies if the target is behind Cloudflare, AWS, Google Cloud, Akamai, Fastly, etc.

### 🌐 Web Application Scanning
- **Directory & File Bruteforce** – Discovers hidden directories and files with extension fuzzing.
- **Endpoint Discovery** – Finds common API endpoints, configuration files, backup files, and admin interfaces.
- **403 Bypass Testing** – Attempts various techniques to bypass forbidden directories.
- **Technology Fingerprinting** – Detects CMS, frameworks, web servers, and client-side libraries.

### 🔬 Vulnerability Assessment
- **SQL Injection** – Basic payload testing against URL parameters.
- **Cross-Site Scripting (XSS)** – Reflected XSS detection.
- **CORS Misconfiguration** – Checks for overly permissive CORS policies.
- **Open Redirect** – Identifies redirect vulnerabilities.
- **Local File Inclusion (LFI)** – Tests for file inclusion flaws.
- **Server-Side Template Injection (SSTI)** – Basic payloads to detect template injection.
- **Security Header Analysis** – Reports missing security headers.
- **Weak SSL/TLS Ciphers** – Detects outdated or weak cipher suites.

### 📦 Additional Modules
- **Wayback Machine Integration** – Fetches historical URLs for expanded attack surface.
- **GitHub Dorking** – Searches for exposed secrets and sensitive data (requires GitHub API key).
- **Port Scanning** – Advanced scanning with service version detection (via Nmap) or simple socket fallback.
- **SSL Certificate Analysis** – Extracts certificate details and checks validity.

### 📊 Reporting
- **Text Report** – Comprehensive summary of findings.
- **HTML Report** – Beautiful, interactive report with tables and color-coded vulnerabilities (requires Jinja2).

---

## Installation

### Prerequisites
- Python 3.6 or higher
- pip (Python package manager)
- (Optional) Nmap installed system-wide for advanced port scanning

### Install from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/psycho/bugbounty-toolkit.git
   cd bugbounty-toolkit
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Install the package globally for command-line access:
   ```bash
   pip install .
   ```

### Using a Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
python3 bugbounty_toolkit.py -d example.com
```

### Scan with Custom Options
```bash
python3 bugbounty_toolkit.py -u https://example.com -t 20 --timeout 15 -o results.txt --wordlist /path/to/wordlist.txt
```

### Skip Certain Modules
```bash
python3 bugbounty_toolkit.py -d example.com --no-ports --no-dns
```

### Provide API Keys for Enhanced Enumeration
Create a JSON file (e.g., `keys.json`):
```json
{
    "virustotal": "YOUR_VT_API_KEY",
    "securitytrails": "YOUR_ST_API_KEY",
    "github": "YOUR_GITHUB_TOKEN"
}
```
Then run:
```bash
python3 bugbounty_toolkit.py -d example.com --api-keys keys.json
```

### Full Command Line Options
```
usage: bugbounty_toolkit.py [-h] [-d DOMAIN] [-u URL] [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT] [--user-agent USER_AGENT] [--wordlist WORDLIST] [--api-keys API_KEYS]
                            [--no-subdomain] [--no-ports] [--no-dns] [--no-ssl] [--no-directories] [--no-endpoints] [--no-vulnerabilities] [--no-technology]
                            [--no-cloud] [--no-wayback] [--no-github]

Bug Bounty Comprehensive Toolkit v2.1.0 - Educational Purpose Only

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain to scan
  -u URL, --url URL     Target URL to scan
  -o OUTPUT, --output OUTPUT
                        Output file for results
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --user-agent USER_AGENT
                        Custom User-Agent string
  --wordlist WORDLIST   Custom wordlist path for directories/subdomains
  --api-keys API_KEYS   JSON file containing API keys (e.g., {"virustotal":"key","github":"key"})

Module Control:
  --no-subdomain        Skip subdomain enumeration
  --no-ports            Skip port scanning
  --no-dns              Skip DNS analysis
  --no-ssl              Skip SSL analysis
  --no-directories      Skip directory bruteforce
  --no-endpoints        Skip endpoint discovery
  --no-vulnerabilities  Skip vulnerability scanning
  --no-technology       Skip technology detection
  --no-cloud            Skip cloud detection
  --no-wayback          Skip Wayback Machine fetch
  --no-github           Skip GitHub dorking
```

---

## Examples

### 1. Full Reconnaissance on a Domain
```bash
python3 bugbounty_toolkit.py -d target.com -o full_scan.txt
```
Generates both text and HTML reports in the current directory.

### 2. Quick Web Vulnerability Scan
```bash
python3 bugbounty_toolkit.py -u https://target.com --no-subdomain --no-ports --no-dns
```

### 3. Subdomain Takeover Potential
```bash
python3 bugbounty_toolkit.py -d target.com --no-directories --no-vulnerabilities
```
Focuses on subdomain enumeration and DNS records.

### 4. Using Custom Wordlist for Directory Bruteforce
```bash
python3 bugbounty_toolkit.py -u https://target.com --wordlist ./my_dirs.txt
```

---

## Output

The toolkit produces two types of reports:
- **Text Report**: `bugbounty_report_<target>_<timestamp>.txt` – concise findings.
- **HTML Report**: `bugbounty_report_<target>_<timestamp>.html` – detailed, styled report with tables.

All discovered URLs and vulnerabilities are also saved to the specified output file (if provided).

---

## Dependencies

| Package       | Purpose                          | Required |
|---------------|----------------------------------|----------|
| requests      | HTTP requests                    | Yes      |
| beautifulsoup4| HTML parsing                     | Yes      |
| urllib3       | HTTP library (used by requests)  | Yes      |
| dnspython     | DNS record retrieval & zone xfr  | No*      |
| python-nmap   | Advanced port scanning            | No*      |
| tqdm          | Progress bars                    | No*      |
| jinja2        | HTML report generation           | No*      |

*Optional but recommended for full functionality.

---

## Contributing

Contributions are welcome! If you have ideas for new features, bug fixes, or improved wordlists, please open an issue or submit a pull request.

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

---

## License

This project is licensed under the **Educational Use Only** license. Redistribution and commercial use are prohibited without explicit permission. See the `LICENSE` file for details.

---

## Credits

- **Psycho** ([@the_psycho_of_hackers](https://instagram.com/the_psycho_of_hackers)) – Creator and maintainer.
- **Open Source Community** – For the amazing libraries that make this tool possible.

---

## Contact

For questions, suggestions, or collaboration, reach out via Instagram: [@the_psycho_of_hackers](https://instagram.com/the_psycho_of_hackers)

---

**Happy Hunting!** 🕵️‍♂️🔒
```
