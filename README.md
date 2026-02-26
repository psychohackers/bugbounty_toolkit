

# 🛡️ Bug Bounty Comprehensive Toolkit v2.1.0

> Educational Purpose Only – Cybersecurity Research Tool
> Created by **Psycho (@the_psycho_of_hackers)**


## 📌 Overview

Bug Bounty Comprehensive Toolkit is an advanced, modular reconnaissance and vulnerability scanning framework built in Python.

It automates:

* Passive & Active Recon
* Subdomain Enumeration
* Port Scanning
* Directory Bruteforcing
* Cloud/CDN Detection
* Vulnerability Testing
* Historical URL Collection
* GitHub Secret Discovery
* Technology Fingerprinting
* DNS & SSL Analysis
* Automated HTML Reporting

⚠️ **This tool is strictly for educational use and authorized testing only.**

---

## 🚀 Features (Detailed Explanation)

### 1️⃣ Subdomain Enumeration

✔ Passive Enumeration:

* crt.sh (Certificate Transparency logs)
* AlienVault OTX
* ThreatMiner
* Bufferover
* VirusTotal (API required)
* SecurityTrails (API required)

✔ Active Enumeration:

* DNS brute-force using wordlists
* Multi-threaded resolution
* Wildcard DNS detection

👉 Why this matters:
Subdomains expand the attack surface. Many vulnerabilities exist on forgotten subdomains.

---

### 2️⃣ Cloud / CDN Detection

Detects if target is behind:

* Cloudflare
* Amazon AWS
* Google Cloud
* Akamai
* Fastly
* CloudFront

Uses:

* IP CIDR matching
* HTTP header fingerprinting

👉 Useful for bypass strategies and understanding infrastructure.

---

### 3️⃣ Advanced Port Scanning

✔ Uses `python-nmap` if installed
✔ Falls back to socket scanning
✔ Detects:

* Open ports
* Services
* Product versions
* Extra service info

Default ports include:
21, 22, 80, 443, 3306, 8080, 8443, 27017, etc.

---

### 4️⃣ Directory Bruteforcing

✔ Multi-threaded directory discovery
✔ Tests multiple extensions:
`.php`, `.html`, `.asp`, `.json`, `.xml`

✔ Flags interesting responses:

* 200
* 301
* 302
* 403
* 401
* 500

---

### 5️⃣ 403 Bypass Testing

Attempts:

* Path manipulation
* Encoding tricks
* Header injection bypass
* X-Forwarded-For tricks

Detects potential access control misconfigurations.

---

### 6️⃣ Vulnerability Scanning

Includes detection for:

| Vulnerability   | Description                      |
| --------------- | -------------------------------- |
| SQL Injection   | Basic injection testing          |
| XSS             | Reflected payload detection      |
| CORS Misconfig  | Dangerous Access-Control headers |
| Open Redirect   | Redirect parameter abuse         |
| LFI             | Local file inclusion attempts    |
| SSTI            | Server-side template injection   |
| Weak SSL Cipher | Insecure TLS cipher detection    |

---

### 7️⃣ DNS Analysis

✔ A, AAAA, MX, TXT, NS records
✔ Zone transfer attempt
✔ Wildcard DNS detection

---

### 8️⃣ SSL/TLS Analysis

✔ Certificate details
✔ Cipher suite detection
✔ Expiry info
✔ Weak cipher detection

---

### 9️⃣ Technology Detection

Detects:

* WordPress
* Drupal
* Joomla
* Laravel
* Django
* React
* Angular
* Vue
* Express
* Apache
* nginx
* IIS
* Cloudflare

Uses HTML fingerprinting + header analysis.

---

### 🔟 Wayback Machine Integration

Fetches:

* Historical URLs
* Hidden endpoints
* Old backup files

---

### 1️⃣1️⃣ GitHub Secret Discovery (API Required)

Searches GitHub for:

* API keys
* Passwords
* Secrets
* Tokens
* .env files
* AWS keys

---

### 📊 Report Generation

✔ Plain text report
✔ Professional HTML report
✔ Executive summary
✔ Vulnerability breakdown
✔ Tables for findings

---

## 🛠 Installation

```bash
git clone https://github.com/psychohackers/bugbounty_toolkit.git
cd bugbounty_toolkit
pip install -r requirements.txt
```

Optional dependencies:

* python-nmap
* dnspython
* jinja2
* tqdm

---

## 📌 Usage

### Basic Scan

```bash
python3 bugbounty_toolkit.py -d example.com
```

### Scan a URL

```bash
python3 bugbounty_toolkit.py -u https://example.com
```

### Increase Threads

```bash
python3 bugbounty_toolkit.py -d example.com -t 20
```

### Use Custom Wordlist

```bash
python3 bugbounty_toolkit.py -d example.com --wordlist custom.txt
```

### Load API Keys

```bash
python3 bugbounty_toolkit.py -d example.com --api-keys keys.json
```

Example keys.json:

```json
{
  "virustotal": "YOUR_KEY",
  "github": "YOUR_KEY",
  "securitytrails": "YOUR_KEY"
}
```

---

## ⚙️ Advanced Module Control

Disable specific modules:

```bash
--no-subdomain
--no-ports
--no-dns
--no-ssl
--no-directories
--no-endpoints
--no-vulnerabilities
--no-technology
--no-cloud
--no-wayback
--no-github
```

Example:

```bash
python3 bugbounty_toolkit.py -d example.com --no-ports --no-dns
```

---

## 🧠 Scan Flow

1. Banner & initialization
2. Subdomain enumeration
3. Cloud detection
4. Port scanning
5. DNS & SSL analysis
6. Directory brute force
7. Vulnerability testing
8. Technology fingerprinting
9. Historical URL collection
10. GitHub leak search
11. Report generation

---

## 🧪 Educational Purpose

This toolkit is designed for:

* Cybersecurity students
* Ethical hackers
* Bug bounty hunters
* Research environments
* Capture The Flag practice

---

## ⚠️ Legal Disclaimer

This tool must only be used:

✔ On systems you own
✔ With written authorization
✔ In legal environments

Unauthorized testing is illegal and punishable by law.

---

## 🔮 Future Improvements (Ideas)

* Graphical dashboard
* AI-based vulnerability correlation
* Burp/ZAP integration
* JSON API export
* CVE auto-matching
* Subdomain takeover detection

---

## 🤝 Contributing

Pull requests welcome.
Feature suggestions encouraged.

---

## 📜 License

Educational Use Only

---


