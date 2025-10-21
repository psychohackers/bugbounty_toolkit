# 🛡️ Bug Bounty Comprehensive Toolkit v2.0.0

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0.0-green)
![License](https://img.shields.io/badge/License-EDUCATIONAL-red)
![Platform](https://img.shields.io/badge/Platform-Linux%2FWindows%2FmacOS-lightgrey)

## ⚠️ DISCLAIMER

**THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY!**

- 🔒 Use only on systems you own or have explicit written permission to test
- ⚖️ Unauthorized testing is illegal and unethical
- 🎯 Created for cybersecurity education and research
- 📝 The creator is not responsible for any misuse

**Created by: Psycho (@the_psycho_of_hackers) - Cybersecurity Education Project**

---

## 🚀 Quick Start

### Installation
```bash
# Clone and install
git clone https://github.com/psychohackers/bugbounty-toolkit.git
cd bugbounty-toolkit
pip install -r requirements.txt

# Or install the package
pip install .
```

### Basic Usage
```bash
# Scan a domain
python bugbounty_toolkit.py -d example.com

# Scan with custom threads
python bugbounty_toolkit.py -d example.com -t 20

# Save results to file
python bugbounty_toolkit.py -d example.com -o results.txt
```

### After Installation (if using setup.py)
```bash
bugbounty-toolkit -d example.com
bbtoolkit -d example.com
psycho-toolkit -d example.com
```

---

## 📋 Features Overview

### 🔍 Reconnaissance
- **Subdomain Enumeration** - Certificate Transparency, DNS brute force
- **Port Scanning** - Nmap integration with service detection  
- **DNS Analysis** - Comprehensive record enumeration
- **SSL/TLS Analysis** - Certificate information extraction

### 📁 Discovery
- **Directory Bruteforce** - Common directories with extensions
- **Endpoint Discovery** - API endpoints and sensitive files
- **Technology Detection** - Frameworks, CMS, server identification
- **Website Crawling** - Basic URL discovery

### 🛡️ Security Testing
- **Vulnerability Scanning** - SQL Injection, XSS detection
- **Security Headers Analysis** - Missing security headers
- **Sensitive Information Discovery** - Environment files, backups
- **Configuration Analysis** - Common misconfigurations

### 📊 Reporting
- **Comprehensive Reports** - Detailed findings with recommendations
- **Color-coded Output** - Easy-to-read terminal interface
- **Multiple Formats** - Console and file export

---

## 🛠️ Complete Installation Guide

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Nmap (for port scanning features)

### Windows Installation
```bash
# 1. Install Python from python.org
# 2. Install Nmap from nmap.org (add to PATH)
# 3. Install toolkit:
pip install -r requirements.txt
```

### Linux Installation
```bash
sudo apt update
sudo apt install python3 python3-pip nmap
pip3 install -r requirements.txt
```

### macOS Installation
```bash
brew install python3 nmap
pip3 install -r requirements.txt
```

### Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

---

## 📖 Complete Usage Guide

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-d, --domain` | Target domain to scan | - |
| `-u, --url` | Target URL to scan | - |
| `-o, --output` | Output file for results | - |
| `-t, --threads` | Number of threads | 10 |
| `--timeout` | Request timeout in seconds | 10 |
| `--user-agent` | Custom User-Agent string | - |
| `--no-subdomain` | Skip subdomain enumeration | - |
| `--no-ports` | Skip port scanning | - |
| `--no-dns` | Skip DNS analysis | - |
| `--no-ssl` | Skip SSL analysis | - |
| `--no-directories` | Skip directory bruteforce | - |
| `--no-endpoints` | Skip endpoint discovery | - |
| `--no-vulnerabilities` | Skip vulnerability scanning | - |
| `--no-technology` | Skip technology detection | - |

### Advanced Usage Examples

```bash
# Comprehensive scan with custom settings
python bugbounty_toolkit.py -d example.com -t 20 --timeout 30 -o full_scan.txt

# Targeted scan (only subdomains and ports)
python bugbounty_toolkit.py -d example.com --no-dns --no-directories --no-vulnerabilities

# URL scan with custom user agent
python bugbounty_toolkit.py -u https://target.com --user-agent "Mozilla/5.0 Custom"

# Skip port scanning (if Nmap not available)
python bugbounty_toolkit.py -d example.com --no-ports
```

---

## 🔧 Module Details

### 1. Subdomain Enumeration
**Methods Used:**
- Certificate Transparency logs (crt.sh)
- DNS brute force with common wordlists
- Common subdomain permutations
- Multi-threaded discovery

**Features:**
- Finds 77+ common subdomains automatically
- Checks certificate transparency databases
- Uses multiple wordlist sources
- Threaded for performance

### 2. Port Scanning
**Requirements:** Nmap installed and in PATH

**Ports Scanned:**
`21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,27017`

**Scan Types:**
- TCP SYN scan (requires privileges)
- TCP connect scan (fallback)
- Service version detection

### 3. Directory Bruteforce
**Directories Checked:**
- Admin panels (`/admin`, `/wp-admin`, `/cpanel`)
- Configuration files (`.env`, `.git`, `.htaccess`)
- Backup files (`/backup`, `/database.sql`)
- Common directories (`/api`, `/uploads`, `/images`)

**File Extensions:**
`[.php, .html, .htm, .asp, .aspx, .jsp, .txt, .bak, .old]`

### 4. DNS Analysis
**Record Types:**
`A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV`

**Features:**
- Comprehensive DNS enumeration
- Subdomain takeover detection
- Mail server configuration analysis

### 5. Vulnerability Scanning
**SQL Injection Testing:**
- Common SQLi payloads
- Error-based detection
- Parameter testing on search endpoints

**XSS Testing:**
- Reflected XSS payloads
- Multiple vector testing
- Common parameter testing

**Security Headers:**
- X-Frame-Options
- Content-Security-Policy
- Strict-Transport-Security
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

### 6. Technology Detection
**Frameworks Detected:**
- WordPress, Drupal, Joomla
- Laravel, Django, Flask
- React, Angular, Vue.js
- Express.js, Ruby on Rails

**Server Detection:**
- Web server identification
- Programming language detection
- JavaScript libraries
- Version information

### 7. SSL/TLS Analysis
**Certificate Information:**
- Subject and issuer details
- Validity periods
- Subject Alternative Names
- Serial numbers

---

## 📊 Output & Reporting

### Report Structure
```
bugbounty_report_example.com_1691234567.txt
├── Executive Summary
├── Subdomains Discovered
├── Open Ports & Services
├── Directory Structure
├── Security Findings
├── DNS Configuration
├── Technology Stack
├── SSL/TLS Information
└── Security Recommendations
```

### Console Output Colors
- 🟢 **Green**: Success findings
- 🟡 **Yellow**: Warnings and information  
- 🔴 **Red**: Errors and critical issues
- 🔵 **Blue**: Status updates

### Sample Output
```bash
╔════════════════════════════════════════════════════════════════╗
║    🛡️  BUG BOUNTY COMPREHENSIVE TOOLKIT v2.0.0 🛡️           ║
╚════════════════════════════════════════════════════════════════╝

[*] Starting comprehensive scan for: example.com
[*] Starting Advanced Subdomain Enumeration...
[+] Found: www.example.com
[+] Found: mail.example.com
[+] Found 15 subdomains
...
[+] Comprehensive report saved as: bugbounty_report_example.com_1691234567.txt
```

---

## 🐛 Troubleshooting Guide

### Common Issues & Solutions

**1. Nmap Not Found**
```bash
# Windows: Download from nmap.org and add to PATH
# Linux: sudo apt install nmap
# macOS: brew install nmap

# Test installation:
nmap --version
```

**2. Python3 Command Not Found (Windows)**
```bash
# Use python instead of python3 on Windows
python bugbounty_toolkit.py -d example.com

# Or use py command
py bugbounty_toolkit.py -d example.com
```

**3. Virtual Environment Issues**
```bash
# Windows activation
venv\Scripts\activate

# Linux/macOS activation  
source venv/bin/activate

# WSL from Windows directory
source /mnt/c/path/to/venv/Scripts/activate
```

**4. Module Import Errors**
```bash
# Reinstall requirements
pip install --upgrade -r requirements.txt

# Force reinstall specific packages
pip install --force-reinstall requests beautifulsoup4 python-nmap
```

**5. Permission Errors (Port Scanning)**
```bash
# Run as administrator/root for SYN scans
sudo python bugbounty_toolkit.py -d example.com  # Linux/macOS
# Run Command Prompt as Admin on Windows
```

**6. SSL Certificate Errors**
- Tool includes proper SSL handling
- Use `--timeout 30` for slow networks
- Certificate transparency may timeout on slow connections

### Performance Tips
- Use `-t` to increase threads for faster scanning
- Use `--timeout` to adjust for slow networks
- Skip unnecessary modules with `--no-*` flags
- Use output file `-o` to save results

---

## 🔒 Legal & Ethical Usage

### ✅ Permitted Usage
- Testing your own systems and applications
- Authorized penetration testing with written permission
- Educational environments and cybersecurity courses
- CTF (Capture The Flag) competitions
- Security research with explicit authorization

### ❌ Prohibited Usage
- Unauthorized testing of systems
- Malicious activities or attacks
- Privacy violation or data theft
- Service disruption or downtime
- Any illegal or unethical activities

### Responsible Disclosure
If you find vulnerabilities during authorized testing:

1. 📝 **Document** findings thoroughly
2. 📧 **Contact** organization responsibly  
3. 🔒 **Follow** their disclosure policy
4. ⏰ **Allow** reasonable time for fixes
5. 🚫 **Never** exploit vulnerabilities maliciously

---

## 🤝 Contributing

### Development Setup
```bash
# Fork and clone repository
git clone https://github.com/psychohackers/bugbounty-toolkit.git
cd bugbounty-toolkit

# Create feature branch
git checkout -b feature/new-feature

# Install in development mode
pip install -e .
```

### Code Guidelines
- Follow PEP 8 style guide
- Add comments for complex logic
- Include proper error handling
- Test on multiple platforms
- Update documentation

### Adding New Modules
1. Create module class method in `BugBountyToolkit` class
2. Add proper error handling and logging
3. Include color-coded output methods
4. Update results collection
5. Add command-line arguments
6. Update README documentation

---

## 🎯 Development Methodology

### Architecture
```python
BugBountyToolkit
├── Reconnaissance (Subdomains, Ports, DNS)
├── Discovery (Directories, Endpoints, Technology)  
├── Security Testing (Vulnerabilities, Headers)
└── Reporting (Console, File Export)
```

### Key Features
- **Modular Design**: Each module operates independently
- **Educational Focus**: Comprehensive code comments
- **Error Handling**: Robust exception management
- **Performance**: Multi-threading for faster scans
- **User-Friendly**: Color-coded output and clear reports

---

## 📞 Support

### Documentation
- Full code documentation in script comments
- Example usage in README
- Troubleshooting guide included

### Issues & Bugs
Report issues at: https://github.com/psychohackers/bugbounty-toolkit/issues

### Educational Resources
- Cybersecurity fundamentals
- Responsible disclosure practices  
- Bug bounty hunting guidelines
- Security testing methodologies

---

## 📜 License

**EDUCATIONAL USE ONLY**

This project is created exclusively for educational purposes in cybersecurity. Users are solely responsible for ensuring they have proper authorization before using this tool.

See [LICENSE](LICENSE) file for complete terms and conditions.

---

## ⚠️ FINAL WARNING

**USE RESPONSIBLY AND ETHICALLY!**

This tool is powerful and should only be used for:
- 🎓 Education and learning
- 🔒 Authorized security testing  
- 📚 Cybersecurity research
- 🛡️ Improving security posture

**Always remember:**
- Get explicit written permission
- Follow responsible disclosure
- Respect privacy and laws
- Use knowledge for good

**Stay Ethical, Stay Secure! 🛡️**

---
*Created by Psycho (@the_psycho_of_hackers) - Cybersecurity Education Project*  
*GitHub: https://github.com/psychohackers*
