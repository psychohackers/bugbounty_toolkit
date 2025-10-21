#!/usr/bin/env python3
"""
Comprehensive Bug Bounty Toolkit
Educational Purpose Only - Cybersecurity Project

Version: 2.0.0
Coded by: Psycho (@the_psycho_of_hackers)
Disclaimer: Use only on authorized systems and for educational purposes
"""

__version__ = "2.0.0"
__author__ = "Psycho"
__instagram__ = "@the_psycho_of_hackers"
__license__ = "Educational Use Only"

import os
import sys
import subprocess
import requests
import socket
import threading
import time
import argparse
import json
import urllib.parse
import random
import hashlib
import base64
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import ssl
import urllib3
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[!] dnspython not available. DNS features disabled.")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[!] python-nmap not available. Port scanning disabled.")

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class BugBountyToolkit:
    def __init__(self, target_domain=None, threads=10, timeout=10, user_agent=None, output_file=None):
        self.target_domain = target_domain
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.results = {
            'subdomains': [],
            'open_ports': [],
            'directories': [],
            'endpoints': [],
            'vulnerabilities': [],
            'dns_records': {},
            'technologies': [],
            'crawled_urls': [],
            'sensitive_info': [],
            'headers_analysis': [],
            'ssl_info': {}
        }
        
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
    def banner(self):
        print(f"""{Colors.RED}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    🛡️  BUG BOUNTY COMPREHENSIVE TOOLKIT v2.0.0 🛡️             ║
║                                                                ║
║    Created by: Psycho (@the_psycho_of_hackers)                 ║
║    Purpose: Educational & Cybersecurity Research Only          ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Colors.END}""")

    def print_status(self, message, color=Colors.BLUE):
        print(f"{color}[*] {message}{Colors.END}")

    def print_success(self, message):
        print(f"{Colors.GREEN}[+] {message}{Colors.END}")

    def print_warning(self, message):
        print(f"{Colors.YELLOW}[!] {message}{Colors.END}")

    def print_error(self, message):
        print(f"{Colors.RED}[-] {message}{Colors.END}")

    def save_to_file(self, content):
        if self.output_file:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(content + '\n')

    def subdomain_enumeration(self):
        """Advanced subdomain enumeration using multiple techniques"""
        self.print_status("Starting Advanced Subdomain Enumeration...")
        
        subdomains = set()
        
        # Common subdomains wordlist
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 
            'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 
            'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 
            'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'api', 
            'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 
            'sip', 'dns2', 'search', 'staging', 'server', 'cdn', 'stats', 'api', 'app',
            'apps', 'backup', 'backups', 'cdn', 'cloud', 'demo', 'dev', 'development',
            'test', 'testing', 'stage', 'staging', 'prod', 'production', 'secure', 'admin',
            'administrator', 'login', 'dashboard', 'internal', 'private', 'secure', 'ssl'
        ]
        
        # Method 1: Common subdomains
        for sub in common_subs:
            subdomains.add(f"{sub}.{self.target_domain}")

        # Method 2: Certificate Transparency
        self.print_status("Checking Certificate Transparency logs...")
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    name_value = cert['name_value'].lower().strip()
                    if self.target_domain in name_value:
                        if '\n' in name_value:
                            for sub in name_value.split('\n'):
                                if self.target_domain in sub:
                                    subdomains.add(sub)
                        else:
                            subdomains.add(name_value)
        except Exception as e:
            self.print_error(f"Certificate Transparency failed: {e}")

        # Method 3: DNS brute force with threading
        self.print_status("Starting DNS brute force...")
        wordlists = [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt',
            './wordlists/subdomains.txt',
            '/usr/share/wordlists/amass/subdomains.txt'
        ]

        def check_subdomain(sub):
            test_sub = f"{sub}.{self.target_domain}"
            try:
                socket.gethostbyname(test_sub)
                subdomains.add(test_sub)
                self.print_success(f"Found: {test_sub}")
                return test_sub
            except:
                return None

        valid_wordlists = []
        for wordlist_path in wordlists:
            if os.path.exists(wordlist_path):
                valid_wordlists.append(wordlist_path)

        if valid_wordlists:
            all_subs = set()
            for wordlist_path in valid_wordlists:
                try:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            sub = line.strip()
                            if sub and not sub.startswith('#'):
                                all_subs.add(sub)
                except Exception as e:
                    self.print_error(f"Error reading {wordlist_path}: {e}")

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(check_subdomain, sub) for sub in list(all_subs)[:1000]]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        self.save_to_file(f"Subdomain: {result}")

        self.results['subdomains'] = list(subdomains)
        self.print_success(f"Found {len(subdomains)} subdomains")
        return list(subdomains)

    def port_scanning(self, target_ip=None):
        """Advanced port scanning with service detection"""
        if not NMAP_AVAILABLE:
            self.print_error("Nmap not available. Skipping port scanning.")
            return []

        self.print_status("Starting Advanced Port Scanning...")
        
        if not target_ip:
            try:
                target_ip = socket.gethostbyname(self.target_domain)
                self.print_success(f"Resolved IP: {target_ip}")
            except Exception as e:
                self.print_error(f"Could not resolve domain: {e}")
                return []

        nm = nmap.PortScanner()
        try:
            # Common ports for web applications
            common_ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,27017'
            
            self.print_status(f"Scanning common ports on {target_ip}...")
            nm.scan(target_ip, common_ports, arguments='-sS -T4 --open')
            
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            service = nm[host][proto][port]['name']
                            version = nm[host][proto][port].get('version', 'Unknown')
                            open_ports.append((port, proto, service, version))
                            self.print_success(f"Open Port: {port}/{proto} - {service} ({version})")
                            self.save_to_file(f"Open Port: {port}/{proto} - {service} ({version})")

            self.results['open_ports'] = open_ports
            return open_ports
        except Exception as e:
            self.print_error(f"Port scanning failed: {e}")
            return []

    def directory_bruteforce(self, base_url):
        """Advanced directory and file brute force"""
        self.print_status("Starting Advanced Directory Bruteforce...")
        
        # Extended directory wordlist
        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'wp-login', 'phpmyadmin', 
            'cpanel', 'webmail', 'backup', 'backups', 'uploads', 'images', 'css', 
            'js', 'api', 'doc', 'docs', 'test', 'demo', 'old', 'new', 'dev',
            'config', 'include', 'inc', 'src', 'source', 'assets', 'static',
            'files', 'database', 'db', 'sql', 'bak', 'tmp', 'temp', 'cache',
            'logs', 'archive', 'old-site', 'beta', 'staging', 'debug',
            'phpinfo', 'info', 'test.php', 'admin.php', 'config.php',
            '.git', '.svn', '.env', '.htaccess', 'robots.txt', 'sitemap.xml',
            'crossdomain.xml', 'clientaccesspolicy.xml'
        ]
        
        # File extensions to try
        extensions = ['', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.txt', '.bak', '.old']
        
        found_dirs = []
        
        def check_directory(dir_path):
            for ext in extensions:
                url = f"{base_url}/{dir_path}{ext}"
                try:
                    response = self.session.get(url, timeout=5, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403, 401]:
                        found_dirs.append((url, response.status_code, len(response.content)))
                        status_color = Colors.GREEN if response.status_code == 200 else Colors.YELLOW
                        print(f"{status_color}[+] Found: {url} [{response.status_code}] - Size: {len(response.content)} bytes{Colors.END}")
                        self.save_to_file(f"Directory: {url} [{response.status_code}]")
                        break
                except Exception:
                    pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_directory, common_dirs)
        
        self.results['directories'] = found_dirs
        return found_dirs

    def endpoint_discovery(self, base_url):
        """Advanced API endpoint and sensitive file discovery"""
        self.print_status("Starting Advanced Endpoint Discovery...")
        
        endpoints = [
            # Common files
            'robots.txt', 'sitemap.xml', '.htaccess', '.git/HEAD', '.env',
            'web.config', 'crossdomain.xml', 'clientaccesspolicy.xml',
            
            # API endpoints
            'api/v1', 'api/v2', 'api/v3', 'v1/api', 'v2/api', 'v3/api',
            'graphql', 'api/graphql', 'rest/api', 'api/rest',
            'swagger.json', 'swagger-ui.html', 'api-docs', 'openapi.json',
            
            # Configuration files
            'config.json', 'package.json', 'composer.json', 'yarn.lock',
            'package-lock.json', 'pom.xml', 'build.gradle', 'requirements.txt',
            
            # Backup files
            'backup.zip', 'backup.tar', 'backup.tar.gz', 'backup.sql',
            'dump.sql', 'database.sql', 'backup.rar',
            
            # Log files
            'logs/access.log', 'logs/error.log', 'access.log', 'error.log',
            
            # Admin interfaces
            'admin/', 'administrator/', 'wp-admin/', 'manager/', 'webadmin/'
        ]
        
        found_endpoints = []
        
        for endpoint in endpoints:
            url = f"{base_url}/{endpoint}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 301, 302, 403, 401]:
                    found_endpoints.append((endpoint, response.status_code, len(response.content)))
                    self.print_success(f"Found: {url} [{response.status_code}]")
                    self.save_to_file(f"Endpoint: {url} [{response.status_code}]")
                    
                    # Special handling for important files
                    if endpoint == 'robots.txt' and response.status_code == 200:
                        self.print_warning("Robots.txt content:")
                        for line in response.text.split('\n'):
                            if line.strip() and not line.startswith('#'):
                                print(f"    {Colors.CYAN}{line.strip()}{Colors.END}")
                    
                    elif '.env' in endpoint and response.status_code == 200:
                        self.print_warning(f"Potential .env file found: {url}")
            except Exception as e:
                pass
        
        self.results['endpoints'] = found_endpoints
        return found_endpoints

    def vulnerability_scanning(self, base_url):
        """Advanced vulnerability scanning"""
        self.print_status("Starting Advanced Vulnerability Scanning...")
        
        vulnerabilities = []
        
        # SQL Injection payloads
        sql_payloads = [
            "'", "';", "' OR '1'='1", "' UNION SELECT 1,2,3--", 
            "' AND 1=1--", "' AND 1=2--", "') OR ('1'='1",
            "1' ORDER BY 1--", "1' ORDER BY 10--"
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            '"><script>alert("XSS")</script>',
            "javascript:alert('XSS')",
            "<svg onload=alert(1)>"
        ]
        
        # Test parameters for common endpoints
        test_params = ['q', 'search', 'id', 'page', 'file', 'name', 'user', 'email']
        
        # SQL Injection testing
        self.print_status("Testing for SQL Injection...")
        for param in test_params:
            for payload in sql_payloads:
                test_url = f"{base_url}/search?{param}={urllib.parse.quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    error_indicators = [
                        'sql', 'mysql', 'ora-', 'syntax', 'database', 'query failed',
                        'you have an error', 'warning', 'mysql_fetch', 'pg_',
                        'microsoft odbc', 'odbc driver', 'postgresql', 'oracle'
                    ]
                    if any(error in response.text.lower() for error in error_indicators):
                        vulnerabilities.append(('SQL Injection', test_url, 'Potential SQLi detected'))
                        self.print_error(f"Possible SQL Injection: {test_url}")
                        break
                except:
                    pass
        
        # XSS testing
        self.print_status("Testing for XSS...")
        for param in test_params:
            for payload in xss_payloads:
                test_url = f"{base_url}/search?{param}={urllib.parse.quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    if payload in response.text:
                        vulnerabilities.append(('XSS', test_url, 'Reflected XSS possible'))
                        self.print_error(f"Possible XSS: {test_url}")
                        break
                except:
                    pass
        
        # Security headers analysis
        self.print_status("Analyzing security headers...")
        try:
            response = self.session.get(base_url, timeout=5)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HSTS enforcement',
                'Content-Security-Policy': 'Content Security Policy',
                'X-XSS-Protection': 'XSS protection',
                'Referrer-Policy': 'Referrer information control',
                'Permissions-Policy': 'Browser features control'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulnerabilities.append(('Missing Security Header', header, description))
                    self.print_warning(f"Missing security header: {header} - {description}")
                else:
                    self.print_success(f"Security header present: {header} = {headers[header]}")
        except Exception as e:
            self.print_error(f"Header analysis failed: {e}")
        
        self.results['vulnerabilities'] = vulnerabilities
        return vulnerabilities

    def dns_analysis(self):
        """Advanced DNS record analysis"""
        if not DNS_AVAILABLE:
            self.print_error("dnspython not available. Skipping DNS analysis.")
            return {}

        self.print_status("Starting Advanced DNS Analysis...")
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV']
        dns_records = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target_domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
                self.print_success(f"{record_type} Records:")
                for record in dns_records[record_type]:
                    print(f"    {Colors.CYAN}{record}{Colors.END}")
                    self.save_to_file(f"DNS {record_type}: {record}")
            except Exception as e:
                self.print_warning(f"No {record_type} records found: {e}")
        
        self.results['dns_records'] = dns_records
        return dns_records

    def technology_detection(self, base_url):
        """Advanced technology detection"""
        self.print_status("Starting Advanced Technology Detection...")
        
        technologies = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            headers = response.headers
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Server detection from headers
            server_headers = ['Server', 'X-Powered-By', 'X-Generator', 'X-AspNet-Version']
            for header in server_headers:
                if header in headers:
                    tech_value = headers[header]
                    technologies.append(('Server Header', f"{header}: {tech_value}"))
                    self.print_success(f"Server Technology: {header} = {tech_value}")
            
            # Framework detection
            framework_indicators = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Drupal': ['drupal.js', 'drupal.css', 'Drupal.settings'],
                'Joomla': ['joomla', 'media/jui', 'Joomla!'],
                'Laravel': ['laravel', 'csrf-token', 'Illuminate'],
                'React': ['react', 'react-dom', '__NEXT_DATA__'],
                'Angular': ['angular', 'ng-', 'ng-app'],
                'Vue.js': ['vue', 'v-app', '__vue__'],
                'Django': ['django', 'csrfmiddlewaretoken'],
                'Flask': ['flask', 'werkzeug'],
                'Express.js': ['express', 'x-powered-by: express'],
                'Ruby on Rails': ['rails', 'csrf-param']
            }
            
            for framework, indicators in framework_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in html_content.lower() or \
                       any(indicator.lower() in headers.get(h, '').lower() for h in headers):
                        technologies.append(('Framework', framework))
                        self.print_success(f"Framework detected: {framework}")
                        break
            
            # CMS detection
            if any(indicator in html_content.lower() for indicator in ['wp-content', 'wp-includes']):
                technologies.append(('CMS', 'WordPress'))
                self.print_success("CMS: WordPress")
            elif 'drupal' in html_content.lower():
                technologies.append(('CMS', 'Drupal'))
                self.print_success("CMS: Drupal")
            elif 'joomla' in html_content.lower():
                technologies.append(('CMS', 'Joomla'))
                self.print_success("CMS: Joomla")
            
        except Exception as e:
            self.print_error(f"Technology detection failed: {e}")
        
        self.results['technologies'] = technologies
        return technologies

    def ssl_analysis(self, domain):
        """SSL/TLS certificate analysis"""
        self.print_status("Starting SSL/TLS Analysis...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Certificate information
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    ssl_info = {
                        'subject': subject,
                        'issuer': issuer,
                        'version': cert.get('version', 'Unknown'),
                        'serialNumber': cert.get('serialNumber', 'Unknown'),
                        'notBefore': cert.get('notBefore', 'Unknown'),
                        'notAfter': cert.get('notAfter', 'Unknown'),
                        'subjectAltName': cert.get('subjectAltName', []),
                    }
                    
                    self.print_success("SSL Certificate Information:")
                    print(f"    {Colors.CYAN}Subject: {subject.get('commonName', 'N/A')}{Colors.END}")
                    print(f"    {Colors.CYAN}Issuer: {issuer.get('organizationName', 'N/A')}{Colors.END}")
                    print(f"    {Colors.CYAN}Valid From: {cert.get('notBefore', 'N/A')}{Colors.END}")
                    print(f"    {Colors.CYAN}Valid Until: {cert.get('notAfter', 'N/A')}{Colors.END}")
                    
                    self.results['ssl_info'] = ssl_info
                    return ssl_info
                    
        except Exception as e:
            self.print_error(f"SSL analysis failed: {e}")
            return {}

    def generate_report(self):
        """Generate comprehensive report"""
        self.print_status("Generating Comprehensive Report...")
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Format subdomains
        subdomains_text = "\n".join([f"  - {sub}" for sub in self.results.get('subdomains', [])]) or "  None found"
        
        # Format open ports
        ports_text = "\n".join([f"  - {port[0]}/{port[1]} - {port[2]} ({port[3]})" for port in self.results.get('open_ports', [])]) or "  None found"
        
        # Format directories
        dirs_text = "\n".join([f"  - {dir[0]} [{dir[1]}] - {dir[2]} bytes" for dir in self.results.get('directories', [])]) or "  None found"
        
        # Format endpoints
        endpoints_text = "\n".join([f"  - {endpoint[0]} [{endpoint[1]}] - {endpoint[2]} bytes" for endpoint in self.results.get('endpoints', [])]) or "  None found"
        
        # Format vulnerabilities
        vulns_text = "\n".join([f"  - {vuln[0]}: {vuln[1]} - {vuln[2]}" for vuln in self.results.get('vulnerabilities', [])]) or "  None found"
        
        # Format DNS records
        dns_text = ""
        for rtype, records in self.results.get('dns_records', {}).items():
            dns_text += f"  {rtype}:\n"
            for record in records:
                dns_text += f"    - {record}\n"
        dns_text = dns_text or "  None found"
        
        # Format technologies
        tech_text = "\n".join([f"  - {tech[0]}: {tech[1]}" for tech in self.results.get('technologies', [])]) or "  None found"
        
        # Format SSL info
        ssl_text = "\n".join([f"  {key}: {value}" for key, value in self.results.get('ssl_info', {}).items()]) or "  None found"
        
        report = f"""
BUG BOUNTY TOOLKIT REPORT v2.0.0
=================================
Target: {self.target_domain}
Scan Date: {timestamp}
Generated by: Psycho Bug Bounty Toolkit (@the_psycho_of_hackers)

EXECUTIVE SUMMARY:
------------------
Subdomains Found: {len(self.results.get('subdomains', []))}
Open Ports: {len(self.results.get('open_ports', []))}
Directories Found: {len(self.results.get('directories', []))}
Endpoints Found: {len(self.results.get('endpoints', []))}
Vulnerabilities Found: {len(self.results.get('vulnerabilities', []))}
Technologies Detected: {len(self.results.get('technologies', []))}

DETAILED FINDINGS:
==================

SUBDOMAINS:
-----------
{subdomains_text}

OPEN PORTS:
-----------
{ports_text}

DIRECTORIES FOUND:
------------------
{dirs_text}

ENDPOINTS FOUND:
----------------
{endpoints_text}

VULNERABILITIES:
----------------
{vulns_text}
  
DNS RECORDS:
------------
{dns_text}

TECHNOLOGIES DETECTED:
----------------------
{tech_text}

SSL/TLS INFORMATION:
--------------------
{ssl_text}

SECURITY RECOMMENDATIONS:
-------------------------
1. Implement proper security headers
2. Regularly update all software components
3. Conduct periodic security assessments
4. Implement WAF protection
5. Enable proper logging and monitoring

DISCLAIMER:
-----------
This report is generated for EDUCATIONAL PURPOSES ONLY.
Use this information only on systems you own or have explicit permission to test.
Unauthorized testing is illegal and unethical.

{__instagram__} - Educational Cybersecurity Project
        """
        
        filename = f"bugbounty_report_{self.target_domain}_{int(time.time())}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.print_success(f"Comprehensive report saved as: {filename}")
        return report

    def run_complete_scan(self, target_domain, options=None):
        """Run complete bug bounty reconnaissance with advanced options"""
        self.target_domain = target_domain
        self.banner()
        
        options = options or {}
        self.print_status(f"Starting comprehensive scan for: {target_domain}")
        
        # Ensure URL has scheme
        if not target_domain.startswith(('http://', 'https://')):
            base_url = f"https://{target_domain}"
        else:
            base_url = target_domain
        
        try:
            # Run selected modules based on options
            if options.get('subdomain', True):
                self.subdomain_enumeration()
                time.sleep(1)
            
            if options.get('ports', True) and NMAP_AVAILABLE:
                self.port_scanning()
                time.sleep(1)
            
            if options.get('dns', True) and DNS_AVAILABLE:
                self.dns_analysis()
                time.sleep(1)
            
            if options.get('ssl', True):
                self.ssl_analysis(self.target_domain)
                time.sleep(1)
            
            if options.get('directories', True):
                self.directory_bruteforce(base_url)
                time.sleep(1)
            
            if options.get('endpoints', True):
                self.endpoint_discovery(base_url)
                time.sleep(1)
            
            if options.get('vulnerabilities', True):
                self.vulnerability_scanning(base_url)
                time.sleep(1)
            
            if options.get('technology', True):
                self.technology_detection(base_url)
                time.sleep(1)
            
            # Generate final report
            self.generate_report()
            
            self.print_success("Complete! All modules finished successfully.")
            
        except KeyboardInterrupt:
            self.print_error("Scan interrupted by user")
        except Exception as e:
            self.print_error(f"Error during scan: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Bug Bounty Comprehensive Toolkit v2.0.0 - Educational Purpose Only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bugbounty_toolkit.py -d example.com
  python3 bugbounty_toolkit.py -u https://example.com -t 20 -o scan_results.txt
  python3 bugbounty_toolkit.py -d example.com --no-ports

Advanced Options:
  Use --help to see all available options for customized scanning.

Disclaimer:
  This tool is for EDUCATIONAL PURPOSES ONLY. Always get proper authorization.
  Created by Psycho (@the_psycho_of_hackers)
        """
    )
    
    parser.add_argument('-d', '--domain', help='Target domain to scan')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    # Module selection
    parser.add_argument('--no-subdomain', action='store_true', help='Skip subdomain enumeration')
    parser.add_argument('--no-ports', action='store_true', help='Skip port scanning')
    parser.add_argument('--no-dns', action='store_true', help='Skip DNS analysis')
    parser.add_argument('--no-ssl', action='store_true', help='Skip SSL analysis')
    parser.add_argument('--no-directories', action='store_true', help='Skip directory bruteforce')
    parser.add_argument('--no-endpoints', action='store_true', help='Skip endpoint discovery')
    parser.add_argument('--no-vulnerabilities', action='store_true', help='Skip vulnerability scanning')
    parser.add_argument('--no-technology', action='store_true', help='Skip technology detection')
    
    args = parser.parse_args()
    
    # Build options dictionary
    options = {
        'subdomain': not args.no_subdomain,
        'ports': not args.no_ports,
        'dns': not args.no_dns,
        'ssl': not args.no_ssl,
        'directories': not args.no_directories,
        'endpoints': not args.no_endpoints,
        'vulnerabilities': not args.no_vulnerabilities,
        'technology': not args.no_technology,
    }
    
    toolkit = BugBountyToolkit(
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_file=args.output
    )
    
    if args.domain:
        toolkit.run_complete_scan(args.domain, options)
    elif args.url:
        toolkit.run_complete_scan(args.url, options)
    else:
        toolkit.banner()
        print(f"\n{Colors.YELLOW}Usage examples:{Colors.END}")
        print("  python3 bugbounty_toolkit.py -d example.com")
        print("  python3 bugbounty_toolkit.py -u https://example.com")
        print("  python3 bugbounty_toolkit.py -d example.com --no-ports --no-dns")
        print(f"\n{Colors.RED}DISCLAIMER: For educational and authorized testing only!{Colors.END}")

if __name__ == "__main__":
    # Disclaimer
    print(f"""
{Colors.RED}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                       ⚠️  DISCLAIMER ⚠️                       ║
║                                                                ║
║  THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY!                   ║
║  USE ONLY ON SYSTEMS YOU OWN OR HAVE EXPLICIT PERMISSION TO    ║
║  TEST. UNAUTHORIZED ACCESS IS ILLEGAL AND UNETHICAL.           ║
║                                                                ║
║  Created by: Psycho (@the_psycho_of_hackers)                   ║
║  Cybersecurity Education Project                               ║
╚════════════════════════════════════════════════════════════════╝
{Colors.END}""")
    
    time.sleep(2)
    main()