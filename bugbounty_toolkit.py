#!/usr/bin/env python3
"""
Comprehensive Bug Bounty Toolkit
Educational Purpose Only - Cybersecurity Project

Version: 2.1.0
Coded by: Psycho (@the_psycho_of_hackers)
Contributors: Community
Disclaimer: Use only on authorized systems and for educational purposes
"""

__version__ = "2.1.0"
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
import ipaddress
import tempfile

# Optional imports for enhanced features
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    def __init__(self, target_domain=None, threads=10, timeout=10, user_agent=None,
                 output_file=None, api_keys=None, wordlist_path=None):
        self.target_domain = target_domain
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.api_keys = api_keys or {}
        self.wordlist_path = wordlist_path
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
            'ssl_info': {},
            'cloud_provider': None,
            'wayback_urls': [],
            'github_leaks': [],
            'cves': []
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

    # -------------------------------------------------------------------------
    # Utility methods
    # -------------------------------------------------------------------------
    def print_status(self, message):
        print(f"{Colors.BLUE}[*] {message}{Colors.END}")

    def print_success(self, message):
        print(f"{Colors.GREEN}[+] {message}{Colors.END}")

    def print_error(self, message):
        print(f"{Colors.RED}[-] {message}{Colors.END}")

    def print_warning(self, message):
        print(f"{Colors.YELLOW}[!] {message}{Colors.END}")

    def save_to_file(self, data):
        if self.output_file:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(data + '\n')

    def banner(self):
        print(f"""{Colors.RED}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    🛡️  BUG BOUNTY COMPREHENSIVE TOOLKIT v2.1.0 🛡️             ║
║                                                                ║
║    Created by: Psycho (@the_psycho_of_hackers)                 ║
║    Contributors: Community                                      ║
║    Purpose: Educational & Cybersecurity Research Only          ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Colors.END}""")

    # -------------------------------------------------------------------------
    # Subdomain enumeration
    # -------------------------------------------------------------------------
    def passive_subdomain_enum(self):
        """Passive subdomain enumeration using various APIs"""
        self.print_status("Starting Passive Subdomain Enumeration...")
        subdomains = set()

        # 1. Certificate Transparency (crt.sh)
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry['name_value'].lower()
                    if '\n' in name:
                        for n in name.split('\n'):
                            if self.target_domain in n:
                                subdomains.add(n.strip())
                    else:
                        if self.target_domain in name:
                            subdomains.add(name.strip())
        except Exception as e:
            self.print_error(f"crt.sh failed: {e}")

        # 2. AlienVault OTX
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target_domain}/passive_dns"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get('passive_dns', []):
                    if entry.get('hostname'):
                        subdomains.add(entry['hostname'].lower())
        except Exception as e:
            self.print_error(f"AlienVault OTX failed: {e}")

        # 3. VirusTotal (requires API key)
        vt_key = self.api_keys.get('virustotal')
        if vt_key:
            try:
                url = f"https://www.virustotal.com/api/v3/domains/{self.target_domain}/subdomains"
                headers = {'x-apikey': vt_key}
                resp = self.session.get(url, headers=headers, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get('data', []):
                        subdomains.add(item['id'].lower())
            except Exception as e:
                self.print_error(f"VirusTotal failed: {e}")

        # 4. SecurityTrails (requires API key)
        st_key = self.api_keys.get('securitytrails')
        if st_key:
            try:
                url = f"https://api.securitytrails.com/v1/domain/{self.target_domain}/subdomains"
                headers = {'APIKEY': st_key}
                resp = self.session.get(url, headers=headers, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    for sub in data.get('subdomains', []):
                        subdomains.add(f"{sub}.{self.target_domain}".lower())
            except Exception as e:
                self.print_error(f"SecurityTrails failed: {e}")

        # 5. ThreatMiner
        try:
            url = f"https://api.threatminer.org/v2/domain.php?q={self.target_domain}&rt=5"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get('results', []):
                    subdomains.add(sub.lower())
        except Exception as e:
            self.print_error(f"ThreatMiner failed: {e}")

        # 6. Bufferover.run (DNS dumpster)
        try:
            url = f"https://dns.bufferover.run/dns?q=.{self.target_domain}"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get('FDNS_A', []):
                    parts = entry.split(',')
                    if len(parts) > 1:
                        subdomains.add(parts[1].strip().lower())
                for entry in data.get('RDNS', []):
                    parts = entry.split(',')
                    if len(parts) > 1:
                        subdomains.add(parts[1].strip().lower())
        except Exception as e:
            self.print_error(f"Bufferover.run failed: {e}")

        self.results['subdomains'].extend(subdomains)
        self.print_success(f"Found {len(subdomains)} subdomains via passive sources")
        return list(subdomains)

    def active_subdomain_enum(self):
        """Active subdomain enumeration via DNS brute force"""
        self.print_status("Starting Active Subdomain Enumeration...")
        found = set()

        # Load wordlist
        wordlists = [
            self.wordlist_path if self.wordlist_path else None,
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt',
            './wordlists/subdomains.txt'
        ]

        valid_wordlist = None
        for wl in wordlists:
            if wl and os.path.exists(wl):
                valid_wordlist = wl
                break

        if not valid_wordlist:
            self.print_warning("No subdomain wordlist found. Using built-in small list.")
            common_subs = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                          'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
                          'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
                          'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',
                          'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'api']
            subs_to_check = common_subs
        else:
            with open(valid_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                subs_to_check = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        def check(sub):
            fqdn = f"{sub}.{self.target_domain}"
            try:
                socket.gethostbyname(fqdn)
                self.print_success(f"Found: {fqdn}")
                return fqdn
            except:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            if TQDM_AVAILABLE:
                futures = {executor.submit(check, sub): sub for sub in subs_to_check}
                for future in tqdm(as_completed(futures), total=len(futures), desc="DNS Brute", unit="sub"):
                    result = future.result()
                    if result:
                        found.add(result)
            else:
                for sub in subs_to_check:
                    result = check(sub)
                    if result:
                        found.add(result)

        self.results['subdomains'].extend(found)
        self.print_success(f"Found {len(found)} active subdomains")
        return list(found)

    def subdomain_enumeration(self):
        """Combined subdomain enumeration (passive + active)"""
        passive = self.passive_subdomain_enum()
        active = self.active_subdomain_enum()
        all_subs = list(set(passive + active))
        self.results['subdomains'] = all_subs
        return all_subs

    # -------------------------------------------------------------------------
    # Cloud detection
    # -------------------------------------------------------------------------
    def cloud_detection(self):
        """Detect if target is behind a cloud provider or CDN"""
        self.print_status("Detecting Cloud Provider / CDN...")
        try:
            ip = socket.gethostbyname(self.target_domain)
            # Check common CDN ranges
            cloud_ranges = {
                'Cloudflare': ['103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '104.16.0.0/12', '108.162.192.0/18', '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15', '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20', '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17'],
                'Amazon AWS': ['13.32.0.0/15', '13.48.0.0/15', '13.112.0.0/14', '52.4.0.0/14', '52.16.0.0/15', '52.32.0.0/14', '52.46.0.0/15', '52.52.0.0/15', '52.64.0.0/17', '52.68.0.0/15', '52.72.0.0/15', '52.74.0.0/16', '52.76.0.0/17', '52.77.0.0/16', '52.84.0.0/15', '52.88.0.0/15', '52.92.0.0/14', '52.192.0.0/15', '52.196.0.0/14', '52.220.0.0/15'],
                'Google Cloud': ['8.34.208.0/20', '8.35.192.0/21', '8.35.200.0/23', '23.236.48.0/20', '23.251.128.0/19', '34.64.0.0/11', '34.96.0.0/12', '34.112.0.0/13', '34.128.0.0/10'],
                'Akamai': ['2.16.0.0/13', '2.20.0.0/14', '23.0.0.0/12', '23.32.0.0/11', '23.64.0.0/14', '23.72.0.0/13', '23.192.0.0/11', '63.208.0.0/12'],
                'Fastly': ['23.235.32.0/20', '104.156.80.0/20', '146.75.0.0/16', '151.101.0.0/16', '199.27.128.0/21'],
                'CloudFront': ['13.32.0.0/15', '13.224.0.0/14', '13.248.0.0/14', '52.84.0.0/15', '54.182.0.0/16', '54.192.0.0/16', '54.230.0.0/16', '54.239.128.0/18', '54.239.192.0/19', '64.252.64.0/18', '71.152.0.0/17', '204.246.164.0/22', '204.246.168.0/22', '205.251.192.0/19', '216.137.32.0/19']
            }

            ip_obj = ipaddress.ip_address(ip)
            for provider, cidrs in cloud_ranges.items():
                for cidr in cidrs:
                    if ip_obj in ipaddress.ip_network(cidr):
                        self.results['cloud_provider'] = provider
                        self.print_success(f"Target is using {provider}")
                        return provider

            # Check headers for CDN
            try:
                resp = self.session.get(f"https://{self.target_domain}", timeout=5)
                headers = resp.headers
                server = headers.get('Server', '')
                via = headers.get('Via', '')
                cf_ray = headers.get('CF-Ray', '')
                x_amz_cf_id = headers.get('X-Amz-Cf-Id', '')

                if 'cloudflare' in server.lower() or cf_ray:
                    self.results['cloud_provider'] = 'Cloudflare'
                elif 'cloudfront' in server.lower() or x_amz_cf_id:
                    self.results['cloud_provider'] = 'CloudFront'
                elif 'akamai' in server.lower() or 'akamaighost' in server.lower():
                    self.results['cloud_provider'] = 'Akamai'
                elif 'fastly' in server.lower() or 'x-fastly-request-id' in headers:
                    self.results['cloud_provider'] = 'Fastly'
                elif 'incapsula' in server.lower():
                    self.results['cloud_provider'] = 'Incapsula'
                elif 'sucuri' in server.lower():
                    self.results['cloud_provider'] = 'Sucuri'
                else:
                    self.results['cloud_provider'] = 'Unknown/None'
            except:
                pass

        except Exception as e:
            self.print_error(f"Cloud detection failed: {e}")

        return self.results.get('cloud_provider')

    # -------------------------------------------------------------------------
    # Port scanning
    # -------------------------------------------------------------------------
    def port_scanning(self, target_ip=None, ports=None):
        """Advanced port scanning with service version detection"""
        if not NMAP_AVAILABLE:
            self.print_error("python-nmap not available. Using socket fallback.")
            return self._port_scan_socket(target_ip, ports)

        self.print_status("Starting Advanced Port Scanning with Nmap...")
        if not target_ip:
            try:
                target_ip = socket.gethostbyname(self.target_domain)
            except:
                self.print_error("Could not resolve domain")
                return []

        nm = nmap.PortScanner()
        port_spec = ports or '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,9090,27017'
        try:
            nm.scan(target_ip, port_spec, arguments='-sV -T4 --open')
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            service = nm[host][proto][port]['name']
                            product = nm[host][proto][port].get('product', '')
                            version = nm[host][proto][port].get('version', '')
                            extrainfo = nm[host][proto][port].get('extrainfo', '')
                            open_ports.append((port, proto, service, product, version, extrainfo))
                            self.print_success(f"Port {port}/{proto}: {service} {product} {version} {extrainfo}")
            self.results['open_ports'] = open_ports
            return open_ports
        except Exception as e:
            self.print_error(f"Nmap scan failed: {e}. Falling back to socket.")
            return self._port_scan_socket(target_ip, ports)

    def _port_scan_socket(self, target_ip, ports):
        """Fallback port scanner using sockets"""
        self.print_status("Using socket port scanner (no version detection)")
        if not ports:
            ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,9090,27017]
        else:
            ports = [int(p.strip()) for p in ports.split(',')]

        open_ports = []
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = 'unknown'
                open_ports.append((port, 'tcp', service, '', '', ''))
                self.print_success(f"Port {port}/tcp open - {service}")
            sock.close()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            if TQDM_AVAILABLE:
                list(tqdm(executor.map(check_port, ports), total=len(ports), desc="Port Scan", unit="port"))
            else:
                executor.map(check_port, ports)

        self.results['open_ports'] = open_ports
        return open_ports

    # -------------------------------------------------------------------------
    # Directory bruteforce and 403 bypass
    # -------------------------------------------------------------------------
    def directory_bruteforce(self, base_url, extensions=None):
        """Directory brute force with status code filtering and fuzzing"""
        self.print_status("Starting Advanced Directory Bruteforce...")

        # Load wordlist
        wordlist_path = self.wordlist_path or './wordlists/directories.txt'
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                dirs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        else:
            # Built-in small list
            dirs = ['admin', 'api', 'backup', 'css', 'js', 'images', 'img', 'uploads', 'files',
                    'include', 'inc', 'src', 'source', 'test', 'tests', 'temp', 'tmp', 'logs',
                    'config', '.git', '.svn', '.env', 'vendor', 'node_modules']

        extensions = extensions or ['', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.do', '.action', '.json', '.xml']

        found = []
        def check(path):
            for ext in extensions:
                url = f"{base_url}/{path}{ext}"
                try:
                    resp = self.session.get(url, timeout=5, allow_redirects=False)
                    # Consider 200, 301, 302, 403, 401 as interesting
                    if resp.status_code in [200, 301, 302, 403, 401, 500]:
                        found.append((url, resp.status_code, len(resp.content)))
                        self.print_success(f"{url} [{resp.status_code}] Size:{len(resp.content)}")
                        self.save_to_file(f"Directory: {url} [{resp.status_code}]")
                        break  # Found with one extension, stop trying others
                except:
                    pass

        if TQDM_AVAILABLE:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                list(tqdm(executor.map(check, dirs), total=len(dirs), desc="Dir brute", unit="path"))
        else:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(check, dirs)

        self.results['directories'] = found
        return found

    def bypass_403(self, base_url):
        """Test for 403 bypass techniques on discovered directories"""
        self.print_status("Testing for 403 bypass techniques...")
        bypasses = []
        # If we have directories with 403 status, try bypass
        for url, code, size in self.results.get('directories', []):
            if code == 403:
                path = url.replace(base_url, '')
                # Various bypass payloads
                payloads = [
                    f"{path}/", f"{path}..;/", f"{path}?", f"{path}?.", f"{path}?testparam",
                    f"{path}.json", f"{path}.xml", f"{path}.php",
                    f"{path}/%2e/", f"{path}/./", f"{path}//", f"//{path}//",
                    f"/%2f{path}", f"/./{path}", f"/{path}/..;/",
                    # Add headers bypass
                ]
                # Also try with different headers
                headers_bypass = [
                    {'X-Original-URL': path},
                    {'X-Rewrite-URL': path},
                    {'Referer': base_url},
                    {'X-Custom-IP-Authorization': '127.0.0.1'},
                    {'X-Forwarded-For': '127.0.0.1'},
                    {'X-Forwarded-Host': '127.0.0.1'},
                    {'X-Real-IP': '127.0.0.1'},
                ]

                for payload in payloads:
                    test_url = base_url + payload
                    try:
                        resp = self.session.get(test_url, timeout=5)
                        if resp.status_code == 200:
                            bypasses.append((url, test_url, 'Path manipulation'))
                            self.print_error(f"Bypass found: {test_url} returned 200")
                            break
                    except:
                        pass

                for headers in headers_bypass:
                    try:
                        resp = self.session.get(base_url + path, headers=headers, timeout=5)
                        if resp.status_code == 200:
                            bypasses.append((url, base_url + path, f"Header bypass: {headers}"))
                            self.print_error(f"Bypass found with header {headers}: returned 200")
                            break
                    except:
                        pass

        self.results['vulnerabilities'].extend([('403 Bypass', b[1], b[2]) for b in bypasses])
        return bypasses

    # -------------------------------------------------------------------------
    # Wayback Machine
    # -------------------------------------------------------------------------
    def wayback_machine(self):
        """Fetch historical URLs from Wayback Machine"""
        self.print_status("Fetching URLs from Wayback Machine...")
        urls = set()
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target_domain}/*&output=json&fl=original&collapse=urlkey"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data[1:]:  # Skip header
                    if entry and len(entry) > 0:
                        urls.add(entry[0])
        except Exception as e:
            self.print_error(f"Wayback Machine failed: {e}")

        self.results['wayback_urls'] = list(urls)
        self.print_success(f"Found {len(urls)} historical URLs")
        return list(urls)

    # -------------------------------------------------------------------------
    # GitHub dorking
    # -------------------------------------------------------------------------
    def github_dorking(self):
        """Search GitHub for exposed secrets related to domain"""
        gh_key = self.api_keys.get('github')
        if not gh_key:
            self.print_warning("GitHub API key not provided. Skipping GitHub dorking.")
            return []

        self.print_status("Searching GitHub for exposed secrets...")
        queries = [
            f'"{self.target_domain}" api_key',
            f'"{self.target_domain}" password',
            f'"{self.target_domain}" secret',
            f'"{self.target_domain}" token',
            f'"{self.target_domain}" aws_access_key',
            f'"{self.target_domain}" .env',
            f'"{self.target_domain}" config',
        ]

        headers = {'Authorization': f'token {gh_key}'}
        results = []

        for query in queries:
            try:
                url = f"https://api.github.com/search/code?q={urllib.parse.quote(query)}"
                resp = self.session.get(url, headers=headers, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get('items', []):
                        repo = item['repository']['full_name']
                        path = item['path']
                        html_url = item['html_url']
                        results.append((query, repo, path, html_url))
                        self.print_error(f"GitHub leak: {html_url}")
                elif resp.status_code == 403:
                    self.print_warning("GitHub API rate limit exceeded")
                    break
            except Exception as e:
                self.print_error(f"GitHub search failed: {e}")

        self.results['github_leaks'] = results
        return results

    # -------------------------------------------------------------------------
    # Vulnerability scanning (SQLi, XSS, CORS, Open Redirect, LFI, SSTI)
    # -------------------------------------------------------------------------
    def advanced_vuln_scan(self, base_url):
        """Run advanced vulnerability checks"""
        self.print_status("Running Advanced Vulnerability Scanning...")

        self._sqli_scan(base_url)
        self._xss_scan(base_url)
        self._cors_misconfig(base_url)
        self._open_redirect(base_url)
        self._lfi_scan(base_url)
        self._ssti_scan(base_url)
        # self._cve_scan()  # Optional external API

    def _sqli_scan(self, base_url):
        """Basic SQL injection detection"""
        self.print_status("Testing for SQL Injection...")
        payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "' OR '1'='1' --", "\" OR \"1\"=\"1\" --"]
        for param in ['id', 'page', 'user', 'name', 'category']:
            for payload in payloads:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=5)
                    # Check for SQL errors in response
                    errors = ['sql', 'mysql', 'syntax error', 'unclosed quotation mark', 'you have an error in your sql']
                    if any(error in resp.text.lower() for error in errors):
                        self.results['vulnerabilities'].append(('SQLi', test_url, f'Possible SQL injection with {payload}'))
                        self.print_error(f"SQLi detected: {test_url}")
                        break
                except:
                    pass

    def _xss_scan(self, base_url):
        """Basic XSS detection"""
        self.print_status("Testing for XSS...")
        payload = "<script>alert('XSS')</script>"
        for param in ['q', 's', 'search', 'id', 'page']:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                resp = self.session.get(test_url, timeout=5)
                if payload in resp.text:
                    self.results['vulnerabilities'].append(('XSS', test_url, f'Reflected XSS with {payload}'))
                    self.print_error(f"XSS detected: {test_url}")
            except:
                pass

    def _cors_misconfig(self, base_url):
        """Check for CORS misconfiguration"""
        self.print_status("Testing CORS misconfiguration...")
        try:
            origin = "https://evil.com"
            headers = {'Origin': origin}
            resp = self.session.get(base_url, headers=headers, timeout=5)
            acao = resp.headers.get('Access-Control-Allow-Origin')
            acac = resp.headers.get('Access-Control-Allow-Credentials')
            if acao == '*' or (acao == origin and acac == 'true'):
                self.results['vulnerabilities'].append(('CORS Misconfig', base_url, f'Allow-Origin: {acao}, Credentials: {acac}'))
                self.print_error(f"CORS misconfiguration detected: {acao} with credentials {acac}")
        except Exception as e:
            pass

    def _open_redirect(self, base_url):
        """Test for open redirect vulnerabilities"""
        self.print_status("Testing Open Redirect...")
        payloads = [
            '//evil.com',
            'https://evil.com',
            '/\\evil.com',
            '?next=evil.com',
            '?redirect=evil.com',
            '?url=evil.com',
            '?return=evil.com'
        ]
        for param in ['redirect', 'url', 'next', 'return', 'r', 'u']:
            for payload in payloads:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                    if resp.status_code in [301, 302] and 'evil.com' in resp.headers.get('Location', ''):
                        self.results['vulnerabilities'].append(('Open Redirect', test_url, f'Redirects to {resp.headers["Location"]}'))
                        self.print_error(f"Open redirect: {test_url} -> {resp.headers['Location']}")
                        break
                except:
                    pass

    def _lfi_scan(self, base_url):
        """Test for Local File Inclusion"""
        self.print_status("Testing LFI...")
        payloads = [
            '../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '..;/..;/..;/etc/passwd',
            'file=../../../../etc/passwd',
            '?page=php://filter/convert.base64-encode/resource=index',
        ]
        for param in ['file', 'page', 'document', 'folder', 'root', 'path', 'pg']:
            for payload in payloads:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=5)
                    if 'root:x:0:0' in resp.text or 'bin/bash' in resp.text or 'BASE64' in resp.text:
                        self.results['vulnerabilities'].append(('LFI', test_url, f'Possible LFI with {payload}'))
                        self.print_error(f"LFI detected: {test_url}")
                        break
                except:
                    pass

    def _ssti_scan(self, base_url):
        """Test for Server-Side Template Injection"""
        self.print_status("Testing SSTI...")
        payloads = [
            '{{7*7}}',
            '${7*7}',
            '{{7*\'7\'}}',
            '<%= 7*7 %>',
            '{{config}}',
            '{{self.__class__.__mro__}}'
        ]
        for param in ['name', 'user', 'id', 'page', 'template']:
            for payload in payloads:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=5)
                    if '49' in resp.text or '7*7' in resp.text:
                        self.results['vulnerabilities'].append(('SSTI', test_url, f'Possible SSTI with {payload}'))
                        self.print_error(f"SSTI detected: {test_url}")
                        break
                except:
                    pass

    # -------------------------------------------------------------------------
    # Technology detection
    # -------------------------------------------------------------------------
    def technology_detection(self, base_url):
        """Enhanced technology detection using fingerprinting"""
        self.print_status("Detecting technologies...")
        # Load fingerprint database (simplified version)
        fingerprints = {
            'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
            'Drupal': [r'drupal.js', r'Drupal.settings', r'SESS[0-9a-z]+='],
            'Joomla': [r'joomla', r'media/jui', r'Joomla!'],
            'Laravel': [r'laravel', r'csrf-token', r'__token'],
            'React': [r'react', r'react-dom', r'__NEXT_DATA__'],
            'Angular': [r'angular', r'ng-', r'ng-app'],
            'Vue.js': [r'vue', r'v-app', r'__vue__'],
            'Django': [r'django', r'csrfmiddlewaretoken'],
            'Flask': [r'flask', r'werkzeug'],
            'Express': [r'express', r'x-powered-by: express'],
            'Ruby on Rails': [r'rails', r'csrf-param', r'csrf-token'],
            'ASP.NET': [r'__VIEWSTATE', r'__EVENTVALIDATION', r'X-AspNet-Version'],
            'nginx': [r'nginx'],
            'Apache': [r'apache'],
            'IIS': [r'iis', r'X-Powered-By: ASP.NET'],
            'Cloudflare': [r'cloudflare', r'CF-Ray'],
            'jQuery': [r'jquery'],
            'Bootstrap': [r'bootstrap'],
        }

        try:
            resp = self.session.get(base_url, timeout=10)
            headers = resp.headers
            html = resp.text.lower()

            detected = []
            # Check headers
            server = headers.get('Server', '')
            powered_by = headers.get('X-Powered-By', '')
            if server:
                detected.append(('Server', server))
            if powered_by:
                detected.append(('X-Powered-By', powered_by))

            # Check HTML
            for tech, patterns in fingerprints.items():
                for pattern in patterns:
                    if re.search(pattern, html, re.I) or re.search(pattern, server, re.I) or re.search(pattern, powered_by, re.I):
                        detected.append(('Technology', tech))
                        break

            # Deduplicate
            tech_list = list(set([(cat, val) for cat, val in detected]))
            self.results['technologies'] = tech_list
            for cat, val in tech_list:
                self.print_success(f"{cat}: {val}")
        except Exception as e:
            self.print_error(f"Technology detection failed: {e}")

    # -------------------------------------------------------------------------
    # DNS analysis
    # -------------------------------------------------------------------------
    def dns_analysis(self):
        """Comprehensive DNS analysis including zone transfer attempts"""
        if not DNS_AVAILABLE:
            self.print_error("dnspython not available. Skipping DNS analysis.")
            return {}

        self.print_status("Starting Comprehensive DNS Analysis...")
        records = {}

        # Standard records
        for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV']:
            try:
                answers = dns.resolver.resolve(self.target_domain, rtype)
                records[rtype] = [str(r) for r in answers]
                self.print_success(f"{rtype} Records:")
                for r in records[rtype]:
                    print(f"    {Colors.CYAN}{r}{Colors.END}")
            except:
                pass

        # Attempt zone transfer
        try:
            ns_answers = dns.resolver.resolve(self.target_domain, 'NS')
            for ns in ns_answers:
                ns = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.target_domain, timeout=5))
                    records['ZoneTransfer'] = [str(zone)]
                    self.print_error(f"Zone transfer succeeded from {ns}!")
                except:
                    pass
        except:
            pass

        # Wildcard detection
        try:
            random_sub = f"rand{random.randint(1000,9999)}.{self.target_domain}"
            socket.gethostbyname(random_sub)
            records['Wildcard'] = True
            self.print_warning("Wildcard DNS detected")
        except:
            records['Wildcard'] = False

        self.results['dns_records'] = records
        return records

    # -------------------------------------------------------------------------
    # SSL analysis
    # -------------------------------------------------------------------------
    def ssl_analysis(self, domain):
        """SSL/TLS certificate analysis with weak cipher detection"""
        self.print_status("Starting SSL/TLS Analysis...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Correct parsing of subject and issuer
                    subject = {k: v for (k, v) in cert['subject']}
                    issuer = {k: v for (k, v) in cert['issuer']}

                    ssl_info = {
                        'subject': subject,
                        'issuer': issuer,
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName'),
                        'cipher': ssock.cipher(),
                    }

                    # Check for weak ciphers (simplified)
                    cipher_name = ssock.cipher()[0]
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'EXPORT', 'NULL']
                    if any(w in cipher_name for w in weak_ciphers):
                        self.results['vulnerabilities'].append(('Weak SSL Cipher', domain, f'Cipher: {cipher_name}'))
                        self.print_error(f"Weak cipher detected: {cipher_name}")

                    self.print_success("SSL Certificate Information:")
                    print(f"    Subject: {subject.get('commonName')}")
                    print(f"    Issuer: {issuer.get('organizationName')}")
                    print(f"    Valid until: {cert.get('notAfter')}")

                    self.results['ssl_info'] = ssl_info
                    return ssl_info
        except Exception as e:
            self.print_error(f"SSL analysis failed: {e}")
            return {}

    # -------------------------------------------------------------------------
    # Endpoint discovery
    # -------------------------------------------------------------------------
    def endpoint_discovery(self, base_url):
        """Discover endpoints from JavaScript files and other sources"""
        self.print_status("Discovering endpoints...")
        endpoints = set()
        try:
            resp = self.session.get(base_url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            # Find script tags with src
            for script in soup.find_all('script', src=True):
                js_url = urllib.parse.urljoin(base_url, script['src'])
                try:
                    js_resp = self.session.get(js_url, timeout=5)
                    # Look for URLs in JS
                    urls = re.findall(r'["\'](/[^"\']*?)["\']', js_resp.text)
                    for u in urls:
                        if u.startswith('/') and not u.startswith('//'):
                            endpoints.add(urllib.parse.urljoin(base_url, u))
                except:
                    pass
            # Also look for links
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('/') and not href.startswith('//'):
                    endpoints.add(urllib.parse.urljoin(base_url, href))
            self.results['endpoints'] = list(endpoints)
            self.print_success(f"Found {len(endpoints)} endpoints")
        except Exception as e:
            self.print_error(f"Endpoint discovery failed: {e}")

    # -------------------------------------------------------------------------
    # Report generation
    # -------------------------------------------------------------------------
    def generate_html_report(self):
        """Generate an HTML report with findings"""
        if not JINJA2_AVAILABLE:
            self.print_warning("Jinja2 not installed. Skipping HTML report.")
            return

        template_str = """
<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Report - {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        h2 { color: #555; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
        .summary { background: #e8f4f8; padding: 10px; border-radius: 5px; }
        .vuln { background: #ffe6e6; padding: 5px; border-left: 4px solid #cc0000; margin: 5px 0; }
        .info { background: #e6ffe6; padding: 5px; border-left: 4px solid #00cc00; }
        .warning { background: #fff3e6; padding: 5px; border-left: 4px solid #ff9900; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .footer { margin-top: 30px; font-size: 0.8em; color: #777; text-align: center; }
    </style>
</head>
<body>
    <h1>Bug Bounty Comprehensive Report</h1>
    <p><strong>Target:</strong> {{ target }}</p>
    <p><strong>Scan Date:</strong> {{ date }}</p>
    <p><strong>Tool Version:</strong> {{ version }}</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <ul>
            <li>Subdomains Found: {{ results.subdomains|length }}</li>
            <li>Open Ports: {{ results.open_ports|length }}</li>
            <li>Directories Found: {{ results.directories|length }}</li>
            <li>Endpoints Found: {{ results.endpoints|length }}</li>
            <li>Vulnerabilities Found: {{ results.vulnerabilities|length }}</li>
            <li>Technologies Detected: {{ results.technologies|length }}</li>
            <li>Historical URLs: {{ results.wayback_urls|length }}</li>
            <li>GitHub Leaks: {{ results.github_leaks|length }}</li>
        </ul>
    </div>
    
    <h2>Subdomains</h2>
    {% if results.subdomains %}
    <table>
        <tr><th>Subdomain</th></tr>
        {% for sub in results.subdomains %}
        <tr><td>{{ sub }}</td></tr>
        {% endfor %}
    </table>
    {% else %}
    <p>None found.</p>
    {% endif %}
    
    <h2>Open Ports</h2>
    {% if results.open_ports %}
    <table>
        <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>
        {% for port in results.open_ports %}
        <tr><td>{{ port[0] }}</td><td>{{ port[1] }}</td><td>{{ port[2] }}</td><td>{{ port[3] }}</td><td>{{ port[4] }} {{ port[5] }}</td></tr>
        {% endfor %}
    </table>
    {% else %}
    <p>None found.</p>
    {% endif %}
    
    <h2>Directories</h2>
    {% if results.directories %}
    <table>
        <tr><th>URL</th><th>Status</th><th>Size</th></tr>
        {% for dir in results.directories %}
        <tr><td>{{ dir[0] }}</td><td>{{ dir[1] }}</td><td>{{ dir[2] }}</td></tr>
        {% endfor %}
    </table>
    {% else %}
    <p>None found.</p>
    {% endif %}
    
    <h2>Vulnerabilities</h2>
    {% if results.vulnerabilities %}
    {% for vuln in results.vulnerabilities %}
    <div class="vuln">
        <strong>{{ vuln[0] }}</strong><br>
        URL: {{ vuln[1] }}<br>
        Details: {{ vuln[2] }}
    </div>
    {% endfor %}
    {% else %}
    <p>No vulnerabilities found.</p>
    {% endif %}
    
    <h2>Technologies</h2>
    {% if results.technologies %}
    <table>
        <tr><th>Category</th><th>Technology</th></tr>
        {% for tech in results.technologies %}
        <tr><td>{{ tech[0] }}</td><td>{{ tech[1] }}</td></tr>
        {% endfor %}
    </table>
    {% else %}
    <p>None detected.</p>
    {% endif %}
    
    <h2>DNS Records</h2>
    {% for rtype, records in results.dns_records.items() %}
    <h3>{{ rtype }}</h3>
    <ul>
        {% for rec in records %}
        <li>{{ rec }}</li>
        {% endfor %}
    </ul>
    {% endfor %}
    
    <h2>SSL/TLS Info</h2>
    {% if results.ssl_info %}
    <pre>{{ results.ssl_info|tojson(indent=2) }}</pre>
    {% endif %}
    
    <h2>Cloud Provider</h2>
    <p>{{ results.cloud_provider or 'Unknown' }}</p>
    
    <h2>Historical URLs (Wayback Machine)</h2>
    {% if results.wayback_urls %}
    <p>Total: {{ results.wayback_urls|length }} (first 50 shown)</p>
    <ul>
        {% for url in results.wayback_urls[:50] %}
        <li><a href="{{ url }}" target="_blank">{{ url }}</a></li>
        {% endfor %}
    </ul>
    {% else %}
    <p>None.</p>
    {% endif %}
    
    <h2>GitHub Leaks</h2>
    {% if results.github_leaks %}
    <table>
        <tr><th>Query</th><th>Repo</th><th>Path</th><th>URL</th></tr>
        {% for leak in results.github_leaks %}
        <tr><td>{{ leak[0] }}</td><td>{{ leak[1] }}</td><td>{{ leak[2] }}</td><td><a href="{{ leak[3] }}">Link</a></td></tr>
        {% endfor %}
    </table>
    {% else %}
    <p>None.</p>
    {% endif %}
    
    <div class="footer">
        Generated by Psycho Bug Bounty Toolkit v{{ version }} | Educational Purpose Only
    </div>
</body>
</html>
        """
        template = Template(template_str)
        html_content = template.render(target=self.target_domain,
                                       date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                       version=__version__,
                                       results=self.results)

        filename = f"bugbounty_report_{self.target_domain}_{int(time.time())}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        self.print_success(f"HTML report saved: {filename}")
        return filename

    def generate_report(self):
        """Generate comprehensive text report"""
        self.print_status("Generating Text Report...")
        report_lines = []
        report_lines.append("BUG BOUNTY TOOLKIT REPORT v2.1.0")
        report_lines.append("=" * 60)
        report_lines.append(f"Target: {self.target_domain}")
        report_lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        report_lines.append("=== SUBDOMAINS ===")
        for sub in self.results['subdomains']:
            report_lines.append(f"  {sub}")
        report_lines.append("")
        report_lines.append("=== OPEN PORTS ===")
        for port in self.results['open_ports']:
            report_lines.append(f"  {port[0]}/{port[1]} - {port[2]} {port[3]} {port[4]} {port[5]}")
        report_lines.append("")
        report_lines.append("=== DIRECTORIES ===")
        for dir in self.results['directories']:
            report_lines.append(f"  {dir[0]} [{dir[1]}] Size:{dir[2]}")
        report_lines.append("")
        report_lines.append("=== VULNERABILITIES ===")
        for vuln in self.results['vulnerabilities']:
            report_lines.append(f"  {vuln[0]} - {vuln[1]} - {vuln[2]}")
        report_lines.append("")
        report_lines.append("=== ENDPOINTS ===")
        for ep in self.results['endpoints']:
            report_lines.append(f"  {ep}")
        report_lines.append("")
        report_lines.append("=== TECHNOLOGIES ===")
        for cat, val in self.results['technologies']:
            report_lines.append(f"  {cat}: {val}")
        report_lines.append("")
        report_lines.append("=== DNS RECORDS ===")
        for rtype, recs in self.results['dns_records'].items():
            report_lines.append(f"  {rtype}: {', '.join(recs)}")
        report_lines.append("")
        report_lines.append("=== SSL INFO ===")
        if self.results['ssl_info']:
            report_lines.append(f"  Subject: {self.results['ssl_info'].get('subject', {}).get('commonName', 'N/A')}")
            report_lines.append(f"  Issuer: {self.results['ssl_info'].get('issuer', {}).get('organizationName', 'N/A')}")
            report_lines.append(f"  Valid Until: {self.results['ssl_info'].get('notAfter', 'N/A')}")
        else:
            report_lines.append("  No SSL info")
        report_lines.append("")
        report_lines.append("=== CLOUD PROVIDER ===")
        report_lines.append(f"  {self.results.get('cloud_provider', 'Unknown')}")
        report_lines.append("")
        report_lines.append("=== WAYBACK MACHINE URLS (first 20) ===")
        for url in self.results['wayback_urls'][:20]:
            report_lines.append(f"  {url}")
        report_lines.append("")
        report_lines.append("=== GITHUB LEAKS ===")
        for leak in self.results['github_leaks']:
            report_lines.append(f"  Query: {leak[0]}, Repo: {leak[1]}, Path: {leak[2]}, URL: {leak[3]}")
        report_lines.append("")
        report_lines.append("=" * 60)
        report_lines.append("Report generated by Psycho Bug Bounty Toolkit - Educational Purpose Only")

        filename = f"bugbounty_report_{self.target_domain}_{int(time.time())}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("\n".join(report_lines))
        self.print_success(f"Text report saved: {filename}")
        return filename

    # -------------------------------------------------------------------------
    # Main orchestration
    # -------------------------------------------------------------------------
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
            # Extract domain from URL
            parsed = urllib.parse.urlparse(base_url)
            self.target_domain = parsed.netloc

        try:
            # Run selected modules
            if options.get('subdomain', True):
                self.subdomain_enumeration()

            if options.get('cloud', True):
                self.cloud_detection()

            if options.get('ports', True):
                self.port_scanning()

            if options.get('dns', True) and DNS_AVAILABLE:
                self.dns_analysis()

            if options.get('ssl', True):
                self.ssl_analysis(self.target_domain)

            if options.get('wayback', True):
                self.wayback_machine()

            if options.get('directories', True):
                self.directory_bruteforce(base_url)
                self.bypass_403(base_url)

            if options.get('endpoints', True):
                self.endpoint_discovery(base_url)

            if options.get('vulnerabilities', True):
                self.advanced_vuln_scan(base_url)

            if options.get('technology', True):
                self.technology_detection(base_url)

            if options.get('github', True) and self.api_keys.get('github'):
                self.github_dorking()

            # Generate reports
            self.generate_report()
            self.generate_html_report()

            self.print_success("Complete! All modules finished successfully.")

        except KeyboardInterrupt:
            self.print_error("Scan interrupted by user")
        except Exception as e:
            self.print_error(f"Error during scan: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Bug Bounty Comprehensive Toolkit v2.1.0 - Educational Purpose Only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bugbounty_toolkit.py -d example.com
  python3 bugbounty_toolkit.py -u https://example.com -t 20 -o results.txt
  python3 bugbounty_toolkit.py -d example.com --api-keys keys.json

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
    parser.add_argument('--wordlist', help='Custom wordlist path for directories/subdomains')
    parser.add_argument('--api-keys', help='JSON file containing API keys (e.g., {"virustotal":"key","github":"key"})')

    # Module selection
    parser.add_argument('--no-subdomain', action='store_true', help='Skip subdomain enumeration')
    parser.add_argument('--no-ports', action='store_true', help='Skip port scanning')
    parser.add_argument('--no-dns', action='store_true', help='Skip DNS analysis')
    parser.add_argument('--no-ssl', action='store_true', help='Skip SSL analysis')
    parser.add_argument('--no-directories', action='store_true', help='Skip directory bruteforce')
    parser.add_argument('--no-endpoints', action='store_true', help='Skip endpoint discovery')
    parser.add_argument('--no-vulnerabilities', action='store_true', help='Skip vulnerability scanning')
    parser.add_argument('--no-technology', action='store_true', help='Skip technology detection')
    parser.add_argument('--no-cloud', action='store_true', help='Skip cloud detection')
    parser.add_argument('--no-wayback', action='store_true', help='Skip Wayback Machine fetch')
    parser.add_argument('--no-github', action='store_true', help='Skip GitHub dorking')

    args = parser.parse_args()

    # Load API keys if provided
    api_keys = {}
    if args.api_keys:
        try:
            with open(args.api_keys, 'r') as f:
                api_keys = json.load(f)
        except Exception as e:
            print(f"Error loading API keys: {e}")

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
        'cloud': not args.no_cloud,
        'wayback': not args.no_wayback,
        'github': not args.no_github,
    }

    toolkit = BugBountyToolkit(
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_file=args.output,
        api_keys=api_keys,
        wordlist_path=args.wordlist
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
