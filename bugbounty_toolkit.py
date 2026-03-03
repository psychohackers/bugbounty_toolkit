#!/usr/bin/env python3
"""
Comprehensive Bug Bounty Toolkit
Educational Purpose Only - Cybersecurity Project

Version: 2.1.0
Coded by: Psycho (@the_psycho_of_hackers)
Contributors: Community
Disclaimer: Use only on authorized systems and for educational purposes
"""

__version__ = "3.0.0"
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
            'vulnerabilities': [],       # (type, url, detail, severity)
            'dns_records': {},
            'technologies': [],
            'crawled_urls': [],
            'sensitive_info': [],
            'headers_analysis': [],
            'ssl_info': {},
            'cloud_provider': None,
            'wayback_urls': [],
            'github_leaks': [],
            'cves': [],
            'waf': None,
            'takeover_candidates': [],
            'security_headers': [],
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
        lines = [
            f"{Colors.RED}{Colors.BOLD}",
            r"  ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗",
            r"  ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝",
            r"  ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ ",
            r"  ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  ",
            r"  ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   ",
            r"  ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   ",
            f"{Colors.END}",
            f"{Colors.PURPLE}{Colors.BOLD}  ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗{Colors.END}",
            f"{Colors.PURPLE}{Colors.BOLD}  ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝{Colors.END}",
            f"{Colors.CYAN}{Colors.BOLD}     ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   {Colors.END}",
            f"{Colors.CYAN}{Colors.BOLD}     ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   {Colors.END}",
            f"{Colors.GREEN}{Colors.BOLD}     ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   {Colors.END}",
            f"{Colors.GREEN}{Colors.BOLD}     ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   {Colors.END}",
        ]
        for line in lines:
            print(line)
        print()
        info = [
            f"  {Colors.YELLOW}{'─'*70}{Colors.END}",
            f"  {Colors.BOLD}{Colors.WHITE}  🛡️  Advanced Bug Bounty Toolkit  {Colors.CYAN}v{__version__}{Colors.END}",
            f"  {Colors.WHITE}  👤  Author  : {Colors.GREEN}Psycho {Colors.CYAN}(@the_psycho_of_hackers){Colors.END}",
            f"  {Colors.WHITE}  🎯  Purpose : {Colors.YELLOW}Advanced Vulnerability Research & Bug Bounty{Colors.END}",
            f"  {Colors.WHITE}  ⚡  Modules : {Colors.RED}Recon · Vulns · SSRF · XXE · JWT · WAF · S3 · GraphQL{Colors.END}",
            f"  {Colors.YELLOW}{'─'*70}{Colors.END}",
        ]
        for line in info:
            print(line)
        print()

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
                for entry in (data.get('FDNS_A') or []):
                    if not isinstance(entry, str):
                        continue
                    parts = entry.split(',')
                    if len(parts) > 1:
                        subdomains.add(parts[1].strip().lower())
                for entry in (data.get('RDNS') or []):
                    if not isinstance(entry, str):
                        continue
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

        # Classic web vulns
        self._sqli_scan(base_url)
        self._xss_scan(base_url)
        self._cors_misconfig(base_url)
        self._open_redirect(base_url)
        self._lfi_scan(base_url)
        self._ssti_scan(base_url)

        # Advanced vuln modules
        self._ssrf_scan(base_url)
        self._xxe_scan(base_url)
        self._host_header_injection(base_url)
        self._crlf_injection(base_url)
        self._clickjacking_check(base_url)
        self._graphql_check(base_url)
        self._jwt_check(base_url)
        self._request_smuggling_check(base_url)
        self._hpp_scan(base_url)

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

    # ==================== new advanced vuln modules ==========================

    def _ssrf_scan(self, base_url):
        """Test for Server-Side Request Forgery (SSRF)"""
        self.print_status("Testing for SSRF...")
        ssrf_targets = [
            'http://127.0.0.1', 'http://localhost', 'http://169.254.169.254',
            'http://metadata.google.internal', 'http://[::1]',
        ]
        params = ['url', 'uri', 'redirect', 'dest', 'path', 'fetch', 'load',
                  'next', 'data', 'resource', 'img', 'src', 'href', 'callback']
        for param in params:
            for target in ssrf_targets[:2]:  # Limit to avoid slowness
                test_url = f"{base_url}?{param}={urllib.parse.quote(target)}"
                try:
                    resp = self.session.get(test_url, timeout=5)
                    # SSRF indicators
                    indicators = ['ami-id', 'iam', 'computeMetadata', 'root:x', 'localhost']
                    if any(ind in resp.text for ind in indicators):
                        self.results['vulnerabilities'].append(
                            ('SSRF', test_url, f'Possible SSRF via param={param} target={target}', 'CRITICAL'))
                        self.print_error(f"SSRF detected: {test_url}")
                        return
                except:
                    pass

    def _xxe_scan(self, base_url):
        """Test for XML External Entity (XXE) injection"""
        self.print_status("Testing for XXE...")
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        headers = {'Content-Type': 'application/xml'}
        try:
            resp = self.session.post(base_url, data=xxe_payload, headers=headers, timeout=8)
            if 'root:x:0:0' in resp.text or 'bin/bash' in resp.text:
                self.results['vulnerabilities'].append(
                    ('XXE Injection', base_url, 'XXE via /etc/passwd disclosure', 'CRITICAL'))
                self.print_error(f"XXE detected: {base_url}")
        except:
            pass
        # Try GET endpoints that might parse XML
        for path in ['/api', '/xml', '/soap', '/ws', '/service']:
            try:
                resp = self.session.post(f"{base_url}{path}", data=xxe_payload, headers=headers, timeout=5)
                if 'root:x:0:0' in resp.text:
                    self.results['vulnerabilities'].append(
                        ('XXE Injection', f"{base_url}{path}", 'XXE via /etc/passwd', 'CRITICAL'))
                    self.print_error(f"XXE detected: {base_url}{path}")
            except:
                pass

    def _host_header_injection(self, base_url):
        """Test for Host Header Injection"""
        self.print_status("Testing Host Header Injection...")
        poison_host = 'evil.attacker.com'
        try:
            resp = self.session.get(base_url, headers={'Host': poison_host}, timeout=5)
            if poison_host in resp.text or (resp.status_code in [301, 302]
                    and poison_host in resp.headers.get('Location', '')):
                self.results['vulnerabilities'].append(
                    ('Host Header Injection', base_url,
                     f'Host: {poison_host} reflected in response', 'HIGH'))
                self.print_error(f"Host Header Injection: {base_url}")
        except:
            pass
        # Also test X-Forwarded-Host
        try:
            resp = self.session.get(base_url, headers={'X-Forwarded-Host': poison_host}, timeout=5)
            if poison_host in resp.text:
                self.results['vulnerabilities'].append(
                    ('Host Header Injection (X-Forwarded-Host)', base_url,
                     f'X-Forwarded-Host: {poison_host} reflected', 'HIGH'))
                self.print_error(f"X-Forwarded-Host injection: {base_url}")
        except:
            pass

    def _crlf_injection(self, base_url):
        """Test for CRLF Injection"""
        self.print_status("Testing CRLF Injection...")
        payloads = [
            '%0d%0aX-Injected: hacked',
            '%0d%0aSet-Cookie: injected=1',
            '\r\nX-Injected: hacked',
            '%E5%98%8D%E5%98%8AX-Injected: hacked',
        ]
        params = ['url', 'next', 'redirect', 'data', 'ref', 'q', 'search']
        for param in params:
            for payload in payloads:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                    if 'X-Injected' in resp.headers or 'injected' in resp.headers.get('Set-Cookie', ''):
                        self.results['vulnerabilities'].append(
                            ('CRLF Injection', test_url, f'CRLF via param={param}', 'HIGH'))
                        self.print_error(f"CRLF Injection: {test_url}")
                        return
                except:
                    pass

    def _clickjacking_check(self, base_url):
        """Check for Clickjacking vulnerability"""
        self.print_status("Testing Clickjacking...")
        try:
            resp = self.session.get(base_url, timeout=8)
            xfo = resp.headers.get('X-Frame-Options', '').lower()
            csp = resp.headers.get('Content-Security-Policy', '').lower()
            has_frame_protection = (
                xfo in ('deny', 'sameorigin') or
                'frame-ancestors' in csp
            )
            if not has_frame_protection:
                self.results['vulnerabilities'].append(
                    ('Clickjacking', base_url,
                     'Missing X-Frame-Options and CSP frame-ancestors', 'MEDIUM'))
                self.print_error(f"Clickjacking: no frame protection on {base_url}")
            else:
                self.print_success(f"Clickjacking protection present: X-Frame-Options={xfo or 'via CSP'}")
        except Exception as e:
            pass

    def _graphql_check(self, base_url):
        """Detect exposed GraphQL introspection"""
        self.print_status("Testing GraphQL Introspection...")
        introspection = '{"query":"{__schema{types{name}}}"}'
        headers = {'Content-Type': 'application/json'}
        paths = ['/graphql', '/api/graphql', '/graphiql', '/v1/graphql', '/query']
        for path in paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = self.session.post(url, data=introspection, headers=headers, timeout=5)
                if resp.status_code == 200 and '__schema' in resp.text:
                    self.results['vulnerabilities'].append(
                        ('GraphQL Introspection Enabled', url,
                         'GraphQL introspection is exposed - schema disclosure', 'MEDIUM'))
                    self.print_error(f"GraphQL introspection exposed: {url}")
            except:
                pass

    def _jwt_check(self, base_url):
        """Detect and test JWT vulnerabilities"""
        self.print_status("Testing JWT vulnerabilities...")
        try:
            resp = self.session.get(base_url, timeout=8)
            # Look for JWTs in cookies and headers
            jwt_sources = []
            for cookie_name, cookie_val in self.session.cookies.items():
                if len(cookie_val.split('.')) == 3:
                    jwt_sources.append(('cookie', cookie_name, cookie_val))
            auth_hdr = resp.headers.get('Authorization', '')
            if auth_hdr.startswith('Bearer ') and len(auth_hdr.split('.')) == 3:
                jwt_sources.append(('header', 'Authorization', auth_hdr.split(' ')[1]))

            for source, name, token in jwt_sources:
                parts = token.split('.')
                if len(parts) != 3:
                    continue
                try:
                    header_data = json.loads(base64.b64decode(parts[0] + '==').decode('utf-8', errors='ignore'))
                    alg = header_data.get('alg', '')
                    if alg.lower() == 'none':
                        self.results['vulnerabilities'].append(
                            ('JWT alg:none', base_url, f'JWT in {source}:{name} uses alg=none', 'CRITICAL'))
                        self.print_error(f"JWT alg:none vulnerability: {source}:{name}")
                    elif alg.upper() in ('HS256', 'HS384', 'HS512'):
                        self.results['vulnerabilities'].append(
                            ('JWT Weak Algorithm', base_url,
                             f'JWT uses {alg} - susceptible to brute force with weak secrets', 'MEDIUM'))
                        self.print_warning(f"JWT uses {alg}: may be brute-forceable")
                except:
                    pass
        except:
            pass

    def _request_smuggling_check(self, base_url):
        """Detect potential HTTP request smuggling"""
        self.print_status("Testing HTTP Request Smuggling indicators...")
        try:
            # CL.TE probe - send both Content-Length and Transfer-Encoding
            parsed = urllib.parse.urlparse(base_url)
            host = parsed.netloc
            path = parsed.path or '/'
            raw = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n\r\n"
                "G"
            )
            port = 443 if parsed.scheme == 'https' else 80
            sock = socket.create_connection((host.split(':')[0], port), timeout=5)
            if parsed.scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(raw.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            if '400' not in response and '501' not in response and response:
                self.results['vulnerabilities'].append(
                    ('HTTP Request Smuggling (Possible)', base_url,
                     'Server did not reject CL.TE smuggling probe - manual verification needed', 'HIGH'))
                self.print_warning(f"Possible HTTP smuggling: {base_url}")
        except:
            pass

    def _hpp_scan(self, base_url):
        """Test for HTTP Parameter Pollution"""
        self.print_status("Testing HTTP Parameter Pollution...")
        params = ['id', 'user', 'action', 'type', 'page', 'cat']
        for param in params:
            try:
                url1 = f"{base_url}?{param}=1"
                url2 = f"{base_url}?{param}=1&{param}=2"
                r1 = self.session.get(url1, timeout=5)
                r2 = self.session.get(url2, timeout=5)
                if r1.status_code != r2.status_code or abs(len(r1.text) - len(r2.text)) > 200:
                    self.results['vulnerabilities'].append(
                        ('HTTP Parameter Pollution', base_url,
                         f'Different response for {param}=1 vs {param}=1&{param}=2', 'LOW'))
                    self.print_warning(f"HPP detected on param={param}: {base_url}")
                    break
            except:
                pass

    # -------------------------------------------------------------------------
    # WAF Detection
    # -------------------------------------------------------------------------
    def waf_detection(self, base_url):
        """Detect Web Application Firewall presence and type"""
        self.print_status("Detecting WAF...")
        waf_signatures = {
            'Cloudflare':   ['cf-ray', 'cloudflare', '__cfduid', 'cf-cache-status'],
            'Akamai':       ['akamai', 'akamaighost', 'x-akamai-transformed'],
            'ModSecurity':  ['mod_security', 'modsecurity', 'NOYB'],
            'Sucuri':       ['x-sucuri-id', 'sucuri', 'x-sucuri-cache'],
            'Imperva':      ['x-iinfo', 'x-cdn', 'incap_ses'],
            'AWS WAF':      ['x-amzn-requestid', 'awswaf'],
            'Barracuda':    ['barra_counter_session', 'barracuda'],
            'F5 BIG-IP':    ['bigip', 'f5', 'ts'],
            'Fortinet':     ['fortigate', 'fortiweb'],
            'Citrix NetScaler': ['citrix', 'ns_af'],
        }
        try:
            # Normal request first
            resp = self.session.get(base_url, timeout=8)
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            raw = ' '.join(headers_lower.keys()) + ' ' + ' '.join(headers_lower.values())

            detected = None
            for waf_name, sigs in waf_signatures.items():
                if any(sig.lower() in raw for sig in sigs):
                    detected = waf_name
                    break

            # Try a WAF-trigger payload
            if not detected:
                waf_probe = self.session.get(
                    f"{base_url}?q=<script>alert(1)</script>&id=1'+OR+'1'='1",
                    timeout=8
                )
                if waf_probe.status_code in [403, 406, 429, 503]:
                    raw2 = ' '.join(f"{k}: {v}" for k, v in waf_probe.headers.items()).lower()
                    for waf_name, sigs in waf_signatures.items():
                        if any(sig.lower() in raw2 for sig in sigs):
                            detected = waf_name
                            break
                    if not detected and waf_probe.status_code in [403, 406]:
                        detected = 'Unknown WAF (payload triggered block)'

            if detected:
                self.results['waf'] = detected
                self.print_warning(f"WAF detected: {detected}")
            else:
                self.results['waf'] = 'None detected'
                self.print_success("No WAF detected")
        except Exception as e:
            self.print_error(f"WAF detection failed: {e}")

        return self.results['waf']

    # -------------------------------------------------------------------------
    # Subdomain Takeover
    # -------------------------------------------------------------------------
    def subdomain_takeover(self):
        """Check discovered subdomains for takeover vulnerability"""
        self.print_status("Checking for Subdomain Takeover...")
        # Fingerprints for unclaimed services
        takeover_fingerprints = [
            ('GitHub Pages',  ['There isn\'t a GitHub Pages site here', "github.com/404"]),
            ('Heroku',        ['No such app', 'herokucdn.com/error-pages']),
            ('Shopify',       ['Sorry, this shop is currently unavailable']),
            ('Fastly',        ['Fastly error: unknown domain']),
            ('Zendesk',       ['Help Center Closed']),
            ('Tumblr',        ['Whatever you were looking for doesn\'t currently exist']),
            ('Squarespace',   ['No Such Account']),
            ('StatusPage.io', ['You are being redirected']),
            ('AWS S3',        ['NoSuchBucket', 'The specified bucket does not exist']),
            ('Surge.sh',      ['project not found']),
            ('Bitbucket',     ['Repository not found']),
            ('WP Engine',     ['The site you were looking for']),
        ]
        candidates = []
        subs = self.results.get('subdomains', [])
        for sub in subs:
            for scheme in ['https', 'http']:
                try:
                    resp = self.session.get(f"{scheme}://{sub}", timeout=6)
                    body = resp.text.lower()
                    for service, fingerprints in takeover_fingerprints:
                        if any(fp.lower() in body for fp in fingerprints):
                            candidates.append((sub, service))
                            self.results['vulnerabilities'].append(
                                ('Subdomain Takeover', sub,
                                 f'Possible takeover via {service}', 'CRITICAL'))
                            self.print_error(f"Subdomain takeover candidate: {sub} ({service})")
                    break  # Only need one scheme
                except:
                    continue

        self.results['takeover_candidates'] = candidates
        return candidates

    # -------------------------------------------------------------------------
    # S3 Bucket Misconfiguration
    # -------------------------------------------------------------------------
    def s3_bucket_check(self):
        """Check for exposed/misconfigured S3 buckets"""
        self.print_status("Checking S3 Bucket Misconfiguration...")
        domain_base = self.target_domain.replace('www.', '').split('.')[0]
        bucket_names = [
            domain_base,
            f"{domain_base}-backup",
            f"{domain_base}-dev",
            f"{domain_base}-staging",
            f"{domain_base}-assets",
            f"{domain_base}-media",
            f"{domain_base}-static",
            f"{domain_base}-uploads",
            f"backup-{domain_base}",
            f"dev-{domain_base}",
        ]
        bucket_found = []
        for bucket in bucket_names:
            urls = [
                f"https://{bucket}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{bucket}",
            ]
            for url in urls:
                try:
                    resp = self.session.get(url, timeout=6)
                    if resp.status_code == 200 and ('<ListBucketResult' in resp.text or 'Contents' in resp.text):
                        bucket_found.append((bucket, url, 'Public bucket listing enabled'))
                        self.results['vulnerabilities'].append(
                            ('S3 Bucket Public Listing', url,
                             f'Bucket {bucket} is publicly listable', 'CRITICAL'))
                        self.print_error(f"Public S3 bucket: {url}")
                    elif resp.status_code == 403:
                        # Bucket exists but access denied (still noteworthy)
                        bucket_found.append((bucket, url, 'Bucket exists but access denied'))
                        self.print_warning(f"S3 bucket exists (403): {url}")
                    elif 'NoSuchBucket' not in resp.text and resp.status_code != 404:
                        bucket_found.append((bucket, url, f'Unexpected response: {resp.status_code}'))
                except:
                    pass
        return bucket_found

    # -------------------------------------------------------------------------
    # Security Headers Audit
    # -------------------------------------------------------------------------
    def security_headers_audit(self, base_url):
        """Audit security response headers"""
        self.print_status("Auditing Security Headers...")
        header_checks = [
            ('Strict-Transport-Security', 'HSTS missing - site vulnerable to protocol downgrade', 'HIGH'),
            ('X-Content-Type-Options',    'Missing X-Content-Type-Options - MIME sniffing possible', 'MEDIUM'),
            ('X-Frame-Options',           'Missing X-Frame-Options - clickjacking possible', 'MEDIUM'),
            ('Content-Security-Policy',   'Missing CSP - XSS and injection risks', 'HIGH'),
            ('Referrer-Policy',           'Missing Referrer-Policy - referrer leakage possible', 'LOW'),
            ('Permissions-Policy',        'Missing Permissions-Policy header', 'LOW'),
            ('X-XSS-Protection',          'Missing X-XSS-Protection header', 'LOW'),
        ]
        audit_results = []
        try:
            resp = self.session.get(base_url, timeout=8)
            headers = resp.headers
            for header_name, description, severity in header_checks:
                if header_name not in headers:
                    audit_results.append((header_name, 'MISSING', severity))
                    self.results['vulnerabilities'].append(
                        (f'Missing Header: {header_name}', base_url, description, severity))
                    self.print_warning(f"[{severity}] {description}")
                else:
                    val = headers[header_name]
                    audit_results.append((header_name, val, 'OK'))
                    self.print_success(f"{header_name}: {val[:60]}")

            # Extra: check if HSTS max-age is too short
            hsts = headers.get('Strict-Transport-Security', '')
            if hsts:
                match = re.search(r'max-age=(\d+)', hsts)
                if match and int(match.group(1)) < 31536000:
                    audit_results.append(('HSTS max-age', 'weak', 'MEDIUM'))
                    self.results['vulnerabilities'].append(
                        ('Weak HSTS max-age', base_url,
                         f'HSTS max-age={match.group(1)} is less than 1 year', 'MEDIUM'))

            self.results['security_headers'] = audit_results
        except Exception as e:
            self.print_error(f"Security headers audit failed: {e}")
        return audit_results

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
            records['Wildcard'] = ['Yes - wildcard DNS detected']
            self.print_warning("Wildcard DNS detected")
        except:
            records['Wildcard'] = ['No']

        self.results['dns_records'] = records
        return records

    # -------------------------------------------------------------------------
    # SSL analysis
    # -------------------------------------------------------------------------
    def ssl_analysis(self, domain):
        """SSL/TLS certificate analysis with weak cipher detection"""
        self.print_status("Starting SSL/TLS Analysis...")
        def _do_ssl(ctx):
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # cert['subject'] / cert['issuer'] structure:
                    # (  (('commonName', 'x'),),  (('organizationName', 'y'),),  ... )
                    def parse_cert_field(field):
                        result = {}
                        for rdn in (field or []):
                            for k, v in rdn:
                                result[k] = v
                        return result

                    subject = parse_cert_field(cert.get('subject', ()))
                    issuer  = parse_cert_field(cert.get('issuer', ()))

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

                    cipher_name = ssock.cipher()[0] if ssock.cipher() else ''
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'EXPORT', 'NULL']
                    if any(w in cipher_name for w in weak_ciphers):
                        self.results['vulnerabilities'].append(
                            ('Weak SSL Cipher', domain, f'Cipher: {cipher_name}'))
                        self.print_error(f"Weak cipher detected: {cipher_name}")

                    self.print_success("SSL Certificate Information:")
                    print(f"    Subject: {subject.get('commonName')}")
                    print(f"    Issuer:  {issuer.get('organizationName')}")
                    print(f"    Valid until: {cert.get('notAfter')}")

                    self.results['ssl_info'] = ssl_info
                    return ssl_info

        try:
            # First try with full certificate verification
            _do_ssl(ssl.create_default_context())
        except ssl.SSLCertVerificationError:
            # Target uses a self-signed / untrusted cert — retry without verification
            self.print_warning("Certificate verification failed; retrying without verification (self-signed cert).")
            try:
                unverified_ctx = ssl.create_default_context()
                unverified_ctx.check_hostname = False
                unverified_ctx.verify_mode = ssl.CERT_OPTIONAL
                _do_ssl(unverified_ctx)
            except Exception as e:
                self.print_error(f"SSL analysis failed: {e}")
        except Exception as e:
            self.print_error(f"SSL analysis failed: {e}")
        return self.results.get('ssl_info', {})

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
        """Generate a premium dark-mode interactive HTML report"""
        if not JINJA2_AVAILABLE:
            self.print_warning("Jinja2 not installed. Skipping HTML report.")
            return

        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {{ target }}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0a0b10;
            --card-bg: rgba(20, 22, 30, 0.7);
            --accent-cyan: #00f2fe;
            --accent-green: #00ff87;
            --accent-red: #ff3366;
            --accent-orange: #ff9900;
            --text-primary: #e0e0e0;
            --text-secondary: #94a3b8;
            --border-color: rgba(255, 255, 255, 0.1);
            --glass-blur: blur(12px);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            line-height: 1.6;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 20% 30%, rgba(0, 242, 254, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 80% 70%, rgba(0, 255, 135, 0.05) 0%, transparent 40%);
        }

        .container { display: flex; min-height: 100vh; }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background: rgba(15, 17, 26, 0.95);
            border-right: 1px solid var(--border-color);
            position: fixed;
            height: 100vh;
            padding: 30px 20px;
            backdrop-filter: var(--glass-blur);
            z-index: 100;
        }

        .logo {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--accent-cyan);
            margin-bottom: 40px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .nav-menu { list-style: none; }
        .nav-item {
            padding: 12px 15px;
            margin-bottom: 8px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .nav-item:hover, .nav-item.active {
            background: rgba(0, 242, 254, 0.1);
            color: var(--accent-cyan);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }

        /* Main Content */
        .main-content {
            margin-left: 260px;
            flex: 1;
            padding: 40px;
            max-width: 1400px;
        }

        header {
            margin-bottom: 40px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }
        .header-title h1 {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.8rem;
            margin-bottom: 5px;
            background: linear-gradient(to right, var(--accent-cyan), var(--accent-green));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .header-meta { font-size: 0.85rem; color: var(--text-secondary); }

        /* Dashboard Grid */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .stat-card {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid var(--border-color);
            backdrop-filter: var(--glass-blur);
            transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); border-color: var(--accent-cyan); }
        .stat-label { font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; }
        .stat-value { font-size: 2rem; font-weight: 700; color: #fff; margin-top: 5px; }

        /* Sections */
        .section { display: none; animation: fadeIn 0.4s ease; }
        .section.active { display: block; }

        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

        .card {
            background: var(--card-bg);
            border-radius: 15px;
            border: 1px solid var(--border-color);
            margin-bottom: 30px;
            overflow: hidden;
            backdrop-filter: var(--glass-blur);
        }
        .card-header {
            padding: 20px 25px;
            border-bottom: 1px solid var(--border-color);
            background: rgba(255, 255, 255, 0.03);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-title { font-weight: 600; font-size: 1.1rem; color: var(--accent-cyan); }
        .card-body { padding: 25px; }

        /* Tables */
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { text-align: left; padding: 12px 15px; color: var(--text-secondary); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; border-bottom: 2px solid var(--border-color); }
        td { padding: 12px 15px; border-bottom: 1px solid var(--border-color); font-size: 0.9rem; color: var(--text-primary); }
        tr:hover { background: rgba(255, 255, 255, 0.02); }

        /* Vulcan Cards */
        .vuln-item {
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 15px;
            background: rgba(0, 0, 0, 0.2);
            transition: all 0.3s ease;
        }
        .vuln-header {
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .vuln-header:hover { background: rgba(255, 255, 255, 0.05); }
        .vuln-type { font-weight: 600; font-size: 1rem; flex: 1; }
        .vuln-content { 
            padding: 0 20px 20px 20px; 
            display: none; 
            border-top: 1px solid var(--border-color);
            margin-top: 10px;
            padding-top: 15px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        .vuln-item.open .vuln-content { display: block; }
        
        .badge { padding: 4px 10px; border-radius: 6px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
        .badge-critical { background: rgba(255, 51, 102, 0.2); color: #ff3366; border: 1px solid rgba(255, 51, 102, 0.3); }
        .badge-high { background: rgba(255, 153, 0, 0.2); color: #ff9900; border: 1px solid rgba(255, 153, 0, 0.3); }
        .badge-medium { background: rgba(255, 255, 0, 0.2); color: #ffff00; border: 1px solid rgba(255, 255, 0, 0.3); }
        .badge-low { background: rgba(0, 242, 254, 0.2); color: #00f2fe; border: 1px solid rgba(0, 242, 254, 0.3); }
        .badge-info { background: rgba(0, 255, 135, 0.2); color: #00ff87; border: 1px solid rgba(0, 255, 135, 0.3); }

        /* Search/Filter */
        .search-container { position: relative; margin-bottom: 20px; }
        .search-input {
            width: 100%;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            padding: 10px 15px;
            border-radius: 8px;
            color: #fff;
            font-size: 0.9rem;
            outline: none;
            transition: all 0.3s ease;
        }
        .search-input:focus { border-color: var(--accent-cyan); box-shadow: 0 0 10px rgba(0, 242, 254, 0.2); }

        .btn-copy {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            cursor: pointer;
            margin-left: 10px;
        }
        .btn-copy:hover { border-color: var(--accent-cyan); color: var(--accent-cyan); }

        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-align: center;
        }

        /* Mobile Adjustments */
        @media (max-width: 900px) {
            .sidebar { width: 70px; padding: 30px 10px; }
            .logo { display: none; }
            .nav-item span { display: none; }
            .main-content { margin-left: 70px; padding: 20px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Sidebar Navigation -->
        <div class="sidebar">
            <div class="logo">
                <span>🛡️TOOLKIT</span>
            </div>
            <ul class="nav-menu">
                <li class="nav-item active" onclick="showSection('summary')">📊 <span>Summary</span></li>
                <li class="nav-item" onclick="showSection('vulnerabilities')">🔴 <span>Findings</span></li>
                <li class="nav-item" onclick="showSection('subdomains')">🌐 <span>Subdomains</span></li>
                <li class="nav-item" onclick="showSection('ports')">🔌 <span>Ports</span></li>
                <li class="nav-item" onclick="showSection('directories')">📁 <span>Directories</span></li>
                <li class="nav-item" onclick="showSection('endpoints')">🔗 <span>Endpoints</span></li>
                <li class="nav-item" onclick="showSection('technologies')">⚙️ <span>Technologies</span></li>
                <li class="nav-item" onclick="showSection('dns')">🔡 <span>DNS</span></li>
                <li class="nav-item" onclick="showSection('ssl')">🔒 <span>SSL/TLS</span></li>
                {% if results.wayback_urls %}
                <li class="nav-item" onclick="showSection('wayback')">🕰️ <span>Wayback</span></li>
                {% endif %}
                {% if results.github_leaks %}
                <li class="nav-item" onclick="showSection('github')">🐙 <span>github</span></li>
                {% endif %}
            </ul>
        </div>

        <div class="main-content">
            <header>
                <div class="header-title">
                    <h1>Security Reconnaissance Report</h1>
                    <div class="header-meta">
                        Target: <span style="color: var(--accent-cyan)">{{ target }}</span> &nbsp;|&nbsp; 
                        Date: {{ date }} &nbsp;|&nbsp; 
                        WAF: <span style="color: var(--accent-green)">{{ results.waf or 'None Detected' }}</span>
                    </div>
                </div>
                <div class="header-meta">v{{ version }}</div>
            </header>

            <!-- Stat Cards -->
            <div class="dashboard-grid">
                <div class="stat-card">
                    <div class="stat-label">Vulnerabilities</div>
                    <div class="stat-value" style="color: var(--accent-red)">{{ results.vulnerabilities|length }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Subdomains</div>
                    <div class="stat-value">{{ results.subdomains|length }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Endpoints</div>
                    <div class="stat-value">{{ results.endpoints|length }}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Security Headers</div>
                    <div class="stat-value">{{ results.security_headers|length }}</div>
                </div>
            </div>

            <!-- Dashboard Summary -->
            <section id="summary" class="section active">
                <div class="card">
                    <div class="card-header"><span class="card-title">Executive Summary</span></div>
                    <div class="card-body">
                        <p style="margin-bottom: 20px; font-size: 0.95rem; color: var(--text-secondary);">
                            Comprehensive scan results for <b>{{ target }}</b>. High-level findings summary:
                        </p>
                        <div style="display: flex; flex-wrap: wrap; gap: 30px;">
                            <div>
                                <h4 style="color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase;">Infrastructure</h4>
                                <ul style="list-style: none; margin-top: 10px;">
                                    <li>⚡ Cloud Provider: <b>{{ results.cloud_provider or 'Unknown' }}</b></li>
                                    <li>🌐 Total Subdomains: <b>{{ results.subdomains|length }}</b></li>
                                    <li>🔌 Open Ports: <b>{{ results.open_ports|length }}</b></li>
                                </ul>
                            </div>
                            <div>
                                <h4 style="color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase;">Web & Content</h4>
                                <ul style="list-style: none; margin-top: 10px;">
                                    <li>📂 Directories: <b>{{ results.directories|length }}</b></li>
                                    <li>🔗 Active Endpoints: <b>{{ results.endpoints|length }}</b></li>
                                    <li>🛠 Technologies: <b>{{ results.technologies|length }}</b></li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Vulnerabilities Section -->
            <section id="vulnerabilities" class="section">
                <div class="card">
                    <div class="card-header"><span class="card-title">Vulnerabilities & Security Risks</span></div>
                    <div class="card-body">
                        {% if sorted_vulns %}
                            {% for vuln in sorted_vulns %}
                                <div class="vuln-item">
                                    <div class="vuln-header" onclick="toggleVuln(this)">
                                        <span class="vuln-type">
                                            <span class="badge badge-{{ (vuln[3] or 'info')|lower }}">{{ vuln[3] or 'INFO' }}</span>
                                            &nbsp; {{ vuln[0] }}
                                        </span>
                                        <span style="font-size: 0.8rem; color: var(--text-secondary);">Click to expand</span>
                                    </div>
                                    <div class="vuln-content">
                                        <p><b>Target URL:</b> <a href="{{ vuln[1] }}" target="_blank" style="color: var(--accent-cyan);">{{ vuln[1] }}</a></p>
                                        <p style="margin-top: 10px;"><b>Details:</b> {{ vuln[2] }}</p>
                                    </div>
                                </div>
                            {% endfor %}
                        {% else %}
                            <p style="color: var(--text-secondary);">No high-risk vulnerabilities detected.</p>
                        {% endif %}
                    </div>
                </div>
            </section>

            <!-- Subdomains Section -->
            <section id="subdomains" class="section">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Subdomain Enumeration</span>
                        <span class="badge badge-info">{{ results.subdomains|length }} Found</span>
                    </div>
                    <div class="card-body">
                        <div class="search-container">
                            <input type="text" class="search-input" placeholder="Search subdomains..." onkeyup="filterTable(this, 'table-subs')">
                        </div>
                        <table id="table-subs">
                            <thead><tr><th>Subdomain</th><th>Action</th></tr></thead>
                            <tbody>
                                {% for sub in results.subdomains %}
                                <tr>
                                    <td>{{ sub }}</td>
                                    <td><button class="btn-copy" onclick="copyText('{{ sub }}')">Copy</button></td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
                
                {% if results.takeover_candidates %}
                <div class="card" style="border-color: var(--accent-red);">
                    <div class="card-header"><span class="card-title" style="color: var(--accent-red);">🚨 Potential Takeover Candidates</span></div>
                    <div class="card-body">
                        <table>
                            <thead><tr><th>Subdomain</th><th>Service Identified</th></tr></thead>
                            <tbody>
                                {% for cand in results.takeover_candidates %}
                                <tr><td>{{ cand[0] }}</td><td style="color: var(--accent-red)">{{ cand[1] }}</td></tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
                {% endif %}
            </section>

            <!-- Ports Section -->
            <section id="ports" class="section">
                <div class="card">
                    <div class="card-header"><span class="card-title">Port Scan Results</span></div>
                    <div class="card-body">
                        {% if results.open_ports %}
                        <table>
                            <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
                            <tbody>
                                {% for port in results.open_ports %}
                                <tr>
                                    <td>{{ port[0] }}</td>
                                    <td>{{ port[1] }}</td>
                                    <td>{{ port[2] }}</td>
                                    <td>{{ port[3] }}</td>
                                    <td>{{ port[4] }} {{ port[5] }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        {% else %}<p>No open ports discovered.</p>{% endif %}
                    </div>
                </div>
            </section>

            <!-- Directories Section -->
            <section id="directories" class="section">
                <div class="card">
                    <div class="card-header"><span class="card-title">Directory Brute Force</span></div>
                    <div class="card-body">
                        <div class="search-container">
                            <input type="text" class="search-input" placeholder="Filter URLs..." onkeyup="filterTable(this, 'table-dirs')">
                        </div>
                        <table id="table-dirs">
                            <thead><tr><th>URL</th><th>Status</th><th>Size</th></tr></thead>
                            <tbody>
                                {% for dir in results.directories %}
                                <tr>
                                    <td><a href="{{ dir[0] }}" target="_blank" style="color: var(--text-primary);">{{ dir[0] }}</a></td>
                                    <td><span class="badge {% if dir[1] == 200 %}badge-info{% else %}badge-low{% endif %}">{{ dir[1] }}</span></td>
                                    <td>{{ dir[2] }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <!-- Endpoints Section -->
            <section id="endpoints" class="section">
                <div class="card">
                    <div class="card-header"><span class="card-title">Discovered Endpoints</span></div>
                    <div class="card-body">
                        <div class="search-container">
                            <input type="text" class="search-input" placeholder="Filter endpoints..." onkeyup="filterList(this, 'list-endpoints')">
                        </div>
                        <ul id="list-endpoints" style="list-style: none; font-size: 0.85rem;">
                            {% for ep in results.endpoints %}
                            <li style="padding: 8px 0; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                                <span>{{ ep }}</span>
                                <button class="btn-copy" onclick="copyText('{{ ep }}')">Copy</button>
                            </li>
                            {% endfor %}
                        </ul>
                    </div>
                </div>
            </section>

            <!-- Technologies Section -->
            <section id="technologies" class="section">
                <div class="card">
                    <div class="card-header"><span class="card-title">Technology Fingerprinting</span></div>
                    <div class="card-body">
                        <table>
                            <thead><tr><th>Category</th><th>Technology</th></tr></thead>
                            <tbody>
                                {% for tech in results.technologies %}
                                <tr><td>{{ tech[0] }}</td><td><b>{{ tech[1] }}</b></td></tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <!-- DNS Section -->
            <section id="dns" class="section">
                <div class="card">
                    <div class="card-header"><span class="card-title">DNS Records</span></div>
                    <div class="card-body">
                        {% for rtype, records in results.dns_records.items() %}
                        <div style="margin-bottom: 25px;">
                            <h4 style="color: var(--accent-cyan); font-size: 0.9rem; margin-bottom: 10px;">{{ rtype }} Records</h4>
                            <ul style="list-style: none; background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;">
                                {% for rec in records %}
                                <li style="margin-bottom: 5px; font-family: monospace; font-size: 0.85rem;">{{ rec }}</li>
                                {% endfor %}
                            </ul>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <!-- SSL Section -->
            <section id="ssl" class="section">
                <div class="card">
                    <div class="card-header"><span class="card-title">SSL/TLS Configuration</span></div>
                    <div class="card-body">
                        {% if results.ssl_info %}
                        <pre style="background: rgba(0,0,0,0.3); padding: 20px; border-radius: 10px; font-family: monospace; font-size: 0.85rem; color: var(--accent-green); overflow-x: auto;">
{{ results.ssl_info | tojson(indent=2) }}</pre>
                        {% else %}<p>No SSL information available.</p>{% endif %}
                    </div>
                </div>
            </section>

            <!-- Wayback Section -->
            <section id="wayback" class="section">
                <div class="card">
                    <div class="card-header"><span class="card-title">Wayback Machine Archives</span></div>
                    <div class="card-body">
                        <p style="font-size: 0.8rem; margin-bottom: 20px; color: var(--text-secondary);">Showing first 50 discovered historical URLs.</p>
                        <ul style="list-style: none; font-size: 0.8rem;">
                            {% for url in results.wayback_urls[:50] %}
                            <li style="margin-bottom: 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                <a href="{{ url }}" target="_blank" style="color: var(--text-primary);">{{ url }}</a>
                            </li>
                            {% endfor %}
                        </ul>
                    </div>
                </div>
            </section>

            <!-- GitHub Section -->
            <section id="github" class="section">
                <div class="card">
                    <div class="card-header"><span class="card-title">GitHub Exposure Scanning</span></div>
                    <div class="card-body">
                        {% if results.github_leaks %}
                        <table>
                            <thead><tr><th>Query</th><th>Repo</th><th>Path</th><th>Link</th></tr></thead>
                            <tbody>
                                {% for leak in results.github_leaks %}
                                <tr>
                                    <td>{{ leak[0] }}</td>
                                    <td>{{ leak[1] }}</td>
                                    <td style="font-size: 0.75rem; font-family: monospace;">{{ leak[2] }}</td>
                                    <td><a href="{{ leak[3] }}" target="_blank" style="color: var(--accent-cyan);">View</a></td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        {% else %}<p>No leaks identified on GitHub.</p>{% endif %}
                    </div>
                </div>
            </section>

            <div class="footer">
                Bug Bounty Comprehensive Toolkit Dashboard &bull; v{{ version }} &bull; Generated for Educational Purposes
            </div>
        </div>
    </div>

    <script>
        function showSection(id) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            event.currentTarget.classList.add('active');
            window.scrollTo(0, 0);
        }

        function toggleVuln(header) {
            header.parentElement.classList.toggle('open');
        }

        function filterTable(input, tableId) {
            let filter = input.value.toLowerCase();
            let table = document.getElementById(tableId);
            let tr = table.getElementsByTagName("tr");
            for (let i = 1; i < tr.length; i++) {
                let text = tr[i].textContent.toLowerCase();
                tr[i].style.display = text.includes(filter) ? "" : "none";
            }
        }

        function filterList(input, listId) {
            let filter = input.value.toLowerCase();
            let ul = document.getElementById(listId);
            let li = ul.getElementsByTagName("li");
            for (let i = 0; i < li.length; i++) {
                let text = li[i].textContent.toLowerCase();
                li[i].style.display = text.includes(filter) ? "" : "none";
            }
        }

        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Copied to clipboard: ' + text);
            });
        }
    </script>
</body>
</html>
        """
        # Pre-sort vulnerabilities by severity
        SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        def vuln_sev(v):
            return SEV_ORDER.get(v[3] if len(v) > 3 else 'INFO', 99)
        sorted_vulns = sorted(self.results['vulnerabilities'], key=vuln_sev)

        template = Template(template_str)
        html_content = template.render(target=self.target_domain,
                                       date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                       version=__version__,
                                       results=self.results,
                                       sorted_vulns=sorted_vulns)

        if self.output_file:
            import os
            base = os.path.splitext(self.output_file)[0]
            filename = base + '.html'
        else:
            filename = f"bugbounty_report_{self.target_domain}_{int(time.time())}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        self.print_success(f"HTML report saved: {filename}")
        return filename

    def generate_report(self):
        """Generate comprehensive text report with severity levels"""
        self.print_status("Generating Text Report...")
        SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sep = '=' * 65
        report_lines = []
        report_lines.append(sep)
        report_lines.append(f" BUG BOUNTY TOOLKIT REPORT v{__version__}")
        report_lines.append(sep)
        report_lines.append(f" Target    : {self.target_domain}")
        report_lines.append(f" Scan Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f" WAF       : {self.results.get('waf', 'Not checked')}")
        report_lines.append(sep)

        # ---- Vulnerabilities (sorted by severity) ----
        report_lines.append("")
        report_lines.append("[!] VULNERABILITIES")
        report_lines.append("-" * 65)
        vulns = self.results['vulnerabilities']
        # Support both 3-tuple and 4-tuple (type, url, detail[, severity])
        def vuln_sev(v):
            return SEV_ORDER.get(v[3] if len(v) > 3 else 'INFO', 99)
        for v in sorted(vulns, key=vuln_sev):
            sev = v[3] if len(v) > 3 else 'INFO'
            report_lines.append(f"  [{sev}] {v[0]}")
            report_lines.append(f"        URL   : {v[1]}")
            report_lines.append(f"        Detail: {v[2]}")
        if not vulns:
            report_lines.append("  No vulnerabilities found.")

        # ---- Security Headers ----
        report_lines.append("")
        report_lines.append("[*] SECURITY HEADERS AUDIT")
        report_lines.append("-" * 65)
        for h, val, status in self.results.get('security_headers', []):
            report_lines.append(f"  {status:8s} {h}: {str(val)[:60]}")
        if not self.results.get('security_headers'):
            report_lines.append("  Not checked.")

        # ---- Subdomains ----
        report_lines.append("")
        report_lines.append("[*] SUBDOMAINS")
        report_lines.append("-" * 65)
        for sub in self.results['subdomains']:
            report_lines.append(f"  {sub}")
        if not self.results['subdomains']:
            report_lines.append("  None found.")

        # ---- Takeover candidates ----
        report_lines.append("")
        report_lines.append("[!] SUBDOMAIN TAKEOVER CANDIDATES")
        report_lines.append("-" * 65)
        for sub, service in self.results.get('takeover_candidates', []):
            report_lines.append(f"  {sub}  ->  {service}")
        if not self.results.get('takeover_candidates'):
            report_lines.append("  None found.")

        # ---- Open Ports ----
        report_lines.append("")
        report_lines.append("[*] OPEN PORTS")
        report_lines.append("-" * 65)
        for port in self.results['open_ports']:
            report_lines.append(f"  {port[0]}/{port[1]} - {port[2]} {port[3]} {port[4]} {port[5]}")
        if not self.results['open_ports']:
            report_lines.append("  None found.")

        # ---- Directories ----
        report_lines.append("")
        report_lines.append("[*] DIRECTORIES")
        report_lines.append("-" * 65)
        for d in self.results['directories']:
            report_lines.append(f"  {d[0]} [{d[1]}] Size:{d[2]}")
        if not self.results['directories']:
            report_lines.append("  None found.")

        # ---- Endpoints ----
        report_lines.append("")
        report_lines.append("[*] ENDPOINTS")
        report_lines.append("-" * 65)
        for ep in self.results['endpoints']:
            report_lines.append(f"  {ep}")
        if not self.results['endpoints']:
            report_lines.append("  None found.")

        # ---- Technologies ----
        report_lines.append("")
        report_lines.append("[*] TECHNOLOGIES")
        report_lines.append("-" * 65)
        for cat, val in self.results['technologies']:
            report_lines.append(f"  {cat}: {val}")

        # ---- DNS Records ----
        report_lines.append("")
        report_lines.append("[*] DNS RECORDS")
        report_lines.append("-" * 65)
        for rtype, recs in self.results['dns_records'].items():
            report_lines.append(f"  {rtype}: {', '.join(str(r) for r in recs)}")

        # ---- SSL Info ----
        report_lines.append("")
        report_lines.append("[*] SSL INFO")
        report_lines.append("-" * 65)
        if self.results['ssl_info']:
            report_lines.append(f"  Subject   : {self.results['ssl_info'].get('subject', {}).get('commonName', 'N/A')}")
            report_lines.append(f"  Issuer    : {self.results['ssl_info'].get('issuer', {}).get('organizationName', 'N/A')}")
            report_lines.append(f"  Valid Until: {self.results['ssl_info'].get('notAfter', 'N/A')}")
            report_lines.append(f"  Cipher    : {self.results['ssl_info'].get('cipher', 'N/A')}")
        else:
            report_lines.append("  No SSL info collected.")

        # ---- Cloud ----
        report_lines.append("")
        report_lines.append("[*] CLOUD / CDN")
        report_lines.append("-" * 65)
        report_lines.append(f"  {self.results.get('cloud_provider', 'Unknown')}")

        # ---- Wayback URLs ----
        report_lines.append("")
        report_lines.append("[*] WAYBACK MACHINE URLS (first 20)")
        report_lines.append("-" * 65)
        for url in self.results['wayback_urls'][:20]:
            report_lines.append(f"  {url}")

        # ---- GitHub Leaks ----
        report_lines.append("")
        report_lines.append("[*] GITHUB LEAKS")
        report_lines.append("-" * 65)
        for leak in self.results['github_leaks']:
            report_lines.append(f"  Query: {leak[0]} | Repo: {leak[1]} | Path: {leak[2]}")
            report_lines.append(f"    URL: {leak[3]}")

        report_lines.append("")
        report_lines.append(sep)
        report_lines.append(" Report by Psycho Bug Bounty Toolkit v{} - Educational Use Only".format(__version__))
        report_lines.append(sep)

        if self.output_file:
            filename = self.output_file
        else:
            filename = f"bugbounty_report_{self.target_domain}_{int(time.time())}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
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
            parsed = urllib.parse.urlparse(base_url)
            self.target_domain = parsed.netloc

        try:
            if options.get('waf', True):
                self.waf_detection(base_url)

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

            if options.get('security_headers', True):
                self.security_headers_audit(base_url)

            if options.get('takeover', True):
                self.subdomain_takeover()

            if options.get('s3', True):
                self.s3_bucket_check()

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
            import traceback
            self.print_error(f"Error during scan: {e}")
            traceback.print_exc()

def _print_disclaimer():
    print(f"""{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                        ⚠️  DISCLAIMER ⚠️                        ║
║                                                                  ║
║  THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY!                     ║
║  USE ONLY ON SYSTEMS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST ║
║  UNAUTHORIZED ACCESS IS ILLEGAL AND UNETHICAL.                   ║
║                                                                  ║
║  Created by: Psycho (@the_psycho_of_hackers)  v{__version__}     ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.END}""")


CONFIG_DIR  = os.path.join(os.path.expanduser('~'), '.bugbounty_toolkit')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'keys.json')


def _load_api_keys():
    """Load saved API keys from ~/.bugbounty_toolkit/keys.json"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_api_keys(keys: dict):
    """Persist API keys to ~/.bugbounty_toolkit/keys.json (mode 600)"""
    try:
        os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(keys, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)
    except Exception as e:
        print(f"  [!] Could not save API keys: {e}")


def _mask(key):
    """Return a safely masked version of an API key for display"""
    if not key:
        return ''
    return key[:6] + '***' if len(key) > 6 else '***'


def _interactive_menu(toolkit):
    """Interactive session when no CLI args are given"""
    c = Colors
    toolkit.banner()
    _print_disclaimer()
    time.sleep(1)

    print(f"{c.CYAN}{c.BOLD}  ╔══════════════════════════════════════════╗{c.END}")
    print(f"{c.CYAN}{c.BOLD}  ║       INTERACTIVE RECON SESSION          ║{c.END}")
    print(f"{c.CYAN}{c.BOLD}  ╚══════════════════════════════════════════╝{c.END}\n")

    # --- Target ---
    while True:
        target = input(f"  {c.YELLOW}[?]{c.END} {c.BOLD}Target domain/URL{c.END}  : ").strip()
        if target:
            break
        print(f"  {c.RED}[!] Target cannot be empty.{c.END}")

    threads = input(f"  {c.YELLOW}[?]{c.END} Threads          {c.BOLD}[10]{c.END}: ").strip() or '10'
    timeout = input(f"  {c.YELLOW}[?]{c.END} Timeout (sec)    {c.BOLD}[10]{c.END}: ").strip() or '10'
    output  = input(f"  {c.YELLOW}[?]{c.END} Output file      {c.BOLD}[skip]{c.END}: ").strip() or None
    wordlist = input(f"  {c.YELLOW}[?]{c.END} Wordlist path    {c.BOLD}[built-in]{c.END}: ").strip() or None

    # --- API Keys (load saved, allow update) ---
    KEY_DEFS = [
        ('virustotal',    'VirusTotal API key  '),
        ('github',        'GitHub API key      '),
        ('securitytrails','SecurityTrails key  '),
        ('shodan',        'Shodan API key      '),
        ('otx',           'AlienVault OTX key  '),
    ]
    saved_keys = _load_api_keys()
    if saved_keys:
        print(f"\n  {c.GREEN}[✓] Saved API keys found ({CONFIG_FILE}):{c.END}")
        for k, label in KEY_DEFS:
            if saved_keys.get(k):
                print(f"      {label}: {c.CYAN}{_mask(saved_keys[k])}{c.END}")
        reuse = input(f"\n  {c.YELLOW}[?]{c.END} Use saved keys? {c.BOLD}[Y/n]{c.END}: ").strip().lower()
        if reuse in ('', 'y', 'yes'):
            api_keys = dict(saved_keys)
            print(f"  {c.GREEN}[✓] Loaded saved API keys.{c.END}")
        else:
            api_keys = dict(saved_keys)
            print(f"  {c.PURPLE}─── Update keys (Enter = keep current, type new value to replace) ───{c.END}")
            for k, label in KEY_DEFS:
                current = saved_keys.get(k, '')
                hint = f"current: {_mask(current)}" if current else 'not set'
                new_val = input(f"  {c.YELLOW}[?]{c.END} {label} [{hint}]: ").strip()
                if new_val:
                    api_keys[k] = new_val
                elif not current:
                    api_keys.pop(k, None)
            _save_api_keys({k: v for k, v in api_keys.items() if v})
            print(f"  {c.GREEN}[✓] API keys updated and saved.{c.END}")
    else:
        print(f"\n  {c.PURPLE}─── Optional API Keys (press Enter to skip) ───{c.END}")
        api_keys = {}
        for k, label in KEY_DEFS:
            val = input(f"  {c.YELLOW}[?]{c.END} {label}: ").strip()
            if val:
                api_keys[k] = val
        if api_keys:
            _save_api_keys(api_keys)
            print(f"  {c.GREEN}[✓] API keys saved to {CONFIG_FILE}{c.END}")


    # --- Module Menu ---
    modules = [
        ('waf',             'WAF Detection'),
        ('subdomain',       'Subdomain Enumeration'),
        ('cloud',           'Cloud / CDN Detection'),
        ('ports',           'Port Scanning'),
        ('dns',             'DNS Analysis'),
        ('ssl',             'SSL/TLS Analysis'),
        ('wayback',         'Wayback Machine URLs'),
        ('directories',     'Directory Bruteforce + 403 Bypass'),
        ('endpoints',       'Endpoint Discovery'),
        ('vulnerabilities', 'Advanced Vuln Scan (SQLi/XSS/SSRF/XXE/LFI/SSTI/…)'),
        ('security_headers','Security Headers Audit'),
        ('takeover',        'Subdomain Takeover Check'),
        ('s3',              'S3 Bucket Misconfiguration'),
        ('technology',      'Technology Detection'),
        ('github',          'GitHub Dorking'),
    ]
    print(f"\n  {c.PURPLE}─── Module Selection ───────────────────────────{c.END}")
    print(f"  {c.CYAN}[A]{c.END} Run ALL modules (recommended)")
    print(f"  {c.CYAN}[C]{c.END} Choose modules manually")
    choice = input(f"  {c.YELLOW}[?]{c.END} Choice {c.BOLD}[A]{c.END}: ").strip().upper() or 'A'

    options = {}
    if choice == 'C':
        print()
        for i, (key, label) in enumerate(modules, 1):
            print(f"    {c.CYAN}[{i:02d}]{c.END} {label}")
        selected = input(f"\n  {c.YELLOW}[?]{c.END} Enter numbers (e.g. 1,3,5) or {c.BOLD}ALL{c.END}: ").strip()
        if selected.lower() != 'all' and selected:
            chosen_nums = {int(x.strip()) for x in selected.split(',') if x.strip().isdigit()}
            for i, (key, _) in enumerate(modules, 1):
                options[key] = (i in chosen_nums)
        else:
            options = {k: True for k, _ in modules}
    else:
        options = {k: True for k, _ in modules}

    # --- Build toolkit and run ---
    toolkit.threads    = int(threads)
    toolkit.timeout    = int(timeout)
    toolkit.output_file = output
    toolkit.wordlist_path = wordlist
    toolkit.api_keys   = api_keys

    print(f"\n  {c.GREEN}{c.BOLD}Starting scan on: {c.CYAN}{target}{c.END}\n")
    time.sleep(0.5)
    toolkit.run_complete_scan(target, options)


def main():
    parser = argparse.ArgumentParser(
        description=f'Bug Bounty Advanced Toolkit v{__version__} - Educational Purpose Only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 bugbounty_toolkit.py                    # Interactive mode
  python3 bugbounty_toolkit.py -d example.com     # Quick scan
  python3 bugbounty_toolkit.py -u https://example.com -t 20 -o results.txt
  python3 bugbounty_toolkit.py -d example.com --api-keys keys.json

Disclaimer:
  EDUCATIONAL PURPOSES ONLY. Always get proper authorization.
  Created by Psycho (@the_psycho_of_hackers)
        """
    )

    parser.add_argument('-d', '--domain',  help='Target domain')
    parser.add_argument('-u', '--url',     help='Target URL')
    parser.add_argument('-o', '--output',  help='Output file for results')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads [10]')
    parser.add_argument('--timeout',       type=int, default=10, help='Request timeout in seconds [10]')
    parser.add_argument('--user-agent',    help='Custom User-Agent string')
    parser.add_argument('--wordlist',      help='Custom wordlist path')
    parser.add_argument('--api-keys',      help='JSON file with API keys {"virustotal":"key","github":"key"}')

    # Module skip flags
    parser.add_argument('--no-subdomain',       action='store_true')
    parser.add_argument('--no-ports',           action='store_true')
    parser.add_argument('--no-dns',             action='store_true')
    parser.add_argument('--no-ssl',             action='store_true')
    parser.add_argument('--no-directories',     action='store_true')
    parser.add_argument('--no-endpoints',       action='store_true')
    parser.add_argument('--no-vulnerabilities', action='store_true')
    parser.add_argument('--no-technology',      action='store_true')
    parser.add_argument('--no-cloud',           action='store_true')
    parser.add_argument('--no-wayback',         action='store_true')
    parser.add_argument('--no-github',          action='store_true')
    parser.add_argument('--no-waf',             action='store_true')
    parser.add_argument('--no-security-headers',action='store_true')
    parser.add_argument('--no-takeover',        action='store_true')
    parser.add_argument('--no-s3',              action='store_true')

    args = parser.parse_args()

    # Load API keys
    api_keys = {}
    if args.api_keys:
        try:
            with open(args.api_keys, 'r') as f:
                api_keys = json.load(f)
        except Exception as e:
            print(f"Error loading API keys: {e}")

    toolkit = BugBountyToolkit(
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_file=args.output,
        api_keys=api_keys,
        wordlist_path=args.wordlist
    )

    if args.domain or args.url:
        # Non-interactive CLI mode
        _print_disclaimer()
        time.sleep(1)
        options = {
            'waf':             not args.no_waf,
            'subdomain':       not args.no_subdomain,
            'ports':           not args.no_ports,
            'dns':             not args.no_dns,
            'ssl':             not args.no_ssl,
            'directories':     not args.no_directories,
            'endpoints':       not args.no_endpoints,
            'vulnerabilities': not args.no_vulnerabilities,
            'security_headers':not args.no_security_headers,
            'takeover':        not args.no_takeover,
            's3':              not args.no_s3,
            'technology':      not args.no_technology,
            'cloud':           not args.no_cloud,
            'wayback':         not args.no_wayback,
            'github':          not args.no_github,
        }
        target = args.domain or args.url
        toolkit.run_complete_scan(target, options)
    else:
        # Interactive mode
        _interactive_menu(toolkit)


if __name__ == "__main__":
    main()
