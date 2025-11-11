#!/usr/bin/env python3
"""
Web Application Security Testing Script - Low-Hanging Fruit Edition
Focuses on easily exploitable vulnerabilities and misconfigurations
"""

import sys
import json
import argparse
import requests
import ssl
import socket
import re
from urllib.parse import urlparse, urljoin, quote
from datetime import datetime
from typing import Dict, List, Tuple
import warnings

# Suppress SSL warnings for testing purposes
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class SecurityScanner:
    """Main security scanner class - focuses on low-hanging fruit vulnerabilities"""

    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = target_url
        self.config = config or {}
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerability_count': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'tests': {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def print_banner(self):
        """Print scanner banner"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}")
        print("Low-Hanging Fruit Web Security Scanner")
        print("Focusing on Easy-to-Exploit Vulnerabilities")
        print(f"{'='*70}{Colors.RESET}\n")
        print(f"Target: {Colors.BOLD}{self.target_url}{Colors.RESET}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    def print_section(self, title: str):
        """Print section header"""
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}[*] {title}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'-'*70}{Colors.RESET}")

    def print_result(self, severity: str, message: str):
        """Print test result with severity"""
        if severity == "CRITICAL":
            self.results['vulnerability_count']['critical'] += 1
            print(f"{Colors.RED}{Colors.BOLD}[CRITICAL] {message}{Colors.RESET}")
        elif severity == "HIGH":
            self.results['vulnerability_count']['high'] += 1
            print(f"{Colors.RED}[HIGH] {message}{Colors.RESET}")
        elif severity == "MEDIUM":
            self.results['vulnerability_count']['medium'] += 1
            print(f"{Colors.YELLOW}[MEDIUM] {message}{Colors.RESET}")
        elif severity == "LOW":
            self.results['vulnerability_count']['low'] += 1
            print(f"{Colors.YELLOW}[LOW] {message}{Colors.RESET}")
        elif severity == "PASS":
            print(f"{Colors.GREEN}[✓] {message}{Colors.RESET}")
        else:
            print(f"{Colors.BLUE}[i] {message}{Colors.RESET}")

    def test_security_headers(self) -> Dict:
        """Comprehensive security headers testing - Primary low-hanging fruit"""
        self.print_section("Security Headers Analysis (HIGH PRIORITY)")
        results = {}

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            results['headers'] = dict(headers)

            # Critical Security Headers
            critical_headers = {
                'Strict-Transport-Security': {
                    'missing': 'HSTS not set - vulnerable to SSL stripping attacks',
                    'severity': 'HIGH',
                    'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
                },
                'X-Frame-Options': {
                    'missing': 'X-Frame-Options not set - vulnerable to clickjacking',
                    'severity': 'HIGH',
                    'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
                },
                'Content-Security-Policy': {
                    'missing': 'CSP not set - vulnerable to XSS and data injection',
                    'severity': 'HIGH',
                    'recommendation': "Add: Content-Security-Policy: default-src 'self'"
                },
                'X-Content-Type-Options': {
                    'missing': 'X-Content-Type-Options not set - vulnerable to MIME sniffing',
                    'severity': 'MEDIUM',
                    'recommendation': 'Add: X-Content-Type-Options: nosniff'
                }
            }

            results['missing_headers'] = []
            for header, info in critical_headers.items():
                if header not in headers:
                    self.print_result(info['severity'], info['missing'])
                    self.print_result("INFO", f"  Fix: {info['recommendation']}")
                    results['missing_headers'].append({
                        'header': header,
                        'severity': info['severity'],
                        'recommendation': info['recommendation']
                    })
                else:
                    value = headers[header]
                    self.print_result("PASS", f"{header}: {value}")

                    # Validate header values
                    if header == 'Strict-Transport-Security':
                        if 'max-age' not in value.lower():
                            self.print_result("MEDIUM", "HSTS missing max-age directive")
                        elif int(re.search(r'max-age=(\d+)', value).group(1)) < 31536000:
                            self.print_result("MEDIUM", "HSTS max-age is less than 1 year")

                    elif header == 'X-Frame-Options':
                        if value.upper() not in ['DENY', 'SAMEORIGIN']:
                            self.print_result("MEDIUM", f"Weak X-Frame-Options value: {value}")

                    elif header == 'Content-Security-Policy':
                        if 'unsafe-inline' in value or 'unsafe-eval' in value:
                            self.print_result("MEDIUM", "CSP contains unsafe directives")

            # Information Disclosure Headers (Easy Fixes)
            disclosure_headers = {
                'Server': 'Server version disclosed',
                'X-Powered-By': 'Technology stack disclosed',
                'X-AspNet-Version': 'ASP.NET version disclosed',
                'X-AspNetMvc-Version': 'ASP.NET MVC version disclosed',
                'X-Generator': 'Generator information disclosed'
            }

            results['information_disclosure'] = []
            for header, message in disclosure_headers.items():
                if header in headers:
                    self.print_result("MEDIUM", f"{message}: {headers[header]}")
                    results['information_disclosure'].append({
                        'header': header,
                        'value': headers[header],
                        'message': message
                    })

            # Cache Control Issues
            cache_control = headers.get('Cache-Control', '')
            if not cache_control:
                self.print_result("LOW", "Cache-Control header missing")
            elif 'no-store' not in cache_control and 'private' not in cache_control:
                self.print_result("LOW", "Cache-Control may allow sensitive data caching")

        except Exception as e:
            self.print_result("INFO", f"Header test failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['security_headers'] = results
        return results

    def test_header_injection(self) -> Dict:
        """Test for header injection vulnerabilities"""
        self.print_section("Header Injection Tests")
        results = {'vulnerabilities': []}

        payloads = [
            ('\r\nX-Injected: true', 'CRLF Injection'),
            ('%0d%0aX-Injected: true', 'URL-encoded CRLF'),
            ('\nX-Injected: true', 'LF Injection'),
            ('%0aX-Injected: true', 'URL-encoded LF')
        ]

        try:
            # Test Host header injection
            try:
                malicious_host = 'evil.com'
                response = self.session.get(
                    self.target_url,
                    headers={'Host': malicious_host},
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )
                if malicious_host in response.text or malicious_host in str(response.headers):
                    self.print_result("HIGH", "Host header injection possible - reflected in response")
                    results['vulnerabilities'].append({
                        'type': 'Host Header Injection',
                        'severity': 'HIGH',
                        'description': 'Malicious host header reflected in response'
                    })
                else:
                    self.print_result("PASS", "Host header injection not detected")
            except:
                pass

            # Test X-Forwarded headers
            forwarded_headers = {
                'X-Forwarded-For': '127.0.0.1',
                'X-Forwarded-Host': 'evil.com',
                'X-Forwarded-Proto': 'http',
                'X-Real-IP': '127.0.0.1'
            }

            response = self.session.get(
                self.target_url,
                headers=forwarded_headers,
                timeout=5,
                verify=False
            )

            if 'evil.com' in response.text:
                self.print_result("HIGH", "X-Forwarded-Host header injection detected")
                results['vulnerabilities'].append({
                    'type': 'X-Forwarded-Host Injection',
                    'severity': 'HIGH'
                })

            # Test Referer-based attacks
            malicious_referer = 'https://evil.com/attack'
            response = self.session.get(
                self.target_url,
                headers={'Referer': malicious_referer},
                timeout=5,
                verify=False
            )

            if 'evil.com' in response.text:
                self.print_result("MEDIUM", "Referer header reflected in response")
                results['vulnerabilities'].append({
                    'type': 'Referer Reflection',
                    'severity': 'MEDIUM'
                })

            if not results['vulnerabilities']:
                self.print_result("PASS", "No header injection vulnerabilities detected")

        except Exception as e:
            self.print_result("INFO", f"Header injection test failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['header_injection'] = results
        return results

    def test_clickjacking(self) -> Dict:
        """Test for clickjacking vulnerability"""
        self.print_section("Clickjacking Protection")
        results = {}

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = response.headers

            x_frame = headers.get('X-Frame-Options')
            csp = headers.get('Content-Security-Policy', '')

            vulnerable = True

            if x_frame:
                if x_frame.upper() in ['DENY', 'SAMEORIGIN']:
                    self.print_result("PASS", f"X-Frame-Options set correctly: {x_frame}")
                    vulnerable = False
                else:
                    self.print_result("HIGH", f"Weak X-Frame-Options: {x_frame}")

            if 'frame-ancestors' in csp:
                self.print_result("PASS", "CSP frame-ancestors directive present")
                vulnerable = False

            if vulnerable:
                self.print_result("HIGH", "VULNERABLE to clickjacking attacks")
                self.print_result("INFO", "  Fix: Add X-Frame-Options: DENY or CSP frame-ancestors")
                results['vulnerable'] = True
                results['severity'] = 'HIGH'
            else:
                results['vulnerable'] = False

        except Exception as e:
            results['error'] = str(e)

        self.results['tests']['clickjacking'] = results
        return results

    def test_common_vulnerabilities(self) -> Dict:
        """Test for common easy-to-find vulnerabilities"""
        self.print_section("Common Misconfigurations & Exposed Resources")
        results = {'found': []}

        # Expanded sensitive paths
        sensitive_paths = [
            # Version Control
            ('/.git/HEAD', 'Git repository exposed - source code leakage', 'CRITICAL'),
            ('/.git/config', 'Git config exposed', 'CRITICAL'),
            ('/.svn/entries', 'SVN repository exposed', 'CRITICAL'),

            # Backup Files
            ('/backup.zip', 'Backup file accessible', 'CRITICAL'),
            ('/backup.sql', 'SQL backup exposed', 'CRITICAL'),
            ('/backup.tar.gz', 'Backup archive accessible', 'CRITICAL'),
            ('/db_backup.sql', 'Database backup exposed', 'CRITICAL'),
            ('/dump.sql', 'SQL dump exposed', 'CRITICAL'),
            ('/site-backup.zip', 'Site backup accessible', 'CRITICAL'),

            # Configuration Files
            ('/.env', 'Environment config exposed - may contain secrets', 'CRITICAL'),
            ('/config.php', 'Config file accessible', 'HIGH'),
            ('/config.json', 'JSON config exposed', 'HIGH'),
            ('/web.config', 'Web.config accessible', 'HIGH'),
            ('/.htaccess', '.htaccess file accessible', 'MEDIUM'),
            ('/phpinfo.php', 'PHPInfo page exposed', 'HIGH'),
            ('/info.php', 'PHP info page exposed', 'HIGH'),
            ('/wp-config.php', 'WordPress config accessible', 'CRITICAL'),
            ('/wp-config.php.bak', 'WordPress config backup', 'CRITICAL'),

            # Admin Panels
            ('/admin', 'Admin panel accessible', 'HIGH'),
            ('/admin/', 'Admin panel accessible', 'HIGH'),
            ('/administrator', 'Administrator panel', 'HIGH'),
            ('/phpmyadmin', 'phpMyAdmin accessible', 'HIGH'),
            ('/cpanel', 'cPanel accessible', 'MEDIUM'),
            ('/wp-admin', 'WordPress admin accessible', 'MEDIUM'),

            # Debug/Development
            ('/debug', 'Debug interface accessible', 'HIGH'),
            ('/console', 'Console accessible', 'HIGH'),
            ('/test', 'Test page accessible', 'MEDIUM'),
            ('/test.php', 'Test PHP page accessible', 'MEDIUM'),

            # Information Files
            ('/.DS_Store', 'MacOS .DS_Store file exposed', 'MEDIUM'),
            ('/robots.txt', 'robots.txt present (check for sensitive paths)', 'LOW'),
            ('/.well-known/security.txt', 'Security.txt present', 'INFO'),

            # Logs
            ('/error_log', 'Error log accessible', 'HIGH'),
            ('/error.log', 'Error log accessible', 'HIGH'),
            ('/access.log', 'Access log accessible', 'HIGH'),
            ('/application.log', 'Application log accessible', 'HIGH'),
        ]

        try:
            for path, description, severity in sensitive_paths:
                url = urljoin(self.target_url, path)
                try:
                    response = self.session.get(
                        url,
                        timeout=5,
                        verify=False,
                        allow_redirects=False
                    )

                    if response.status_code == 200:
                        self.print_result(severity, f"{description}: {path}")
                        results['found'].append({
                            'path': path,
                            'status': response.status_code,
                            'description': description,
                            'severity': severity,
                            'size': len(response.content)
                        })
                    elif response.status_code == 403:
                        self.print_result("LOW", f"Path exists but forbidden: {path}")
                        results['found'].append({
                            'path': path,
                            'status': 403,
                            'description': f"{description} (Forbidden)",
                            'severity': 'LOW'
                        })
                except:
                    pass

            if not results['found']:
                self.print_result("PASS", "No common sensitive paths found")

        except Exception as e:
            self.print_result("INFO", f"Path enumeration failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['common_vulnerabilities'] = results
        return results

    def test_information_disclosure(self) -> Dict:
        """Test for information disclosure - easy to exploit"""
        self.print_section("Information Disclosure")
        results = {}

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            content = response.text.lower()

            # Error messages and stack traces
            error_patterns = {
                'SQL Error': r'(sql syntax|mysql|postgres|ora-\d+|sqlite)',
                'Stack Trace': r'(stack trace|traceback|exception in)',
                'Path Disclosure': r'([a-z]:\\\\|/home/|/var/www/|/usr/local)',
                'PHP Error': r'(warning:|fatal error:|parse error:)',
                'ASP.NET Error': r'(server error in|runtime error)',
                'Java Error': r'(java\.|javax\.|\.java:)',
                'Debug Info': r'(debug mode|debug=true|development mode)'
            }

            results['disclosures'] = []
            for error_type, pattern in error_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    self.print_result("MEDIUM", f"{error_type} detected in response")
                    results['disclosures'].append({
                        'type': error_type,
                        'severity': 'MEDIUM'
                    })

            # Check comments for sensitive information
            comments = re.findall(r'<!--.*?-->', response.text, re.DOTALL)
            sensitive_in_comments = []

            for comment in comments[:10]:  # Check first 10 comments
                comment_lower = comment.lower()
                if any(word in comment_lower for word in ['password', 'api', 'key', 'secret', 'token', 'todo', 'fix', 'bug']):
                    self.print_result("MEDIUM", f"Sensitive info in HTML comment")
                    sensitive_in_comments.append(comment[:100])

            if sensitive_in_comments:
                results['sensitive_comments'] = sensitive_in_comments

            # Directory listing
            if '<title>Index of' in response.text or 'Directory Listing' in response.text:
                self.print_result("HIGH", "Directory listing enabled")
                results['directory_listing'] = True

            # Test 404 page
            not_found = self.session.get(
                urljoin(self.target_url, '/nonexistent-' + 'x'*20),
                timeout=5,
                verify=False
            )

            if len(not_found.text) > 2000:
                self.print_result("LOW", "Verbose error pages (may leak information)")
                results['verbose_errors'] = True

            if not results.get('disclosures') and not results.get('sensitive_comments'):
                self.print_result("PASS", "No obvious information disclosure detected")

        except Exception as e:
            results['error'] = str(e)

        self.results['tests']['information_disclosure'] = results
        return results

    def test_http_methods(self) -> Dict:
        """Test for dangerous HTTP methods"""
        self.print_section("HTTP Methods Security")
        results = {}

        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'TRACK', 'CONNECT']

        try:
            # Test OPTIONS
            response = self.session.options(self.target_url, timeout=10, verify=False)
            allowed = response.headers.get('Allow', '')

            if allowed:
                results['allowed_methods'] = allowed
                self.print_result("INFO", f"Allowed methods: {allowed}")

                for method in dangerous_methods:
                    if method in allowed.upper():
                        self.print_result("HIGH", f"Dangerous method enabled: {method}")
                        results[f'dangerous_{method}'] = True

            # Test TRACE specifically (XST attack)
            trace_response = self.session.request('TRACE', self.target_url, timeout=5, verify=False)
            if trace_response.status_code < 400:
                self.print_result("HIGH", "TRACE method enabled - Cross-Site Tracing (XST) possible")
                results['trace_enabled'] = True
            else:
                self.print_result("PASS", "TRACE method disabled")

            # Test if PUT actually works
            try:
                put_test = self.session.request(
                    'PUT',
                    urljoin(self.target_url, '/test-' + str(datetime.now().timestamp()) + '.txt'),
                    data='test',
                    timeout=5,
                    verify=False
                )
                if put_test.status_code in [200, 201, 204]:
                    self.print_result("CRITICAL", "PUT method allows file upload!")
                    results['put_upload_possible'] = True
            except:
                pass

        except Exception as e:
            results['error'] = str(e)

        self.results['tests']['http_methods'] = results
        return results

    def test_ssl_tls(self) -> Dict:
        """Quick SSL/TLS check for common issues"""
        self.print_section("SSL/TLS Configuration")
        results = {}

        parsed = urlparse(self.target_url)
        if parsed.scheme != 'https':
            self.print_result("HIGH", "Site not using HTTPS - data transmitted in clear text")
            results['https_enabled'] = False
            return results

        try:
            hostname = parsed.hostname
            port = parsed.port or 443

            # Test for weak protocols
            weak_protocols = {
                ssl.PROTOCOL_TLSv1: 'TLSv1.0',
                ssl.PROTOCOL_TLSv1_1: 'TLSv1.1'
            }

            results['weak_protocols'] = []
            for protocol, name in weak_protocols.items():
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            self.print_result("MEDIUM", f"Weak protocol supported: {name}")
                            results['weak_protocols'].append(name)
                except:
                    pass

            if not results['weak_protocols']:
                self.print_result("PASS", "No weak TLS protocols detected")

            # Get current protocol
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocol = ssock.version()
                    self.print_result("INFO", f"TLS version: {protocol}")
                    results['current_protocol'] = protocol

        except Exception as e:
            results['error'] = str(e)

        self.results['tests']['ssl_tls'] = results
        return results

    def test_cors_misconfiguration(self) -> Dict:
        """Test for CORS misconfigurations - easy to exploit"""
        self.print_section("CORS Misconfiguration")
        results = {}

        evil_origins = [
            'https://evil.com',
            'http://evil.com',
            'null'
        ]

        try:
            for origin in evil_origins:
                response = self.session.get(
                    self.target_url,
                    headers={'Origin': origin},
                    timeout=5,
                    verify=False
                )

                acao = response.headers.get('Access-Control-Allow-Origin')
                acac = response.headers.get('Access-Control-Allow-Credentials')

                if acao == origin:
                    severity = "CRITICAL" if acac == 'true' else "HIGH"
                    self.print_result(
                        severity,
                        f"CORS reflects origin: {origin}" +
                        (" with credentials!" if acac == 'true' else "")
                    )
                    results['reflects_origin'] = True
                    results['severity'] = severity
                    break
                elif acao == '*':
                    severity = "HIGH" if acac != 'true' else "CRITICAL"
                    self.print_result(severity, "CORS allows all origins (*)")
                    results['wildcard'] = True
                    break

            if not results.get('reflects_origin') and not results.get('wildcard'):
                self.print_result("PASS", "No CORS misconfiguration detected")

        except Exception as e:
            results['error'] = str(e)

        self.results['tests']['cors'] = results
        return results

    def test_open_redirect(self) -> Dict:
        """Test for open redirect vulnerabilities"""
        self.print_section("Open Redirect Detection")
        results = {'vulnerable_params': []}

        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'goto', 'target', 'dest', 'destination']
        test_url = 'https://evil.com'

        try:
            for param in redirect_params:
                test_target = f"{self.target_url}?{param}={test_url}"
                try:
                    response = self.session.get(
                        test_target,
                        timeout=5,
                        verify=False,
                        allow_redirects=False
                    )

                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location:
                            self.print_result("HIGH", f"Open redirect via parameter: {param}")
                            results['vulnerable_params'].append(param)
                except:
                    pass

            if not results['vulnerable_params']:
                self.print_result("PASS", "No open redirect vulnerabilities found")

        except Exception as e:
            results['error'] = str(e)

        self.results['tests']['open_redirect'] = results
        return results

    def run_all_tests(self) -> Dict:
        """Run all security tests focused on low-hanging fruit"""
        self.print_banner()

        # Priority order - most critical/easy to exploit first
        self.test_common_vulnerabilities()      # Check exposed files/dirs first
        self.test_security_headers()            # Missing security headers
        self.test_clickjacking()                # Quick clickjacking check
        self.test_header_injection()            # Header manipulation
        self.test_information_disclosure()      # Info leakage
        self.test_http_methods()                # Dangerous methods
        self.test_cors_misconfiguration()       # CORS issues
        self.test_open_redirect()               # Open redirects
        self.test_ssl_tls()                     # SSL/TLS issues

        return self.results

    def generate_summary(self):
        """Generate vulnerability summary"""
        self.print_section("Vulnerability Summary")

        counts = self.results['vulnerability_count']
        total = sum(counts.values())

        print(f"\nTotal Issues Found: {Colors.BOLD}{total}{Colors.RESET}")
        print(f"  {Colors.RED}Critical: {counts['critical']}{Colors.RESET}")
        print(f"  {Colors.RED}High: {counts['high']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Medium: {counts['medium']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Low: {counts['low']}{Colors.RESET}")

        if counts['critical'] > 0:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠ CRITICAL issues found! Immediate action required.{Colors.RESET}")
        elif counts['high'] > 0:
            print(f"\n{Colors.RED}⚠ HIGH severity issues found. Should be addressed soon.{Colors.RESET}")
        elif total > 0:
            print(f"\n{Colors.YELLOW}Some security issues found. Review and fix when possible.{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}No major low-hanging fruit vulnerabilities detected.{Colors.RESET}")

    def generate_report(self, output_file: str = None):
        """Generate JSON report"""
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.print_section("Report Generated")
            print(f"Detailed report saved to: {output_file}")

        return self.results


def main():
    parser = argparse.ArgumentParser(
        description='Web Application Security Scanner - Low-Hanging Fruit Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This scanner focuses on easily exploitable vulnerabilities:
  - Missing security headers
  - Exposed configuration files and backups
  - Information disclosure
  - Common misconfigurations
  - Header injection attacks
  - CORS issues
  - Open redirects

Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com -o report.json
  %(prog)s -f targets.txt -o results/
        """
    )

    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs to scan')
    parser.add_argument('-o', '--output', help='Output file/directory for JSON report')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error('Either --url or --file must be specified')

    targets = []
    if args.url:
        targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File not found: {args.file}{Colors.RESET}")
            sys.exit(1)

    for target in targets:
        scanner = SecurityScanner(target)
        scanner.run_all_tests()
        scanner.generate_summary()

        if args.output:
            if len(targets) > 1:
                import os
                os.makedirs(args.output, exist_ok=True)
                filename = urlparse(target).netloc.replace(':', '_') + '.json'
                output_path = os.path.join(args.output, filename)
            else:
                output_path = args.output

            scanner.generate_report(output_path)

        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}\n")


if __name__ == '__main__':
    main()
