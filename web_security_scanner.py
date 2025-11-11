#!/usr/bin/env python3
"""
Web Application Security Testing Script
Automates security testing for external-facing web applications
"""

import sys
import json
import argparse
import requests
import ssl
import socket
from urllib.parse import urlparse, urljoin
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
    """Main security scanner class"""

    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = target_url
        self.config = config or {}
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'tests': {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security-Scanner/1.0'
        })

    def print_banner(self):
        """Print scanner banner"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}")
        print("Web Application Security Scanner")
        print(f"{'='*70}{Colors.RESET}\n")
        print(f"Target: {Colors.BOLD}{self.target_url}{Colors.RESET}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    def print_section(self, title: str):
        """Print section header"""
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}[*] {title}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'-'*70}{Colors.RESET}")

    def print_result(self, status: str, message: str):
        """Print test result"""
        if status == "PASS":
            print(f"{Colors.GREEN}[✓] {message}{Colors.RESET}")
        elif status == "FAIL":
            print(f"{Colors.RED}[✗] {message}{Colors.RESET}")
        elif status == "WARN":
            print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")
        else:
            print(f"{Colors.BLUE}[i] {message}{Colors.RESET}")

    def test_ssl_tls(self) -> Dict:
        """Test SSL/TLS configuration"""
        self.print_section("SSL/TLS Security")
        results = {}

        parsed = urlparse(self.target_url)
        if parsed.scheme != 'https':
            self.print_result("WARN", "Target is not using HTTPS")
            results['https_enabled'] = False
            return results

        try:
            hostname = parsed.hostname
            port = parsed.port or 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    results['protocol'] = protocol
                    results['cipher'] = cipher
                    results['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'notAfter': cert['notAfter']
                    }

                    self.print_result("PASS", f"HTTPS enabled with {protocol}")
                    self.print_result("INFO", f"Cipher: {cipher[0]}")

                    # Check for weak protocols
                    if protocol in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        self.print_result("FAIL", f"Weak protocol detected: {protocol}")
                        results['weak_protocol'] = True
                    else:
                        self.print_result("PASS", "Strong TLS protocol in use")
                        results['weak_protocol'] = False

        except Exception as e:
            self.print_result("FAIL", f"SSL/TLS test failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['ssl_tls'] = results
        return results

    def test_security_headers(self) -> Dict:
        """Test HTTP security headers"""
        self.print_section("HTTP Security Headers")
        results = {}

        required_headers = {
            'Strict-Transport-Security': 'HSTS not set - site vulnerable to downgrade attacks',
            'X-Content-Type-Options': 'X-Content-Type-Options not set - vulnerable to MIME sniffing',
            'X-Frame-Options': 'X-Frame-Options not set - vulnerable to clickjacking',
            'Content-Security-Policy': 'CSP not set - vulnerable to XSS attacks',
            'X-XSS-Protection': 'X-XSS-Protection not set',
            'Referrer-Policy': 'Referrer-Policy not set - may leak sensitive URLs'
        }

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = response.headers

            for header, warning in required_headers.items():
                if header in headers:
                    self.print_result("PASS", f"{header}: {headers[header]}")
                    results[header] = {'present': True, 'value': headers[header]}
                else:
                    self.print_result("FAIL", warning)
                    results[header] = {'present': False}

            # Check for information disclosure headers
            disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in disclosure_headers:
                if header in headers:
                    self.print_result("WARN", f"{header} header present: {headers[header]} (information disclosure)")
                    results[f'disclosure_{header}'] = headers[header]

        except Exception as e:
            self.print_result("FAIL", f"Header test failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['security_headers'] = results
        return results

    def test_cookie_security(self) -> Dict:
        """Test cookie security attributes"""
        self.print_section("Cookie Security")
        results = {}

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            cookies = response.cookies

            if not cookies:
                self.print_result("INFO", "No cookies set by the application")
                results['cookies_present'] = False
                return results

            results['cookies_present'] = True
            results['cookies'] = []

            for cookie in cookies:
                cookie_info = {
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': cookie.get_nonstandard_attr('SameSite')
                }
                results['cookies'].append(cookie_info)

                self.print_result("INFO", f"Cookie: {cookie.name}")

                if not cookie.secure and self.target_url.startswith('https'):
                    self.print_result("FAIL", f"  Secure flag not set on cookie: {cookie.name}")
                else:
                    self.print_result("PASS", f"  Secure flag set")

                if not cookie.has_nonstandard_attr('HttpOnly'):
                    self.print_result("FAIL", f"  HttpOnly flag not set - vulnerable to XSS")
                else:
                    self.print_result("PASS", f"  HttpOnly flag set")

                samesite = cookie.get_nonstandard_attr('SameSite')
                if not samesite:
                    self.print_result("WARN", f"  SameSite attribute not set - vulnerable to CSRF")
                else:
                    self.print_result("PASS", f"  SameSite: {samesite}")

        except Exception as e:
            self.print_result("FAIL", f"Cookie test failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['cookie_security'] = results
        return results

    def test_cors_policy(self) -> Dict:
        """Test CORS policy"""
        self.print_section("CORS Policy")
        results = {}

        try:
            # Test with a foreign origin
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(self.target_url, headers=headers, timeout=10, verify=False)

            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')

            if acao:
                results['acao'] = acao
                if acao == '*':
                    self.print_result("FAIL", f"CORS allows all origins: {acao}")
                    if acac == 'true':
                        self.print_result("FAIL", "CRITICAL: Credentials allowed with wildcard origin")
                        results['critical_misconfiguration'] = True
                elif acao == 'https://evil.com':
                    self.print_result("FAIL", "CORS reflects arbitrary origins - potential vulnerability")
                    results['reflects_origin'] = True
                else:
                    self.print_result("PASS", f"CORS restricted to: {acao}")
            else:
                self.print_result("PASS", "No CORS headers present")
                results['cors_enabled'] = False

        except Exception as e:
            self.print_result("FAIL", f"CORS test failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['cors_policy'] = results
        return results

    def test_http_methods(self) -> Dict:
        """Test allowed HTTP methods"""
        self.print_section("HTTP Methods")
        results = {}

        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']

        try:
            response = self.session.options(self.target_url, timeout=10, verify=False)
            allowed = response.headers.get('Allow', '')
            results['allowed_methods'] = allowed

            if allowed:
                self.print_result("INFO", f"Allowed methods: {allowed}")

                for method in dangerous_methods:
                    if method in allowed.upper():
                        self.print_result("WARN", f"Potentially dangerous method allowed: {method}")
                        results[f'dangerous_{method}'] = True
            else:
                self.print_result("INFO", "No Allow header returned")

            # Test TRACE method specifically
            trace_response = self.session.request('TRACE', self.target_url, timeout=10, verify=False)
            if trace_response.status_code != 405:
                self.print_result("FAIL", "TRACE method is enabled - vulnerable to XST attacks")
                results['trace_enabled'] = True
            else:
                self.print_result("PASS", "TRACE method disabled")
                results['trace_enabled'] = False

        except Exception as e:
            self.print_result("FAIL", f"HTTP methods test failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['http_methods'] = results
        return results

    def test_common_paths(self) -> Dict:
        """Test for common sensitive paths and files"""
        self.print_section("Common Sensitive Paths")
        results = {}

        common_paths = [
            '/.git/config',
            '/.env',
            '/admin',
            '/administrator',
            '/phpmyadmin',
            '/backup',
            '/backup.zip',
            '/backup.sql',
            '/.DS_Store',
            '/web.config',
            '/config.php',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml'
        ]

        results['found_paths'] = []

        try:
            for path in common_paths:
                url = urljoin(self.target_url, path)
                try:
                    response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                    if response.status_code == 200:
                        self.print_result("FAIL", f"Sensitive path accessible: {path} (Status: {response.status_code})")
                        results['found_paths'].append({'path': path, 'status': response.status_code})
                    elif response.status_code in [301, 302]:
                        self.print_result("WARN", f"Path redirects: {path} (Status: {response.status_code})")
                except:
                    pass

            if not results['found_paths']:
                self.print_result("PASS", "No common sensitive paths found")

        except Exception as e:
            self.print_result("FAIL", f"Path enumeration failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['common_paths'] = results
        return results

    def test_input_validation(self) -> Dict:
        """Test basic input validation"""
        self.print_section("Input Validation Tests")
        results = {}

        # XSS payloads
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "javascript:alert(1)"
        ]

        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "admin' --"
        ]

        results['xss_tests'] = []
        results['sql_tests'] = []

        try:
            # Test for reflected XSS (basic check)
            for payload in xss_payloads:
                test_url = f"{self.target_url}?test={payload}"
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    if payload in response.text:
                        self.print_result("WARN", f"Potential XSS: Payload reflected in response")
                        results['xss_tests'].append({'payload': payload, 'reflected': True})
                        break
                except:
                    pass

            if not results['xss_tests']:
                self.print_result("PASS", "No obvious XSS vulnerabilities detected (basic check)")

            self.print_result("INFO", "SQL injection requires manual testing with tools like SQLMap")

        except Exception as e:
            self.print_result("FAIL", f"Input validation test failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['input_validation'] = results
        return results

    def test_information_disclosure(self) -> Dict:
        """Test for information disclosure"""
        self.print_section("Information Disclosure")
        results = {}

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check for error messages
            error_indicators = [
                'fatal error',
                'warning:',
                'mysql_',
                'syntax error',
                'stack trace',
                'exception',
                'traceback'
            ]

            results['error_disclosure'] = False
            for indicator in error_indicators:
                if indicator.lower() in response.text.lower():
                    self.print_result("WARN", f"Potential error message disclosure: '{indicator}' found in response")
                    results['error_disclosure'] = True
                    break

            if not results['error_disclosure']:
                self.print_result("PASS", "No obvious error message disclosure")

            # Check response size for 404 errors
            try:
                not_found = self.session.get(urljoin(self.target_url, '/nonexistent-page-12345'),
                                            timeout=5, verify=False)
                if len(not_found.text) > 1000:
                    self.print_result("WARN", "Verbose 404 error page (may disclose information)")
                    results['verbose_404'] = True
            except:
                pass

        except Exception as e:
            self.print_result("FAIL", f"Information disclosure test failed: {str(e)}")
            results['error'] = str(e)

        self.results['tests']['information_disclosure'] = results
        return results

    def run_all_tests(self) -> Dict:
        """Run all security tests"""
        self.print_banner()

        self.test_ssl_tls()
        self.test_security_headers()
        self.test_cookie_security()
        self.test_cors_policy()
        self.test_http_methods()
        self.test_common_paths()
        self.test_input_validation()
        self.test_information_disclosure()

        return self.results

    def generate_report(self, output_file: str = None):
        """Generate JSON report"""
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.print_section("Report Generated")
            print(f"Report saved to: {output_file}")

        return self.results


def main():
    parser = argparse.ArgumentParser(
        description='Web Application Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
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
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File not found: {args.file}{Colors.RESET}")
            sys.exit(1)

    for target in targets:
        scanner = SecurityScanner(target)
        scanner.run_all_tests()

        if args.output:
            if len(targets) > 1:
                # Multiple targets - create separate files
                import os
                os.makedirs(args.output, exist_ok=True)
                filename = urlparse(target).netloc.replace(':', '_') + '.json'
                output_path = os.path.join(args.output, filename)
            else:
                output_path = args.output

            scanner.generate_report(output_path)

        print(f"\n{Colors.GREEN}{Colors.BOLD}Scan completed!{Colors.RESET}\n")


if __name__ == '__main__':
    main()
