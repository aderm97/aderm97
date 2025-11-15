"""
Perimeter Security Assessment Module
Checks for internet-facing infrastructure vulnerabilities
"""

import socket
import ssl
import subprocess
from typing import Dict, List, Any
import re


def run(config: Dict, logger) -> Dict[str, Any]:
    """Run perimeter security checks"""
    findings = {
        'module': 'Perimeter Security',
        'checks': []
    }

    targets = config.get('targets', {}).get('internet_facing', [])
    if not targets and config.get('target'):
        targets = [config['target']]

    for target in targets:
        logger.info(f"  Scanning perimeter target: {target}")

        # Port scanning and service enumeration
        findings['checks'].extend(check_open_ports(target, logger))

        # SSL/TLS configuration
        findings['checks'].extend(check_ssl_tls_config(target, logger))

        # Banner grabbing
        findings['checks'].extend(check_service_banners(target, logger))

        # Common vulnerabilities
        findings['checks'].extend(check_common_vulns(target, logger))

    return findings


def check_open_ports(target: str, logger, common_ports: List[int] = None) -> List[Dict]:
    """Check for open ports and services"""
    if common_ports is None:
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]

    checks = []
    open_ports = []

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                logger.debug(f"    Port {port} is open on {target}")
        except socket.gaierror:
            checks.append({
                'check': 'DNS Resolution',
                'target': target,
                'status': 'failed',
                'severity': 'high',
                'finding': f'Cannot resolve hostname: {target}',
                'recommendation': 'Verify target hostname/IP address'
            })
            return checks
        except socket.error:
            pass
        finally:
            sock.close()

    # Evaluate findings
    risky_ports = {
        21: 'FTP - Insecure file transfer protocol',
        23: 'Telnet - Unencrypted remote access',
        3389: 'RDP - Remote Desktop exposed to internet',
        3306: 'MySQL - Database exposed to internet',
        5432: 'PostgreSQL - Database exposed to internet'
    }

    for port in open_ports:
        severity = 'critical' if port in risky_ports else 'medium'
        status = 'failed' if port in risky_ports else 'warning'

        checks.append({
            'check': 'Open Port Detection',
            'target': f'{target}:{port}',
            'status': status,
            'severity': severity,
            'finding': f'Port {port} is open' + (f' - {risky_ports[port]}' if port in risky_ports else ''),
            'recommendation': 'Review if this port should be exposed to internet' if port in risky_ports else 'Verify service necessity'
        })

    if not open_ports:
        checks.append({
            'check': 'Open Port Detection',
            'target': target,
            'status': 'passed',
            'severity': 'info',
            'finding': 'No common ports open',
            'recommendation': 'Continue monitoring'
        })

    return checks


def check_ssl_tls_config(target: str, logger, ports: List[int] = None) -> List[Dict]:
    """Check SSL/TLS configuration"""
    if ports is None:
        ports = [443, 8443]

    checks = []

    for port in ports:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    # Check TLS version
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    if protocol in weak_protocols:
                        checks.append({
                            'check': 'TLS Protocol Version',
                            'target': f'{target}:{port}',
                            'status': 'failed',
                            'severity': 'high',
                            'finding': f'Weak TLS protocol in use: {protocol}',
                            'recommendation': 'Upgrade to TLS 1.2 or 1.3'
                        })
                    else:
                        checks.append({
                            'check': 'TLS Protocol Version',
                            'target': f'{target}:{port}',
                            'status': 'passed',
                            'severity': 'info',
                            'finding': f'Using {protocol}',
                            'recommendation': 'Continue using strong TLS versions'
                        })

                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
                        if any(weak in cipher_name for weak in weak_ciphers):
                            checks.append({
                                'check': 'TLS Cipher Strength',
                                'target': f'{target}:{port}',
                                'status': 'failed',
                                'severity': 'high',
                                'finding': f'Weak cipher in use: {cipher_name}',
                                'recommendation': 'Configure strong cipher suites only'
                            })
                        else:
                            checks.append({
                                'check': 'TLS Cipher Strength',
                                'target': f'{target}:{port}',
                                'status': 'passed',
                                'severity': 'info',
                                'finding': f'Using cipher: {cipher_name}',
                                'recommendation': 'Continue monitoring cipher strength'
                            })

        except ssl.SSLError as e:
            checks.append({
                'check': 'SSL/TLS Configuration',
                'target': f'{target}:{port}',
                'status': 'failed',
                'severity': 'medium',
                'finding': f'SSL error: {str(e)}',
                'recommendation': 'Review SSL/TLS configuration'
            })
        except (socket.timeout, ConnectionRefusedError, OSError):
            # Port not open for SSL
            pass

    return checks


def check_service_banners(target: str, logger) -> List[Dict]:
    """Grab service banners for version information"""
    checks = []
    banner_ports = {
        21: 'FTP',
        22: 'SSH',
        25: 'SMTP',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP'
    }

    for port, service in banner_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))

            if port == 80:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            else:
                sock.send(b'\r\n')

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            if banner:
                # Check if version info is exposed
                version_pattern = r'\d+\.\d+(\.\d+)?'
                if re.search(version_pattern, banner):
                    checks.append({
                        'check': 'Service Banner Information Disclosure',
                        'target': f'{target}:{port}',
                        'status': 'warning',
                        'severity': 'low',
                        'finding': f'{service} service exposing version: {banner[:100]}',
                        'recommendation': 'Configure service to hide version information'
                    })
                else:
                    checks.append({
                        'check': 'Service Banner Configuration',
                        'target': f'{target}:{port}',
                        'status': 'passed',
                        'severity': 'info',
                        'finding': f'{service} banner does not expose version',
                        'recommendation': 'Continue hiding version information'
                    })
        except:
            pass

    return checks


def check_common_vulns(target: str, logger) -> List[Dict]:
    """Check for common vulnerabilities"""
    checks = []

    # Check for HTTP methods
    try:
        import urllib.request
        import urllib.error

        # Test for dangerous HTTP methods
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        for method in dangerous_methods:
            try:
                req = urllib.request.Request(f'http://{target}', method=method)
                req.add_header('User-Agent', 'Security-Scanner/1.0')
                response = urllib.request.urlopen(req, timeout=5)

                if response.getcode() != 405:  # Method not allowed
                    checks.append({
                        'check': 'HTTP Methods',
                        'target': target,
                        'status': 'failed',
                        'severity': 'medium',
                        'finding': f'Dangerous HTTP method {method} is allowed',
                        'recommendation': f'Disable {method} method on web server'
                    })
            except urllib.error.HTTPError as e:
                if e.code == 405:
                    # Method not allowed - good
                    pass
            except:
                pass
    except:
        pass

    # Check for robots.txt and sitemap.xml exposure
    try:
        import urllib.request
        for path in ['/robots.txt', '/sitemap.xml', '/.git/config', '/.env']:
            try:
                url = f'http://{target}{path}'
                response = urllib.request.urlopen(url, timeout=5)
                if response.getcode() == 200:
                    content = response.read().decode('utf-8', errors='ignore')
                    if path in ['/.git/config', '/.env']:
                        checks.append({
                            'check': 'Sensitive File Exposure',
                            'target': url,
                            'status': 'failed',
                            'severity': 'critical',
                            'finding': f'Sensitive file accessible: {path}',
                            'recommendation': 'Immediately block access to sensitive files'
                        })
                    elif len(content) > 0:
                        checks.append({
                            'check': 'Information Disclosure',
                            'target': url,
                            'status': 'warning',
                            'severity': 'low',
                            'finding': f'File accessible: {path}',
                            'recommendation': 'Review if this file should be publicly accessible'
                        })
            except:
                pass
    except:
        pass

    return checks
