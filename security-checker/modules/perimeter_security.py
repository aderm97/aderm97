"""
Perimeter Security Assessment Module
Checks for internet-facing infrastructure vulnerabilities using professional tools
"""

import socket
import ssl
import subprocess
from typing import Dict, List, Any
import re
import json
import os


def run(config: Dict, logger) -> Dict[str, Any]:
    """Run perimeter security checks"""
    findings = {
        'module': 'Perimeter Security',
        'checks': []
    }

    targets = config.get('targets', {}).get('internet_facing', [])
    if not targets and config.get('target'):
        targets = [{'ip': config['target'], 'name': config['target']}]

    # Check tool availability
    tools_available = {
        'nmap': check_tool('nmap'),
        'masscan': check_tool('masscan'),
        'testssl': check_tool('testssl.sh') or check_tool('testssl'),
        'nikto': check_tool('nikto'),
        'sslscan': check_tool('sslscan'),
        'sslyze': check_tool('sslyze'),
    }

    for target_info in targets:
        target = target_info.get('ip') if isinstance(target_info, dict) else target_info
        name = target_info.get('name', target) if isinstance(target_info, dict) else target

        logger.info(f"  Scanning perimeter target: {name} ({target})")

        # Port scanning with nmap or fallback
        if tools_available['nmap']:
            findings['checks'].extend(nmap_port_scan(target, name, logger))
            findings['checks'].extend(nmap_service_detection(target, name, logger))
            findings['checks'].extend(nmap_vuln_scan(target, name, logger))
        elif tools_available['masscan']:
            findings['checks'].extend(masscan_port_scan(target, name, logger))
        else:
            findings['checks'].extend(basic_port_scan(target, name, logger))

        # SSL/TLS testing with specialized tools
        if tools_available['testssl']:
            findings['checks'].extend(testssl_scan(target, name, logger))
        elif tools_available['sslscan']:
            findings['checks'].extend(sslscan_scan(target, name, logger))
        elif tools_available['sslyze']:
            findings['checks'].extend(sslyze_scan(target, name, logger))
        else:
            findings['checks'].extend(basic_ssl_check(target, name, logger))

        # Web server scanning
        if tools_available['nikto']:
            findings['checks'].extend(nikto_scan(target, name, logger))

    return findings


def check_tool(tool_name: str) -> bool:
    """Check if a tool is available"""
    try:
        result = subprocess.run(
            ['which', tool_name],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False


def nmap_port_scan(target: str, name: str, logger, scan_type: str = 'quick') -> List[Dict]:
    """
    Perform port scan using nmap
    scan_type: 'quick', 'full', 'stealth'
    """
    checks = []
    logger.info(f"    Running nmap port scan...")

    try:
        if scan_type == 'quick':
            # Quick scan of common ports
            cmd = ['nmap', '-T4', '-F', '--open', '-oX', '-', target]
        elif scan_type == 'full':
            # Full port scan
            cmd = ['nmap', '-T4', '-p-', '--open', '-oX', '-', target]
        elif scan_type == 'stealth':
            # SYN stealth scan (requires root)
            cmd = ['sudo', 'nmap', '-sS', '-T4', '-F', '--open', '-oX', '-', target]
        else:
            cmd = ['nmap', '-T4', '-F', '--open', '-oX', '-', target]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes
        )

        if result.returncode == 0:
            # Parse nmap XML output
            open_ports = parse_nmap_ports(result.stdout)

            if open_ports:
                # Check for risky ports
                risky_ports = {
                    21: 'FTP - Insecure file transfer',
                    23: 'Telnet - Unencrypted remote access',
                    25: 'SMTP - Email server exposed',
                    69: 'TFTP - Trivial FTP (very insecure)',
                    135: 'MS RPC - Windows RPC',
                    139: 'NetBIOS - File sharing',
                    445: 'SMB - File sharing (ransomware risk)',
                    1433: 'MS SQL - Database exposed',
                    3306: 'MySQL - Database exposed',
                    3389: 'RDP - Remote Desktop exposed',
                    5432: 'PostgreSQL - Database exposed',
                    5900: 'VNC - Remote access',
                    6379: 'Redis - Database exposed',
                    27017: 'MongoDB - Database exposed',
                }

                for port_info in open_ports:
                    port = port_info['port']
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', '')

                    if port in risky_ports:
                        checks.append({
                            'check': 'Risky Port Exposed',
                            'target': f'{name} ({target}:{port})',
                            'status': 'failed',
                            'severity': 'critical' if port in [23, 69, 3389] else 'high',
                            'finding': f'{risky_ports[port]} | Service: {service} {version}',
                            'recommendation': f'Close port {port} or restrict access to trusted networks only'
                        })
                    else:
                        checks.append({
                            'check': 'Open Port Detection',
                            'target': f'{name} ({target}:{port})',
                            'status': 'warning',
                            'severity': 'medium',
                            'finding': f'Port {port} open | Service: {service} {version}',
                            'recommendation': 'Verify if this port should be exposed to internet'
                        })
            else:
                checks.append({
                    'check': 'Port Scan',
                    'target': f'{name} ({target})',
                    'status': 'passed',
                    'severity': 'info',
                    'finding': 'No open ports detected in quick scan',
                    'recommendation': 'Good security posture - continue monitoring'
                })

        else:
            logger.warning(f"    Nmap scan failed: {result.stderr}")

    except subprocess.TimeoutExpired:
        checks.append({
            'check': 'Port Scan',
            'target': f'{name} ({target})',
            'status': 'warning',
            'severity': 'low',
            'finding': 'Port scan timed out',
            'recommendation': 'Target may be rate-limiting or blocking scans'
        })
    except Exception as e:
        logger.error(f"    Nmap error: {e}")

    return checks


def nmap_service_detection(target: str, name: str, logger) -> List[Dict]:
    """Run nmap service and version detection"""
    checks = []
    logger.info(f"    Running nmap service detection...")

    try:
        cmd = ['nmap', '-sV', '--version-intensity', '5', '-T4', '-F', target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0:
            # Check for version information disclosure
            if 'version' in result.stdout.lower():
                checks.append({
                    'check': 'Service Version Disclosure',
                    'target': f'{name} ({target})',
                    'status': 'warning',
                    'severity': 'low',
                    'finding': 'Services exposing version information',
                    'recommendation': 'Configure services to hide version banners where possible'
                })

    except Exception as e:
        logger.debug(f"    Service detection error: {e}")

    return checks


def nmap_vuln_scan(target: str, name: str, logger) -> List[Dict]:
    """Run nmap vulnerability scripts"""
    checks = []
    logger.info(f"    Running nmap vulnerability scan...")

    try:
        cmd = ['nmap', '--script', 'vuln', '-T4', '-Pn', target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes
        )

        if result.returncode == 0:
            # Parse for vulnerabilities
            if 'VULNERABLE' in result.stdout:
                vulns = re.findall(r'\|.*VULNERABLE.*', result.stdout)
                for vuln in vulns[:5]:  # Limit to first 5
                    checks.append({
                        'check': 'Nmap Vulnerability Detection',
                        'target': f'{name} ({target})',
                        'status': 'failed',
                        'severity': 'high',
                        'finding': vuln.strip('|').strip(),
                        'recommendation': 'Patch vulnerable services immediately'
                    })

    except Exception as e:
        logger.debug(f"    Vuln scan error: {e}")

    return checks


def masscan_port_scan(target: str, name: str, logger) -> List[Dict]:
    """Fast port scan using masscan"""
    checks = []
    logger.info(f"    Running masscan (fast port scan)...")

    try:
        # Masscan is VERY fast but requires root
        cmd = ['sudo', 'masscan', target, '-p1-65535', '--rate=1000', '--open']
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0:
            # Parse masscan output
            ports = re.findall(r'Discovered open port (\d+)/tcp', result.stdout)
            if ports:
                checks.append({
                    'check': 'Masscan Port Discovery',
                    'target': f'{name} ({target})',
                    'status': 'info',
                    'severity': 'info',
                    'finding': f'Found {len(ports)} open ports: {", ".join(ports[:10])}',
                    'recommendation': 'Review all open ports with detailed nmap scan'
                })

    except Exception as e:
        logger.debug(f"    Masscan error: {e}")

    return checks


def testssl_scan(target: str, name: str, logger) -> List[Dict]:
    """Comprehensive SSL/TLS testing using testssl.sh"""
    checks = []
    logger.info(f"    Running testssl.sh SSL/TLS analysis...")

    try:
        cmd = ['testssl.sh', '--jsonfile', '/tmp/testssl_out.json', '--quiet', target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0 and os.path.exists('/tmp/testssl_out.json'):
            with open('/tmp/testssl_out.json', 'r') as f:
                data = json.load(f)

            # Parse critical findings
            for finding in data:
                severity_map = {
                    'CRITICAL': 'critical',
                    'HIGH': 'high',
                    'MEDIUM': 'medium',
                    'LOW': 'low',
                    'OK': 'info'
                }

                if finding.get('severity') in ['CRITICAL', 'HIGH']:
                    checks.append({
                        'check': 'SSL/TLS Security (testssl.sh)',
                        'target': f'{name} ({target})',
                        'status': 'failed',
                        'severity': severity_map.get(finding['severity'], 'medium'),
                        'finding': finding.get('finding', 'SSL/TLS issue detected'),
                        'recommendation': 'Update SSL/TLS configuration - ' + finding.get('cve', '')
                    })

            # Clean up
            os.remove('/tmp/testssl_out.json')

    except Exception as e:
        logger.debug(f"    testssl error: {e}")

    return checks


def sslscan_scan(target: str, name: str, logger) -> List[Dict]:
    """SSL scan using sslscan"""
    checks = []
    logger.info(f"    Running sslscan...")

    try:
        cmd = ['sslscan', '--no-colour', target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0:
            output = result.stdout

            # Check for weak protocols
            if 'SSLv2' in output or 'SSLv3' in output:
                checks.append({
                    'check': 'Weak SSL Protocol',
                    'target': f'{name} ({target})',
                    'status': 'failed',
                    'severity': 'critical',
                    'finding': 'SSLv2/SSLv3 enabled (POODLE, DROWN vulnerabilities)',
                    'recommendation': 'Disable SSLv2 and SSLv3 immediately'
                })

            if 'TLSv1.0' in output:
                checks.append({
                    'check': 'Outdated TLS Protocol',
                    'target': f'{name} ({target})',
                    'status': 'failed',
                    'severity': 'high',
                    'finding': 'TLSv1.0 enabled (deprecated)',
                    'recommendation': 'Disable TLSv1.0, use TLSv1.2+ only'
                })

            # Check for weak ciphers
            weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
            for cipher in weak_ciphers:
                if re.search(f'Accepted.*{cipher}', output, re.IGNORECASE):
                    checks.append({
                        'check': 'Weak Cipher Suite',
                        'target': f'{name} ({target})',
                        'status': 'failed',
                        'severity': 'high',
                        'finding': f'Weak cipher {cipher} accepted',
                        'recommendation': 'Remove weak cipher suites from configuration'
                    })

    except Exception as e:
        logger.debug(f"    sslscan error: {e}")

    return checks


def sslyze_scan(target: str, name: str, logger) -> List[Dict]:
    """SSL analysis using sslyze"""
    checks = []
    logger.info(f"    Running sslyze...")

    try:
        cmd = ['sslyze', '--regular', target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0:
            output = result.stdout

            if 'VULNERABLE' in output or 'INSECURE' in output:
                checks.append({
                    'check': 'SSL/TLS Vulnerability (sslyze)',
                    'target': f'{name} ({target})',
                    'status': 'failed',
                    'severity': 'high',
                    'finding': 'SSL/TLS vulnerability detected',
                    'recommendation': 'Review sslyze output and patch SSL/TLS configuration'
                })

    except Exception as e:
        logger.debug(f"    sslyze error: {e}")

    return checks


def nikto_scan(target: str, name: str, logger) -> List[Dict]:
    """Web server scanning with Nikto"""
    checks = []
    logger.info(f"    Running Nikto web server scan...")

    try:
        cmd = ['nikto', '-h', target, '-Format', 'csv', '-output', '/tmp/nikto_out.csv']
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )

        if os.path.exists('/tmp/nikto_out.csv'):
            with open('/tmp/nikto_out.csv', 'r') as f:
                lines = f.readlines()

            # Parse CSV (skip header)
            for line in lines[1:]:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 4:
                        osvdb = parts[0]
                        method = parts[2]
                        finding = parts[3]

                        checks.append({
                            'check': 'Nikto Web Server Scan',
                            'target': f'{name} ({target})',
                            'status': 'warning',
                            'severity': 'medium',
                            'finding': finding.strip('"'),
                            'recommendation': 'Review and remediate web server misconfiguration'
                        })

            os.remove('/tmp/nikto_out.csv')

    except Exception as e:
        logger.debug(f"    Nikto error: {e}")

    return checks


def basic_port_scan(target: str, name: str, logger) -> List[Dict]:
    """Fallback basic port scan using Python sockets"""
    checks = []
    logger.info(f"    Running basic port scan (no nmap)...")

    common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
    open_ports = []

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
        except:
            pass
        finally:
            sock.close()

    if open_ports:
        checks.append({
            'check': 'Basic Port Scan',
            'target': f'{name} ({target})',
            'status': 'warning',
            'severity': 'medium',
            'finding': f'Open ports detected: {", ".join(map(str, open_ports))}',
            'recommendation': 'Install nmap for detailed port scanning'
        })

    return checks


def basic_ssl_check(target: str, name: str, logger) -> List[Dict]:
    """Fallback basic SSL check"""
    checks = []
    logger.info(f"    Running basic SSL check (no testssl/sslscan)...")

    for port in [443, 8443]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        checks.append({
                            'check': 'SSL/TLS Protocol',
                            'target': f'{name} ({target}:{port})',
                            'status': 'failed',
                            'severity': 'high',
                            'finding': f'Weak protocol {protocol} in use',
                            'recommendation': 'Upgrade to TLSv1.2 or TLSv1.3'
                        })
        except:
            pass

    return checks


def parse_nmap_ports(xml_output: str) -> List[Dict]:
    """Parse nmap XML output for port information"""
    ports = []

    # Simple regex parsing (for production, use xml.etree)
    port_matches = re.findall(
        r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="(\w+)".*?<service name="([^"]*)".*?version="([^"]*)"',
        xml_output,
        re.DOTALL
    )

    for match in port_matches:
        if match[2] == 'open':
            ports.append({
                'protocol': match[0],
                'port': int(match[1]),
                'service': match[3],
                'version': match[4]
            })

    return ports
