"""
Firewall Security Testing Module
Tests firewall configurations, rules, and bypass attempts
"""

import socket
import subprocess
from typing import Dict, List, Any
import time


def run(config: Dict, logger) -> Dict[str, Any]:
    """Run firewall security checks"""
    findings = {
        'module': 'Firewall Security',
        'checks': []
    }

    firewalls = config.get('targets', {}).get('firewalls', [])

    for fw in firewalls:
        logger.info(f"  Testing firewall: {fw.get('name', fw.get('ip'))}")

        # Firewall accessibility check
        findings['checks'].extend(check_firewall_mgmt_access(fw, logger))

        # Rule base analysis
        findings['checks'].extend(check_firewall_rules(fw, logger))

        # Bypass attempts
        findings['checks'].extend(check_firewall_bypass(fw, logger))

        # Protocol tunneling tests
        findings['checks'].extend(check_protocol_tunneling(fw, logger))

        # Fragmentation tests
        findings['checks'].extend(check_fragmentation_handling(fw, logger))

    return findings


def check_firewall_mgmt_access(fw: Dict, logger) -> List[Dict]:
    """Check if firewall management interfaces are exposed"""
    checks = []
    ip = fw.get('ip', fw.get('name'))
    mgmt_ports = {
        22: 'SSH',
        23: 'Telnet',
        80: 'HTTP',
        443: 'HTTPS',
        161: 'SNMP',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT'
    }

    exposed_ports = []

    for port, service in mgmt_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                exposed_ports.append((port, service))
                logger.debug(f"    Management port {port} ({service}) is accessible")
        except:
            pass
        finally:
            sock.close()

    for port, service in exposed_ports:
        severity = 'critical' if port in [23, 80, 161] else 'high'
        checks.append({
            'check': 'Firewall Management Interface Exposure',
            'target': f'{ip}:{port}',
            'status': 'failed',
            'severity': severity,
            'finding': f'{service} management interface accessible on port {port}',
            'recommendation': f'Restrict {service} access to management network only'
        })

    if not exposed_ports:
        checks.append({
            'check': 'Firewall Management Interface Exposure',
            'target': ip,
            'status': 'passed',
            'severity': 'info',
            'finding': 'No management interfaces exposed to scanned network',
            'recommendation': 'Continue restricting management access'
        })

    return checks


def check_firewall_rules(fw: Dict, logger) -> List[Dict]:
    """Analyze firewall rule configurations"""
    checks = []
    ip = fw.get('ip')

    # Manual check placeholder
    checks.append({
        'check': 'Firewall Rule Base Analysis',
        'target': ip,
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual review required',
        'recommendation': '''Review firewall rules for:
            - Overly permissive ANY-ANY rules
            - Disabled/inactive rules
            - Duplicate rules
            - Rules without logging
            - Source/destination IP validation
            - Service restrictions'''
    })

    # Check for common ANY rules by testing access
    test_services = [
        (21, 'FTP'),
        (23, 'Telnet'),
        (3389, 'RDP'),
        (5900, 'VNC')
    ]

    allowed_services = []
    for port, service in test_services:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                allowed_services.append((port, service))
        except:
            pass
        finally:
            sock.close()

    for port, service in allowed_services:
        checks.append({
            'check': 'Firewall Rule Validation',
            'target': f'{ip}:{port}',
            'status': 'failed',
            'severity': 'high',
            'finding': f'Potentially insecure service {service} is accessible through firewall',
            'recommendation': f'Review firewall rules allowing {service} (port {port})'
        })

    return checks


def check_firewall_bypass(fw: Dict, logger) -> List[Dict]:
    """Test for firewall bypass techniques"""
    checks = []
    ip = fw.get('ip')

    # Check for source port bypass (using privileged source ports)
    privileged_ports = [20, 53, 88, 123]
    for src_port in privileged_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', src_port))
            sock.settimeout(2)
            result = sock.connect_ex((ip, 80))
            if result == 0:
                checks.append({
                    'check': 'Firewall Source Port Bypass',
                    'target': ip,
                    'status': 'failed',
                    'severity': 'high',
                    'finding': f'Firewall may allow bypass using source port {src_port}',
                    'recommendation': 'Configure firewall to not trust source ports'
                })
                sock.close()
                break
            sock.close()
        except PermissionError:
            # Can't bind to privileged port without root
            logger.debug("    Skipping privileged port test (requires root)")
            break
        except:
            pass

    # Check for IP fragmentation handling
    checks.append({
        'check': 'Firewall Fragmentation Handling',
        'target': ip,
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual testing required for fragmentation attacks',
        'recommendation': 'Test with tools like fragroute or hping3 to verify fragmentation handling'
    })

    return checks


def check_protocol_tunneling(fw: Dict, logger) -> List[Dict]:
    """Check for protocol tunneling vulnerabilities"""
    checks = []
    ip = fw.get('ip')

    # DNS tunneling check
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # Send DNS query
        dns_query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        sock.sendto(dns_query, (ip, 53))
        data, _ = sock.recvfrom(512)
        if data:
            checks.append({
                'check': 'DNS Protocol Tunneling Risk',
                'target': f'{ip}:53',
                'status': 'warning',
                'severity': 'medium',
                'finding': 'DNS port is open - potential for DNS tunneling',
                'recommendation': 'Implement DNS query inspection and rate limiting'
            })
        sock.close()
    except:
        pass

    # ICMP tunneling check
    checks.append({
        'check': 'ICMP Tunneling Risk',
        'target': ip,
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual verification required for ICMP tunneling',
        'recommendation': 'Test ICMP traffic for data exfiltration and implement size restrictions'
    })

    # HTTP tunneling check
    checks.append({
        'check': 'HTTP/HTTPS Tunneling',
        'target': ip,
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual verification required',
        'recommendation': 'Implement deep packet inspection for HTTP/HTTPS tunneling detection'
    })

    return checks


def check_fragmentation_handling(fw: Dict, logger) -> List[Dict]:
    """Test firewall fragmentation handling"""
    checks = []
    ip = fw.get('ip')

    checks.append({
        'check': 'IP Fragmentation Testing',
        'target': ip,
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Requires manual testing with specialized tools',
        'recommendation': '''Test fragmentation handling with:
            - hping3 for custom fragmented packets
            - fragroute for fragmentation attacks
            - Verify firewall reassembles fragments correctly
            - Check for fragment overlap handling
            - Test timeout and resource exhaustion'''
    })

    return checks
