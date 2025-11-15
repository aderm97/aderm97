"""
VPN Security Assessment Module
Tests VPN configurations, authentication, and encryption
"""

import socket
import ssl
from typing import Dict, List, Any


def run(config: Dict, logger) -> Dict[str, Any]:
    """Run VPN security checks"""
    findings = {
        'module': 'VPN Security',
        'checks': []
    }

    vpn_endpoints = config.get('targets', {}).get('vpn', [])

    for vpn in vpn_endpoints:
        logger.info(f"  Checking VPN: {vpn.get('name', vpn.get('ip'))}")

        # VPN accessibility and protocol checks
        findings['checks'].extend(check_vpn_accessibility(vpn, logger))

        # Authentication mechanisms
        findings['checks'].extend(check_vpn_authentication(vpn, logger))

        # Encryption configuration
        findings['checks'].extend(check_vpn_encryption(vpn, logger))

        # Session management
        findings['checks'].extend(check_vpn_session_security(vpn, logger))

    return findings


def check_vpn_accessibility(vpn: Dict, logger) -> List[Dict]:
    """Check VPN endpoint accessibility and configuration"""
    checks = []
    ip = vpn.get('ip')
    name = vpn.get('name', ip)
    vpn_type = vpn.get('type', 'unknown')

    # Common VPN ports
    vpn_ports = {
        500: 'IPSec IKE',
        1194: 'OpenVPN',
        1723: 'PPTP',
        4500: 'IPSec NAT-T',
        443: 'SSL VPN'
    }

    detected_ports = []

    for port, protocol in vpn_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if port in [500, 4500] else socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            if port in [500, 4500]:  # UDP ports
                sock.sendto(b'\x00' * 20, (ip, port))
                data, _ = sock.recvfrom(1024)
                if data:
                    detected_ports.append((port, protocol))
            else:  # TCP ports
                result = sock.connect_ex((ip, port))
                if result == 0:
                    detected_ports.append((port, protocol))
        except:
            pass
        finally:
            sock.close()

    # Check for insecure protocols
    if 1723 in [p[0] for p in detected_ports]:
        checks.append({
            'check': 'VPN Protocol Security',
            'target': f'{name} ({ip})',
            'status': 'failed',
            'severity': 'critical',
            'finding': 'PPTP protocol detected - known to be insecure',
            'recommendation': 'Disable PPTP and migrate to IKEv2, OpenVPN, or WireGuard'
        })

    for port, protocol in detected_ports:
        if port not in [1723]:  # Already handled above
            checks.append({
                'check': 'VPN Service Detection',
                'target': f'{name} ({ip}:{port})',
                'status': 'info',
                'severity': 'info',
                'finding': f'{protocol} service detected',
                'recommendation': f'Verify {protocol} is using strong encryption and authentication'
            })

    if not detected_ports:
        checks.append({
            'check': 'VPN Accessibility',
            'target': f'{name} ({ip})',
            'status': 'warning',
            'severity': 'low',
            'finding': 'No VPN services detected on common ports',
            'recommendation': 'Verify VPN endpoint configuration or firewall rules'
        })

    return checks


def check_vpn_authentication(vpn: Dict, logger) -> List[Dict]:
    """Check VPN authentication mechanisms"""
    checks = []
    name = vpn.get('name')
    ip = vpn.get('ip')

    # These are manual checks that require configuration review
    checks.append({
        'check': 'VPN Multi-Factor Authentication',
        'target': name,
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify MFA is enforced:
            - All VPN connections require MFA
            - MFA cannot be bypassed
            - Strong MFA methods (hardware tokens, authenticator apps)
            - No SMS-based MFA for privileged access'''
    })

    checks.append({
        'check': 'VPN Certificate Authentication',
        'target': name,
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify certificate-based authentication:
            - Client certificates required
            - Certificate revocation checking enabled (CRL/OCSP)
            - Strong key lengths (RSA 2048+ or ECC)
            - Certificates issued by trusted internal CA
            - Certificate expiration monitoring'''
    })

    checks.append({
        'check': 'VPN Pre-Shared Key Security',
        'target': name,
        'status': 'manual',
        'severity': 'critical',
        'finding': 'Manual verification required',
        'recommendation': '''If PSK is used, verify:
            - Strong, random PSK (minimum 20 characters)
            - Regular PSK rotation
            - PSK stored securely
            - Consider migrating to certificate-based auth
            - PREFER: Use certificates instead of PSK'''
    })

    return checks


def check_vpn_encryption(vpn: Dict, logger) -> List[Dict]:
    """Check VPN encryption configuration"""
    checks = []
    name = vpn.get('name')
    vpn_type = vpn.get('type', 'unknown')

    # IPSec specific checks
    if 'ipsec' in vpn_type.lower() or vpn_type == 'unknown':
        checks.append({
            'check': 'IPSec Phase 1 Configuration',
            'target': name,
            'status': 'manual',
            'severity': 'high',
            'finding': 'Manual verification required',
            'recommendation': '''Verify IPSec Phase 1 (IKE):
                - IKEv2 preferred over IKEv1
                - Encryption: AES-256-GCM or AES-256-CBC
                - Integrity: SHA-256 or SHA-384 (not SHA-1 or MD5)
                - DH Group: 14 or higher (2048-bit or stronger)
                - Lifetime: 8-24 hours maximum'''
        })

        checks.append({
            'check': 'IPSec Phase 2 Configuration',
            'target': name,
            'status': 'manual',
            'severity': 'high',
            'finding': 'Manual verification required',
            'recommendation': '''Verify IPSec Phase 2 (ESP):
                - Encryption: AES-256-GCM or AES-256-CBC
                - Integrity: SHA-256 or SHA-384
                - Perfect Forward Secrecy (PFS) enabled
                - PFS DH Group: 14 or higher
                - Lifetime: 1-8 hours maximum'''
        })

    # OpenVPN specific checks
    if 'openvpn' in vpn_type.lower() or vpn_type == 'unknown':
        checks.append({
            'check': 'OpenVPN Encryption Configuration',
            'target': name,
            'status': 'manual',
            'severity': 'high',
            'finding': 'Manual verification required',
            'recommendation': '''Verify OpenVPN configuration:
                - Cipher: AES-256-GCM or AES-256-CBC
                - Auth: SHA256 or SHA512
                - TLS version: 1.2 or 1.3
                - tls-auth or tls-crypt enabled
                - Compression disabled (security risk)'''
        })

    # General encryption checks
    checks.append({
        'check': 'VPN Weak Encryption Algorithms',
        'target': name,
        'status': 'manual',
        'severity': 'critical',
        'finding': 'Manual verification required',
        'recommendation': '''Ensure these weak algorithms are DISABLED:
            - DES, 3DES, RC4, Blowfish
            - MD5, SHA-1 for integrity
            - DH Group 1, 2, 5 (< 2048-bit)
            - NULL encryption'''
    })

    return checks


def check_vpn_session_security(vpn: Dict, logger) -> List[Dict]:
    """Check VPN session management and security controls"""
    checks = []
    name = vpn.get('name')

    checks.append({
        'check': 'VPN Session Timeout',
        'target': name,
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual verification required',
        'recommendation': '''Verify session timeout configuration:
            - Idle timeout: 15-30 minutes maximum
            - Maximum session duration: 8-12 hours
            - Re-authentication required after timeout
            - Forced disconnect on policy violation'''
    })

    checks.append({
        'check': 'VPN Split Tunneling',
        'target': name,
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify split tunneling configuration:
            - DISABLE split tunneling for production access
            - All traffic should route through VPN
            - DNS queries through VPN (prevent DNS leaks)
            - IPv6 disabled or tunneled (prevent IPv6 leaks)'''
    })

    checks.append({
        'check': 'VPN Client Posture Assessment',
        'target': name,
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify endpoint compliance checking:
            - Antivirus/EDR running and updated
            - OS patches current
            - Host firewall enabled
            - Disk encryption enabled
            - Unauthorized software check
            - Quarantine non-compliant devices'''
    })

    checks.append({
        'check': 'VPN Connection Limits',
        'target': name,
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual verification required',
        'recommendation': '''Verify connection limits:
            - Maximum concurrent connections per user
            - IP pool exhaustion protection
            - Connection rate limiting
            - Geographic restriction if applicable'''
    })

    return checks
