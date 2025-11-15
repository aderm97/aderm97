"""
Network Segmentation & Internal Security Module
Tests VLAN isolation, network segmentation, and internal security controls
"""

import socket
import subprocess
from typing import Dict, List, Any
import ipaddress


def run(config: Dict, logger) -> Dict[str, Any]:
    """Run network segmentation checks"""
    findings = {
        'module': 'Network Segmentation',
        'checks': []
    }

    # Core switch security
    switches = config.get('targets', {}).get('switches', [])
    for switch in switches:
        logger.info(f"  Checking switch: {switch.get('name', switch.get('ip'))}")
        findings['checks'].extend(check_switch_security(switch, logger))

    # Network segment isolation
    segments = config.get('targets', {}).get('segments', [])
    for segment in segments:
        logger.info(f"  Checking segment: {segment.get('name')}")
        findings['checks'].extend(check_segment_isolation(segment, logger))

    # VLAN security
    findings['checks'].extend(check_vlan_security(config, logger))

    return findings


def check_switch_security(switch: Dict, logger) -> List[Dict]:
    """Check core switch security configurations"""
    checks = []
    ip = switch.get('ip')
    name = switch.get('name', ip)

    # Check for management interface exposure
    mgmt_ports = [22, 23, 80, 443, 161]
    accessible_ports = []

    for port in mgmt_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                accessible_ports.append(port)
        except:
            pass
        finally:
            sock.close()

    if 23 in accessible_ports:
        checks.append({
            'check': 'Switch Telnet Access',
            'target': f'{name} ({ip})',
            'status': 'failed',
            'severity': 'critical',
            'finding': 'Telnet (unencrypted) access enabled on switch',
            'recommendation': 'Disable Telnet and use SSH only'
        })

    if 161 in accessible_ports:
        checks.append({
            'check': 'Switch SNMP Access',
            'target': f'{name} ({ip})',
            'status': 'warning',
            'severity': 'medium',
            'finding': 'SNMP port accessible',
            'recommendation': 'Ensure SNMPv3 is used with strong authentication, disable SNMPv1/v2c'
        })

    if 80 in accessible_ports and 443 not in accessible_ports:
        checks.append({
            'check': 'Switch HTTP Management',
            'target': f'{name} ({ip})',
            'status': 'failed',
            'severity': 'high',
            'finding': 'HTTP (unencrypted) management enabled without HTTPS',
            'recommendation': 'Disable HTTP and enable HTTPS only'
        })

    # Manual checks for switch security features
    checks.append({
        'check': 'Port Security Configuration',
        'target': name,
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify the following are configured:
            - Port security with MAC address limits
            - DHCP snooping enabled
            - Dynamic ARP Inspection (DAI)
            - IP Source Guard
            - Storm control for broadcast/multicast
            - Disabled unused ports
            - Management VLAN separation'''
    })

    checks.append({
        'check': 'Spanning Tree Security',
        'target': name,
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual verification required',
        'recommendation': '''Verify STP security:
            - BPDU Guard enabled on access ports
            - Root Guard on appropriate ports
            - Loop Guard enabled
            - Portfast on access ports only'''
    })

    return checks


def check_segment_isolation(segment: Dict, logger) -> List[Dict]:
    """Check network segment isolation"""
    checks = []
    name = segment.get('name')
    network = segment.get('network')
    restricted_access = segment.get('restricted_access', True)

    try:
        net = ipaddress.ip_network(network)

        # Check if segment should be isolated
        if 'vpn' in name.lower() or 'partner' in name.lower() or 'external' in name.lower():
            checks.append({
                'check': 'Segment Isolation Policy',
                'target': f'{name} ({network})',
                'status': 'manual',
                'severity': 'high',
                'finding': 'High-risk segment requiring strict isolation',
                'recommendation': f'''Verify isolation for {name}:
                    - No direct access to production systems
                    - Firewall rules restricting lateral movement
                    - Traffic monitoring enabled
                    - Access logging to SIEM
                    - Jump host/bastion requirement'''
            })

        # Check for proper segmentation
        checks.append({
            'check': 'Inter-VLAN Routing Security',
            'target': name,
            'status': 'manual',
            'severity': 'high',
            'finding': 'Manual verification required',
            'recommendation': f'''Verify routing security for {name}:
                - ACLs on inter-VLAN routing
                - Traffic inspection between segments
                - Logged denied traffic
                - Least privilege access model'''
        })

    except ValueError:
        checks.append({
            'check': 'Segment Configuration',
            'target': name,
            'status': 'failed',
            'severity': 'high',
            'finding': f'Invalid network configuration: {network}',
            'recommendation': 'Fix network configuration'
        })

    return checks


def check_vlan_security(config: Dict, logger) -> List[Dict]:
    """Check VLAN security configurations"""
    checks = []

    # VLAN hopping protection
    checks.append({
        'check': 'VLAN Hopping Protection',
        'target': 'All Switches',
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify VLAN hopping protections:
            - Native VLAN is not VLAN 1
            - Native VLAN is unused
            - Trunk ports explicitly configured
            - DTP (Dynamic Trunking Protocol) disabled
            - All unused ports in unused VLAN
            - Double tagging protection enabled'''
    })

    # MAC flooding protection
    checks.append({
        'check': 'MAC Flooding Protection',
        'target': 'All Switches',
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify MAC flooding protections:
            - Port security enabled with maximum MAC addresses
            - Violation action configured (shutdown recommended)
            - Sticky MAC addressing where appropriate
            - MAC aging time configured'''
    })

    # VLAN access control
    checks.append({
        'check': 'VLAN Access Control',
        'target': 'All Switches',
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual verification required',
        'recommendation': '''Verify VLAN access controls:
            - VLANs properly documented
            - VLAN pruning on trunk links
            - Private VLANs where appropriate
            - Management VLAN isolated
            - Voice VLAN security (if applicable)'''
    })

    return checks
