"""
Connectivity and Liveness Checker Module
Verifies if targets are online, responsive, or blocking before running tests
"""

import subprocess
import socket
import platform
from typing import Dict, List, Tuple
import time


def check_target_liveness(target: str, logger) -> Dict[str, any]:
    """
    Comprehensive liveness check for a target
    Returns status: 'online', 'blocking', 'offline', 'unknown'
    """
    result = {
        'target': target,
        'status': 'unknown',
        'icmp_reachable': False,
        'tcp_reachable': False,
        'udp_reachable': False,
        'response_time': None,
        'details': []
    }

    logger.info(f"  Checking liveness for: {target}")

    # 1. ICMP Ping Check
    icmp_result = check_icmp(target, logger)
    result['icmp_reachable'] = icmp_result['reachable']
    if icmp_result['reachable']:
        result['response_time'] = icmp_result['response_time']
        result['details'].append(f"ICMP: Reachable ({icmp_result['response_time']}ms)")
        logger.debug(f"    ICMP: ✓ Reachable ({icmp_result['response_time']}ms)")
    else:
        result['details'].append("ICMP: No response (may be blocked)")
        logger.debug(f"    ICMP: ✗ No response")

    # 2. TCP Connect to common ports
    tcp_result = check_tcp_ports(target, logger)
    result['tcp_reachable'] = tcp_result['reachable']
    if tcp_result['reachable']:
        result['details'].append(f"TCP: Open ports found {tcp_result['open_ports']}")
        logger.debug(f"    TCP: ✓ Ports open {tcp_result['open_ports']}")
    else:
        result['details'].append("TCP: No open ports on common services")
        logger.debug(f"    TCP: ✗ No open ports detected")

    # 3. UDP probe
    udp_result = check_udp(target, logger)
    result['udp_reachable'] = udp_result['reachable']

    # Determine overall status
    if result['icmp_reachable'] or result['tcp_reachable'] or result['udp_reachable']:
        result['status'] = 'online'
    elif not result['icmp_reachable'] and not result['tcp_reachable']:
        # Could be blocking or offline
        # Try ARP for local networks
        arp_result = check_arp(target, logger)
        if arp_result['reachable']:
            result['status'] = 'blocking'
            result['details'].append("ARP: Responds (device is UP but blocking)")
        else:
            result['status'] = 'offline'
    else:
        result['status'] = 'unknown'

    logger.info(f"  Status: {result['status'].upper()}")
    return result


def check_icmp(target: str, count: int = 3, timeout: int = 2) -> Dict:
    """Check ICMP reachability using ping"""
    result = {'reachable': False, 'response_time': None}

    # Determine OS-specific ping command
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'

    try:
        cmd = ['ping', param, str(count), timeout_param, str(timeout * 1000 if platform.system().lower() == 'windows' else timeout), target]
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * count + 2
        )

        if output.returncode == 0:
            result['reachable'] = True
            # Parse response time
            if 'time=' in output.stdout:
                import re
                times = re.findall(r'time[=<](\d+\.?\d*)', output.stdout)
                if times:
                    result['response_time'] = f"{sum(float(t) for t in times) / len(times):.2f}"
            elif 'Average' in output.stdout:
                import re
                avg = re.search(r'Average = (\d+)ms', output.stdout)
                if avg:
                    result['response_time'] = avg.group(1)

    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        pass

    return result


def check_tcp_ports(target: str, ports: List[int] = None, timeout: int = 2) -> Dict:
    """Check TCP connectivity on common ports"""
    if ports is None:
        # Common ports to check
        ports = [22, 80, 443, 3389, 8080, 8443]

    result = {'reachable': False, 'open_ports': []}

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            conn_result = sock.connect_ex((target, port))
            if conn_result == 0:
                result['open_ports'].append(port)
                result['reachable'] = True
        except (socket.gaierror, socket.timeout, OSError):
            pass
        finally:
            sock.close()

    return result


def check_udp(target: str, port: int = 53, timeout: int = 2) -> Dict:
    """Check UDP connectivity (DNS port)"""
    result = {'reachable': False}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        # Send DNS query-like packet
        dns_query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        sock.sendto(dns_query, (target, port))
        data, _ = sock.recvfrom(512)
        if data:
            result['reachable'] = True
    except (socket.timeout, OSError):
        pass
    finally:
        sock.close()

    return result


def check_arp(target: str, logger) -> Dict:
    """Check ARP table for local network targets"""
    result = {'reachable': False}

    try:
        # Try to ping once first to populate ARP cache
        subprocess.run(
            ['ping', '-c', '1', '-W', '1', target],
            capture_output=True,
            timeout=3
        )

        # Check ARP table
        if platform.system().lower() == 'linux':
            arp_output = subprocess.run(
                ['arp', '-n', target],
                capture_output=True,
                text=True,
                timeout=2
            )
            # If MAC address is found (not <incomplete>), device is up
            if arp_output.returncode == 0 and 'incomplete' not in arp_output.stdout.lower():
                result['reachable'] = True
        elif platform.system().lower() == 'windows':
            arp_output = subprocess.run(
                ['arp', '-a', target],
                capture_output=True,
                text=True,
                timeout=2
            )
            if arp_output.returncode == 0 and target in arp_output.stdout:
                result['reachable'] = True

    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        pass

    return result


def check_tool_availability(tool_name: str) -> bool:
    """Check if a security tool is installed and available"""
    try:
        result = subprocess.run(
            ['which', tool_name] if platform.system() != 'Windows' else ['where', tool_name],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False


def get_available_tools() -> Dict[str, bool]:
    """Check which security tools are available on the system"""
    tools = {
        'nmap': check_tool_availability('nmap'),
        'masscan': check_tool_availability('masscan'),
        'hping3': check_tool_availability('hping3'),
        'nikto': check_tool_availability('nikto'),
        'sqlmap': check_tool_availability('sqlmap'),
        'testssl': check_tool_availability('testssl.sh') or check_tool_availability('testssl'),
        'sslscan': check_tool_availability('sslscan'),
        'sslyze': check_tool_availability('sslyze'),
        'wafw00f': check_tool_availability('wafw00f'),
        'nuclei': check_tool_availability('nuclei'),
        'gobuster': check_tool_availability('gobuster'),
        'ffuf': check_tool_availability('ffuf'),
        'hydra': check_tool_availability('hydra'),
        'medusa': check_tool_availability('medusa'),
        'enum4linux': check_tool_availability('enum4linux'),
        'crackmapexec': check_tool_availability('crackmapexec'),
        'responder': check_tool_availability('responder'),
        'az': check_tool_availability('az'),
    }
    return tools


def run(config: Dict, logger) -> Dict[str, any]:
    """Run connectivity checks and tool availability assessment"""
    findings = {
        'module': 'Connectivity & Tools Check',
        'checks': [],
        'tools_available': get_available_tools()
    }

    logger.info("Checking security tools availability...")
    available_count = sum(1 for available in findings['tools_available'].values() if available)
    total_count = len(findings['tools_available'])
    missing_tools = [tool for tool, avail in findings['tools_available'].items() if not avail]

    # Define critical tools that are required for meaningful scans
    critical_tools = ['nmap', 'testssl', 'sslscan', 'nikto']
    critical_missing = [tool for tool in critical_tools if tool in missing_tools]

    # Display tools status
    if available_count == total_count:
        logger.info(f"  ✅ All {total_count} security tools are installed!")
        findings['checks'].append({
            'check': 'Security Tools Availability',
            'target': 'Local System',
            'status': 'passed',
            'severity': 'info',
            'finding': f'All {total_count} security tools available',
            'recommendation': 'Continue using professional security tools for comprehensive testing'
        })
        findings['can_proceed'] = True
    else:
        logger.warning(f"  ⚠️  {available_count}/{total_count} security tools available")
        logger.warning(f"  Missing tools: {', '.join(missing_tools[:5])}" +
                      (f" (+{len(missing_tools)-5} more)" if len(missing_tools) > 5 else ""))

        # Check if critical tools are missing
        if critical_missing:
            logger.error(f"\n  ❌ CRITICAL TOOLS MISSING: {', '.join(critical_missing)}")
            logger.error(f"  Cannot perform effective security scans without these tools.\n")
            logger.info(f"  💡 To install missing tools, run:")
            logger.info(f"     python3 install_tools.py\n")
            findings['can_proceed'] = False
            findings['checks'].append({
                'check': 'Security Tools Availability',
                'target': 'Local System',
                'status': 'failed',
                'severity': 'critical',
                'finding': f'Critical security tools missing: {", ".join(critical_missing)}. Cannot proceed with scan.',
                'recommendation': 'Run "python3 install_tools.py" to install required security tools before scanning'
            })
        else:
            logger.info(f"\n  💡 To install missing tools, run:")
            logger.info(f"     python3 install_tools.py\n")
            findings['can_proceed'] = True
            findings['checks'].append({
                'check': 'Security Tools Availability',
                'target': 'Local System',
                'status': 'warning',
                'severity': 'low',
                'finding': f'Only {available_count}/{total_count} security tools available. Missing: {", ".join(missing_tools)}',
                'recommendation': 'Run "python3 install_tools.py" to install missing tools for enhanced scanning capabilities'
            })

    # Log available tools in verbose mode
    if logger.level == 10:  # DEBUG level
        logger.debug(f"\n  Tool Status:")
        for tool, available in findings['tools_available'].items():
            status = "✓" if available else "✗"
            logger.debug(f"    {status} {tool}")

    # Check all configured targets
    all_targets = []

    # Collect targets from config
    for section in ['perimeter', 'firewall', 'segmentation', 'vpn', 'access_control', 'waf']:
        section_config = config.get(section, {}).get('targets', {})
        for category, items in section_config.items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        ip = item.get('ip')
                        if ip and ip != 'TBD':
                            all_targets.append({
                                'ip': ip,
                                'name': item.get('name', ip),
                                'type': category
                            })

    # Remove duplicates
    seen = set()
    unique_targets = []
    for target in all_targets:
        if target['ip'] not in seen:
            seen.add(target['ip'])
            unique_targets.append(target)

    logger.info(f"\nChecking connectivity for {len(unique_targets)} unique targets...")

    # Check each target
    for target_info in unique_targets:
        liveness = check_target_liveness(target_info['ip'], logger)

        status_map = {
            'online': 'passed',
            'blocking': 'warning',
            'offline': 'failed',
            'unknown': 'warning'
        }

        severity_map = {
            'online': 'info',
            'blocking': 'medium',
            'offline': 'high',
            'unknown': 'medium'
        }

        findings['checks'].append({
            'check': 'Target Connectivity',
            'target': f"{target_info['name']} ({target_info['ip']})",
            'status': status_map[liveness['status']],
            'severity': severity_map[liveness['status']],
            'finding': f"Status: {liveness['status'].upper()} - {', '.join(liveness['details'])}",
            'recommendation': get_recommendation(liveness['status'])
        })

    return findings


def get_recommendation(status: str) -> str:
    """Get recommendation based on liveness status"""
    recommendations = {
        'online': 'Target is reachable - proceed with security testing',
        'blocking': 'Target is up but blocking probes - may have IPS/firewall. Use careful, targeted scanning',
        'offline': 'Target is offline or unreachable - verify IP address and network connectivity',
        'unknown': 'Unable to determine target status - verify configuration and network access'
    }
    return recommendations.get(status, 'Investigate target connectivity')
