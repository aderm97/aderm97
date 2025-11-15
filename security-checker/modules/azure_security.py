"""
Azure Cloud Security Assessment Module
Tests Azure-specific security configurations and hybrid connectivity
"""

from typing import Dict, List, Any
import subprocess
import json


def run(config: Dict, logger) -> Dict[str, Any]:
    """Run Azure security checks"""
    findings = {
        'module': 'Azure Cloud Security',
        'checks': []
    }

    # Check if Azure CLI is available
    if not check_azure_cli_available():
        findings['checks'].append({
            'check': 'Azure CLI Availability',
            'target': 'Local System',
            'status': 'warning',
            'severity': 'low',
            'finding': 'Azure CLI not installed or not in PATH',
            'recommendation': 'Install Azure CLI for automated Azure security checks: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli'
        })
        # Add manual checks only
        findings['checks'].extend(get_manual_azure_checks(config, logger))
        return findings

    # Check if logged in to Azure
    if not check_azure_login():
        findings['checks'].append({
            'check': 'Azure Authentication',
            'target': 'Azure CLI',
            'status': 'warning',
            'severity': 'low',
            'finding': 'Not authenticated to Azure CLI',
            'recommendation': 'Login with: az login'
        })
        findings['checks'].extend(get_manual_azure_checks(config, logger))
        return findings

    logger.info("  Running Azure automated checks...")

    # Hybrid connectivity
    findings['checks'].extend(check_hybrid_connectivity(config, logger))

    # Network security
    findings['checks'].extend(check_azure_network_security(config, logger))

    # Identity and access
    findings['checks'].extend(check_azure_identity(config, logger))

    # Data security
    findings['checks'].extend(check_azure_data_security(config, logger))

    # Azure-specific vulnerabilities
    findings['checks'].extend(check_azure_vulns(config, logger))

    return findings


def check_azure_cli_available() -> bool:
    """Check if Azure CLI is installed"""
    try:
        result = subprocess.run(['az', '--version'], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False


def check_azure_login() -> bool:
    """Check if logged in to Azure"""
    try:
        result = subprocess.run(
            ['az', 'account', 'show'],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except:
        return False


def check_hybrid_connectivity(config: Dict, logger) -> List[Dict]:
    """Check Azure hybrid connectivity security"""
    checks = []

    # VPN Gateway checks
    try:
        result = subprocess.run(
            ['az', 'network', 'vnet-gateway', 'list', '--output', 'json'],
            capture_output=True,
            timeout=30,
            text=True
        )

        if result.returncode == 0:
            gateways = json.loads(result.stdout)

            if not gateways:
                checks.append({
                    'check': 'Azure VPN Gateway',
                    'target': 'Azure Subscription',
                    'status': 'info',
                    'severity': 'info',
                    'finding': 'No VPN gateways found',
                    'recommendation': 'Verify if VPN connectivity is required'
                })
            else:
                for gw in gateways:
                    name = gw.get('name')
                    sku = gw.get('sku', {}).get('name')

                    # Check SKU
                    if sku in ['Basic']:
                        checks.append({
                            'check': 'Azure VPN Gateway SKU',
                            'target': name,
                            'status': 'warning',
                            'severity': 'medium',
                            'finding': f'VPN Gateway using Basic SKU',
                            'recommendation': 'Upgrade to VpnGw1 or higher for better security and performance'
                        })
    except:
        pass

    # ExpressRoute checks
    checks.append({
        'check': 'Azure ExpressRoute Security',
        'target': 'Azure Subscription',
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify ExpressRoute security:
            - MACsec encryption enabled (where available)
            - Private peering only (no Microsoft peering)
            - Route filters configured
            - BGP authentication enabled
            - Monitoring and alerting configured'''
    })

    return checks


def check_azure_network_security(config: Dict, logger) -> List[Dict]:
    """Check Azure network security configurations"""
    checks = []

    # NSG checks
    try:
        result = subprocess.run(
            ['az', 'network', 'nsg', 'list', '--output', 'json'],
            capture_output=True,
            timeout=30,
            text=True
        )

        if result.returncode == 0:
            nsgs = json.loads(result.stdout)

            for nsg in nsgs:
                name = nsg.get('name')
                rules = nsg.get('securityRules', [])

                # Check for overly permissive rules
                for rule in rules:
                    if rule.get('access') == 'Allow':
                        src = rule.get('sourceAddressPrefix', '')
                        dst = rule.get('destinationAddressPrefix', '')

                        if src in ['*', 'Internet'] and dst == '*':
                            checks.append({
                                'check': 'Azure NSG Overly Permissive Rule',
                                'target': f"{name}/{rule.get('name')}",
                                'status': 'failed',
                                'severity': 'critical',
                                'finding': f"Rule allows traffic from Internet to all destinations",
                                'recommendation': 'Restrict source and destination to specific IP ranges/subnets'
                            })

                        if rule.get('protocol') == '*' and src in ['*', 'Internet']:
                            checks.append({
                                'check': 'Azure NSG Protocol Restriction',
                                'target': f"{name}/{rule.get('name')}",
                                'status': 'warning',
                                'severity': 'high',
                                'finding': 'Rule allows all protocols from Internet',
                                'recommendation': 'Specify explicit protocols (TCP, UDP) instead of *'
                            })
    except:
        pass

    # Azure Firewall
    checks.append({
        'check': 'Azure Firewall Deployment',
        'target': 'Azure VNets',
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify Azure Firewall:
            - Azure Firewall or NVA deployed in hub VNet
            - Force tunneling configured
            - Threat intelligence enabled
            - DNS proxy enabled
            - Logging to Log Analytics'''
    })

    return checks


def check_azure_identity(config: Dict, logger) -> List[Dict]:
    """Check Azure identity and access security"""
    checks = []

    # Conditional Access
    checks.append({
        'check': 'Azure AD Conditional Access',
        'target': 'Azure AD',
        'status': 'manual',
        'severity': 'critical',
        'finding': 'Manual verification required',
        'recommendation': '''Verify Conditional Access policies:
            - MFA required for all users
            - Block legacy authentication
            - Require compliant/managed devices
            - Geographic restrictions where appropriate
            - Risk-based policies enabled
            - Break-glass accounts excluded'''
    })

    # Privileged Identity Management
    checks.append({
        'check': 'Azure AD Privileged Identity Management',
        'target': 'Azure AD',
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify PIM configuration:
            - All privileged roles require activation
            - Time-limited role assignments
            - Approval required for high-privilege roles
            - MFA required for activation
            - Access reviews configured
            - Alerts configured for privilege escalation'''
    })

    # Service Principals
    checks.append({
        'check': 'Azure Service Principal Security',
        'target': 'Azure AD',
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify service principal security:
            - Minimal permissions (least privilege)
            - Regular credential rotation
            - Managed identities used where possible
            - Unused service principals removed
            - Service principal usage monitoring'''
    })

    # RBAC
    checks.append({
        'check': 'Azure RBAC Configuration',
        'target': 'Azure Subscriptions',
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify RBAC:
            - No custom roles with overly broad permissions
            - Owner role limited to minimal users
            - Resource-level assignments where possible
            - Regular access reviews
            - Deny assignments where appropriate'''
    })

    return checks


def check_azure_data_security(config: Dict, logger) -> List[Dict]:
    """Check Azure data security"""
    checks = []

    # Storage account encryption
    try:
        result = subprocess.run(
            ['az', 'storage', 'account', 'list', '--output', 'json'],
            capture_output=True,
            timeout=30,
            text=True
        )

        if result.returncode == 0:
            accounts = json.loads(result.stdout)

            for account in accounts:
                name = account.get('name')
                https_only = account.get('enableHttpsTrafficOnly', False)

                if not https_only:
                    checks.append({
                        'check': 'Azure Storage HTTPS Enforcement',
                        'target': name,
                        'status': 'failed',
                        'severity': 'high',
                        'finding': 'Storage account allows HTTP traffic',
                        'recommendation': 'Enable "Secure transfer required" to enforce HTTPS only'
                    })

                # Check public access
                allow_blob_public_access = account.get('allowBlobPublicAccess', True)
                if allow_blob_public_access:
                    checks.append({
                        'check': 'Azure Storage Public Access',
                        'target': name,
                        'status': 'warning',
                        'severity': 'medium',
                        'finding': 'Storage account allows public blob access',
                        'recommendation': 'Disable public blob access unless specifically required'
                    })
    except:
        pass

    # Key Vault
    checks.append({
        'check': 'Azure Key Vault Security',
        'target': 'Azure Key Vaults',
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify Key Vault security:
            - Soft delete enabled
            - Purge protection enabled
            - Private endpoint connectivity
            - RBAC mode (not access policies)
            - Logging enabled to Log Analytics
            - Alerts on key vault access
            - Key rotation policies'''
    })

    return checks


def check_azure_vulns(config: Dict, logger) -> List[Dict]:
    """Check for Azure-specific attack vectors"""
    checks = []

    # IMDS exploitation
    checks.append({
        'check': 'Azure IMDS Protection',
        'target': 'Azure VMs',
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual verification required',
        'recommendation': '''Verify IMDS protection:
            - Applications don't expose IMDS tokens
            - Network controls prevent IMDS access from untrusted sources
            - Managed identities scoped appropriately
            - Monitor unusual IMDS access patterns'''
    })

    # Subscription enumeration
    checks.append({
        'check': 'Azure Subscription Enumeration',
        'target': 'Azure AD',
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual verification required',
        'recommendation': '''Verify protection against enumeration:
            - Guest user permissions restricted
            - External collaboration settings reviewed
            - Resource naming doesn't reveal sensitive info
            - Monitor for reconnaissance activity'''
    })

    # Cross-tenant attacks
    checks.append({
        'check': 'Azure Cross-Tenant Security',
        'target': 'Azure AD',
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual verification required',
        'recommendation': '''Verify cross-tenant controls:
            - B2B collaboration restrictions
            - Tenant restrictions enforced
            - External identity governance
            - Cross-tenant access monitoring'''
    })

    return checks


def get_manual_azure_checks(config: Dict, logger) -> List[Dict]:
    """Return manual checks when Azure CLI is not available"""
    return [
        {
            'check': 'Azure Network Security',
            'target': 'Azure Infrastructure',
            'status': 'manual',
            'severity': 'high',
            'finding': 'Manual verification required - Azure CLI not available',
            'recommendation': 'Review NSGs, Azure Firewall, VNet peering security, and private endpoints'
        },
        {
            'check': 'Azure Identity Security',
            'target': 'Azure AD',
            'status': 'manual',
            'severity': 'critical',
            'finding': 'Manual verification required - Azure CLI not available',
            'recommendation': 'Review Conditional Access, PIM, MFA enforcement, and service principal security'
        },
        {
            'check': 'Azure Data Protection',
            'target': 'Azure Data Services',
            'status': 'manual',
            'severity': 'high',
            'finding': 'Manual verification required - Azure CLI not available',
            'recommendation': 'Review encryption at rest/transit, Key Vault configuration, and storage account security'
        }
    ]
