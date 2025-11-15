# FMDQ Network Infrastructure Security Configuration Checker

A comprehensive security configuration checker for FMDQ's network infrastructure based on the VAPT (Vulnerability Assessment and Penetration Testing) checklist covering Exchange Place, Production Site, DR Site, and Azure cloud integration.

## 🎯 Overview

This tool automates security configuration checks across:
- **Perimeter Security** - Internet-facing infrastructure and edge routers
- **Firewall Security** - Rule analysis and bypass testing
- **Network Segmentation** - VLAN isolation and switch security
- **VPN Security** - Authentication, encryption, and session management
- **Access Control** - NAC, wireless, and access switch security
- **WAF Security** - Web application firewall testing
- **Azure Cloud Security** - Hybrid connectivity and cloud-specific checks
- **Internal Penetration Testing** - Credential attacks, lateral movement, privilege escalation
- **Monitoring & IR** - Logging infrastructure and detection capabilities
- **Compliance** - CBN, SEC Nigeria, NDPR, ISO 27001

## 📋 Features

✅ **Automated Checks** - Port scanning, SSL/TLS analysis, service detection
✅ **Manual Check Guidance** - Detailed recommendations for manual verification
✅ **Multiple Report Formats** - HTML, JSON, CSV, PDF
✅ **Modular Architecture** - Run specific modules or full scans
✅ **Severity Ratings** - Critical, High, Medium, Low classifications
✅ **Compliance Mapping** - Aligned with Nigerian financial regulations
✅ **Azure Integration** - Cloud security assessment via Azure CLI

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.8 or higher
python3 --version

# Install dependencies
pip install -r requirements.txt

# For Azure checks (optional)
pip install azure-cli
az login
```

### Installation

```bash
# Clone or download the security-checker directory
cd security-checker

# Make the script executable
chmod +x security_checker.py
```

### Configuration

1. Edit `config/targets.yaml` with your infrastructure details:

```yaml
perimeter:
  targets:
    internet_facing:
      - ip: "217.117.13.209"
        name: "INQ Digital Connection"
```

2. Update network ranges, firewall IPs, and Azure subscription details

### Usage Examples

#### Full Comprehensive Scan
```bash
python3 security_checker.py --config config/targets.yaml --full-scan --output reports/
```

#### Single Module Scan
```bash
# Perimeter security only
python3 security_checker.py --module perimeter --config config/targets.yaml

# Firewall security
python3 security_checker.py --module firewall --config config/targets.yaml

# Azure security
python3 security_checker.py --module azure --config config/targets.yaml
```

#### Quick Network Scan
```bash
python3 security_checker.py --quick-scan --network 10.10.10.0/24
```

#### Specific Target Scan
```bash
python3 security_checker.py --module perimeter --target 217.117.13.209
```

#### Generate Different Report Formats
```bash
# HTML report (default)
python3 security_checker.py --full-scan --format html

# JSON report
python3 security_checker.py --full-scan --format json

# CSV report
python3 security_checker.py --full-scan --format csv
```

#### Verbose Output
```bash
python3 security_checker.py --full-scan --verbose
```

## 📊 Report Output

Reports are generated in the `reports/` directory with timestamps:

```
reports/
├── security_report_20250115_143022.html
├── security_report_20250115_143022.json
└── security_report_20250115_143022.csv
```

### HTML Report Features
- Executive summary with metrics
- Color-coded severity levels
- Detailed findings by module
- Actionable recommendations
- Print-friendly formatting

## 🔧 Available Modules

| Module | Description | Automated |
|--------|-------------|-----------|
| `perimeter` | Internet-facing infrastructure checks | ✅ Partial |
| `firewall` | Firewall configuration and bypass tests | ✅ Partial |
| `segmentation` | Network segmentation and VLAN security | ⚠️ Manual |
| `vpn` | VPN authentication and encryption | ⚠️ Manual |
| `access_control` | NAC and wireless security | ⚠️ Manual |
| `waf` | Web application firewall testing | ✅ Partial |
| `azure` | Azure cloud security assessment | ✅ Partial |
| `pentest` | Internal penetration testing | ⚠️ Manual |
| `monitoring` | Logging and detection capabilities | ⚠️ Manual |
| `compliance` | Regulatory compliance checks | ⚠️ Manual |

## 🔍 Check Types

### Automated Checks
- Port scanning and service detection
- SSL/TLS configuration analysis
- Banner grabbing and version detection
- HTTP method testing
- Azure resource configuration (via Azure CLI)
- WAF protection testing

### Manual Verification Required
- Firewall rule base analysis
- Network device configuration review
- VPN encryption standards
- Access control policies
- Incident response procedures
- Compliance documentation review

## ⚙️ Configuration File Structure

```yaml
# config/targets.yaml

scope:
  organization: "FMDQ"
  sites: ["Exchange Place", "Production Site", "DR Site"]

perimeter:
  targets:
    internet_facing:
      - ip: "217.117.13.209"
        name: "INQ Digital Connection"

firewall:
  targets:
    firewalls:
      - ip: "154.113.146.117"
        name: "Exchange Place Firewall"

# ... additional configuration
```

## 🛡️ Security Considerations

### Authorization Required
- Obtain written authorization before scanning
- Define clear scope boundaries
- Establish emergency contact procedures
- Follow rules of engagement

### Recommended Testing Windows
- **Production Site**: Coordinate with change management
- **DR Site**: Preferred for aggressive testing
- **Trading Hours**: Avoid during market operations (09:00-17:00 WAT)
- **Weekend Windows**: For disruptive tests

### Exclusions (DO NOT SCAN)
- Main One ISP infrastructure
- NIBSS integration endpoints
- Production databases during business hours

## 📈 Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| 🔴 **Critical** | Immediate risk, active exploitation possible | < 24 hours |
| 🟠 **High** | Significant risk, requires urgent attention | < 1 week |
| 🟡 **Medium** | Moderate risk, should be addressed | < 1 month |
| 🟢 **Low** | Minor risk, address in regular cycle | < 3 months |
| ℹ️ **Info** | Informational, no immediate action | N/A |

## 🔄 Continuous Improvement

### Regular Scanning Schedule
- **Full Scan**: Quarterly
- **Perimeter Scan**: Monthly
- **Critical Systems**: Bi-weekly
- **After Changes**: Post-deployment

### Integration
- Integrate with CI/CD pipelines
- Schedule automated scans via cron
- Export to SIEM for correlation
- Track remediation progress

Example cron job:
```bash
# Run weekly scan every Sunday at 2 AM
0 2 * * 0 /usr/bin/python3 /path/to/security_checker.py --full-scan --config /path/to/config.yaml --output /path/to/reports/
```

## 🛠️ Advanced Features

### Custom Checks
Add custom checks by extending modules in `modules/` directory:

```python
# modules/custom_checks.py
def run(config: Dict, logger) -> Dict[str, Any]:
    findings = {'module': 'Custom Checks', 'checks': []}
    # Your custom logic here
    return findings
```

### Integration with Other Tools
- **Nmap**: For detailed port scanning
- **OpenVAS/Nessus**: For vulnerability scanning
- **Metasploit**: For penetration testing
- **ScoutSuite**: For Azure cloud scanning

## 📝 Requirements

```
Python 3.8+
PyYAML>=6.0
```

Optional:
```
azure-cli (for Azure checks)
weasyprint (for PDF generation)
```

## 🐛 Troubleshooting

### Common Issues

**"Permission denied" errors during port scanning:**
```bash
# Run with sudo for privileged ports (not recommended)
sudo python3 security_checker.py --module perimeter

# OR use capability (Linux)
sudo setcap cap_net_raw+ep $(which python3)
```

**Azure CLI authentication failed:**
```bash
# Re-authenticate
az login
az account show
```

**Module import errors:**
```bash
# Ensure you're in the security-checker directory
cd security-checker
python3 -m pip install -r requirements.txt
```

## 📞 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the VAPT checklist for manual verification requirements
3. Consult with your security team or FMDQ IT department

## 🔒 Compliance Mapping

### CBN IT Standards
- Information Security Policy
- Business Continuity Planning
- Vulnerability Assessments (Quarterly)
- Penetration Testing (Annual)

### SEC Nigeria
- Transaction Integrity Controls
- System Availability (99.5%+)
- Cybersecurity Framework

### NDPR (Nigeria Data Protection Regulation)
- Data Protection Policy
- Privacy Impact Assessments
- Data Breach Notification

### ISO 27001
- All Annex A controls mapped
- Control validation automated where possible

## 📄 License

This tool is proprietary to FMDQ and intended for authorized security assessment purposes only.

## ⚠️ Disclaimer

This tool is provided "as-is" for security assessment purposes. Always:
- Obtain proper authorization before scanning
- Understand the impact of security testing
- Have incident response procedures ready
- Test in non-production environments first
- Follow your organization's security policies

## 🎓 Best Practices

1. **Before Scanning**
   - Review and update configuration
   - Verify scope and exclusions
   - Notify stakeholders
   - Prepare incident response

2. **During Scanning**
   - Monitor for issues
   - Have rollback procedures ready
   - Document findings in real-time

3. **After Scanning**
   - Review all findings
   - Prioritize remediation
   - Track progress
   - Schedule re-testing

---

**Version:** 1.0.0
**Last Updated:** 2025-01-15
**Maintained by:** FMDQ Security Team
