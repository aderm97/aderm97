# FMDQ Security Checker - Complete Step-by-Step Guide

## 📋 Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running Your First Scan](#running-your-first-scan)
5. [Understanding the Output](#understanding-the-output)
6. [Advanced Usage](#advanced-usage)
7. [Troubleshooting](#troubleshooting)

---

## 1. Prerequisites

### ✅ What You Need Before Starting

**A. Operating System**
- Linux (Ubuntu 20.04+, Debian 11+, Kali Linux) - **Recommended**
- macOS (with Homebrew)
- Windows (via WSL2 with Ubuntu)

**B. Python**
- Python 3.8 or higher

**C. Permissions**
- Sudo/root access (for installing security tools)
- Network access to targets you want to scan

**D. Authorization**
- **CRITICAL:** Written authorization to scan target systems
- Never scan systems you don't own or have permission to test

### 🔍 Check Your System

```bash
# Check Python version
python3 --version
# Should show: Python 3.8.x or higher

# Check if you have sudo access
sudo -v
# You should be prompted for password

# Check git (should already be installed)
git --version
```

---

## 2. Installation

### Step 2.1: Navigate to the Security Checker Directory

```bash
# You should already have this from the repository
cd /home/user/aderm97/security-checker

# Verify you're in the right place
ls -la
# You should see: security_checker.py, config/, modules/, utils/, etc.
```

### Step 2.2: Install Python Dependencies

```bash
# Install required Python packages
pip3 install -r requirements.txt

# Expected output:
# Collecting PyYAML>=6.0
# Installing collected packages: PyYAML
# Successfully installed PyYAML-6.0
```

### Step 2.3: Make the Script Executable (Optional)

```bash
chmod +x security_checker.py
```

### Step 2.4: Verify Installation

```bash
# Test that the script can run
python3 security_checker.py --help

# You should see the help menu with all options
```

---

## 3. Configuration

### Step 3.1: Understand the Configuration File

The configuration file defines what to scan. Let's examine it:

```bash
# View the sample configuration
cat config/targets.yaml
```

### Step 3.2: Create Your Own Configuration

**Option A: Use the Sample Configuration (For Testing)**

```bash
# The sample config has example IPs - good for learning
# No changes needed for first test
```

**Option B: Create Custom Configuration (For Real Scanning)**

```bash
# Make a backup of the sample
cp config/targets.yaml config/targets.yaml.backup

# Edit with your actual infrastructure
nano config/targets.yaml
```

**Example Minimal Configuration:**

```yaml
scope:
  organization: "My Company"
  assessment_type: "Network Infrastructure VAPT"

perimeter:
  targets:
    internet_facing:
      - ip: "203.0.113.10"              # Replace with your public IP
        name: "Public Web Server"
        type: "internet_gateway"

firewall:
  targets:
    firewalls:
      - ip: "192.168.1.1"               # Replace with your firewall IP
        name: "Main Firewall"
        location: "Main Office"
```

**Save and Exit:**
- Press `Ctrl + O` to save
- Press `Enter` to confirm
- Press `Ctrl + X` to exit

### Step 3.3: Validate Your Configuration

```bash
# Quick syntax check
python3 -c "import yaml; yaml.safe_load(open('config/targets.yaml'))"

# No output = good!
# Error = fix the YAML syntax
```

---

## 4. Running Your First Scan

### Step 4.1: Install Security Tools (First Time Only)

When you run the scanner for the first time, it will automatically detect missing tools and offer to install them.

```bash
# Run the installer
python3 security_checker.py --install-only
```

**You'll see:**
```
🔧 Checking security tools...

================================================================================
SECURITY TOOLS INSTALLATION WIZARD
================================================================================

Found 15 missing security tools:

  Essential:
    ✗ nmap                - Network scanner and security auditing tool
    ✗ netcat              - Network utility

  [... more tools listed ...]

--------------------------------------------------------------------------------

Would you like to install these 15 missing tools?
This will use sudo and may require your password.

Install missing tools? [Y/n]:
```

**Type:** `y` and press Enter

**What Happens Next:**
1. Your sudo password will be requested
2. Package manager updates (apt/dnf/brew)
3. Each tool installs one by one
4. Progress shown for each tool
5. Summary displayed at the end

**Expected Duration:** 5-15 minutes depending on internet speed

### Step 4.2: Run a Simple Connectivity Check

Let's start with the simplest scan - just checking if targets are reachable:

```bash
# Run connectivity check only
python3 security_checker.py --module connectivity --config config/targets.yaml
```

**You'll see:**
```
[1/1] Checking Connectivity & Security Tools...
  Available tools (14/18):
    ✓ nmap
    ✓ masscan
    ✓ testssl.sh
    ...

  Checking connectivity for 5 unique targets...

  Checking liveness for: 203.0.113.10
    ✓ ICMP: Reachable (15.3ms)
    ✓ TCP: Open ports [80, 443]
    Status: ONLINE

  Checking liveness for: 192.168.1.1
    ✗ ICMP: No response
    ✓ TCP: Port 443 open
    Status: BLOCKING (IPS/Firewall detected)
```

### Step 4.3: Run a Single Module Test

Test one security module at a time:

```bash
# Test perimeter security only
python3 security_checker.py --module perimeter --config config/targets.yaml --verbose
```

**What This Does:**
- Scans internet-facing targets only
- Uses nmap for port scanning
- Tests SSL/TLS with testssl.sh
- Checks for common vulnerabilities
- Shows detailed progress (--verbose)

### Step 4.4: Run a Full Security Scan

Now run the complete assessment:

```bash
# Full comprehensive scan
python3 security_checker.py --config config/targets.yaml --full-scan --verbose
```

**What This Does:**
- Runs all 11 security modules
- Checks connectivity first
- Tests perimeter security
- Analyzes firewall configurations
- Checks network segmentation
- Tests VPN security
- Validates SSL/TLS
- Scans for web vulnerabilities
- Checks Azure cloud security
- Validates compliance
- Generates comprehensive report

**Expected Duration:**
- Small network (5-10 targets): 10-20 minutes
- Medium network (20-50 targets): 30-60 minutes
- Large network (100+ targets): 2-4 hours

### Step 4.5: Skip Tool Installation (Subsequent Runs)

After the first run, skip the installation wizard:

```bash
# Skip installation, go straight to scanning
python3 security_checker.py --config config/targets.yaml --full-scan --skip-install
```

---

## 5. Understanding the Output

### Step 5.1: Console Output

**During the scan, you'll see:**

```
================================================================================
FMDQ NETWORK INFRASTRUCTURE SECURITY ASSESSMENT
================================================================================
Start time: 2025-01-16 14:30:00

[1/11] Checking Connectivity & Security Tools...
  Available tools (14/18):
    ✓ nmap
    ✓ testssl.sh
    ...

[2/11] Running Perimeter Security Assessment...
  Scanning perimeter target: Public Web Server (203.0.113.10)
    Running nmap port scan...
    Running nmap service detection...
    Running testssl.sh SSL/TLS analysis...
    Running Nikto web server scan...

[3/11] Running Firewall Security Testing...
  Testing firewall: Main Firewall (192.168.1.1)
    Checking management interface exposure...
    Testing for bypass techniques...

[... continues through all 11 modules ...]

================================================================================
SECURITY ASSESSMENT SUMMARY
================================================================================
Total Checks:    247
Passed:          189 ✓
Failed:          42 ✗
Warnings:        16 ⚠

Severity Breakdown:
  Critical:      5
  High:          15
  Medium:        18
  Low:           4

Report saved to: reports/security_report_20250116_143000.html
================================================================================
```

### Step 5.2: HTML Report

**Open the report:**

```bash
# Find the latest report
ls -lt reports/

# Open in browser
firefox reports/security_report_*.html
# OR
google-chrome reports/security_report_*.html
# OR
open reports/security_report_*.html  # macOS
```

**The HTML report contains:**

1. **Executive Summary**
   - Total checks performed
   - Pass/fail statistics
   - Severity breakdown
   - Risk score

2. **Findings by Module**
   - Perimeter Security
   - Firewall Security
   - Network Segmentation
   - VPN Security
   - SSL/TLS Configuration
   - Web Application Security
   - Azure Cloud Security
   - Compliance Status

3. **For Each Finding:**
   - ✅ Status (Passed/Failed/Warning)
   - 🔴 Severity (Critical/High/Medium/Low)
   - 📍 Target system
   - 🔍 What was found
   - 💡 Recommendation to fix

### Step 5.3: JSON Report (For Automation)

```bash
# Generate JSON format
python3 security_checker.py --config config/targets.yaml --full-scan --format json

# View the JSON
cat reports/security_report_*.json | python3 -m json.tool | less
```

### Step 5.4: CSV Report (For Spreadsheets)

```bash
# Generate CSV format
python3 security_checker.py --config config/targets.yaml --full-scan --format csv

# Open in Excel/LibreOffice
libreoffice reports/security_report_*.csv
```

---

## 6. Advanced Usage

### Option 1: Scan Specific Modules

```bash
# Connectivity only
python3 security_checker.py --module connectivity --config config/targets.yaml

# Perimeter security only
python3 security_checker.py --module perimeter --config config/targets.yaml

# Azure cloud security only
python3 security_checker.py --module azure --config config/targets.yaml

# Compliance checks only
python3 security_checker.py --module compliance --config config/targets.yaml
```

### Option 2: Quick Network Scan

```bash
# Scan entire subnet quickly
python3 security_checker.py --quick-scan --network 192.168.1.0/24
```

### Option 3: Single Target Scan

```bash
# Scan one specific IP
python3 security_checker.py --module perimeter --target 203.0.113.10
```

### Option 4: Generate Multiple Report Formats

```bash
# HTML report
python3 security_checker.py --config config/targets.yaml --full-scan --format html

# JSON report
python3 security_checker.py --config config/targets.yaml --full-scan --format json

# CSV report
python3 security_checker.py --config config/targets.yaml --full-scan --format csv
```

### Option 5: Verbose Mode (See Everything)

```bash
# Maximum detail in console output
python3 security_checker.py --config config/targets.yaml --full-scan --verbose
```

### Option 6: Scheduled Scans (Cron)

```bash
# Edit crontab
crontab -e

# Add this line for weekly Sunday 2 AM scan:
0 2 * * 0 cd /home/user/aderm97/security-checker && python3 security_checker.py --config config/targets.yaml --full-scan --skip-install --format html >> /var/log/security-scan.log 2>&1
```

---

## 7. Troubleshooting

### Problem 1: "Permission denied" During Scan

**Cause:** Some tools need root privileges

**Solution:**
```bash
# Run with sudo
sudo python3 security_checker.py --config config/targets.yaml --full-scan

# OR set capabilities (Linux only)
sudo setcap cap_net_raw+ep /usr/bin/masscan
sudo setcap cap_net_raw+ep /usr/bin/hping3
```

### Problem 2: "Tool not found" Error

**Cause:** Security tool not installed

**Solution:**
```bash
# Re-run installer
python3 security_checker.py --install-only

# OR install manually
sudo apt update
sudo apt install nmap masscan nikto sslscan testssl.sh
```

### Problem 3: "Connection timed out" Errors

**Cause:** Firewall blocking or target offline

**Solution:**
- Verify target IPs are correct
- Check firewall allows scanning from your IP
- Run connectivity check first:
  ```bash
  python3 security_checker.py --module connectivity --config config/targets.yaml
  ```

### Problem 4: "No module named 'yaml'"

**Cause:** Python dependencies not installed

**Solution:**
```bash
pip3 install -r requirements.txt
```

### Problem 5: Scan Takes Too Long

**Cause:** Too many targets or detailed scanning

**Solution:**
```bash
# Use quick scan mode
python3 security_checker.py --quick-scan --network 192.168.1.0/24

# OR scan one module at a time
python3 security_checker.py --module perimeter --config config/targets.yaml

# OR reduce targets in config file
```

### Problem 6: Too Many False Positives

**Cause:** Default security checks are comprehensive

**Solution:**
- Review the findings in the HTML report
- Mark known/accepted risks as exceptions
- Focus on Critical and High severity findings first
- Use the compliance module to align with your standards

---

## 🎯 Quick Reference Commands

### First Time Setup
```bash
cd /home/user/aderm97/security-checker
pip3 install -r requirements.txt
python3 security_checker.py --install-only
```

### Edit Configuration
```bash
nano config/targets.yaml
```

### Run Full Scan
```bash
python3 security_checker.py --config config/targets.yaml --full-scan --skip-install
```

### View Latest Report
```bash
firefox reports/security_report_*.html
```

### Scan Single Module
```bash
python3 security_checker.py --module perimeter --config config/targets.yaml
```

### Quick Network Scan
```bash
python3 security_checker.py --quick-scan --network 192.168.1.0/24
```

---

## 📞 Getting Help

### Documentation Files
- `README.md` - Complete documentation
- `QUICK_START.md` - Quick reference guide
- `requirements.txt` - Tool descriptions
- `config/targets.yaml` - Configuration examples

### Command Help
```bash
python3 security_checker.py --help
```

### Check Tool Status
```bash
python3 security_checker.py --module connectivity --config config/targets.yaml
```

---

## ✅ Next Steps

After successfully running your first scan:

1. **Review the HTML Report**
   - Understand Critical and High severity findings
   - Plan remediation for failed checks
   - Document accepted risks

2. **Customize Your Configuration**
   - Add all your infrastructure targets
   - Set up exclusions for out-of-scope systems
   - Configure time windows

3. **Schedule Regular Scans**
   - Set up weekly/monthly automated scans
   - Compare reports over time
   - Track remediation progress

4. **Integrate with Your Workflow**
   - Export JSON for ticketing systems
   - Generate CSV for management reports
   - Archive reports for compliance

---

**🎉 You're Ready!**

Start with:
```bash
python3 security_checker.py --config config/targets.yaml --full-scan
```

The tool will guide you through installation and scanning automatically! 🚀
