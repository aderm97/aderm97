# Security Tool Requirements

## Overview

The FMDQ Security Checker requires professional security tools to perform effective vulnerability assessments. This document explains the tool requirements and what happens when they are not installed.

---

## Critical Tools

The following tools are **REQUIRED** for the security scanner to run:

| Tool | Purpose | Why Critical |
|------|---------|--------------|
| **nmap** | Network scanning & service detection | Essential for discovering open ports, services, and vulnerabilities |
| **testssl** | SSL/TLS security testing | Required for comprehensive SSL/TLS vulnerability assessment |
| **sslscan** | SSL/TLS configuration analysis | Backup tool for SSL/TLS testing if testssl unavailable |
| **nikto** | Web server vulnerability scanning | Critical for identifying web server misconfigurations and vulnerabilities |

**If ANY of these critical tools are missing, the security scan will be ABORTED.**

---

## Additional Tools

While not critical to run a scan, these tools significantly enhance scanning capabilities:

### Port Scanning Tools
- **masscan** - Ultra-fast port scanner
- **unicornscan** - Advanced port scanner

### Web Testing Tools
- **wafw00f** - Web Application Firewall detector
- **sqlmap** - SQL injection testing tool
- **gobuster** - Directory/file bruteforcer
- **ffuf** - Fast web fuzzer

### Network Tools
- **hping3** - Advanced packet crafting tool
- **tcpdump** - Network packet analyzer
- **tshark** - Network protocol analyzer (Wireshark CLI)

### Password Tools
- **hydra** - Network login cracker
- **medusa** - Parallel password cracker

### Enumeration Tools
- **enum4linux** - Windows/Samba enumeration tool
- **nbtscan** - NetBIOS scanner

### Cloud Tools
- **azure-cli** (az) - Azure command-line interface

### Vulnerability Scanning
- **nuclei** - Fast vulnerability scanner

---

## Scan Behavior

### When All Critical Tools Are Installed ✅

```bash
$ python3 security_checker.py --config config/targets.yaml --full-scan

================================================================================
FMDQ NETWORK INFRASTRUCTURE SECURITY ASSESSMENT
================================================================================

[1/11] Checking Connectivity & Security Tools...
Checking security tools availability...
  ✅ All 18 security tools are installed!

[2/11] Running Perimeter Security Assessment...
  [Scan continues normally...]
```

**Result:** Full scan executes with professional tools providing comprehensive results.

---

### When Critical Tools Are Missing ❌

```bash
$ python3 security_checker.py --config config/targets.yaml --full-scan

================================================================================
FMDQ NETWORK INFRASTRUCTURE SECURITY ASSESSMENT
================================================================================

[1/11] Checking Connectivity & Security Tools...
Checking security tools availability...
  ⚠️  0/18 security tools available
  Missing tools: nmap, masscan, hping3, nikto, sqlmap (+13 more)

  ❌ CRITICAL TOOLS MISSING: nmap, testssl, sslscan, nikto
  Cannot perform effective security scans without these tools.

  💡 To install missing tools, run:
     python3 install_tools.py


================================================================================
SCAN ABORTED: Critical security tools are not installed
================================================================================

The security scanner requires professional tools to perform
effective vulnerability assessments. Running without these tools
would produce incomplete and unreliable results.

Please install the required tools by running:
  python3 install_tools.py
```

**Result:** Scan is aborted after tool check. No further modules are executed.

---

### When Some Non-Critical Tools Are Missing ⚠️

If all **critical tools** are installed but some **additional tools** are missing:

```bash
$ python3 security_checker.py --config config/targets.yaml --full-scan

================================================================================
FMDQ NETWORK INFRASTRUCTURE SECURITY ASSESSMENT
================================================================================

[1/11] Checking Connectivity & Security Tools...
Checking security tools availability...
  ⚠️  8/18 security tools available
  Missing tools: masscan, gobuster, ffuf, hydra, medusa (+5 more)

  💡 To install missing tools, run:
     python3 install_tools.py

[2/11] Running Perimeter Security Assessment...
  [Scan continues with available tools...]
```

**Result:** Scan continues using available critical tools. Missing non-critical tools are noted in warnings.

---

## Why Abort on Missing Critical Tools?

The security scanner is designed to provide **reliable, professional-grade vulnerability assessments** for financial infrastructure. Running scans without critical tools would:

1. **Produce Incomplete Results**
   - Many vulnerabilities would go undetected
   - False sense of security

2. **Generate Unreliable Findings**
   - Python fallback methods are basic and limited
   - Cannot match professional tool capabilities

3. **Waste Time and Resources**
   - Scanning without proper tools takes time but yields little value
   - Better to install tools first, then run comprehensive scan

4. **Compliance Issues**
   - Financial institutions require thorough security assessments
   - Incomplete scans may not meet regulatory requirements (CBN, SEC Nigeria, ISO 27001)

---

## Installation Instructions

### Quick Installation (Recommended)

```bash
# Install all security tools automatically
python3 install_tools.py
```

This will:
1. Check which tools are missing
2. Display installation summary
3. Prompt for confirmation: "Install missing tools? [Y/n]:"
4. Install tools using your system's package manager

### Check What's Missing (No Installation)

```bash
# Check which tools are missing without installing
python3 install_tools.py --check-only
```

### List All Supported Tools

```bash
# List all supported security tools with descriptions
python3 install_tools.py --list
```

### Force Installation (No Prompts)

```bash
# Install without confirmation prompt
python3 install_tools.py --force
```

---

## Platform Support

The tool installer supports:

- **Ubuntu / Debian / Kali** (apt)
- **Fedora / RHEL / CentOS** (dnf)
- **Arch / Manjaro** (pacman)
- **macOS** (brew)

**Note:** Some tools require **sudo privileges** for installation.

---

## Manual Installation

If you prefer to install tools manually:

### Ubuntu/Debian/Kali
```bash
sudo apt update
sudo apt install -y nmap nikto sslscan tshark hping3 tcpdump

# Install testssl.sh manually
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
sudo ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl

# Install additional tools
sudo apt install -y sqlmap wafw00f gobuster ffuf hydra medusa \
                    enum4linux nbtscan nuclei
```

### macOS
```bash
brew install nmap nikto sslscan wireshark nmap hping

# Install testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/testssl.sh
sudo ln -s ~/testssl.sh/testssl.sh /usr/local/bin/testssl

# Install additional tools
brew install sqlmap nuclei ffuf gobuster
```

---

## Verifying Installation

After installing tools, verify they're available:

```bash
# Quick check
python3 install_tools.py --check-only

# Or run a test scan on a safe target
python3 security_checker.py --module connectivity --target 8.8.8.8
```

Expected output when tools are installed:
```
Checking security tools availability...
  ✅ All 18 security tools are installed!
```

---

## Troubleshooting

### Problem: "CRITICAL TOOLS MISSING" error

**Solution:**
```bash
python3 install_tools.py
```

### Problem: Installation fails with permission errors

**Solution:** Run with sudo:
```bash
sudo python3 install_tools.py
```

### Problem: Tool installed but still shows as missing

**Solution:**
1. Check if tool is in PATH:
   ```bash
   which nmap
   which testssl
   ```

2. If not found, add installation directory to PATH
3. Restart terminal session

### Problem: Can't install testssl.sh via package manager

**Solution:** Install manually:
```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
sudo ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl
```

---

## Bypass Tool Check (Not Recommended)

**WARNING:** This is NOT recommended and will produce unreliable results.

If you absolutely need to run a scan without critical tools (e.g., for testing purposes), you can modify the critical tools list in `modules/connectivity.py`:

```python
# Line ~248 in modules/connectivity.py
critical_tools = []  # Empty list = no critical tools required
```

However, this is **strongly discouraged** for production security assessments.

---

## Summary

| Scenario | Critical Tools Status | Scan Behavior |
|----------|----------------------|---------------|
| ✅ All tools installed | All present | Full scan executes normally |
| ❌ Critical tools missing | Any missing | **Scan aborted** with error message |
| ⚠️ Only additional tools missing | All present | Scan continues with warnings |

**Best Practice:** Always run `python3 install_tools.py` before your first scan to ensure all tools are available.

---

**Last Updated:** 2025-11-16
**Version:** 1.0
