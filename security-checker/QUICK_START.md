# FMDQ Security Checker - Quick Start Guide

## 🚀 Installation & First Run

### Step 1: Install Python Dependencies

```bash
cd security-checker
pip install -r requirements.txt
```

### Step 2: Run the Security Checker

The tool will **automatically** check for missing security tools and offer to install them!

```bash
python3 security_checker.py --config config/targets.yaml --full-scan
```

### What Happens:

```
🔧 Checking security tools...

================================================================================
SECURITY TOOLS INSTALLATION WIZARD
================================================================================

Found 15 missing security tools:

  Essential:
    ✗ nmap                - Network scanner and security auditing tool
    ✗ netcat              - Network utility for reading/writing network connections

  Port Scanning:
    ✗ masscan             - Ultra-fast port scanner

  SSL/TLS Testing:
    ✗ sslscan             - SSL/TLS scanner
    ✗ sslyze              - SSL configuration analyzer

  Web Testing:
    ✗ nikto               - Web server vulnerability scanner
    ✗ wafw00f             - Web Application Firewall detector
    ✗ sqlmap              - SQL injection testing tool

  Network Tools:
    ✗ hping3              - Advanced packet crafting tool

--------------------------------------------------------------------------------

Would you like to install these 15 missing tools?
This will use sudo and may require your password.

Install missing tools? [Y/n]: █
```

### Step 3: Respond to Prompt

**Option A: Install All Tools (Recommended)**
```
Install missing tools? [Y/n]: y
```

The installer will:
- ✅ Update package manager (apt/dnf/brew)
- ✅ Install all missing tools automatically
- ✅ Show progress for each tool
- ✅ Display installation summary
- ✅ Proceed to security scan

**Option B: Skip Installation**
```
Install missing tools? [Y/n]: n
```

The scanner will:
- ⚠️ Use basic Python fallback checks
- ⚠️ Limited scan capabilities
- ⚠️ Still provide useful results

## 📋 Command-Line Options

### Full Scan (Recommended)
```bash
python3 security_checker.py --config config/targets.yaml --full-scan
```

### Install Tools Only (No Scan)
```bash
python3 security_checker.py --install-only
```

### Skip Tool Installation
```bash
python3 security_checker.py --config config/targets.yaml --full-scan --skip-install
```

### Single Module Scan
```bash
python3 security_checker.py --module perimeter --target 217.117.13.209
```

### Quick Network Scan
```bash
python3 security_checker.py --quick-scan --network 10.10.10.0/24
```

## 🎯 Complete Workflow Example

```bash
# 1. First time - install everything
python3 security_checker.py --install-only

# 2. Configure your targets
nano config/targets.yaml

# 3. Run full security assessment
python3 security_checker.py --config config/targets.yaml --full-scan --verbose

# 4. View HTML report
firefox reports/security_report_*.html
```

## 🛠️ Supported Platforms

### ✅ Fully Supported
- **Kali Linux** (recommended)
- **Ubuntu 20.04+**
- **Debian 11+**
- **macOS** (with Homebrew)

### ⚠️ Partial Support
- **Fedora / RHEL / CentOS** (DNF package manager)
- **Arch Linux / Manjaro** (Pacman)

### Manual Installation Required
- **Windows** (Use WSL2 with Ubuntu)

## 📦 What Gets Installed

### Essential Tools (Always Recommended)
| Tool | Purpose | Size |
|------|---------|------|
| nmap | Port scanning, service detection | ~7 MB |
| netcat | Network connections | ~100 KB |

### Port Scanning Tools
| Tool | Purpose | Size |
|------|---------|------|
| masscan | Ultra-fast port scanner | ~500 KB |

### SSL/TLS Testing Tools
| Tool | Purpose | Size |
|------|---------|------|
| testssl.sh | Comprehensive SSL/TLS testing | ~2 MB |
| sslscan | SSL configuration scanner | ~100 KB |
| sslyze | Python SSL analyzer | ~5 MB |

### Web Application Tools
| Tool | Purpose | Size |
|------|---------|------|
| nikto | Web server scanner | ~2 MB |
| wafw00f | WAF detection | ~1 MB |
| sqlmap | SQL injection testing | ~8 MB |
| gobuster | Directory bruteforcer | ~7 MB |

### Network Tools
| Tool | Purpose | Size |
|------|---------|------|
| hping3 | Packet crafting | ~200 KB |
| tcpdump | Packet capture | ~1 MB |

### Cloud Tools
| Tool | Purpose | Size |
|------|---------|------|
| azure-cli | Azure security testing | ~60 MB |

**Total Disk Space Required:** ~100-150 MB

## 🔐 Permission Requirements

Some tools require **sudo** access for installation and operation:

### Installation (One-time)
```bash
sudo apt install nmap masscan nikto ...
```

### Operation (Some Tools)
- `masscan` - Requires root for raw sockets
- `hping3` - Requires root for packet crafting
- `tcpdump` - Requires root for packet capture

**Solution:** Run security checker with sudo, or use capabilities:
```bash
# Option 1: Run with sudo
sudo python3 security_checker.py --full-scan

# Option 2: Set capabilities (Linux only)
sudo setcap cap_net_raw+ep /usr/bin/masscan
sudo setcap cap_net_raw+ep /usr/bin/hping3
```

## ❓ Troubleshooting

### "Permission denied" during installation
```bash
# Make sure you have sudo access
sudo -v

# Try manual installation
sudo apt update
sudo apt install nmap masscan nikto sslscan
```

### "Homebrew not found" (macOS)
```bash
# Install Homebrew first
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### "Tool not found after installation"
```bash
# Verify installation
which nmap
nmap --version

# Reload shell
hash -r

# Or start new terminal session
```

### "Import error: No module named 'yaml'"
```bash
# Install Python dependencies
pip3 install PyYAML
```

## 📝 Configuration Quick Reference

### Minimal config/targets.yaml
```yaml
scope:
  organization: "Your Company"

perimeter:
  targets:
    internet_facing:
      - ip: "203.0.113.10"
        name: "Public Web Server"
```

### Full scan with all modules
```yaml
scope:
  organization: "FMDQ"
  sites: ["Exchange Place", "Production", "DR"]

perimeter:
  targets:
    internet_facing:
      - ip: "217.117.13.209"
        name: "INQ Digital Connection"

firewall:
  targets:
    firewalls:
      - ip: "154.113.146.117"
        name: "Main Firewall"
```

## 🎓 Best Practices

1. **First Run**
   - Use `--install-only` to install all tools first
   - Review what gets installed
   - Test with a single target before full scan

2. **Regular Scans**
   - Use `--skip-install` to skip tool check
   - Schedule with cron for automated scanning
   - Keep tools updated: `sudo apt upgrade`

3. **Security**
   - Always get written authorization before scanning
   - Use `--verbose` to see exactly what's being tested
   - Review reports before sharing

4. **Performance**
   - Start with `--quick-scan` for initial assessment
   - Use `--full-scan` for comprehensive testing
   - Run intensive scans during maintenance windows

## 🔗 Next Steps

1. **Review Full Documentation**
   - See `README.md` for detailed usage
   - Check `requirements.txt` for tool descriptions

2. **Customize Configuration**
   - Edit `config/targets.yaml` with your infrastructure
   - Set up exclusions and time windows

3. **Run First Scan**
   - Start with single module: `--module connectivity`
   - Progress to full scan: `--full-scan`

4. **Analyze Reports**
   - Open HTML report in browser
   - Export to JSON for automation
   - Track remediation progress

## 📞 Support

- **Documentation:** See `README.md`
- **Configuration:** See `config/targets.yaml`
- **Tool Details:** See `requirements.txt`
- **Examples:** See usage examples above

---

**Ready to start?** Run this command:

```bash
python3 security_checker.py --config config/targets.yaml --full-scan
```

The tool will guide you through installation and start scanning! 🚀
