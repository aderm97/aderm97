# 🔄 New Workflow - Separate Installation Script

## What Changed?

The tool installation is now **completely separate** from the security scanner.

### ✅ Benefits
1. **Cleaner separation** - Install tools once, scan many times
2. **No interruptions** - Scanning never prompts for installation
3. **Flexible workflow** - Install tools when convenient
4. **Better control** - Easy to check/manage tools independently

---

## 📝 New Two-Step Workflow

### Step 1: Install Tools (One Time)

```bash
# Run the separate installer
python3 install_tools.py
```

**What it does:**
- Checks which security tools are missing
- Prompts: "Install missing tools? [Y/n]"
- Installs all tools with progress indicators
- Shows summary of installed/failed tools

**Output Example:**
```
================================================================================
FMDQ SECURITY TOOLS INSTALLER
================================================================================

Found 15 missing security tools:

  Essential:
    ✗ nmap
    ✗ netcat

  SSL/TLS Testing:
    ✗ sslscan
    ✗ testssl.sh

  [... more tools ...]

Install missing tools? [Y/n]: y

[1/15] Installing nmap...
  ✓ nmap installed successfully

[2/15] Installing sslscan...
  ✓ sslscan installed successfully

[... continues ...]

================================================================================
INSTALLATION COMPLETE
================================================================================

✓ Successfully installed (14):
  • nmap
  • sslscan
  • nikto
  [... etc ...]
```

### Step 2: Run Security Scans (Any Time)

```bash
# Run the security checker
python3 security_checker.py --config config/targets.yaml --full-scan
```

**What it does:**
- Checks which tools are available
- **Displays missing tools as warnings** (if any)
- **Continues with the scan anyway** using available tools
- Uses fallback methods for missing tools
- **Never prompts for installation**

**Output Example:**
```
[1/11] Checking Connectivity & Security Tools...
  Checking security tools availability...
  ⚠️  14/18 security tools available
  Missing tools: masscan, nuclei, gobuster, enum4linux

  💡 To install missing tools, run:
     python3 install_tools.py

  Checking connectivity for 5 unique targets...
  [Scan continues with available tools...]

[2/11] Running Perimeter Security Assessment...
  Scanning: Web Server (203.0.113.10)
    Running nmap port scan...      ← Uses nmap (installed)
    Running basic port scan...      ← Falls back to Python (masscan missing)
    [... scan continues ...]
```

---

## 🎯 Command Reference

### Installer Commands

| Command | Purpose |
|---------|---------|
| `python3 install_tools.py` | Install all missing tools (interactive) |
| `python3 install_tools.py --check-only` | Just check what's missing, don't install |
| `python3 install_tools.py --list` | List all supported tools and their status |
| `python3 install_tools.py --force` | Install without confirmation prompt |

### Scanner Commands (Same as Before)

| Command | Purpose |
|---------|---------|
| `python3 security_checker.py --full-scan` | Full scan with all modules |
| `python3 security_checker.py --module perimeter` | Single module scan |
| `python3 security_checker.py --quick-scan --network 192.168.1.0/24` | Quick network scan |

---

## 📋 Complete Example Workflow

### First Time Setup

```bash
# 1. Install Python dependencies
pip3 install -r requirements.txt

# 2. Install security tools
python3 install_tools.py
# Type 'y' when prompted

# 3. Configure targets
nano config/targets.yaml

# 4. Run first scan
python3 security_checker.py --config config/targets.yaml --full-scan
```

### Subsequent Scans

```bash
# Just run the scanner - tools already installed
python3 security_checker.py --config config/targets.yaml --full-scan
```

### Check Tool Status Anytime

```bash
# See which tools are installed
python3 install_tools.py --check-only
```

**Output:**
```
🔍 Checking installed security tools...

  Essential:
    ✓ nmap                - Network scanner
    ✓ netcat              - Network utility

  SSL/TLS Testing:
    ✓ sslscan             - SSL/TLS scanner
    ✗ testssl.sh          - Comprehensive SSL/TLS tester

  [... continues ...]

To install missing tools, run:
  python3 install_tools.py
```

### Install Missing Tools Later

```bash
# Reinstall/update tools
python3 install_tools.py
```

---

## 🔍 What Happens During Scans?

### Scenario 1: All Tools Installed ✅

```bash
python3 security_checker.py --full-scan
```

**Output:**
```
[1/11] Checking Connectivity & Security Tools...
  ✅ All 18 security tools are installed!

[2/11] Running Perimeter Security Assessment...
  Scanning with nmap (professional tool)
  Testing SSL/TLS with testssl.sh (professional tool)
  [... all professional tools used ...]
```

### Scenario 2: Some Tools Missing ⚠️

```bash
python3 security_checker.py --full-scan
```

**Output:**
```
[1/11] Checking Connectivity & Security Tools...
  ⚠️  12/18 security tools available
  Missing tools: masscan, nuclei, gobuster, enum4linux, hydra, medusa

  💡 To install missing tools, run:
     python3 install_tools.py

[2/11] Running Perimeter Security Assessment...
  Scanning with nmap (available) ✓
  Running basic port scan (masscan missing, using Python fallback)
  Testing SSL/TLS with sslscan (available) ✓
  [... scan continues with mix of professional tools and fallbacks ...]
```

**Key Point:** Scan **always continues** regardless of missing tools!

---

## 🆚 Old vs New Workflow

### ❌ Old Workflow (Removed)
```bash
# Scanner would interrupt you with installation prompt
python3 security_checker.py --full-scan

# Output:
# "Install missing tools? [Y/n]:"  ← Interrupted the scan!
# If you said 'no', scan would use fallbacks
```

### ✅ New Workflow (Current)
```bash
# Install tools separately (one time)
python3 install_tools.py

# Run scans anytime (no interruptions)
python3 security_checker.py --full-scan

# Output:
# Just shows missing tools as warnings
# Scan continues immediately!
```

---

## 💡 Tips & Best Practices

### 1. Install Tools on a Schedule
```bash
# Monthly tool updates
crontab -e

# Add: Update tools first Sunday of each month at 3 AM
0 3 1-7 * 0 cd /path/to/security-checker && python3 install_tools.py --force
```

### 2. Check Tool Status Before Important Scans
```bash
# Before quarterly audit
python3 install_tools.py --check-only
python3 security_checker.py --full-scan
```

### 3. Run Scans Even Without All Tools
```bash
# Quick check with whatever tools you have
python3 security_checker.py --module connectivity --config config/targets.yaml

# Scan will show what's missing but still run
```

### 4. Install Tools in Parallel with Scanning
```bash
# Terminal 1: Install tools in background
python3 install_tools.py &

# Terminal 2: Run scan immediately
python3 security_checker.py --quick-scan --network 192.168.1.0/24
```

---

## 📞 Quick Help

### "How do I install tools?"
```bash
python3 install_tools.py
```

### "How do I check what's installed?"
```bash
python3 install_tools.py --check-only
```

### "How do I run a scan?"
```bash
python3 security_checker.py --full-scan
```

### "Will scans fail if tools are missing?"
**No!** Scans always continue. Missing tools just trigger warnings and fallback methods.

---

## 🎯 Summary

| Task | Old Command | New Command |
|------|-------------|-------------|
| **Install tools** | `python3 security_checker.py --install-only` | `python3 install_tools.py` |
| **Check tools** | (not available) | `python3 install_tools.py --check-only` |
| **Run scan** | `python3 security_checker.py --full-scan --skip-install` | `python3 security_checker.py --full-scan` |

**The new workflow is cleaner, simpler, and never interrupts your scans!** 🚀
