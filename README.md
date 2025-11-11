# Low-Hanging Fruit Web Security Scanner

An automated security testing tool focusing on **easily exploitable vulnerabilities** in external-facing web applications. This scanner prioritizes quick wins - common misconfigurations and security issues that attackers exploit first.

## Why Focus on Low-Hanging Fruit?

**80% of successful attacks exploit simple, preventable vulnerabilities:**
- Missing security headers (quick fix, high impact)
- Exposed configuration files and backups (critical data leakage)
- Information disclosure through headers and errors (helps attackers)
- Common misconfigurations (often overlooked)
- Header injection attacks (easy to test and exploit)

This tool helps you find and fix these issues **before attackers do**.

## Key Features - Easy to Find, Easy to Fix

### 1. **Security Headers Analysis** (HIGH PRIORITY)
Missing security headers are the #1 low-hanging fruit vulnerability.

**Checks:**
- **HSTS** - Prevents SSL stripping attacks
- **X-Frame-Options** - Stops clickjacking
- **Content-Security-Policy** - Blocks XSS and data injection
- **X-Content-Type-Options** - Prevents MIME sniffing
- Information disclosure headers (Server, X-Powered-By, etc.)
- Cache-Control issues

**Example Fix:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
```

### 2. **Exposed Files & Directories** (CRITICAL)
Scans for commonly exposed sensitive resources:

**Version Control:**
- `.git/` - Full source code exposure
- `.svn/` - SVN repository leakage

**Backups:**
- `backup.zip`, `backup.sql`, `db_backup.sql`
- `dump.sql`, `site-backup.zip`

**Configuration:**
- `.env` - Environment variables (API keys, passwords)
- `config.php`, `web.config`
- `wp-config.php` - WordPress database credentials
- `phpinfo.php` - Full server configuration

**Admin Panels:**
- `/admin`, `/administrator`
- `/phpmyadmin`, `/cpanel`
- `/wp-admin`

**Logs:**
- `error.log`, `access.log`, `application.log`

### 3. **Header Injection Attacks**
Tests for header manipulation vulnerabilities:

- **Host Header Injection** - Can lead to password reset poisoning
- **X-Forwarded-Host Injection** - Bypasses security controls
- **X-Forwarded-For Manipulation** - IP spoofing
- **Referer Reflection** - Potential XSS vector

### 4. **Clickjacking Protection**
Quick test for frame protection:
- X-Frame-Options validation
- CSP frame-ancestors checking
- Provides immediate fix recommendations

### 5. **Information Disclosure**
Detects information leakage that helps attackers:

- SQL error messages
- Stack traces and debug output
- Path disclosure in errors
- Sensitive data in HTML comments
- Directory listing enabled
- Verbose error pages

### 6. **HTTP Method Security**
Tests for dangerous HTTP methods:

- **PUT** - File upload capability
- **DELETE** - Resource deletion
- **TRACE** - Cross-Site Tracing (XST) attacks
- Attempts actual exploitation to verify

### 7. **CORS Misconfigurations**
Identifies CORS issues that allow data theft:

- Wildcard origins (`Access-Control-Allow-Origin: *`)
- Reflected arbitrary origins
- Credentials with wildcard (CRITICAL)

### 8. **Open Redirect Vulnerabilities**
Tests common redirect parameters:
- `url`, `redirect`, `next`, `return`, `goto`, etc.
- Used in phishing and OAuth attacks

### 9. **SSL/TLS Weaknesses**
Checks for outdated protocols:
- TLS 1.0 / 1.1 support
- HTTP usage (no HTTPS)

## Installation

### Prerequisites
- Python 3.7+
- pip

### Setup

```bash
# Clone repository
git clone https://github.com/aderm97/aderm97.git
cd aderm97

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x web_security_scanner.py
```

## Usage

### Quick Scan

```bash
python web_security_scanner.py -u https://example.com
```

### Generate Detailed Report

```bash
python web_security_scanner.py -u https://example.com -o report.json
```

### Scan Multiple Sites

```bash
# Create targets file
echo "https://site1.com" > targets.txt
echo "https://site2.com" >> targets.txt

# Scan all
python web_security_scanner.py -f targets.txt -o reports/
```

### Command Options

```
usage: web_security_scanner.py [-h] [-u URL] [-f FILE] [-o OUTPUT] [--timeout TIMEOUT]

Options:
  -u, --url URL         Target URL to scan
  -f, --file FILE       File with URLs (one per line)
  -o, --output OUTPUT   JSON report output file/directory
  --timeout TIMEOUT     Request timeout (default: 10s)
```

## Understanding Output

### Severity Levels

The scanner categorizes issues by severity:

- **[CRITICAL]** - Immediate action required (exposed secrets, critical misconfig)
- **[HIGH]** - Should be fixed soon (missing headers, exposed admin panels)
- **[MEDIUM]** - Important but lower risk (info disclosure, cache issues)
- **[LOW]** - Minor issues (verbose errors, missing best practices)
- **[✓]** - Test passed, security control present
- **[i]** - Informational message

### Example Output

```
======================================================================
Low-Hanging Fruit Web Security Scanner
Focusing on Easy-to-Exploit Vulnerabilities
======================================================================

[*] Common Misconfigurations & Exposed Resources
----------------------------------------------------------------------
[CRITICAL] Git repository exposed - source code leakage: /.git/HEAD
[CRITICAL] Environment config exposed - may contain secrets: /.env
[HIGH] Admin panel accessible: /admin
[HIGH] PHPInfo page exposed: /phpinfo.php

[*] Security Headers Analysis (HIGH PRIORITY)
----------------------------------------------------------------------
[HIGH] HSTS not set - vulnerable to SSL stripping attacks
  [i]  Fix: Add: Strict-Transport-Security: max-age=31536000; includeSubDomains
[HIGH] X-Frame-Options not set - vulnerable to clickjacking
  [i]  Fix: Add: X-Frame-Options: DENY or SAMEORIGIN
[MEDIUM] Server version disclosed: nginx/1.18.0

[*] Vulnerability Summary
----------------------------------------------------------------------
Total Issues Found: 6
  Critical: 2
  High: 3
  Medium: 1
  Low: 0

⚠ CRITICAL issues found! Immediate action required.
```

## Quick Fixes for Common Issues

### 1. Add Security Headers

**Nginx:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
```

**Apache:**
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "default-src 'self'"
```

**Node.js/Express:**
```javascript
const helmet = require('helmet');
app.use(helmet());
```

### 2. Hide Version Information

**Nginx:**
```nginx
server_tokens off;
```

**Apache:**
```apache
ServerTokens Prod
ServerSignature Off
```

**PHP:**
```php
expose_php = Off
```

### 3. Block Sensitive Files

**Nginx:**
```nginx
location ~ /\.(git|env|svn) {
    deny all;
    return 404;
}

location ~ \.(sql|zip|tar\.gz|bak)$ {
    deny all;
    return 404;
}
```

**Apache:**
```apache
<DirectoryMatch "^/.*/\.(git|svn|env)">
    Require all denied
</DirectoryMatch>

<FilesMatch "\.(sql|zip|tar\.gz|bak)$">
    Require all denied
</FilesMatch>
```

### 4. Disable Dangerous HTTP Methods

**Nginx:**
```nginx
if ($request_method !~ ^(GET|POST|HEAD)$ ) {
    return 405;
}
```

**Apache:**
```apache
<Limit TRACE>
    Require all denied
</Limit>
```

### 5. Fix CORS Issues

```javascript
// DO NOT use wildcard with credentials
// Bad:
res.header('Access-Control-Allow-Origin', '*');
res.header('Access-Control-Allow-Credentials', 'true');

// Good:
const allowedOrigins = ['https://trusted-site.com'];
const origin = req.headers.origin;
if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
}
```

## Real-World Impact

### Case Study: Missing Security Headers
- **Issue**: No HSTS header
- **Risk**: SSL stripping attacks on public WiFi
- **Fix Time**: 2 minutes
- **Impact**: Protects all users from MITM attacks

### Case Study: Exposed .git Directory
- **Issue**: `.git/` directory accessible
- **Risk**: Complete source code + credentials exposure
- **Fix Time**: 1 minute (add deny rule)
- **Impact**: Prevents complete application compromise

### Case Study: Information Disclosure
- **Issue**: Server header shows "Apache/2.4.29 (Ubuntu)"
- **Risk**: Attackers know exact version for exploit search
- **Fix Time**: 30 seconds
- **Impact**: Reduces attack surface

## What This Scanner Does NOT Cover

This scanner focuses on **non-invasive, quick checks**. It does NOT:

- Perform deep application testing (use Burp Suite, OWASP ZAP)
- Test authentication mechanisms (use specialized tools)
- Perform SQL injection testing (use SQLMap)
- Scan for all XSS variants (requires manual testing)
- Test business logic flaws (requires human analysis)
- Perform brute force attacks
- Exploit vulnerabilities (only detects them)

## Best Practices

### Before Scanning

1. **Get Permission** - Only scan systems you own or have written authorization to test
2. **Review Scope** - Ensure target is appropriate for testing
3. **Check Timing** - Consider running during off-peak hours

### After Scanning

1. **Prioritize** - Fix CRITICAL and HIGH issues first
2. **Validate** - Verify fixes don't break functionality
3. **Retest** - Run scanner again to confirm fixes
4. **Document** - Keep records of findings and remediation

### Responsible Disclosure

If you find vulnerabilities in third-party systems:
1. Report to security contact or website owner
2. Provide detailed information
3. Allow reasonable time for fix (90 days typical)
4. Do not publicly disclose until patched

## Integration with CI/CD

### Run in GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Security Scanner
        run: |
          pip install -r requirements.txt
          python web_security_scanner.py -u https://staging.example.com -o report.json
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: report.json
```

### Fail Build on Critical Issues

```bash
#!/bin/bash
python web_security_scanner.py -u https://staging.example.com -o report.json

# Check for critical issues
CRITICAL=$(jq '.vulnerability_count.critical' report.json)
if [ "$CRITICAL" -gt 0 ]; then
    echo "CRITICAL issues found! Failing build."
    exit 1
fi
```

## Comparison with Other Tools

| Feature | This Scanner | OWASP ZAP | Burp Suite | Nikto |
|---------|-------------|-----------|------------|-------|
| Low-hanging fruit focus | ✓ | ✗ | ✗ | ✓ |
| Fast scan (< 1 min) | ✓ | ✗ | ✗ | ✗ |
| Easy setup | ✓ | ✗ | ✗ | ✓ |
| Header injection tests | ✓ | ✓ | ✓ | ✗ |
| Exposed files | ✓ | ✓ | ✓ | ✓ |
| Deep crawling | ✗ | ✓ | ✓ | ✓ |
| Active exploitation | ✗ | ✓ | ✓ | ✗ |
| Manual testing support | ✗ | ✓ | ✓ | ✗ |

**Use this scanner for**: Quick wins, CI/CD integration, initial assessment
**Use professional tools for**: Comprehensive pentesting, compliance audits

## Troubleshooting

### Connection Timeouts

```bash
python web_security_scanner.py -u https://example.com --timeout 30
```

### SSL Errors

The scanner intentionally disables SSL verification for testing purposes. This allows testing of sites with self-signed certificates.

### False Positives

Some findings may be false positives:
- Admin panels may be IP-restricted (still good to verify)
- Some headers may be set by CDN/proxy
- robots.txt is not a vulnerability (but check contents)

Always verify findings manually.

## Contributing

Contributions welcome! Focus areas:
- Additional low-hanging fruit checks
- Better detection accuracy
- Performance improvements
- Documentation improvements

## License

Educational and authorized security testing only.

## Disclaimer

**CRITICAL**: Only use on systems you own or have explicit written permission to test. Unauthorized security testing is illegal. The authors accept no liability for misuse.

## Author

@aderm97

## Version

2.0.0 - Low-Hanging Fruit Edition

## Changelog

### Version 2.0.0 (2025-11-11) - Low-Hanging Fruit Focus
- Complete rewrite focusing on easily exploitable vulnerabilities
- Added comprehensive header injection testing
- Enhanced exposed file/directory detection (40+ paths)
- Added severity-based vulnerability counting
- Improved information disclosure detection
- Added open redirect testing
- Added clickjacking-specific testing
- Enhanced CORS misconfiguration detection
- Added vulnerability summary with severity breakdown
- Improved output formatting with actionable recommendations
- Added quick fix examples for common issues

### Version 1.0.0 (2025-11-11)
- Initial release
- Basic security testing functionality

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SecurityHeaders.com](https://securityheaders.com/) - Test your headers
- [Mozilla Observatory](https://observatory.mozilla.org/) - Security assessment
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

**Remember**: Security is a process, not a product. This scanner helps you find quick wins, but comprehensive security requires ongoing effort, testing, and vigilance.
