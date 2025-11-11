# Web Application Security Scanner

An automated security testing tool for external-facing web applications. This script performs comprehensive security assessments covering common vulnerabilities and security misconfigurations.

## Features

### Security Tests Performed

1. **SSL/TLS Configuration**
   - Protocol version verification
   - Cipher suite analysis
   - Certificate validation
   - Detection of weak protocols (SSLv3, TLSv1.0, TLSv1.1)

2. **HTTP Security Headers**
   - Strict-Transport-Security (HSTS)
   - X-Content-Type-Options
   - X-Frame-Options
   - Content-Security-Policy
   - X-XSS-Protection
   - Referrer-Policy
   - Detection of information disclosure headers

3. **Cookie Security**
   - Secure flag validation
   - HttpOnly flag verification
   - SameSite attribute checking
   - CSRF vulnerability assessment

4. **CORS Policy Analysis**
   - Access-Control-Allow-Origin validation
   - Credential exposure checks
   - Origin reflection detection

5. **HTTP Methods Testing**
   - Dangerous method detection (PUT, DELETE, TRACE)
   - XST (Cross-Site Tracing) vulnerability check
   - OPTIONS method analysis

6. **Common Path Enumeration**
   - Sensitive file detection (.git, .env, backup files)
   - Admin panel discovery
   - Configuration file exposure
   - Directory listing vulnerabilities

7. **Input Validation Testing**
   - Basic XSS payload testing
   - Reflected input detection
   - Error-based information disclosure

8. **Information Disclosure**
   - Error message leakage
   - Stack trace exposure
   - Verbose error pages

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/aderm97/aderm97.git
cd aderm97
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make the script executable (Linux/Mac):
```bash
chmod +x web_security_scanner.py
```

## Usage

### Basic Scan

Scan a single URL:
```bash
python web_security_scanner.py -u https://example.com
```

### Generate JSON Report

Save scan results to a JSON file:
```bash
python web_security_scanner.py -u https://example.com -o report.json
```

### Scan Multiple Targets

Create a file with target URLs (one per line):
```bash
python web_security_scanner.py -f targets.txt -o reports/
```

### Command Line Options

```
usage: web_security_scanner.py [-h] [-u URL] [-f FILE] [-o OUTPUT] [--timeout TIMEOUT]

Web Application Security Scanner

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL to scan
  -f FILE, --file FILE  File containing list of URLs to scan
  -o OUTPUT, --output OUTPUT
                        Output file/directory for JSON report
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
```

### Examples

#### Single Target with Report
```bash
python web_security_scanner.py -u https://example.com -o example_report.json
```

#### Multiple Targets from File
```bash
# Create targets.txt with your URLs
echo "https://example.com" > targets.txt
echo "https://test.example.com" >> targets.txt

# Scan all targets
python web_security_scanner.py -f targets.txt -o reports/
```

#### Custom Timeout
```bash
python web_security_scanner.py -u https://example.com --timeout 30
```

## Configuration

You can customize the scanner behavior by creating a `config.json` file based on `config.example.json`:

```json
{
  "targets": [
    "https://example.com"
  ],
  "scan_options": {
    "timeout": 10,
    "verify_ssl": false,
    "follow_redirects": true,
    "max_retries": 3
  },
  "tests": {
    "ssl_tls": true,
    "security_headers": true,
    "cookie_security": true,
    "cors_policy": true,
    "http_methods": true,
    "common_paths": true,
    "input_validation": true,
    "information_disclosure": true
  }
}
```

## Output

### Console Output

The scanner provides color-coded console output:
- **GREEN (✓)**: Test passed - security control is properly configured
- **RED (✗)**: Test failed - security vulnerability detected
- **YELLOW (!)**: Warning - potential security issue
- **BLUE (i)**: Informational message

### JSON Report

The `-o` option generates a detailed JSON report containing:
- Target URL and timestamp
- Complete test results for all security checks
- Detected vulnerabilities and misconfigurations
- SSL/TLS certificate information
- HTTP headers and cookie attributes

Example report structure:
```json
{
  "target": "https://example.com",
  "timestamp": "2025-11-11T10:30:00",
  "tests": {
    "ssl_tls": {
      "protocol": "TLSv1.3",
      "cipher": ["TLS_AES_256_GCM_SHA384", 256],
      "weak_protocol": false
    },
    "security_headers": {
      "Strict-Transport-Security": {
        "present": true,
        "value": "max-age=31536000"
      }
    }
  }
}
```

## Security Testing Best Practices

### Authorization

- **Only test applications you own or have explicit permission to test**
- Unauthorized security testing may be illegal
- Obtain written permission before scanning third-party websites

### Responsible Disclosure

If you discover vulnerabilities:
1. Report them to the website owner/security team
2. Provide detailed information about the vulnerability
3. Allow reasonable time for remediation
4. Follow responsible disclosure practices

### Rate Limiting

- Be mindful of request rates to avoid impacting target servers
- Use the `--timeout` option to control request timing
- Consider running scans during off-peak hours

## Limitations

This tool provides automated basic security testing but should not replace:
- Manual security assessments
- Professional penetration testing
- Comprehensive security audits
- Specialized tools (SQLMap, Burp Suite, OWASP ZAP)

The scanner performs non-invasive checks and does not:
- Exploit vulnerabilities
- Modify application data
- Perform brute-force attacks
- Execute advanced attack vectors

## Common Vulnerabilities Detected

### OWASP Top 10 Coverage

- **A01:2021 - Broken Access Control**: Path enumeration, admin panel detection
- **A02:2021 - Cryptographic Failures**: SSL/TLS configuration, cookie security
- **A03:2021 - Injection**: Basic XSS testing, input validation
- **A05:2021 - Security Misconfiguration**: Security headers, HTTP methods, error disclosure
- **A07:2021 - Identification and Authentication Failures**: Cookie security attributes
- **A08:2021 - Software and Data Integrity Failures**: CORS policy testing

## Troubleshooting

### SSL Certificate Errors

If you encounter SSL certificate verification errors:
```bash
# The script already disables SSL verification for testing
# This is intentional for security assessment purposes
```

### Connection Timeouts

Increase the timeout value:
```bash
python web_security_scanner.py -u https://example.com --timeout 30
```

### Permission Denied

Make the script executable:
```bash
chmod +x web_security_scanner.py
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This tool is provided for educational and authorized security testing purposes only.

## Disclaimer

**IMPORTANT**: This tool is designed for legal security testing of applications you own or have explicit permission to test. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this tool.

## Author

@aderm97

## Version

1.0.0

## Changelog

### Version 1.0.0 (2025-11-11)
- Initial release
- SSL/TLS testing
- Security headers validation
- Cookie security checks
- CORS policy analysis
- HTTP methods testing
- Common path enumeration
- Input validation testing
- Information disclosure detection
- JSON report generation
- Multi-target support
