"""
Web Application Firewall (WAF) Security Module
Tests WAF configurations and bypass techniques
"""

import urllib.request
import urllib.error
import socket
from typing import Dict, List, Any
import time


def run(config: Dict, logger) -> Dict[str, Any]:
    """Run WAF security checks"""
    findings = {
        'module': 'WAF Security',
        'checks': []
    }

    wafs = config.get('targets', {}).get('waf', [])

    for waf in wafs:
        logger.info(f"  Testing WAF: {waf.get('name')}")

        # Basic WAF detection
        findings['checks'].extend(check_waf_detection(waf, logger))

        # OWASP Top 10 protection
        findings['checks'].extend(check_owasp_protection(waf, logger))

        # WAF bypass attempts
        findings['checks'].extend(check_waf_bypass_techniques(waf, logger))

        # Rate limiting
        findings['checks'].extend(check_rate_limiting(waf, logger))

    return findings


def check_waf_detection(waf: Dict, logger) -> List[Dict]:
    """Detect WAF presence and type"""
    checks = []
    target = waf.get('target_url')
    name = waf.get('name')

    if not target:
        checks.append({
            'check': 'WAF Detection',
            'target': name,
            'status': 'warning',
            'severity': 'low',
            'finding': 'No target URL configured for WAF testing',
            'recommendation': 'Configure target URL in config file'
        })
        return checks

    try:
        # Test with a suspicious request
        req = urllib.request.Request(
            target,
            headers={
                'User-Agent': 'Mozilla/5.0',
                'X-Scanner': 'Security-Test'
            }
        )
        response = urllib.request.urlopen(req, timeout=10)

        # Check response headers for WAF signatures
        waf_headers = {
            'X-WAF': 'Generic WAF',
            'X-Sucuri-ID': 'Sucuri',
            'X-Cloud-Trace-Context': 'Google Cloud Armor',
            'X-CDN': 'CDN with WAF',
            'Server': None  # Will check value
        }

        detected_waf = None
        for header, waf_name in waf_headers.items():
            if header in response.headers:
                if header == 'Server':
                    server_value = response.headers.get('Server', '').lower()
                    if any(w in server_value for w in ['cloudflare', 'cloudfront', 'akamai']):
                        detected_waf = f"CDN WAF: {response.headers['Server']}"
                else:
                    detected_waf = waf_name
                break

        if detected_waf:
            checks.append({
                'check': 'WAF Detection',
                'target': target,
                'status': 'info',
                'severity': 'info',
                'finding': f'WAF detected: {detected_waf}',
                'recommendation': 'Verify WAF is properly configured'
            })
        else:
            checks.append({
                'check': 'WAF Detection',
                'target': target,
                'status': 'warning',
                'severity': 'medium',
                'finding': 'No WAF headers detected - WAF may not be present or is in stealth mode',
                'recommendation': 'Verify WAF is deployed and active'
            })

    except Exception as e:
        checks.append({
            'check': 'WAF Detection',
            'target': target,
            'status': 'warning',
            'severity': 'low',
            'finding': f'Could not test WAF: {str(e)}',
            'recommendation': 'Verify target URL is accessible'
        })

    return checks


def check_owasp_protection(waf: Dict, logger) -> List[Dict]:
    """Test WAF protection against OWASP Top 10"""
    checks = []
    target = waf.get('target_url')

    if not target:
        return checks

    # SQL Injection tests
    sql_payloads = [
        "' OR '1'='1",
        "1' UNION SELECT NULL--",
        "admin'--",
        "' OR 1=1--"
    ]

    blocked_count = 0
    for payload in sql_payloads:
        try:
            test_url = f"{target}?id={urllib.parse.quote(payload)}"
            req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=5)

            # If we get here, request wasn't blocked
            logger.debug(f"    SQL payload not blocked: {payload}")

        except urllib.error.HTTPError as e:
            if e.code in [403, 406, 419, 429, 999]:  # Common WAF block codes
                blocked_count += 1
        except:
            pass

        time.sleep(0.5)  # Rate limit our tests

    if blocked_count == 0:
        checks.append({
            'check': 'WAF SQL Injection Protection',
            'target': target,
            'status': 'failed',
            'severity': 'critical',
            'finding': 'WAF not blocking SQL injection attempts',
            'recommendation': 'Enable SQL injection protection rules immediately'
        })
    elif blocked_count == len(sql_payloads):
        checks.append({
            'check': 'WAF SQL Injection Protection',
            'target': target,
            'status': 'passed',
            'severity': 'info',
            'finding': f'WAF blocking SQL injection attempts ({blocked_count}/{len(sql_payloads)})',
            'recommendation': 'Continue monitoring and updating SQL injection signatures'
        })
    else:
        checks.append({
            'check': 'WAF SQL Injection Protection',
            'target': target,
            'status': 'warning',
            'severity': 'high',
            'finding': f'WAF blocking some but not all SQL injection attempts ({blocked_count}/{len(sql_payloads)})',
            'recommendation': 'Review and strengthen SQL injection protection rules'
        })

    # XSS tests
    xss_payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>'
    ]

    blocked_count = 0
    for payload in xss_payloads:
        try:
            test_url = f"{target}?q={urllib.parse.quote(payload)}"
            req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            if e.code in [403, 406, 419, 429, 999]:
                blocked_count += 1
        except:
            pass

        time.sleep(0.5)

    if blocked_count == 0:
        checks.append({
            'check': 'WAF XSS Protection',
            'target': target,
            'status': 'failed',
            'severity': 'critical',
            'finding': 'WAF not blocking XSS attempts',
            'recommendation': 'Enable XSS protection rules immediately'
        })
    elif blocked_count == len(xss_payloads):
        checks.append({
            'check': 'WAF XSS Protection',
            'target': target,
            'status': 'passed',
            'severity': 'info',
            'finding': f'WAF blocking XSS attempts ({blocked_count}/{len(xss_payloads)})',
            'recommendation': 'Continue monitoring and updating XSS signatures'
        })
    else:
        checks.append({
            'check': 'WAF XSS Protection',
            'target': target,
            'status': 'warning',
            'severity': 'high',
            'finding': f'WAF blocking some but not all XSS attempts ({blocked_count}/{len(xss_payloads)})',
            'recommendation': 'Review and strengthen XSS protection rules'
        })

    return checks


def check_waf_bypass_techniques(waf: Dict, logger) -> List[Dict]:
    """Test common WAF bypass techniques"""
    checks = []
    target = waf.get('target_url')

    if not target:
        return checks

    # Manual checks for advanced bypass
    checks.append({
        'check': 'WAF Bypass - Encoding Techniques',
        'target': target,
        'status': 'manual',
        'severity': 'high',
        'finding': 'Manual testing required',
        'recommendation': '''Test advanced bypass techniques:
            - URL encoding variations (double, hex, unicode)
            - Case variation bypass
            - Comment injection in payloads
            - Null byte injection
            - HPP (HTTP Parameter Pollution)
            - HTTP verb tampering'''
    })

    checks.append({
        'check': 'WAF Bypass - Fragmentation',
        'target': target,
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual testing required',
        'recommendation': '''Test fragmentation bypass:
            - Request fragmentation
            - Chunked encoding abuse
            - Multipart/form-data parsing
            - Large payload testing
            - Pipeline abuse'''
    })

    return checks


def check_rate_limiting(waf: Dict, logger) -> List[Dict]:
    """Test WAF rate limiting"""
    checks = []
    target = waf.get('target_url')
    name = waf.get('name')

    if not target:
        return checks

    # Simple rate limit test
    request_count = 50
    blocked_after = None

    for i in range(request_count):
        try:
            req = urllib.request.Request(target, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=2)
        except urllib.error.HTTPError as e:
            if e.code in [429, 503]:  # Rate limit codes
                blocked_after = i
                break
        except:
            break

        time.sleep(0.1)  # 10 requests per second

    if blocked_after:
        checks.append({
            'check': 'WAF Rate Limiting',
            'target': target,
            'status': 'passed',
            'severity': 'info',
            'finding': f'Rate limiting active - blocked after {blocked_after} requests',
            'recommendation': 'Verify rate limits are appropriate for legitimate traffic'
        })
    else:
        checks.append({
            'check': 'WAF Rate Limiting',
            'target': target,
            'status': 'warning',
            'severity': 'medium',
            'finding': 'No rate limiting detected in basic test',
            'recommendation': 'Configure rate limiting to prevent abuse and DDoS'
        })

    # Bot detection
    checks.append({
        'check': 'WAF Bot Detection',
        'target': name,
        'status': 'manual',
        'severity': 'medium',
        'finding': 'Manual verification required',
        'recommendation': '''Verify bot detection:
            - Challenge-response for suspicious traffic
            - JavaScript execution verification
            - Browser fingerprinting
            - Known bot signatures blocked
            - Good bots (search engines) allowed'''
    })

    return checks
