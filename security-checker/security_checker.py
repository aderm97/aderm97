#!/usr/bin/env python3
"""
FMDQ Network Infrastructure Security Configuration Checker
==========================================================
Comprehensive vulnerability assessment and configuration checker
for network infrastructure based on VAPT checklist.

Usage:
    python3 security_checker.py --config config/targets.yaml --output reports/
    python3 security_checker.py --module perimeter --target 217.117.13.209
    python3 security_checker.py --full-scan --verbose

Author: Security Assessment Team
Version: 1.0.0
"""

import argparse
import sys
import json
import yaml
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Import security modules
from modules import (
    connectivity,
    perimeter_security,
    firewall_security,
    network_segmentation,
    vpn_security,
    access_control,
    waf_security,
    azure_security,
    internal_pentest,
    monitoring,
    compliance
)

# Import utilities
from utils.report_generator import ReportGenerator
from utils.logger import setup_logger
from utils.tool_installer import ToolInstaller


class SecurityChecker:
    """Main security checker orchestrator"""

    def __init__(self, config_file: str = None, verbose: bool = False):
        """Initialize security checker"""
        self.config = self._load_config(config_file) if config_file else {}
        self.logger = setup_logger(verbose)
        self.findings = []
        self.start_time = datetime.now()

        self.modules = {
            'connectivity': connectivity,
            'perimeter': perimeter_security,
            'firewall': firewall_security,
            'segmentation': network_segmentation,
            'vpn': vpn_security,
            'access_control': access_control,
            'waf': waf_security,
            'azure': azure_security,
            'pentest': internal_pentest,
            'monitoring': monitoring,
            'compliance': compliance
        }

    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)

    def run_full_scan(self) -> Dict[str, Any]:
        """Run comprehensive security scan across all modules"""
        self.logger.info("=" * 80)
        self.logger.info("FMDQ NETWORK INFRASTRUCTURE SECURITY ASSESSMENT")
        self.logger.info("=" * 80)
        self.logger.info(f"Start time: {self.start_time}")
        self.logger.info("")

        results = {
            'scan_info': {
                'start_time': self.start_time.isoformat(),
                'config': self.config.get('scope', {})
            },
            'findings': {}
        }

        # 0. Connectivity & Tool Check (FIRST - verify targets are reachable)
        self.logger.info("[1/11] Checking Connectivity & Security Tools...")
        results['findings']['connectivity'] = self._run_module('connectivity')

        # 1. Perimeter Security Assessment
        self.logger.info("[2/11] Running Perimeter Security Assessment...")
        results['findings']['perimeter'] = self._run_module('perimeter')

        # 2. Firewall Security Testing
        self.logger.info("[3/11] Running Firewall Security Testing...")
        results['findings']['firewall'] = self._run_module('firewall')

        # 3. Network Segmentation & Internal Security
        self.logger.info("[4/11] Running Network Segmentation Checks...")
        results['findings']['segmentation'] = self._run_module('segmentation')

        # 4. VPN Security Assessment
        self.logger.info("[5/11] Running VPN Security Assessment...")
        results['findings']['vpn'] = self._run_module('vpn')

        # 5. Access Control & Wireless Security
        self.logger.info("[6/11] Running Access Control Assessment...")
        results['findings']['access_control'] = self._run_module('access_control')

        # 6. WAF Testing
        self.logger.info("[7/11] Running WAF Security Testing...")
        results['findings']['waf'] = self._run_module('waf')

        # 7. Azure Cloud Security
        self.logger.info("[8/11] Running Azure Cloud Security Assessment...")
        results['findings']['azure'] = self._run_module('azure')

        # 8. Internal Penetration Testing
        self.logger.info("[9/11] Running Internal Penetration Tests...")
        results['findings']['pentest'] = self._run_module('pentest')

        # 9. Monitoring & Incident Response
        self.logger.info("[10/11] Running Monitoring Assessment...")
        results['findings']['monitoring'] = self._run_module('monitoring')

        # 10. Compliance & Regulatory
        self.logger.info("[11/11] Running Compliance Checks...")
        results['findings']['compliance'] = self._run_module('compliance')

        # Calculate statistics
        results['summary'] = self._generate_summary(results['findings'])
        results['scan_info']['end_time'] = datetime.now().isoformat()
        results['scan_info']['duration'] = str(datetime.now() - self.start_time)

        return results

    def run_module(self, module_name: str, target: str = None) -> Dict[str, Any]:
        """Run a specific security module"""
        if module_name not in self.modules:
            self.logger.error(f"Unknown module: {module_name}")
            return {}

        self.logger.info(f"Running {module_name} module...")
        return self._run_module(module_name, target)

    def _run_module(self, module_name: str, target: str = None) -> Dict[str, Any]:
        """Execute a security module and collect findings"""
        try:
            module = self.modules[module_name]
            config = self.config.get(module_name, {})

            if target:
                config['target'] = target

            # Each module has a run() function that returns findings
            findings = module.run(config, self.logger)
            return findings
        except Exception as e:
            self.logger.error(f"Error in {module_name} module: {e}")
            return {'error': str(e)}

    def _generate_summary(self, findings: Dict) -> Dict[str, Any]:
        """Generate summary statistics from findings"""
        summary = {
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'info': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_module': {}
        }

        for module_name, module_findings in findings.items():
            if 'error' in module_findings:
                continue

            module_summary = {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }

            checks = module_findings.get('checks', [])
            for check in checks:
                summary['total_checks'] += 1
                module_summary['total'] += 1

                status = check.get('status', 'unknown')
                severity = check.get('severity', 'info')

                if status == 'passed':
                    summary['passed'] += 1
                    module_summary['passed'] += 1
                elif status == 'failed':
                    summary['failed'] += 1
                    module_summary['failed'] += 1
                elif status == 'warning':
                    summary['warnings'] += 1

                # Count by severity
                if severity in summary:
                    summary[severity] += 1
                if severity in module_summary:
                    module_summary[severity] += 1

            summary['by_module'][module_name] = module_summary

        return summary


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='FMDQ Network Infrastructure Security Configuration Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Full scan with config file:
    %(prog)s --config config/targets.yaml --output reports/

  Single module scan:
    %(prog)s --module perimeter --target 217.117.13.209

  Quick network scan:
    %(prog)s --quick-scan --network 10.10.10.0/24

  Azure security check:
    %(prog)s --module azure --subscription <subscription-id>
        """
    )

    parser.add_argument('-c', '--config', help='Configuration file (YAML)')
    parser.add_argument('-m', '--module', choices=[
        'connectivity', 'perimeter', 'firewall', 'segmentation', 'vpn',
        'access_control', 'waf', 'azure', 'pentest',
        'monitoring', 'compliance'
    ], help='Run specific module')
    parser.add_argument('-t', '--target', help='Target IP/hostname for module')
    parser.add_argument('-o', '--output', default='reports/', help='Output directory for reports')
    parser.add_argument('-f', '--format', choices=['html', 'json', 'pdf', 'csv'],
                       default='html', help='Report format')
    parser.add_argument('--full-scan', action='store_true', help='Run full comprehensive scan')
    parser.add_argument('--quick-scan', action='store_true', help='Run quick basic scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--network', help='Target network CIDR for quick scan')
    parser.add_argument('--skip-install', action='store_true',
                       help='Skip automatic tool installation wizard')
    parser.add_argument('--install-only', action='store_true',
                       help='Only run tool installation wizard, then exit')

    args = parser.parse_args()

    # Setup basic logger for installer
    import logging
    basic_logger = logging.getLogger('installer')
    basic_logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(message)s'))
    basic_logger.addHandler(handler)

    # Run tool installation wizard (unless skipped)
    if not args.skip_install:
        installer = ToolInstaller(basic_logger)
        installer.run_installation_wizard()

        # If --install-only, exit after installation
        if args.install_only:
            sys.exit(0)

        # Add spacing before scan starts
        print("\n")

    # Initialize checker
    checker = SecurityChecker(args.config, args.verbose)

    # Run appropriate scan
    if args.full_scan or (args.config and not args.module):
        results = checker.run_full_scan()
    elif args.module:
        module_results = checker.run_module(args.module, args.target)
        results = {
            'scan_info': {
                'module': args.module,
                'target': args.target,
                'timestamp': datetime.now().isoformat()
            },
            'findings': {args.module: module_results}
        }
    elif args.quick_scan and args.network:
        # Quick network scan
        checker.logger.info(f"Running quick scan on {args.network}")
        results = checker.run_module('perimeter', args.network)
    else:
        parser.print_help()
        sys.exit(1)

    # Generate report
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_gen = ReportGenerator()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if args.format == 'json':
        output_file = output_dir / f'security_report_{timestamp}.json'
        report_gen.generate_json(results, output_file)
    elif args.format == 'html':
        output_file = output_dir / f'security_report_{timestamp}.html'
        report_gen.generate_html(results, output_file)
    elif args.format == 'pdf':
        output_file = output_dir / f'security_report_{timestamp}.pdf'
        report_gen.generate_pdf(results, output_file)
    elif args.format == 'csv':
        output_file = output_dir / f'security_report_{timestamp}.csv'
        report_gen.generate_csv(results, output_file)

    # Print summary
    if 'summary' in results:
        summary = results['summary']
        print("\n" + "="*80)
        print("SECURITY ASSESSMENT SUMMARY")
        print("="*80)
        print(f"Total Checks:    {summary['total_checks']}")
        print(f"Passed:          {summary['passed']} ✓")
        print(f"Failed:          {summary['failed']} ✗")
        print(f"Warnings:        {summary['warnings']} ⚠")
        print("\nSeverity Breakdown:")
        print(f"  Critical:      {summary['critical']}")
        print(f"  High:          {summary['high']}")
        print(f"  Medium:        {summary['medium']}")
        print(f"  Low:           {summary['low']}")
        print("\nReport saved to:", output_file)
        print("="*80)

    # Exit with appropriate code
    if results.get('summary', {}).get('critical', 0) > 0:
        sys.exit(2)  # Critical findings
    elif results.get('summary', {}).get('failed', 0) > 0:
        sys.exit(1)  # Failed checks
    else:
        sys.exit(0)  # All good


if __name__ == '__main__':
    main()
