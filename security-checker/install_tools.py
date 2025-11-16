#!/usr/bin/env python3
"""
Security Tools Installer for FMDQ Network Security Checker
==========================================================
Standalone script to install all required security testing tools.

Run this BEFORE running the security checker for the first time.

Usage:
    python3 install_tools.py
    python3 install_tools.py --list
    python3 install_tools.py --check-only

Author: Security Assessment Team
Version: 1.0.0
"""

import sys
import argparse
import logging
from pathlib import Path

# Add parent directory to path to import utils
sys.path.insert(0, str(Path(__file__).parent))

from utils.tool_installer import ToolInstaller


def setup_logger():
    """Setup basic logger for installer"""
    logger = logging.getLogger('installer')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    return logger


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Install security testing tools for FMDQ Security Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Install all missing tools:
    %(prog)s

  Check which tools are missing (no installation):
    %(prog)s --check-only

  List all supported tools:
    %(prog)s --list

Note: This script requires sudo privileges to install system packages.
"""
    )

    parser.add_argument('--check-only', action='store_true',
                       help='Only check which tools are missing, do not install')
    parser.add_argument('--list', action='store_true',
                       help='List all supported security tools')
    parser.add_argument('--force', action='store_true',
                       help='Force installation without confirmation prompt')

    args = parser.parse_args()

    # Setup logger
    logger = setup_logger()

    # Initialize installer
    installer = ToolInstaller(logger)

    # List all tools
    if args.list:
        logger.info("\n" + "=" * 80)
        logger.info("SUPPORTED SECURITY TOOLS")
        logger.info("=" * 80 + "\n")

        for category, tools in installer.tools.items():
            category_name = category.replace('_', ' ').title()
            logger.info(f"{category_name}:")
            for tool, description in tools.items():
                status = "✓" if installer._is_tool_installed(tool) else "✗"
                logger.info(f"  {status} {tool:20s} - {description}")
            logger.info("")

        logger.info("Special Tools (Manual Installation):")
        for tool, info in installer.manual_tools.items():
            status = "✓" if installer._is_tool_installed(tool) else "✗"
            logger.info(f"  {status} {tool:20s} - {info['description']}")

        logger.info("\n" + "=" * 80 + "\n")
        return

    # Check only mode
    if args.check_only:
        logger.info("\n🔍 Checking installed security tools...\n")
        missing = installer.check_missing_tools()
        installer.display_installation_summary(missing)

        if not missing:
            logger.info("\n✅ All security tools are installed!\n")
        else:
            logger.info("\nTo install missing tools, run:")
            logger.info("  python3 install_tools.py\n")

        return

    # Normal installation mode
    logger.info("\n" + "=" * 80)
    logger.info("FMDQ SECURITY TOOLS INSTALLER")
    logger.info("=" * 80 + "\n")

    # Check what's missing
    missing = installer.check_missing_tools()

    if not missing:
        logger.info("✅ All security tools are already installed!")
        logger.info("\nYou can now run the security checker:")
        logger.info("  python3 security_checker.py --config config/targets.yaml --full-scan\n")
        return

    # Display summary
    installer.display_installation_summary(missing)

    # Get confirmation unless --force
    if not args.force:
        if not installer.prompt_installation(missing):
            logger.info("\nInstallation cancelled. You can run the security checker with")
            logger.info("limited functionality using basic Python fallbacks.\n")
            return

    # Install tools
    logger.info("\n" + "=" * 80)
    logger.info("Starting installation...")
    logger.info("=" * 80 + "\n")

    installed, failed = installer.install_tools(missing)

    # Display final summary
    logger.info("\n" + "=" * 80)
    logger.info("INSTALLATION COMPLETE")
    logger.info("=" * 80 + "\n")

    if installed:
        logger.info(f"✅ Successfully installed {len(installed)} tools:")
        for tool in installed:
            logger.info(f"   • {tool}")
        logger.info("")

    if failed:
        logger.info(f"❌ Failed to install {len(failed)} tools:")
        for tool in failed:
            logger.info(f"   • {tool}")
        logger.info("\nThese tools may need manual installation.")
        logger.info("See requirements.txt for detailed instructions.\n")

    # Next steps
    logger.info("-" * 80)
    logger.info("Next Steps:")
    logger.info("-" * 80)
    logger.info("1. Configure your targets:")
    logger.info("   nano config/targets.yaml")
    logger.info("")
    logger.info("2. Run the security checker:")
    logger.info("   python3 security_checker.py --config config/targets.yaml --full-scan")
    logger.info("")
    logger.info("3. View the report:")
    logger.info("   firefox reports/security_report_*.html")
    logger.info("\n" + "=" * 80 + "\n")


if __name__ == '__main__':
    main()
