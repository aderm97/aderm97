"""
Security Tools Auto-Installer
Automatically detects and installs missing security tools
"""

import subprocess
import platform
import os
import sys
from typing import Dict, List, Tuple


class ToolInstaller:
    """Automatic security tools installer"""

    def __init__(self, logger):
        self.logger = logger
        self.os_type = platform.system().lower()
        self.distro = self._detect_linux_distro()

        # Define all security tools
        self.tools = {
            'essential': {
                'nmap': 'Network scanner and security auditing tool',
                'netcat': 'Network utility for reading/writing network connections',
            },
            'port_scanning': {
                'masscan': 'Ultra-fast port scanner',
                'unicornscan': 'Advanced port scanner',
            },
            'ssl_tls': {
                'sslscan': 'SSL/TLS scanner',
                'sslyze': 'SSL configuration analyzer',
            },
            'web_testing': {
                'nikto': 'Web server vulnerability scanner',
                'wafw00f': 'Web Application Firewall detector',
                'sqlmap': 'SQL injection testing tool',
                'gobuster': 'Directory/file bruteforcer',
                'ffuf': 'Fast web fuzzer',
            },
            'network_tools': {
                'hping3': 'Advanced packet crafting tool',
                'tcpdump': 'Network packet analyzer',
                'wireshark': 'Network protocol analyzer (CLI)',
            },
            'password_tools': {
                'hydra': 'Network login cracker',
                'medusa': 'Parallel password cracker',
            },
            'enumeration': {
                'enum4linux': 'Windows/Samba enumeration tool',
                'nbtscan': 'NetBIOS scanner',
            },
            'cloud_tools': {
                'azure-cli': 'Azure command-line interface',
            },
            'vulnerability_scanning': {
                'nuclei': 'Fast vulnerability scanner',
            }
        }

        # Special tools that need manual installation
        self.manual_tools = {
            'testssl.sh': {
                'url': 'https://github.com/drwetter/testssl.sh.git',
                'install_path': '/opt/testssl.sh',
                'description': 'Comprehensive SSL/TLS testing tool'
            },
            'crackmapexec': {
                'url': 'https://github.com/Porchetta-Industries/CrackMapExec',
                'install_path': '/opt/crackmapexec',
                'description': 'Post-exploitation tool'
            }
        }

    def _detect_linux_distro(self) -> str:
        """Detect Linux distribution"""
        if self.os_type != 'linux':
            return None

        try:
            # Try reading /etc/os-release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('ID='):
                            distro = line.split('=')[1].strip().strip('"')
                            return distro.lower()

            # Fallback to platform module
            import distro
            return distro.id().lower()
        except:
            # Try lsb_release
            try:
                result = subprocess.run(['lsb_release', '-is'], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.strip().lower()
            except:
                pass

        return 'unknown'

    def check_missing_tools(self) -> Dict[str, List[str]]:
        """Check which tools are missing"""
        missing = {}

        for category, tools in self.tools.items():
            missing_in_category = []
            for tool in tools.keys():
                if not self._is_tool_installed(tool):
                    missing_in_category.append(tool)

            if missing_in_category:
                missing[category] = missing_in_category

        return missing

    def _is_tool_installed(self, tool: str) -> bool:
        """Check if a tool is installed"""
        try:
            # Special handling for python packages
            if tool in ['sslyze', 'wafw00f']:
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'show', tool],
                    capture_output=True
                )
                return result.returncode == 0

            # Check PATH for binary tools
            result = subprocess.run(
                ['which', tool] if self.os_type != 'windows' else ['where', tool],
                capture_output=True
            )
            return result.returncode == 0
        except:
            return False

    def display_installation_summary(self, missing: Dict[str, List[str]]):
        """Display summary of missing tools"""
        if not missing:
            self.logger.info("\n✓ All security tools are already installed!")
            return

        self.logger.info("\n" + "=" * 80)
        self.logger.info("SECURITY TOOLS INSTALLATION WIZARD")
        self.logger.info("=" * 80)

        total_missing = sum(len(tools) for tools in missing.values())
        self.logger.info(f"\nFound {total_missing} missing security tools:\n")

        for category, tools in missing.items():
            category_name = category.replace('_', ' ').title()
            self.logger.info(f"  {category_name}:")
            for tool in tools:
                description = self.tools[category][tool]
                self.logger.info(f"    ✗ {tool:20s} - {description}")

        self.logger.info("\n" + "-" * 80)

    def prompt_installation(self, missing: Dict[str, List[str]]) -> bool:
        """Ask user if they want to install missing tools"""
        if not missing:
            return False

        total_missing = sum(len(tools) for tools in missing.values())

        self.logger.info(f"\nWould you like to install these {total_missing} missing tools?")
        self.logger.info("This will use sudo and may require your password.")

        while True:
            response = input("\nInstall missing tools? [Y/n]: ").strip().lower()

            if response in ['y', 'yes', '']:
                return True
            elif response in ['n', 'no']:
                self.logger.info("\nSkipping tool installation. Some checks will use basic fallbacks.")
                return False
            else:
                self.logger.info("Please answer 'y' or 'n'")

    def install_tools(self, missing: Dict[str, List[str]]) -> Tuple[List[str], List[str]]:
        """Install missing tools"""
        installed = []
        failed = []

        self.logger.info("\n" + "=" * 80)
        self.logger.info("INSTALLING SECURITY TOOLS")
        self.logger.info("=" * 80 + "\n")

        # Flatten tools list
        all_tools = []
        for tools_list in missing.values():
            all_tools.extend(tools_list)

        # Update package manager first
        self.logger.info("Updating package manager...")
        self._update_package_manager()

        # Install each tool
        for i, tool in enumerate(all_tools, 1):
            self.logger.info(f"\n[{i}/{len(all_tools)}] Installing {tool}...")

            if self._install_tool(tool):
                installed.append(tool)
                self.logger.info(f"  ✓ {tool} installed successfully")
            else:
                failed.append(tool)
                self.logger.info(f"  ✗ {tool} installation failed")

        # Install manual tools
        self.logger.info("\n" + "-" * 80)
        self.logger.info("Installing special tools that require manual setup...\n")

        for tool_name, tool_info in self.manual_tools.items():
            if not self._is_tool_installed(tool_name):
                self.logger.info(f"Installing {tool_name}...")
                if self._install_manual_tool(tool_name, tool_info):
                    installed.append(tool_name)
                    self.logger.info(f"  ✓ {tool_name} installed successfully")
                else:
                    failed.append(tool_name)
                    self.logger.info(f"  ✗ {tool_name} installation failed")

        return installed, failed

    def _update_package_manager(self):
        """Update package manager cache"""
        try:
            if self.os_type == 'linux':
                if self.distro in ['ubuntu', 'debian', 'kali']:
                    subprocess.run(['sudo', 'apt', 'update'],
                                 capture_output=True, check=False)
                elif self.distro in ['fedora', 'rhel', 'centos']:
                    subprocess.run(['sudo', 'dnf', 'check-update'],
                                 capture_output=True, check=False)
                elif self.distro in ['arch', 'manjaro']:
                    subprocess.run(['sudo', 'pacman', '-Sy'],
                                 capture_output=True, check=False)
            elif self.os_type == 'darwin':
                subprocess.run(['brew', 'update'],
                             capture_output=True, check=False)
        except:
            pass

    def _install_tool(self, tool: str) -> bool:
        """Install a single tool"""
        try:
            # Python packages
            if tool in ['sslyze', 'wafw00f']:
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', tool],
                    capture_output=True,
                    timeout=300
                )
                return result.returncode == 0

            # System packages
            if self.os_type == 'linux':
                return self._install_linux_package(tool)
            elif self.os_type == 'darwin':
                return self._install_macos_package(tool)

            return False

        except Exception as e:
            self.logger.debug(f"Installation error for {tool}: {e}")
            return False

    def _install_linux_package(self, tool: str) -> bool:
        """Install package on Linux"""
        # Map tool names to package names if different
        package_map = {
            'hping3': 'hping3',
            'wireshark': 'tshark',
            'azure-cli': 'azure-cli',
        }

        package = package_map.get(tool, tool)

        try:
            if self.distro in ['ubuntu', 'debian', 'kali']:
                cmd = ['sudo', 'apt', 'install', '-y', package]
            elif self.distro in ['fedora', 'rhel', 'centos']:
                cmd = ['sudo', 'dnf', 'install', '-y', package]
            elif self.distro in ['arch', 'manjaro']:
                cmd = ['sudo', 'pacman', '-S', '--noconfirm', package]
            else:
                # Try apt as fallback
                cmd = ['sudo', 'apt', 'install', '-y', package]

            result = subprocess.run(cmd, capture_output=True, timeout=600)
            return result.returncode == 0

        except Exception as e:
            self.logger.debug(f"Linux package installation error: {e}")
            return False

    def _install_macos_package(self, tool: str) -> bool:
        """Install package on macOS using Homebrew"""
        try:
            # Check if Homebrew is installed
            if subprocess.run(['which', 'brew'], capture_output=True).returncode != 0:
                self.logger.warning("Homebrew not installed. Please install from https://brew.sh")
                return False

            cmd = ['brew', 'install', tool]
            result = subprocess.run(cmd, capture_output=True, timeout=600)
            return result.returncode == 0

        except Exception as e:
            self.logger.debug(f"macOS package installation error: {e}")
            return False

    def _install_manual_tool(self, tool_name: str, tool_info: Dict) -> bool:
        """Install tools that need manual setup (git clones, etc.)"""
        try:
            install_path = tool_info['install_path']
            url = tool_info['url']

            # Clone repository
            if os.path.exists(install_path):
                self.logger.info(f"  {install_path} already exists, updating...")
                result = subprocess.run(
                    ['git', '-C', install_path, 'pull'],
                    capture_output=True,
                    timeout=300
                )
            else:
                result = subprocess.run(
                    ['sudo', 'git', 'clone', url, install_path],
                    capture_output=True,
                    timeout=300
                )

            if result.returncode != 0:
                return False

            # Create symlink for testssl.sh
            if tool_name == 'testssl.sh':
                symlink_path = '/usr/local/bin/testssl.sh'
                if not os.path.exists(symlink_path):
                    subprocess.run(
                        ['sudo', 'ln', '-s',
                         f'{install_path}/testssl.sh',
                         symlink_path],
                        capture_output=True
                    )

            # Set permissions
            subprocess.run(
                ['sudo', 'chmod', '-R', '755', install_path],
                capture_output=True
            )

            return True

        except Exception as e:
            self.logger.debug(f"Manual tool installation error: {e}")
            return False

    def run_installation_wizard(self) -> bool:
        """Main installation wizard workflow"""
        self.logger.info("\n🔧 Checking security tools...")

        # Check what's missing
        missing = self.check_missing_tools()

        # Display summary
        self.display_installation_summary(missing)

        # If nothing missing, we're done
        if not missing:
            return True

        # Ask user if they want to install
        if not self.prompt_installation(missing):
            return False

        # Install tools
        installed, failed = self.install_tools(missing)

        # Display results
        self.logger.info("\n" + "=" * 80)
        self.logger.info("INSTALLATION SUMMARY")
        self.logger.info("=" * 80)

        if installed:
            self.logger.info(f"\n✓ Successfully installed ({len(installed)}):")
            for tool in installed:
                self.logger.info(f"  • {tool}")

        if failed:
            self.logger.info(f"\n✗ Failed to install ({len(failed)}):")
            for tool in failed:
                self.logger.info(f"  • {tool}")
            self.logger.info("\nNote: Some tools may need manual installation.")
            self.logger.info("See requirements.txt for detailed instructions.")

        self.logger.info("\n" + "=" * 80 + "\n")

        return len(installed) > 0 or len(failed) == 0
