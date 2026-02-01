"""
Suricata Runner Module
Manages Suricata IDS execution and configuration.
"""

import logging
import subprocess
from pathlib import Path
from typing import Optional, Dict
import platform

logger = logging.getLogger(__name__)


class SuricataRunner:
    """Manages Suricata IDS execution."""
    
    def __init__(self, suricata_binary: Optional[str] = None):
        """
        Initialize Suricata runner.
        
        Args:
            suricata_binary: Path to Suricata executable (auto-detect if None)
        """
        # Import config to check WSL setting
        from utils.config import USE_WSL_SURICATA, WSL_SURICATA_BINARY
        
        # If WSL mode is enabled, use WSL path directly
        if USE_WSL_SURICATA:
            self.suricata_binary = self._get_wsl_suricata_direct()
        else:
            self.suricata_binary = self._find_suricata(suricata_binary)
        
        self.process = None
        
        if self.suricata_binary:
            logger.info(f"Suricata binary found: {self.suricata_binary}")
        else:
            logger.warning("Suricata binary not found - signature detection disabled")

    def _get_wsl_suricata_direct(self) -> Optional[str]:
        """Get WSL Suricata path directly."""
        from utils.config import WSL_SURICATA_BINARY, WSL_DISTRIBUTION
        
        try:
            # Test if the specified WSL distribution exists
            result = subprocess.run(
                ['wsl', '-d', WSL_DISTRIBUTION, '--', 'echo', 'test'],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            )
            
            if result.returncode != 0:
                logger.warning(f"WSL distribution '{WSL_DISTRIBUTION}' is not available")
                return None
            
            # Check if Suricata exists using 'which'
            result = subprocess.run(
                ['wsl', '-d', WSL_DISTRIBUTION, '--', 'which', 'suricata'],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            )
            
            if result.returncode == 0 and result.stdout.strip():
                actual_path = result.stdout.strip()
                logger.info(f"Found Suricata in WSL {WSL_DISTRIBUTION}: {actual_path}")
                return f"wsl:{WSL_DISTRIBUTION}:{actual_path}"
            else:
                logger.warning(f"Suricata not found in WSL {WSL_DISTRIBUTION}")
                logger.debug(f"which stderr: {result.stderr}")
                return None
                
        except Exception as e:
            logger.warning(f"Failed to check WSL Suricata: {e}")
            return None
        
    def _find_suricata(self, custom_path: Optional[str]) -> Optional[str]:
        """Find Suricata binary."""
        # If custom path provided, check it first
        if custom_path:
            if Path(custom_path).exists():
                return custom_path
            else:
                logger.warning(f"Custom Suricata path not found: {custom_path}")
        
        # Check config SURICATA_BINARY
        from utils.config import SURICATA_BINARY
        if SURICATA_BINARY and Path(SURICATA_BINARY).exists():
            return SURICATA_BINARY
        
        # Check common Windows paths
        common_paths = [
            r"C:\Program Files\Suricata\suricata.exe",
            r"C:\Program Files (x86)\Suricata\suricata.exe",
            r"C:\Suricata\suricata.exe"
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        # Check WSL as fallback
        wsl_path = self._get_wsl_suricata()
        if wsl_path:
            return wsl_path
        
        # Check PATH
        try:
            result = subprocess.run(
                ['where', 'suricata'],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except Exception:
            pass
        
        return None

    
    def _check_wsl(self) -> bool:
        """Check if WSL is available."""
        try:
            result = subprocess.run(['wsl', '--status'], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_wsl_suricata(self) -> Optional[str]:
        """Check for Suricata in WSL."""
        try:
            result = subprocess.run(
                ['wsl', 'which', 'suricata'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                wsl_path = result.stdout.strip()
                logger.info(f"Found Suricata in WSL: {wsl_path}")
                return f"wsl:{wsl_path}"
        except Exception:
            pass
        return None
    
    def is_installed(self) -> bool:
        """Check if Suricata is installed."""
        return self.suricata_binary is not None
    
    def get_version(self) -> str:
        """Get Suricata version."""
        if not self.suricata_binary:
            return "Not installed"
        
        try:
            if self.suricata_binary.startswith('wsl:'):
                # Parse format: wsl:Ubuntu:/usr/bin/suricata
                parts = self.suricata_binary.split(':', 2)
                if len(parts) == 3:
                    distro = parts[1]
                    binary_path = parts[2]
                    cmd = ['wsl', '-d', distro, '--', binary_path, '--version']
                else:
                    # Old format: wsl:/usr/bin/suricata
                    binary_path = self.suricata_binary[4:]
                    cmd = ['wsl', '--', binary_path, '--version']
            else:
                cmd = [self.suricata_binary, '--version']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                if 'Suricata' in output:
                    version_line = output.split('\n')[0]
                    return version_line
            
            return "Unknown version"
            
        except Exception as e:
            logger.error(f"Failed to get Suricata version: {e}")
            return "Version check failed"

    
    def run_on_pcap(self, pcap_path: str, output_dir: str, config_path: Optional[str] = None) -> bool:
        """
        Run Suricata on PCAP file.
        
        Args:
            pcap_path: Path to PCAP file
            output_dir: Output directory for eve.json
            config_path: Path to suricata.yaml (optional)
            
        Returns:
            True if successful
        """
        if not self.is_installed():
            logger.error("Suricata not installed")
            return False
        
        try:
            if self.suricata_binary.startswith('wsl:'):
                # Parse WSL path
                parts = self.suricata_binary.split(':', 2)
                if len(parts) == 3:
                    distro = parts[1]
                    binary_path = parts[2]
                    
                    # Convert Windows paths to WSL paths
                    wsl_pcap = self._windows_to_wsl_path(pcap_path)
                    wsl_output = self._windows_to_wsl_path(output_dir)
                    
                    cmd = ['wsl', '-d', distro, '--', binary_path, '-r', wsl_pcap, '-l', wsl_output]
                    
                    if config_path:
                        wsl_config = self._windows_to_wsl_path(config_path)
                        cmd.extend(['-c', wsl_config])
                else:
                    # Old format
                    binary_path = self.suricata_binary[4:]
                    wsl_pcap = self._windows_to_wsl_path(pcap_path)
                    wsl_output = self._windows_to_wsl_path(output_dir)
                    cmd = ['wsl', '--', binary_path, '-r', wsl_pcap, '-l', wsl_output]
            else:
                cmd = [self.suricata_binary, '-r', pcap_path, '-l', output_dir]
                if config_path:
                    cmd.extend(['-c', config_path])
            
            logger.info(f"Running Suricata: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            )
            
            if result.returncode == 0:
                logger.info("Suricata completed successfully")
                return True
            else:
                logger.error(f"Suricata failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Suricata execution timed out")
            return False
        except Exception as e:
            logger.error(f"Suricata execution failed: {e}")
            return False


    def _windows_to_wsl_path(self, windows_path: str) -> str:
        """
        Convert Windows path to WSL path.
        Example: C:\\Users\\name\\file.pcap -> /mnt/c/Users/name/file.pcap
        """
        import re
        
        # Convert backslashes to forward slashes
        path = windows_path.replace('\\', '/')
        
        # Convert drive letter (C: -> /mnt/c)
        match = re.match(r'^([A-Za-z]):', path)
        if match:
            drive = match.group(1).lower()
            path = f"/mnt/{drive}{path[2:]}"
        
        return path
    
    def start_live_capture(self, interface: str, output_dir: str, config_path: Optional[str] = None):
        """
        Start Suricata in live capture mode.
        
        Args:
            interface: Network interface
            output_dir: Output directory for eve.json
            config_path: Path to suricata.yaml (optional)
        """
        if not self.is_installed():
            logger.error("Suricata not installed")
            return False
        
        try:
            if self.suricata_binary.startswith('wsl:'):
                parts = self.suricata_binary.split(':', 2)
                if len(parts) == 3:
                    distro = parts[1]
                    binary_path = parts[2]
                    wsl_output = self._windows_to_wsl_path(output_dir)
                    cmd = ['wsl', '-d', distro, '--', binary_path, '-i', interface, '-l', wsl_output]
                    
                    if config_path:
                        wsl_config = self._windows_to_wsl_path(config_path)
                        cmd.extend(['-c', wsl_config])
                else:
                    binary_path = self.suricata_binary[4:]
                    wsl_output = self._windows_to_wsl_path(output_dir)
                    cmd = ['wsl', '--', binary_path, '-i', interface, '-l', wsl_output]
            else:
                cmd = [self.suricata_binary, '-i', interface, '-l', output_dir]
                if config_path:
                    cmd.extend(['-c', config_path])
            
            logger.info(f"Starting Suricata live capture: {' '.join(cmd)}")
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            )
            
            logger.info(f"Suricata started with PID: {self.process.pid}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Suricata: {e}")
            return False

    
    def stop(self):
        """Stop Suricata process."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
                logger.info("Suricata stopped")
            except Exception as e:
                logger.error(f"Failed to stop Suricata: {e}")
                self.process.kill()


# Installation instructions
INSTALLATION_INSTRUCTIONS = """
=== Suricata Installation Instructions ===

OPTION 1: Windows Native Installation
--------------------------------------
1. Download Suricata MSI installer from https://suricata.io/download/
2. Run installer as Administrator
3. Default installation path: C:\\Program Files\\Suricata
4. Install Npcap from https://npcap.com/ (if not already installed)
5. Verify installation:
   suricata --version

OPTION 2: WSL (Windows Subsystem for Linux)
-------------------------------------------
1. Install WSL:
   wsl --install -d Ubuntu

2. Open WSL terminal and install Suricata:
   sudo apt update
   sudo add-apt-repository ppa:oisf/suricata-stable
   sudo apt install suricata -y

3. Update rules:
   sudo suricata-update

4. Verify installation:
   suricata --version

Configuration:
--------------
Edit utils/config.py to set:
- SURICATA_BINARY path
- SURICATA_EVE_JSON path
- USE_WSL_SURICATA = True (if using WSL)

For more details, see setup_instructions.md
"""

if __name__ == '__main__':
    print(INSTALLATION_INSTRUCTIONS)
