import subprocess
import platform

print("Testing WSL Suricata detection in Ubuntu...")
print("="*60)

# Test with Ubuntu distribution
print("\n1. Checking 'which suricata' in Ubuntu...")
try:
    result = subprocess.run(
        ['wsl', '-d', 'Ubuntu', '--', 'which', 'suricata'],
        capture_output=True,
        text=True,
        timeout=5,
        creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
    )
    print(f"   Return code: {result.returncode}")
    print(f"   Output: '{result.stdout.strip()}'")
    print(f"   Error: '{result.stderr.strip()}'")
except Exception as e:
    print(f"   ERROR: {e}")

# Test version
print("\n2. Checking 'suricata --version' in Ubuntu...")
try:
    result = subprocess.run(
        ['wsl', '-d', 'Ubuntu', '--', 'suricata', '--version'],
        capture_output=True,
        text=True,
        timeout=10,
        creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
    )
    print(f"   Return code: {result.returncode}")
    print(f"   Output: '{result.stdout[:200]}'")
except Exception as e:
    print(f"   ERROR: {e}")

print("\n" + "="*60)
