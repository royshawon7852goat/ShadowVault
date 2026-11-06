"""
ShadowVault - Automated PyInstaller Build Script
Packages ShadowVault into a standalone Windows executable.
"""

import sys
import subprocess
from pathlib import Path
import config

def build_executable():
    root_dir = Path(__file__).resolve().parent
    main_py = root_dir / "main.py"

    print(f"[*] Building {config.APP_NAME} v{config.APP_VERSION} Executable...")
    print(f"[*] Target script: {main_py}")

    # PyInstaller packaging command
    # --collect-all customtkinter: bundles all CTk json themes, fonts, and assets
    # --collect-all argon2: bundles all argon2 C-FFI binaries
    # --noconsole / --windowed: launches without black terminal window
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name", "ShadowVault",
        "--collect-all", "customtkinter",
        "--collect-all", "argon2",
        "--collect-all", "cryptography",
        "--collect-all", "pyperclip",
        str(main_py)
    ]

    print("[*] Running PyInstaller command:")
    print(" ".join(cmd))

    result = subprocess.run(cmd, cwd=str(root_dir))

    if result.returncode == 0:
        exe_path = root_dir / "dist" / "ShadowVault.exe"
        print("\n=======================================================")
        print(f"[+] Build SUCCESSFUL!")
        print(f"[+] Executable created at: {exe_path}")
        print("=======================================================\n")
    else:
        print("\n[-] Build FAILED with exit code", result.returncode)
        sys.exit(result.returncode)

if __name__ == "__main__":
    build_executable()
