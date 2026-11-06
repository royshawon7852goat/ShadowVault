"""
ShadowVault - Configuration Module
Offline Password Manager for Windows
"""

import os
import sys
from pathlib import Path

# Application Metadata
APP_NAME = "ShadowVault"
APP_VERSION = "1.0.0"
APP_SUBTITLE = "Offline Zero-Knowledge Password Vault"

# Base Directories
BASE_DIR = Path(__file__).resolve().parent

def get_data_dir() -> Path:
    """
    Returns the appropriate user application data directory.
    On Windows: %APPDATA%/ShadowVault
    Fallback: local 'data' directory in project root.
    """
    # Environment override for custom paths or tests
    env_path = os.getenv("SHADOWVAULT_DATA_DIR")
    if env_path:
        path = Path(env_path)
    elif os.name == "nt" and "APPDATA" in os.environ:
        path = Path(os.environ["APPDATA"]) / APP_NAME
    else:
        path = BASE_DIR / "data"

    path.mkdir(parents=True, exist_ok=True)
    return path


def get_default_db_path() -> Path:
    """Returns the default SQLite database path."""
    env_db = os.getenv("SHADOWVAULT_DB_PATH")
    if env_db:
        return Path(env_db)
    return get_data_dir() / "shadowvault.db"


# Cryptographic Constants
# Argon2id Parameters (RFC 9106 recommended guidelines)
ARGON2_TIME_COST = 3          # Iterations
ARGON2_MEMORY_COST = 65536    # 64 MiB
ARGON2_PARALLELISM = 1        # Threads
ARGON2_HASH_LEN = 32          # 32 bytes = 256 bits for AES-256 key
SALT_SIZE = 32                # 32 bytes secure random salt

# AES-256-GCM Parameters
AES_KEY_SIZE = 32             # 256 bits
AES_GCM_NONCE_SIZE = 12       # 96 bits (NIST standard for GCM)
AES_GCM_TAG_SIZE = 16         # 128 bits authentication tag

# Application Security Defaults
MIN_MASTER_PASSWORD_LENGTH = 12
DEFAULT_AUTO_LOCK_SECONDS = 300       # 5 minutes
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30  # 30 seconds

# Categories
DEFAULT_CATEGORIES = [
    "Logins",
    "Financial",
    "Email",
    "Social",
    "Work",
    "Entertainment",
    "Server / Cloud",
    "Secure Notes",
    "Other"
]

# UI Theme & Styling Palette (Modern Dark Charcoal / Linear / Windows 11 Fluent)
COLORS = {
    # Backgrounds
    "bg_main": "#111215",
    "bg_sidebar": "#16181d",
    "bg_card": "#1d2027",
    "bg_card_hover": "#262933",
    "bg_input": "#181a20",
    "bg_modal": "#181a21",
    
    # Borders & Dividers
    "border": "#2c303c",
    "border_focus": "#6366f1",
    "divider": "#22252f",
    
    # Accents & Primary Brand (Indigo Modern)
    "primary": "#6366f1",
    "primary_hover": "#4f46e5",
    "primary_active": "#4338ca",
    "primary_light": "#818cf8",
    
    # Status / Indicators
    "success": "#10b981",       # Emerald
    "success_hover": "#059669",
    "warning": "#f59e0b",       # Amber
    "warning_hover": "#d97706",
    "danger": "#ef4444",        # Red
    "danger_hover": "#dc2626",
    "info": "#3b82f6",          # Sky Blue
    
    # Typography
    "text_primary": "#f9fafb",
    "text_secondary": "#9ca3af",
    "text_muted": "#6b7280",
    "text_on_primary": "#ffffff",
    
    # Badges & Tags
    "badge_bg": "#282b37",
    "star_gold": "#fbbf24"
}

# Typography Configurations
FONT_FAMILY = "Segoe UI"
FONT_MONO = "Consolas"
