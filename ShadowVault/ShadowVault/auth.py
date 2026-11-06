"""
ShadowVault - Authentication & Key Derivation
Implements Argon2id master password verification and AES key derivation.
"""

import time
import secrets
from typing import Tuple, Optional
import argon2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
import config
from encryption import wipe_buffer


class AuthenticationError(Exception):
    """Raised during authentication failures."""
    pass


def get_hasher() -> PasswordHasher:
    """Returns an Argon2id PasswordHasher configured with recommended parameters."""
    return PasswordHasher(
        time_cost=config.ARGON2_TIME_COST,
        memory_cost=config.ARGON2_MEMORY_COST,
        parallelism=config.ARGON2_PARALLELISM,
        hash_len=config.ARGON2_HASH_LEN,
        salt_len=config.SALT_SIZE,
        type=argon2.Type.ID
    )


def validate_master_password(password: str, confirm_password: Optional[str] = None) -> Tuple[bool, str]:
    """
    Validates master password against length, complexity, and confirmation requirements.
    
    Returns:
        (is_valid: bool, error_message: str)
    """
    if not password:
        return False, "Master password cannot be empty."

    if len(password) < config.MIN_MASTER_PASSWORD_LENGTH:
        return False, f"Master password must be at least {config.MIN_MASTER_PASSWORD_LENGTH} characters long."

    if confirm_password is not None and password != confirm_password:
        return False, "Passwords do not match."

    # Complexity checks
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    missing = []
    if not has_upper:
        missing.append("an uppercase letter")
    if not has_lower:
        missing.append("a lowercase letter")
    if not has_digit:
        missing.append("a number")
    if not has_symbol:
        missing.append("a special character")

    if missing:
        return False, f"Master password must include {', '.join(missing)} for optimal vault security."

    return True, ""


def derive_master_key(master_password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit (32-byte) AES master key from the master password and salt using Argon2id.

    Args:
        master_password: Plaintext master password.
        salt: Cryptographically secure random salt (32 bytes).

    Returns:
        32-byte derived encryption key.
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    password_bytes = master_password.encode("utf-8")
    
    # Derive exactly 32 bytes using Argon2id
    derived_key = argon2.low_level.hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=config.ARGON2_TIME_COST,
        memory_cost=config.ARGON2_MEMORY_COST,
        parallelism=config.ARGON2_PARALLELISM,
        hash_len=config.ARGON2_HASH_LEN,
        type=argon2.low_level.Type.ID
    )
    return derived_key


def create_vault_credentials(master_password: str) -> Tuple[bytes, str, bytes]:
    """
    Generates new vault authentication metadata for initial setup.

    Args:
        master_password: The user-chosen master password.

    Returns:
        Tuple of (salt: bytes, verifier_hash: str, master_key: bytes)
    """
    # 1. Generate 32 bytes cryptographically secure random salt
    salt = secrets.token_bytes(config.SALT_SIZE)

    # 2. Derive 256-bit AES master encryption key
    master_key = derive_master_key(master_password, salt)

    # 3. Create independent Argon2id verifier hash (stored in DB for login verification)
    hasher = get_hasher()
    verifier_hash = hasher.hash(master_password)

    return salt, verifier_hash, master_key


def verify_master_password(master_password: str, verifier_hash: str) -> bool:
    """
    Verifies if the entered master password matches the stored Argon2id verifier hash.
    """
    hasher = get_hasher()
    try:
        return hasher.verify(verifier_hash, master_password)
    except (VerifyMismatchError, VerificationError):
        return False
    except Exception:
        return False


def verify_and_unlock(
    master_password: str,
    stored_salt: bytes,
    stored_verifier: str
) -> Tuple[bool, Optional[bytes], str]:
    """
    Verifies master password and derives the master encryption key.

    Returns:
        (success: bool, master_key: bytes or None, message: str)
    """
    if not master_password:
        return False, None, "Please enter your master password."

    if not verify_master_password(master_password, stored_verifier):
        return False, None, "Incorrect master password. Access denied."

    try:
        master_key = derive_master_key(master_password, stored_salt)
        return True, master_key, "Vault unlocked successfully."
    except Exception as exc:
        return False, None, f"Key derivation failed: {str(exc)}"


class SessionManager:
    """
    Manages in-memory session security, vault lock state, and inactivity timeouts.
    Never persists master password or key to disk.
    """

    def __init__(self, auto_lock_seconds: int = config.DEFAULT_AUTO_LOCK_SECONDS):
        self._key_buffer: Optional[bytearray] = None
        self._last_activity: float = 0.0
        self.auto_lock_seconds: int = auto_lock_seconds
        self._is_unlocked: bool = False

    def login(self, key: bytes, auto_lock_seconds: Optional[int] = None) -> None:
        """Unlocks vault and holds key securely in memory."""
        self.lock()  # Clear existing buffer if any
        self._key_buffer = bytearray(key)
        self._is_unlocked = True
        self._last_activity = time.time()
        if auto_lock_seconds is not None:
            self.auto_lock_seconds = max(0, auto_lock_seconds)

    def lock(self) -> None:
        """Immediately locks the vault and wipes the encryption key from memory."""
        if self._key_buffer is not None:
            wipe_buffer(self._key_buffer)
            self._key_buffer = None
        self._is_unlocked = False
        self._last_activity = 0.0

    def is_unlocked(self) -> bool:
        """Returns True if the vault is currently unlocked and key is present."""
        return self._is_unlocked and self._key_buffer is not None

    def get_key(self) -> bytes:
        """
        Retrieves active master key.
        Raises AuthenticationError if vault is locked.
        """
        if not self.is_unlocked() or self._key_buffer is None:
            raise AuthenticationError("Vault is locked. Master key is not accessible.")
        return bytes(self._key_buffer)

    def touch_activity(self) -> None:
        """Records user activity to prevent idle lock."""
        if self.is_unlocked():
            self._last_activity = time.time()

    def check_inactivity(self) -> bool:
        """
        Checks if inactive timeout was exceeded. If exceeded, locks the vault.
        Returns True if session timed out and was locked.
        """
        if not self.is_unlocked():
            return False

        if self.auto_lock_seconds <= 0:
            # 0 means never auto-lock
            return False

        idle_seconds = time.time() - self._last_activity
        if idle_seconds >= self.auto_lock_seconds:
            self.lock()
            return True
        return False

    def get_remaining_idle_time(self) -> int:
        """Returns remaining seconds before auto-lock."""
        if not self.is_unlocked() or self.auto_lock_seconds <= 0:
            return 0
        elapsed = time.time() - self._last_activity
        remaining = int(self.auto_lock_seconds - elapsed)
        return max(0, remaining)
