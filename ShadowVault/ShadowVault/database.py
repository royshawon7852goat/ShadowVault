"""
ShadowVault - SQLite Database Layer
Handles secure local database operations, schema creation, and parameterized queries.
"""

import sqlite3
import datetime
from pathlib import Path
from contextlib import contextmanager
from typing import List, Dict, Any, Optional
import config
from encryption import decrypt_data, encrypt_data


class DatabaseError(Exception):
    """Base exception for database errors."""
    pass


class DatabaseCorruptionError(DatabaseError):
    """Raised when the database file is corrupted."""
    pass


def get_current_iso_timestamp() -> str:
    """Returns current UTC ISO timestamp string."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class DatabaseManager:
    """Manages SQLite storage and transactions for ShadowVault."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else config.get_default_db_path()
        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()

    @contextmanager
    def get_connection(self):
        """Yields a configured SQLite connection and guarantees clean closure."""
        try:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=10.0,
                check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")  # High reliability & concurrency
        except sqlite3.DatabaseError as exc:
            raise DatabaseCorruptionError(f"Failed to connect to database: {str(exc)}") from exc

        try:
            with conn:
                yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def init_database(self) -> None:
        """Initializes tables and indexes if they do not exist."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # 1. Auth Metadata table (strictly 1 row)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS auth_metadata (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        salt BLOB NOT NULL,
                        verifier_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                """)

                # 2. Encrypted Credentials table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS credentials (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        category TEXT NOT NULL DEFAULT 'Logins',
                        url_encrypted TEXT NOT NULL,
                        username_encrypted TEXT NOT NULL,
                        password_encrypted TEXT NOT NULL,
                        notes_encrypted TEXT NOT NULL,
                        is_favorite INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                """)

                # 3. Application Settings table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                """)

                # Indexes for performant searching and filtering
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_cred_title ON credentials(title);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_cred_category ON credentials(category);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_cred_favorite ON credentials(is_favorite);")

                # Insert default settings if missing
                cursor.execute("""
                    INSERT OR IGNORE INTO settings (key, value) VALUES 
                    ('auto_lock_seconds', ?),
                    ('clipboard_clear_seconds', ?);
                """, (str(config.DEFAULT_AUTO_LOCK_SECONDS), str(config.DEFAULT_CLIPBOARD_CLEAR_SECONDS)))

        except sqlite3.DatabaseError as exc:
            raise DatabaseCorruptionError(f"Database initialization failed: {str(exc)}") from exc

    def is_vault_initialized(self) -> bool:
        """Checks if a master password has already been created."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM auth_metadata WHERE id = 1;")
                row = cursor.fetchone()
                return bool(row and row["count"] > 0)
        except sqlite3.DatabaseError as exc:
            raise DatabaseCorruptionError(f"Failed to check vault status: {str(exc)}") from exc

    def setup_vault_auth(self, salt: bytes, verifier_hash: str) -> None:
        """Saves initial master password verifier and salt."""
        now = get_current_iso_timestamp()
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO auth_metadata (id, salt, verifier_hash, created_at, updated_at)
                    VALUES (1, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        salt = excluded.salt,
                        verifier_hash = excluded.verifier_hash,
                        updated_at = excluded.updated_at;
                """, (salt, verifier_hash, now, now))
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Failed to save vault credentials: {str(exc)}") from exc

    def get_auth_metadata(self) -> Optional[Dict[str, Any]]:
        """Returns stored salt and verifier_hash."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT salt, verifier_hash, created_at, updated_at FROM auth_metadata WHERE id = 1;")
                row = cursor.fetchone()
                if row:
                    return {
                        "salt": bytes(row["salt"]),
                        "verifier_hash": row["verifier_hash"],
                        "created_at": row["created_at"],
                        "updated_at": row["updated_at"]
                    }
                return None
        except sqlite3.DatabaseError as exc:
            raise DatabaseCorruptionError(f"Failed to read auth metadata: {str(exc)}") from exc

    def update_auth_metadata(self, new_salt: bytes, new_verifier_hash: str) -> None:
        """Updates stored salt and verifier hash when master password is changed."""
        now = get_current_iso_timestamp()
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE auth_metadata 
                    SET salt = ?, verifier_hash = ?, updated_at = ?
                    WHERE id = 1;
                """, (new_salt, new_verifier_hash, now))
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Failed to update auth metadata: {str(exc)}") from exc

    # ---------------- Credentials CRUD ----------------

    def add_credential(
        self,
        title: str,
        category: str,
        url_encrypted: str,
        username_encrypted: str,
        password_encrypted: str,
        notes_encrypted: str,
        is_favorite: bool = False
    ) -> int:
        """Inserts a new encrypted credential entry."""
        now = get_current_iso_timestamp()
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO credentials (
                        title, category, url_encrypted, username_encrypted,
                        password_encrypted, notes_encrypted, is_favorite,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    title.strip(),
                    category.strip() or "Logins",
                    url_encrypted,
                    username_encrypted,
                    password_encrypted,
                    notes_encrypted,
                    1 if is_favorite else 0,
                    now,
                    now
                ))
                return cursor.lastrowid
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Failed to add credential: {str(exc)}") from exc

    def update_credential(
        self,
        credential_id: int,
        title: str,
        category: str,
        url_encrypted: str,
        username_encrypted: str,
        password_encrypted: str,
        notes_encrypted: str,
        is_favorite: bool
    ) -> bool:
        """Updates an existing credential entry."""
        now = get_current_iso_timestamp()
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE credentials SET
                        title = ?,
                        category = ?,
                        url_encrypted = ?,
                        username_encrypted = ?,
                        password_encrypted = ?,
                        notes_encrypted = ?,
                        is_favorite = ?,
                        updated_at = ?
                    WHERE id = ?;
                """, (
                    title.strip(),
                    category.strip() or "Logins",
                    url_encrypted,
                    username_encrypted,
                    password_encrypted,
                    notes_encrypted,
                    1 if is_favorite else 0,
                    now,
                    credential_id
                ))
                return cursor.rowcount > 0
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Failed to update credential: {str(exc)}") from exc

    def delete_credential(self, credential_id: int) -> bool:
        """Deletes a credential by ID."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM credentials WHERE id = ?;", (credential_id,))
                return cursor.rowcount > 0
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Failed to delete credential: {str(exc)}") from exc

    def toggle_favorite(self, credential_id: int) -> bool:
        """Toggles the favorite status of a credential and returns the new status."""
        now = get_current_iso_timestamp()
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT is_favorite FROM credentials WHERE id = ?;", (credential_id,))
                row = cursor.fetchone()
                if not row:
                    return False
                new_status = 0 if row["is_favorite"] else 1
                cursor.execute("""
                    UPDATE credentials 
                    SET is_favorite = ?, updated_at = ?
                    WHERE id = ?;
                """, (new_status, now, credential_id))
                return bool(new_status)
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Failed to toggle favorite: {str(exc)}") from exc

    def get_all_credentials(self) -> List[Dict[str, Any]]:
        """Returns all credential rows."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, title, category, url_encrypted, username_encrypted,
                           password_encrypted, notes_encrypted, is_favorite,
                           created_at, updated_at
                    FROM credentials
                    ORDER BY is_favorite DESC, title COLLATE NOCASE ASC;
                """)
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Failed to fetch credentials: {str(exc)}") from exc

    def get_credential_by_id(self, credential_id: int) -> Optional[Dict[str, Any]]:
        """Returns a single credential row by ID."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, title, category, url_encrypted, username_encrypted,
                           password_encrypted, notes_encrypted, is_favorite,
                           created_at, updated_at
                    FROM credentials
                    WHERE id = ?;
                """, (credential_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Failed to fetch credential {credential_id}: {str(exc)}") from exc

    # ---------------- Re-encryption for Master Password Change ----------------

    def reencrypt_vault(self, old_key: bytes, new_key: bytes, new_salt: bytes, new_verifier_hash: str) -> None:
        """
        Atomically decrypts all credentials with old_key, re-encrypts with new_key,
        and updates auth_metadata within a single SQLite transaction.
        """
        now = get_current_iso_timestamp()
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, url_encrypted, username_encrypted, password_encrypted, notes_encrypted
                    FROM credentials;
                """)
                rows = cursor.fetchall()

                # Decrypt and re-encrypt every credential
                for row in rows:
                    cred_id = row["id"]
                    url = decrypt_data(row["url_encrypted"], old_key)
                    username = decrypt_data(row["username_encrypted"], old_key)
                    password = decrypt_data(row["password_encrypted"], old_key)
                    notes = decrypt_data(row["notes_encrypted"], old_key)

                    new_url_enc = encrypt_data(url, new_key)
                    new_user_enc = encrypt_data(username, new_key)
                    new_pass_enc = encrypt_data(password, new_key)
                    new_notes_enc = encrypt_data(notes, new_key)

                    cursor.execute("""
                        UPDATE credentials SET
                            url_encrypted = ?,
                            username_encrypted = ?,
                            password_encrypted = ?,
                            notes_encrypted = ?,
                            updated_at = ?
                        WHERE id = ?;
                    """, (new_url_enc, new_user_enc, new_pass_enc, new_notes_enc, now, cred_id))

                # Update auth metadata
                cursor.execute("""
                    UPDATE auth_metadata
                    SET salt = ?, verifier_hash = ?, updated_at = ?
                    WHERE id = 1;
                """, (new_salt, new_verifier_hash, now))

        except Exception as exc:
            raise DatabaseError(f"Vault re-encryption failed: {str(exc)}") from exc

    # ---------------- Application Settings ----------------

    def get_setting(self, key: str, default: str = "") -> str:
        """Retrieves a setting value by key."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM settings WHERE key = ?;", (key,))
                row = cursor.fetchone()
                return str(row["value"]) if row else default
        except sqlite3.DatabaseError:
            return default

    def set_setting(self, key: str, value: str) -> None:
        """Sets or updates an application setting."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO settings (key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                """, (key, str(value)))
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Failed to set setting '{key}': {str(exc)}") from exc

    def get_all_settings(self) -> Dict[str, str]:
        """Returns all settings as a dictionary."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT key, value FROM settings;")
                return {row["key"]: row["value"] for row in cursor.fetchall()}
        except sqlite3.DatabaseError:
            return {}
