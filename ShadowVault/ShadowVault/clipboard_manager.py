"""
ShadowVault - Clipboard Manager
Handles secure clipboard copy operations with automatic timeout zeroing.
"""

import threading
import time
from typing import Optional, Callable
import pyperclip
import config


class ClipboardManager:
    """Manages clipboard actions with timed security clearing."""

    def __init__(self, default_clear_seconds: int = config.DEFAULT_CLIPBOARD_CLEAR_SECONDS):
        self.default_clear_seconds = default_clear_seconds
        self._current_timer: Optional[threading.Timer] = None
        self._last_copied_text: Optional[str] = None
        self._lock = threading.Lock()

    def copy_text(
        self,
        text: str,
        clear_after_seconds: Optional[int] = None,
        on_cleared_callback: Optional[Callable[[], None]] = None
    ) -> bool:
        """
        Copies text to system clipboard and schedules an automatic wipe.

        Args:
            text: Plaintext to copy.
            clear_after_seconds: Seconds before clearing. If <= 0, auto-clear is disabled.
            on_cleared_callback: Optional callback to invoke on main thread after clearing.

        Returns:
            bool: True if copy succeeded, False otherwise.
        """
        if text is None:
            return False

        timeout = self.default_clear_seconds if clear_after_seconds is None else clear_after_seconds

        with self._lock:
            # Cancel any existing clear timer
            if self._current_timer and self._current_timer.is_alive():
                self._current_timer.cancel()
                self._current_timer = None

            try:
                pyperclip.copy(text)
                self._last_copied_text = text
            except Exception:
                return False

            # Schedule clear if timeout is greater than 0
            if timeout > 0:
                def _timed_clear():
                    time.sleep(timeout)
                    with self._lock:
                        try:
                            # Only clear if clipboard still matches what ShadowVault copied
                            current_clip = pyperclip.paste()
                            if current_clip == self._last_copied_text:
                                pyperclip.copy("")
                                self._last_copied_text = None
                                if on_cleared_callback:
                                    on_cleared_callback()
                        except Exception:
                            pass

                # Start daemon worker thread
                t = threading.Thread(target=_timed_clear, daemon=True)
                t.start()

            return True

    def clear_now(self) -> None:
        """Manually clears clipboard immediately."""
        with self._lock:
            try:
                pyperclip.copy("")
                self._last_copied_text = None
            except Exception:
                pass
