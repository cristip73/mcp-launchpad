"""Encrypted token storage for OAuth tokens.

This module provides secure storage for OAuth tokens using:
- Fernet symmetric encryption (AES-128-CBC + HMAC)
- OS keyring for encryption key storage (Keychain, libsecret, DPAPI)
- File permissions for defense in depth
- File locking to prevent race conditions
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import stat
import sys
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Generator

import keyring
from cryptography.fernet import Fernet, InvalidToken

from .tokens import ClientCredentials, TokenSet

logger = logging.getLogger(__name__)

# File locking support
if sys.platform != "win32":
    import fcntl

    @contextmanager
    def _file_lock(filepath: Path, exclusive: bool = True) -> Generator[None, None, None]:
        """Acquire a file lock (Unix implementation using fcntl).

        Args:
            filepath: Path to the file to lock
            exclusive: If True, acquire exclusive lock; otherwise shared lock
        """
        lock_path = filepath.with_suffix(filepath.suffix + ".lock")
        lock_path.touch(exist_ok=True)

        with open(lock_path, "r") as lock_file:
            try:
                if exclusive:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
else:
    # Windows: use msvcrt for file locking
    import msvcrt

    @contextmanager
    def _file_lock(filepath: Path, exclusive: bool = True) -> Generator[None, None, None]:
        """Acquire a file lock (Windows implementation using msvcrt).

        Args:
            filepath: Path to the file to lock
            exclusive: If True, acquire exclusive lock; otherwise shared lock
        """
        lock_path = filepath.with_suffix(filepath.suffix + ".lock")
        lock_path.touch(exist_ok=True)

        with open(lock_path, "r+") as lock_file:
            try:
                if exclusive:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    # Windows doesn't have true shared locks with msvcrt
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                yield
            finally:
                try:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass


# Keyring service name for mcpl
KEYRING_SERVICE = "mcp-launchpad"
KEYRING_USERNAME = "oauth-encryption-key"

# Default storage location
DEFAULT_STORE_DIR = Path.home() / ".cache" / "mcp-launchpad" / "oauth"

# File names
TOKENS_FILE = "tokens.json"
CLIENTS_FILE = "clients.json"

# Cross-process lock serializing token refreshes and login publication
REFRESH_LOCK_FILE = "refresh.lock"
DEFAULT_REFRESH_LOCK_TIMEOUT = 60.0


class TokenStoreError(Exception):
    """Error in token storage operations."""

    pass


class TokenDecryptionError(TokenStoreError):
    """Failed to decrypt token storage file.

    This error indicates the encryption key has changed (e.g., keyring cleared,
    different machine) and existing tokens cannot be read. The caller should
    handle this by either:
    - Prompting the user to re-authenticate
    - Clearing existing tokens with clear_all()
    """

    pass


def _derive_fallback_key() -> bytes:
    """Derive a fallback encryption key from machine-specific data.

    Used when keyring is not available. Less secure than keyring but
    still provides encryption at rest.

    Returns:
        32-byte key suitable for Fernet
    """
    # Gather machine-specific data
    components = []

    # Machine ID (Linux)
    machine_id_path = Path("/etc/machine-id")
    if machine_id_path.exists():
        components.append(machine_id_path.read_text().strip())

    # Home directory (all platforms)
    components.append(str(Path.home()))

    # Username
    components.append(os.environ.get("USER", os.environ.get("USERNAME", "mcpl")))

    # Combine and hash
    combined = ":".join(components)
    key_bytes = hashlib.sha256(combined.encode()).digest()

    # Fernet requires base64-encoded 32-byte key
    return base64.urlsafe_b64encode(key_bytes)


class TokenStore:
    """Encrypted storage for OAuth tokens.

    Tokens are encrypted using Fernet (AES-128-CBC + HMAC) with the
    encryption key stored in the OS keyring for maximum security.

    Token files are stored in ~/.cache/mcp-launchpad/oauth/ with
    restricted file permissions (0600).
    """

    def __init__(self, store_dir: Path | None = None):
        """Initialize token store.

        Args:
            store_dir: Optional custom storage directory
        """
        self.store_dir = store_dir or DEFAULT_STORE_DIR
        self._cipher: Fernet | None = None
        self._using_keyring = False

        self._init_storage()
        self._init_encryption()

    def _init_storage(self) -> None:
        """Initialize storage directory with secure permissions."""
        self.store_dir.mkdir(parents=True, exist_ok=True)

        # Set directory permissions to 0700 (owner only)
        try:
            self.store_dir.chmod(stat.S_IRWXU)
        except OSError as e:
            logger.warning(f"Could not set directory permissions: {e}")

    def _init_encryption(self) -> None:
        """Initialize encryption using keyring or fallback."""
        try:
            # Try to get key from keyring
            key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)

            if key is None:
                # Generate new key and store in keyring
                key = Fernet.generate_key().decode("ascii")
                keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, key)
                logger.debug("Generated new encryption key in keyring")

            self._cipher = Fernet(key.encode("ascii"))
            self._using_keyring = True
            logger.debug("Using keyring for encryption key storage")

        except Exception as e:
            # Fallback to derived key if keyring fails
            error_type = type(e).__name__
            logger.warning(
                f"Keyring not available: {error_type}: {e}. "
                f"Using fallback encryption (machine-derived key). "
                f"Tokens are still encrypted but with reduced security. "
                f"To use keyring: ensure a keyring backend is installed "
                f"(e.g., gnome-keyring on Linux, Keychain on macOS)."
            )
            logger.debug(f"Full keyring error: {e!r}")
            fallback_key = _derive_fallback_key()
            self._cipher = Fernet(fallback_key)
            self._using_keyring = False

    def _encrypt(self, data: str) -> str:
        """Encrypt a string.

        Args:
            data: Plaintext string to encrypt

        Returns:
            Base64-encoded ciphertext
        """
        if self._cipher is None:
            raise TokenStoreError("Encryption not initialized")
        return self._cipher.encrypt(data.encode("utf-8")).decode("ascii")

    def _decrypt(self, data: str) -> str:
        """Decrypt a string.

        Args:
            data: Base64-encoded ciphertext

        Returns:
            Decrypted plaintext string

        Raises:
            TokenStoreError: If decryption fails
        """
        if self._cipher is None:
            raise TokenStoreError("Encryption not initialized")
        try:
            return self._cipher.decrypt(data.encode("ascii")).decode("utf-8")
        except InvalidToken as e:
            raise TokenStoreError(
                "Failed to decrypt token data. The encryption key may have changed."
            ) from e

    def _read_encrypted_file(self, filename: str) -> dict[str, Any]:
        """Read and decrypt a JSON file with file locking.

        Uses shared (read) lock to allow concurrent reads but block writes.

        Args:
            filename: Name of file in store directory

        Returns:
            Decrypted JSON data as dictionary

        Raises:
            TokenDecryptionError: If decryption fails (key changed, corrupted data)
        """
        filepath = self.store_dir / filename

        if not filepath.exists():
            return {}

        try:
            with _file_lock(filepath, exclusive=False):  # Shared lock for reading
                encrypted_data = filepath.read_text()
                decrypted_json = self._decrypt(encrypted_data)
                result: dict[str, Any] = json.loads(decrypted_json)
                return result
        except TokenStoreError as e:
            # Decryption failed - raise so caller can decide how to handle
            raise TokenDecryptionError(
                f"Cannot decrypt {filename}. The encryption key may have changed. "
                f"Run 'mcpl auth logout --all' to clear stored tokens and re-authenticate."
            ) from e
        except json.JSONDecodeError as e:
            # Data decrypted but is not valid JSON - file may be corrupted
            raise TokenDecryptionError(
                f"Token file {filename} is corrupted. "
                f"Run 'mcpl auth logout --all' to clear and re-authenticate."
            ) from e

    def _read_encrypted_file_unlocked(self, filename: str) -> dict[str, Any]:
        """Read and decrypt a JSON file; caller must already hold the file lock."""
        filepath = self.store_dir / filename
        if not filepath.exists():
            return {}
        try:
            decrypted_json = self._decrypt(filepath.read_text())
            result: dict[str, Any] = json.loads(decrypted_json)
            return result
        except TokenStoreError as e:
            raise TokenDecryptionError(
                f"Cannot decrypt {filename}. The encryption key may have changed. "
                f"Run 'mcpl auth logout --all' to clear stored tokens and re-authenticate."
            ) from e
        except json.JSONDecodeError as e:
            raise TokenDecryptionError(
                f"Token file {filename} is corrupted. "
                f"Run 'mcpl auth logout --all' to clear and re-authenticate."
            ) from e

    def _write_unlocked(self, filepath: Path, data: dict[str, Any]) -> None:
        """Encrypt and atomically replace a file; caller must hold the lock.

        Writes to a 0600 temp file in the same directory, then renames it over
        the target, so a crash mid-write never leaves a truncated token file.
        """
        encrypted_data = self._encrypt(json.dumps(data, indent=2))
        tmp_path = filepath.with_name(f".{filepath.name}.{os.getpid()}.tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(encrypted_data)
            os.replace(tmp_path, filepath)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
        try:
            filepath.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError as e:
            logger.warning(f"Could not set file permissions: {e}")

    def _update_encrypted_file(
        self, filename: str, mutate: Callable[[dict[str, Any]], bool]
    ) -> bool:
        """Read-modify-write a file under one exclusive lock.

        Holding the lock across the read and the write prevents a concurrent
        process (another daemon, a CLI refresh) from losing an update made
        between our read and our write.

        Args:
            filename: Name of file in store directory
            mutate: Changes the dict in place; returns False to skip the write

        Returns:
            Whatever ``mutate`` returned
        """
        filepath = self.store_dir / filename
        with _file_lock(filepath, exclusive=True):
            data = self._read_encrypted_file_unlocked(filename)
            changed = mutate(data)
            if changed:
                self._write_unlocked(filepath, data)
            return changed

    def _write_encrypted_file(self, filename: str, data: dict[str, Any]) -> None:
        """Encrypt and write a JSON file with secure permissions and file locking.

        Uses exclusive (write) lock to prevent concurrent reads/writes.

        Args:
            filename: Name of file in store directory
            data: Dictionary to serialize and encrypt
        """
        filepath = self.store_dir / filename

        # Write with exclusive lock and secure permissions
        with _file_lock(filepath, exclusive=True):  # Exclusive lock for writing
            self._write_unlocked(filepath, data)

    @asynccontextmanager
    async def refresh_lock(
        self, timeout: float = DEFAULT_REFRESH_LOCK_TIMEOUT
    ) -> AsyncIterator[bool]:
        """Hold the cross-process OAuth lock (polling, never blocks the loop).

        Serializes token refreshes with each other and with login's final
        publication of a token and its client, so a refresh started with an
        old client can never write its result over a newer login.

        Yields True when the lock is held, False if it could not be taken
        within ``timeout`` seconds. Callers decide what to do without it:
        a refresh must not redeem (fail closed); a login still publishes.
        """
        if sys.platform == "win32":  # pragma: no cover - no cross-process lock
            yield True
            return
        lock_path = self.store_dir / REFRESH_LOCK_FILE
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        locked = False
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError:
                    if loop.time() >= deadline:
                        logger.warning(f"OAuth lock busy for {timeout}s")
                        break
                    await asyncio.sleep(0.1)
            yield locked
        finally:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _normalize_resource(self, resource: str) -> str:
        """Normalize a resource URL for consistent key lookup.

        Args:
            resource: Resource URL or server name

        Returns:
            Normalized key for storage lookup
        """
        # Remove trailing slashes and convert to lowercase for consistency
        return resource.rstrip("/").lower()

    # Token operations

    def get_token(self, resource: str) -> TokenSet | None:
        """Get token for a resource.

        Args:
            resource: The resource URL

        Returns:
            TokenSet if found, None otherwise
        """
        key = self._normalize_resource(resource)
        tokens_data = self._read_encrypted_file(TOKENS_FILE)

        if key not in tokens_data:
            return None

        try:
            return TokenSet.from_dict(tokens_data[key])
        except (KeyError, ValueError) as e:
            logger.warning(f"Invalid token data for {resource}: {e}")
            return None

    def set_token(self, resource: str, token: TokenSet) -> None:
        """Store token for a resource.

        Args:
            resource: The resource URL
            token: The token set to store
        """
        key = self._normalize_resource(resource)

        def _mutate(tokens_data: dict[str, Any]) -> bool:
            tokens_data[key] = token.to_dict()
            return True

        self._update_encrypted_file(TOKENS_FILE, _mutate)

        logger.debug(f"Stored token for {resource}")

    def delete_token(self, resource: str) -> bool:
        """Delete token for a resource.

        Args:
            resource: The resource URL

        Returns:
            True if token was deleted, False if not found
        """
        key = self._normalize_resource(resource)

        def _mutate(tokens_data: dict[str, Any]) -> bool:
            if key not in tokens_data:
                return False
            del tokens_data[key]
            return True

        deleted = self._update_encrypted_file(TOKENS_FILE, _mutate)
        if deleted:
            logger.debug(f"Deleted token for {resource}")
        return deleted

    def list_resources(self) -> list[str]:
        """List all resources with stored tokens.

        Returns:
            List of resource URLs
        """
        tokens_data = self._read_encrypted_file(TOKENS_FILE)
        return list(tokens_data.keys())

    def get_token_info(self, resource: str) -> dict[str, Any] | None:
        """Get non-sensitive token info for display.

        Args:
            resource: The resource URL

        Returns:
            Dictionary with token metadata (no secrets), or None
        """
        token = self.get_token(resource)
        if token is None:
            return None

        info: dict[str, Any] = {
            "resource": resource,
            "token_type": token.token_type,
            "has_refresh_token": token.has_refresh_token(),
            "issued_at": token.issued_at.isoformat() if token.issued_at else None,
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
            "is_expired": token.is_expired(),
            "scope": token.scope,
        }

        return info

    # Client credentials operations

    def get_client(self, auth_server: str) -> ClientCredentials | None:
        """Get client credentials for an authorization server.

        Used for storing DCR-obtained or manually configured client credentials.

        Args:
            auth_server: The authorization server URL

        Returns:
            ClientCredentials if found, None otherwise
        """
        key = self._normalize_resource(auth_server)
        clients_data = self._read_encrypted_file(CLIENTS_FILE)

        if key not in clients_data:
            return None

        try:
            return ClientCredentials.from_dict(clients_data[key])
        except (KeyError, ValueError) as e:
            logger.warning(f"Invalid client data for {auth_server}: {e}")
            return None

    def set_client(self, auth_server: str, client: ClientCredentials) -> None:
        """Store client credentials for an authorization server.

        Args:
            auth_server: The authorization server URL
            client: The client credentials to store
        """
        key = self._normalize_resource(auth_server)

        def _mutate(clients_data: dict[str, Any]) -> bool:
            clients_data[key] = client.to_dict()
            return True

        self._update_encrypted_file(CLIENTS_FILE, _mutate)

        logger.debug(f"Stored client credentials for {auth_server}")

    # Clients are historically keyed by authorization server (issuer) only.
    # Two MCP servers on one issuer can use different clients (one DCR, one
    # configured), so the client that obtained a token is also stored under
    # its resource. Older mcpl versions only read issuer keys and ignore
    # these extra "resource:" entries.
    _RESOURCE_CLIENT_PREFIX = "resource:"

    def get_client_for_resource(self, resource: str) -> ClientCredentials | None:
        """Get the client that obtained the token for a resource, if recorded."""
        return self.get_client(self._RESOURCE_CLIENT_PREFIX + resource)

    def set_client_for_resource(self, resource: str, client: ClientCredentials) -> None:
        """Record the client that obtained the token for a resource."""
        self.set_client(self._RESOURCE_CLIENT_PREFIX + resource, client)

    def delete_client_for_resource(self, resource: str) -> bool:
        """Forget the client recorded for a resource."""
        return self.delete_client(self._RESOURCE_CLIENT_PREFIX + resource)

    def propagate_client_secret(self, client_id: str, client_secret: str) -> int:
        """Set a new secret on every stored record of one client_id.

        The same client can be recorded under its issuer and under several
        resources; a rotated secret must reach all of them, or a stale record
        keeps being selected. Records of other client ids are never touched.

        Returns:
            Number of records changed
        """
        if not client_secret:
            return 0
        changed = 0

        def _mutate(clients_data: dict[str, Any]) -> bool:
            nonlocal changed
            for entry in clients_data.values():
                if (
                    isinstance(entry, dict)
                    and entry.get("client_id") == client_id
                    and entry.get("client_secret") != client_secret
                ):
                    entry["client_secret"] = client_secret
                    changed += 1
            return changed > 0

        self._update_encrypted_file(CLIENTS_FILE, _mutate)
        return changed

    def set_client_if_compatible(
        self,
        auth_server: str,
        client: ClientCredentials,
        replace_same_id: bool = False,
    ) -> bool:
        """Store an issuer client only if it cannot clobber another client.

        Checked and written under one lock, so a concurrent process storing a
        different client for the same issuer is never overwritten.

        Args:
            auth_server: The authorization server URL
            client: The client credentials to store
            replace_same_id: Also replace an entry with the same client_id
                (e.g. a new secret at login); a different client_id is never
                replaced

        Returns:
            True if written
        """
        key = self._normalize_resource(auth_server)

        def _mutate(clients_data: dict[str, Any]) -> bool:
            existing = clients_data.get(key)
            if existing is None:
                clients_data[key] = client.to_dict()
                return True
            if replace_same_id and existing.get("client_id") == client.client_id:
                clients_data[key] = client.to_dict()
                return True
            return False

        return self._update_encrypted_file(CLIENTS_FILE, _mutate)

    def delete_client(self, auth_server: str) -> bool:
        """Delete client credentials for an authorization server.

        Args:
            auth_server: The authorization server URL

        Returns:
            True if deleted, False if not found
        """
        key = self._normalize_resource(auth_server)

        def _mutate(clients_data: dict[str, Any]) -> bool:
            if key not in clients_data:
                return False
            del clients_data[key]
            return True

        deleted = self._update_encrypted_file(CLIENTS_FILE, _mutate)
        if deleted:
            logger.debug(f"Deleted client credentials for {auth_server}")
        return deleted

    # Utility methods

    def clear_all(self) -> None:
        """Clear all stored tokens and client credentials.

        Use with caution - this deletes all authentication data.
        """
        tokens_file = self.store_dir / TOKENS_FILE
        clients_file = self.store_dir / CLIENTS_FILE

        if tokens_file.exists():
            tokens_file.unlink()
        if clients_file.exists():
            clients_file.unlink()

        logger.info("Cleared all stored authentication data")

    def is_using_keyring(self) -> bool:
        """Check if keyring is being used for encryption key storage.

        Returns:
            True if using OS keyring, False if using fallback
        """
        return self._using_keyring
