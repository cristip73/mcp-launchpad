"""High-level OAuth manager for MCP Launchpad.

This module provides the main interface for OAuth operations, used by
both the CLI and daemon to manage authentication for MCP servers.
"""

import logging
import os
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urlparse

from .discovery import DiscoveryError, OAuthConfig, discover_oauth_config
from .flow import OAuthFlow, OAuthFlowError, TokenExchangeError, refresh_token, revoke_token
from .store import REFRESH_LOCK_FILE as STORE_REFRESH_LOCK_FILE
from .store import TokenDecryptionError, TokenStore
from .tokens import ClientCredentials, TokenSet

logger = logging.getLogger(__name__)

# Refresh this many seconds before the access token expires, so a request
# never leaves with a token that dies in flight.
REFRESH_BUFFER_SECONDS = int(os.environ.get("MCPL_OAUTH_REFRESH_BUFFER", "60"))

# Cross-process lock serializing token refreshes (lives in the store dir)
REFRESH_LOCK_FILE = STORE_REFRESH_LOCK_FILE
REFRESH_LOCK_TIMEOUT = 60


def _format_timedelta(td: timedelta) -> str:
    """Format a timedelta into a human-readable string.

    Examples:
        - "45 minutes"
        - "2 hours"
        - "3 days"
        - "2 weeks"

    Args:
        td: The timedelta to format

    Returns:
        Human-readable string representation
    """
    total_seconds = int(td.total_seconds())

    if total_seconds < 0:
        return "Expired"

    if total_seconds < 60:
        return f"{total_seconds} seconds"

    minutes = total_seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"

    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''}"

    days = hours // 24
    if days < 14:
        return f"{days} day{'s' if days != 1 else ''}"

    weeks = days // 7
    return f"{weeks} week{'s' if weeks != 1 else ''}"


def _format_time_ago(dt: datetime) -> str:
    """Format a datetime as time ago from now.

    Examples:
        - "2 minutes ago"
        - "3 hours ago"
        - "1 day ago"

    Args:
        dt: The datetime to format

    Returns:
        Human-readable "time ago" string
    """
    now = datetime.now(timezone.utc)
    # Ensure dt is timezone-aware
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    diff = now - dt
    return _format_timedelta(diff) + " ago"


@dataclass
class AuthStatus:
    """Authentication status for an MCP server.

    Attributes:
        server_url: The MCP server URL
        server_name: The friendly server name
        authenticated: Whether we have valid tokens
        expired: Whether the token is expired
        expires_at: When the token expires (ISO format string)
        expires_in_human: Human-readable time until expiry (e.g., "45 minutes")
        issued_at: When the token was issued (ISO format string)
        issued_ago_human: Human-readable time since issuance (e.g., "2 hours ago")
        has_refresh_token: Whether a refresh token is available
        scope: Granted scopes
        error: Any error message
    """

    server_url: str
    server_name: str
    authenticated: bool = False
    expired: bool = False
    expires_at: str | None = None
    expires_in_human: str | None = None
    issued_at: str | None = None
    issued_ago_human: str | None = None
    has_refresh_token: bool = False
    scope: str | None = None
    token_lifetime_human: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "server_url": self.server_url,
            "server_name": self.server_name,
            "authenticated": self.authenticated,
            "expired": self.expired,
            "expires_at": self.expires_at,
            "expires_in_human": self.expires_in_human,
            "issued_at": self.issued_at,
            "issued_ago_human": self.issued_ago_human,
            "has_refresh_token": self.has_refresh_token,
            "scope": self.scope,
            "token_lifetime_human": self.token_lifetime_human,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthStatus":
        """Deserialize from dictionary."""
        return cls(
            server_url=data["server_url"],
            server_name=data["server_name"],
            authenticated=data.get("authenticated", False),
            expired=data.get("expired", False),
            expires_at=data.get("expires_at"),
            expires_in_human=data.get("expires_in_human"),
            issued_at=data.get("issued_at"),
            issued_ago_human=data.get("issued_ago_human"),
            has_refresh_token=data.get("has_refresh_token", False),
            scope=data.get("scope"),
            token_lifetime_human=data.get("token_lifetime_human"),
            error=data.get("error"),
        )


@dataclass
class OAuthManager:
    """Manages OAuth authentication for MCP servers.

    This is the main interface for OAuth operations. It handles:
    - Checking if servers need authentication
    - Running OAuth flows for authentication
    - Managing stored tokens
    - Providing Authorization headers for HTTP requests
    - Refreshing expired tokens

    Usage:
        manager = OAuthManager()

        # Check if we have a valid token
        if manager.has_valid_token(server_url):
            header = manager.get_auth_header(server_url)

        # Run OAuth flow for new authentication
        await manager.authenticate(server_url, on_status=print)

        # Get status of all servers
        status = manager.get_auth_status(server_url, "my-server")
    """

    _store: TokenStore = field(default_factory=TokenStore)
    _oauth_configs: dict[str, OAuthConfig] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize the manager."""
        # TokenStore is lazy-initialized in field default

    @property
    def token_store(self) -> TokenStore:
        """Get the token store."""
        return self._store

    def _lookup_token(self, server_url: str) -> TokenSet | None:
        """Look up token with fallback to base URL.

        Tries multiple lookup strategies:
        1. Exact server URL match
        2. Base URL (scheme + netloc) match for resource URI compatibility

        This handles the case where tokens are stored by resource URI
        (e.g., https://mcp.notion.com) but lookups use the full server URL
        (e.g., https://mcp.notion.com/mcp).

        Args:
            server_url: The MCP server URL

        Returns:
            TokenSet if found, None otherwise
        """
        # Try exact URL match first
        token = self._store.get_token(server_url)
        if token is not None:
            logger.debug(f"Token found for exact URL: {server_url}")
            return token

        # If not found, try base URL (scheme + netloc) for resource URI match
        parsed = urlparse(server_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        if base_url != server_url:  # Only try if different
            token = self._store.get_token(base_url)
            if token is not None:
                logger.debug(
                    f"Token found using base URL fallback: {base_url} "
                    f"(original: {server_url})"
                )

        return token

    def has_valid_token(self, server_url: str) -> bool:
        """Check if we have a valid (non-expired) token for a server.

        Args:
            server_url: The MCP server URL

        Returns:
            True if we have a valid token

        Raises:
            TokenDecryptionError: If token storage cannot be decrypted
                (encryption key changed, corrupted data)
        """
        try:
            token = self._lookup_token(server_url)
        except TokenDecryptionError:
            # Re-raise to let caller handle - they may want to prompt re-auth
            logger.warning(
                f"Token storage decryption failed for {server_url}. "
                f"Encryption key may have changed."
            )
            raise

        if token is None:
            return False

        return not token.is_expired()

    def get_token(self, server_url: str) -> TokenSet | None:
        """Get the stored token for a server.

        Args:
            server_url: The MCP server URL

        Returns:
            TokenSet if found, None otherwise
        """
        return self._lookup_token(server_url)

    def get_auth_header(self, server_url: str) -> str | None:
        """Get the Authorization header value for a server.

        Args:
            server_url: The MCP server URL

        Returns:
            Authorization header value (e.g., "Bearer abc...") or None
        """
        token = self._lookup_token(server_url)
        if token is None:
            return None

        # Return header even if expired - let the server return 401
        # so we can trigger a refresh
        return token.get_auth_header()

    def get_auth_status(self, server_url: str, server_name: str) -> AuthStatus:
        """Get authentication status for a server.

        Args:
            server_url: The MCP server URL
            server_name: Friendly name for display

        Returns:
            AuthStatus with current authentication state
        """
        token = self._lookup_token(server_url)

        if token is None:
            return AuthStatus(
                server_url=server_url,
                server_name=server_name,
                authenticated=False,
            )

        # Calculate human-readable expiry
        expires_in_human = None
        if token.expires_at:
            # Ensure expires_at is timezone-aware
            expires_at = token.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            remaining = expires_at - now
            if remaining.total_seconds() > 0:
                expires_in_human = _format_timedelta(remaining)
            else:
                expires_in_human = "Expired"

        # Calculate human-readable issue time
        issued_ago_human = None
        if token.issued_at:
            issued_ago_human = _format_time_ago(token.issued_at)

        # Calculate original token lifetime
        token_lifetime_human = None
        if token.expires_at and token.issued_at:
            expires_at = token.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            issued_at = token.issued_at
            if issued_at.tzinfo is None:
                issued_at = issued_at.replace(tzinfo=timezone.utc)
            lifetime = expires_at - issued_at
            if lifetime.total_seconds() > 0:
                token_lifetime_human = _format_timedelta(lifetime)

        return AuthStatus(
            server_url=server_url,
            server_name=server_name,
            authenticated=True,
            expired=token.is_expired(),
            expires_at=token.expires_at.isoformat() if token.expires_at else None,
            expires_in_human=expires_in_human,
            issued_at=token.issued_at.isoformat() if token.issued_at else None,
            issued_ago_human=issued_ago_human,
            has_refresh_token=token.has_refresh_token(),
            scope=token.scope,
            token_lifetime_human=token_lifetime_human,
        )

    async def authenticate(
        self,
        server_url: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        www_authenticate: str | None = None,
        scopes: list[str] | None = None,
        callback_timeout: int = 120,
        callback_port: int = 0,
        on_status: Callable[[str], None] | None = None,
        prompt_for_credentials: Callable[[], tuple[str, str | None]] | None = None,
    ) -> TokenSet:
        """Run OAuth flow to authenticate with a server.

        This is the main entry point for CLI-initiated authentication.

        Args:
            server_url: The MCP server URL
            client_id: Optional pre-configured client ID
            client_secret: Optional client secret
            www_authenticate: Optional WWW-Authenticate header from 401
            scopes: Optional scopes to request
            callback_timeout: Timeout for browser callback
            callback_port: Fixed port for callback server (0 = auto)
            on_status: Callback for status messages
            prompt_for_credentials: Callback for manual credential entry

        Returns:
            TokenSet with new tokens

        Raises:
            OAuthFlowError: If authentication fails
        """
        flow = OAuthFlow(
            server_url=server_url,
            token_store=self._store,
            client_id=client_id,
            client_secret=client_secret,
            www_authenticate=www_authenticate,
            callback_timeout=callback_timeout,
            callback_port=callback_port,
            on_status=on_status,
        )

        token = await flow.run(
            scopes=scopes,
            prompt_for_credentials=prompt_for_credentials,
        )

        # Cache the OAuth config for future refresh operations
        if flow._oauth_config:
            self._oauth_configs[server_url] = flow._oauth_config

        return token

    # ------------------------------------------------------------------
    # Token refresh
    #
    # Several processes share one token store (one daemon per agent session,
    # plus CLI commands such as `mcpl auth refresh`). Short-lived tokens
    # (e.g. 10 minutes) and rotating refresh tokens make uncoordinated
    # refreshes dangerous: two processes redeeming the same refresh token can
    # leave one of them with an invalid_grant. Every refresh therefore runs
    # under a cross-process lock and re-reads the store inside it, so a
    # process that waited simply picks up the token the other one wrote.
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def _refresh_lock(self) -> AsyncIterator[bool]:
        """The store's cross-process OAuth lock (see TokenStore.refresh_lock).

        Yields False after REFRESH_LOCK_TIMEOUT seconds; refresh callers must
        then NOT redeem the refresh token (fail closed: another process is
        mid-refresh and a second redemption could invalidate a rotating one).
        """
        async with self._store.refresh_lock(timeout=REFRESH_LOCK_TIMEOUT) as locked:
            yield locked

    @staticmethod
    def _needs_refresh(
        token: TokenSet, rejected_access_token: str | None
    ) -> bool:
        """A token needs refreshing if it is (nearly) expired or was rejected."""
        if token.is_expired(buffer_seconds=REFRESH_BUFFER_SECONDS):
            return True
        return (
            rejected_access_token is not None
            and token.access_token == rejected_access_token
        )

    async def _get_oauth_config(self, server_url: str) -> OAuthConfig | None:
        oauth_config = self._oauth_configs.get(server_url)
        if oauth_config is not None:
            return oauth_config
        try:
            logger.debug(f"Discovering OAuth config for {server_url} to refresh token")
            oauth_config = await discover_oauth_config(server_url)
        except DiscoveryError as e:
            logger.warning(f"OAuth discovery failed during token refresh: {e}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error during OAuth discovery for refresh: {e}")
            return None
        self._oauth_configs[server_url] = oauth_config
        return oauth_config

    def _lookup_client(self, auth_server: str, resource: str) -> ClientCredentials | None:
        """Client for a resource without config: resource record, then issuer.

        If the chosen record has no secret but another stored record of the
        same client_id has one, that secret is used (same client, never a
        different one).
        """
        by_resource = self._store.get_client_for_resource(resource)
        by_issuer = self._store.get_client(auth_server)
        chosen = by_resource or by_issuer
        if chosen is None or chosen.client_secret:
            return chosen
        for other in (by_resource, by_issuer):
            if other is not None and other.client_id == chosen.client_id and other.client_secret:
                return ClientCredentials(chosen.client_id, other.client_secret, chosen.redirect_uri)
        return chosen

    def _select_client(
        self,
        auth_server: str,
        resource: str,
        client_id: str | None,
        client_secret: str | None,
    ) -> ClientCredentials | None:
        """Pick the client credentials to redeem this resource's refresh token.

        Caller holds the refresh lock. Order: the server's configured client
        id (authoritative), then the client recorded for this resource at
        login, then the issuer client. A stored secret is reused only for the
        same client_id; an explicit (configured) secret is propagated to every
        stored record of that client_id.
        """
        if not client_id:
            return self._lookup_client(auth_server, resource)

        by_resource = self._store.get_client_for_resource(resource)
        by_issuer = self._store.get_client(auth_server)
        same_id = [
            c for c in (by_resource, by_issuer) if c is not None and c.client_id == client_id
        ]
        secret = client_secret or next(
            (c.client_secret for c in same_id if c.client_secret), None
        )
        client = ClientCredentials(client_id, secret)
        try:
            if client_secret:
                self._store.propagate_client_secret(client_id, client_secret)
            # Fill only empty slots: never clobber another server's client
            if by_resource is None:
                self._store.set_client_for_resource(resource, client)
            self._store.set_client_if_compatible(auth_server, client)
        except Exception as e:  # pragma: no cover - best effort
            logger.debug(f"Could not persist configured client for {auth_server}: {e}")
        return client

    async def _do_refresh(
        self,
        server_url: str,
        token: TokenSet,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> TokenSet | None:
        """Redeem the refresh token and store the result. Caller holds the lock.

        Args:
            server_url: The MCP server URL
            token: The current stored token (must have a refresh token)
            client_id: Configured client id, used when the store has no client
                for this authorization server (servers without DCR)
            client_secret: Configured client secret, if any

        Returns:
            The new TokenSet, or None if the refresh failed
        """
        oauth_config = await self._get_oauth_config(server_url)
        if oauth_config is None:
            return None

        auth_server = oauth_config.auth_server_metadata.issuer
        client = self._select_client(
            auth_server,
            oauth_config.resource_uri or server_url,
            client_id,
            client_secret,
        )
        if client is None:
            logger.warning(
                f"No client credentials for {auth_server}. Set oauth_client_id "
                f"in the server config or run: mcpl auth login --force"
            )
            return None

        try:
            token_response = await refresh_token(
                oauth_config.auth_server_metadata,
                client,
                token.refresh_token,  # type: ignore[arg-type]
                oauth_config.resource_uri,
            )
        except TokenExchangeError as e:
            if "invalid_grant" in str(e):
                logger.warning(
                    f"Refresh token revoked/expired for {server_url}: {e}. "
                    f"User must re-authenticate with: mcpl auth login"
                )
            else:
                logger.warning(f"Token refresh failed for {server_url}: {e}")
            return None

        new_token = TokenSet.from_token_response(
            token_response,
            oauth_config.resource_uri,
        )

        # Preserve refresh_token if server didn't return a new one
        # (many OAuth servers only return access_token on refresh)
        if not new_token.has_refresh_token() and token.has_refresh_token():
            new_token.refresh_token = token.refresh_token

        # Save under resource_uri (canonical key), not server_url
        # to avoid duplicate entries in token store
        store_key = oauth_config.resource_uri or server_url
        self._store.set_token(store_key, new_token)
        logger.info(f"Token refreshed for {store_key}")
        return new_token

    async def get_fresh_token(
        self,
        server_url: str,
        rejected_access_token: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> TokenSet | None:
        """Return the best token for a request, refreshing it when needed.

        Always reads the shared store, so a token refreshed by another process
        is picked up without a refresh of our own.

        Args:
            server_url: The MCP server URL
            rejected_access_token: An access token the server just answered
                with 401; forces a refresh unless the store already holds a
                different token
            client_id: Configured client id (fallback when the store has none)
            client_secret: Configured client secret

        Returns:
            The stored (possibly refreshed) token, or None if none is stored.
            If a needed refresh fails, the current token is returned as is.
        """
        token = self._lookup_token(server_url)
        if token is None or not self._needs_refresh(token, rejected_access_token):
            return token
        if not token.has_refresh_token():
            return token

        async with self._refresh_lock() as locked:
            # Re-read under the lock: another process may have refreshed already
            token = self._lookup_token(server_url)
            if token is None or not self._needs_refresh(token, rejected_access_token):
                return token
            if not token.has_refresh_token() or not locked:
                return token
            new_token = await self._do_refresh(
                server_url, token, client_id=client_id, client_secret=client_secret
            )
            return new_token or token

    async def refresh_if_needed(
        self,
        server_url: str,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> bool:
        """Refresh the token if it's expired.

        Args:
            server_url: The MCP server URL
            client_id: Configured client id (fallback when the store has none)
            client_secret: Configured client secret

        Returns:
            True if token was refreshed or is still valid,
            False if refresh failed or no token exists
        """
        token = await self.get_fresh_token(
            server_url, client_id=client_id, client_secret=client_secret
        )
        if token is None:
            logger.debug(f"No token stored for {server_url}, cannot refresh")
            return False
        return not token.is_expired()

    async def refresh_proactively(
        self,
        server_url: str,
        min_remaining_seconds: int | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> bool:
        """Refresh the token proactively, even if not yet expired.

        Used by the daemon's periodic refresh task and by `mcpl auth refresh`.

        Args:
            server_url: The MCP server URL
            min_remaining_seconds: If set, skip the refresh when (after waiting
                for the lock) the stored token still has at least this much
                lifetime left - another process refreshed it meanwhile
            client_id: Configured client id (fallback when the store has none)
            client_secret: Configured client secret

        Returns:
            True if token was refreshed (or found fresh), False if refresh failed
        """
        token = self._lookup_token(server_url)
        if token is None or not token.has_refresh_token():
            return False

        async with self._refresh_lock() as locked:
            token = self._lookup_token(server_url)
            if token is None or not token.has_refresh_token() or not locked:
                return False
            if min_remaining_seconds is not None and not token.is_expired(
                buffer_seconds=min_remaining_seconds
            ):
                return True
            new_token = await self._do_refresh(
                server_url, token, client_id=client_id, client_secret=client_secret
            )
            return new_token is not None

    def logout(self, server_url: str) -> bool:
        """Remove stored authentication for a server (sync version).

        Note: This does not revoke tokens server-side. Use logout_async()
        for full logout with token revocation.

        Args:
            server_url: The MCP server URL

        Returns:
            True if token was deleted, False if not found
        """
        deleted = self._store.delete_token(server_url)
        if deleted:
            logger.info(f"Logged out from {server_url}")
        return deleted

    async def logout_async(self, server_url: str) -> bool:
        """Remove stored authentication with server-side token revocation.

        This method attempts to revoke tokens on the authorization server
        before deleting them locally, per RFC 7009. If revocation fails
        (e.g., server doesn't support it), local tokens are still deleted.

        Args:
            server_url: The MCP server URL

        Returns:
            True if token was deleted, False if not found
        """
        # Get token before deleting
        token = self._lookup_token(server_url)
        if token is None:
            return False

        # Try to get OAuth config for revocation
        oauth_config = self._oauth_configs.get(server_url)
        if oauth_config is None:
            try:
                oauth_config = await discover_oauth_config(server_url)
                self._oauth_configs[server_url] = oauth_config
            except Exception as e:
                logger.debug(f"Could not discover OAuth config for revocation: {e}")
                oauth_config = None

        # Attempt server-side revocation if we have config
        if oauth_config and oauth_config.auth_server_metadata.supports_revocation():
            auth_server = oauth_config.auth_server_metadata.issuer
            # Same selection as refresh: the client that obtained this token
            client = self._lookup_client(
                auth_server, oauth_config.resource_uri or token.resource
            )

            if client:
                # Revoke access token
                await revoke_token(
                    oauth_config.auth_server_metadata,
                    client,
                    token.access_token,
                    token_type_hint="access_token",
                )

                # Revoke refresh token if present
                if token.has_refresh_token():
                    await revoke_token(
                        oauth_config.auth_server_metadata,
                        client,
                        token.refresh_token,  # type: ignore
                        token_type_hint="refresh_token",
                    )

        # Always delete local token (and the client recorded for it)
        deleted = self._store.delete_token(server_url)
        try:
            resource = (oauth_config.resource_uri if oauth_config else None) or token.resource
            if resource:
                self._store.delete_client_for_resource(resource)
        except Exception as e:  # pragma: no cover - best effort
            logger.debug(f"Could not forget resource client for {server_url}: {e}")
        if deleted:
            logger.info(f"Logged out from {server_url}")
        return deleted

    def list_authenticated_servers(self) -> list[str]:
        """Get list of servers with stored tokens.

        Returns:
            List of server URLs with stored tokens
        """
        return self._store.list_resources()


# Global singleton for convenient access (thread-safe)
_manager: OAuthManager | None = None
_manager_lock = threading.Lock()


def get_oauth_manager() -> OAuthManager:
    """Get the global OAuth manager instance (thread-safe).

    Uses double-checked locking pattern for efficient thread-safe
    singleton initialization.

    Returns:
        The singleton OAuthManager instance
    """
    global _manager
    if _manager is None:
        with _manager_lock:
            # Double-check after acquiring lock
            if _manager is None:
                _manager = OAuthManager()
    return _manager
