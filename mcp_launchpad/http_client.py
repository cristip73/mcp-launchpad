"""HTTP client plumbing shared by the daemon and the direct (--no-daemon) path.

Two problems with long-lived MCP sessions over streamable HTTP live here:

1. Short-lived OAuth tokens. The Authorization header used to be baked into
   the httpx client once, at connect time. A daemon session outliving the
   access token (Storyblocks: ~10 minutes) then sent a dead token forever,
   even after another process had refreshed it. ``OAuthBearerAuth`` instead
   reads the shared token store on every request, refreshes it (under a
   cross-process lock) shortly before expiry, and retries once on 401.

2. Swallowed server errors. For any HTTP status >= 400 whose body is not a
   JSON-RPC error, the MCP SDK replaces the body with the fixed text
   "Server returned an error response". ``ErrorBodyTransport`` rewrites such
   bodies into a JSON-RPC error that carries the status and the server's own
   text, and passes JSON-RPC results sent with an error status through as 200.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import AsyncGenerator, Generator
from typing import Any

import httpx

from .oauth import get_oauth_manager
from .oauth.manager import OAuthManager

logger = logging.getLogger("mcpl.http")

# How much of a non-JSON-RPC error body to surface to the caller
ERROR_BODY_MAX_CHARS = int(os.environ.get("MCPL_ERROR_BODY_MAX_CHARS", "1000"))

# JSON-RPC "internal error" code used for synthesized errors
_INTERNAL_ERROR = -32603

# Response headers that no longer describe a rewritten (decoded) body
_DROP_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "content-type"}


def token_fingerprint(access_token: str) -> str:
    """Short non-reversible id of a token, safe for logs."""
    return hashlib.sha256(access_token.encode()).hexdigest()[:10]


class OAuthBearerAuth(httpx.Auth):
    """Bearer auth that always uses the freshest token from the shared store."""

    requires_response_body = False

    def __init__(
        self,
        server_url: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        manager: OAuthManager | None = None,
    ) -> None:
        self.server_url = server_url
        self.client_id = client_id
        self.client_secret = client_secret
        self._manager = manager

    @property
    def manager(self) -> OAuthManager:
        return self._manager or get_oauth_manager()

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        # Sync clients are not used for MCP traffic; send the stored token as is.
        try:
            token = self.manager.get_token(self.server_url)
        except Exception as e:
            logger.warning(f"Could not read OAuth token for {self.server_url}: {e}")
            token = None
        if token is not None:
            request.headers["Authorization"] = token.get_auth_header()
        yield request

    async def _token(self, rejected: str | None = None) -> Any:
        try:
            return await self.manager.get_fresh_token(
                self.server_url,
                rejected_access_token=rejected,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        except Exception as e:
            # Never let token plumbing crash the transport: send without (or
            # with the old) credentials and let the server answer 401.
            logger.warning(f"Could not get OAuth token for {self.server_url}: {e}")
            return None

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        token = await self._token()
        used = token.access_token if token is not None else None
        if token is not None:
            request.headers["Authorization"] = token.get_auth_header()
            logger.debug(
                f"OAuth {request.method} {self.server_url} token fp={token_fingerprint(token.access_token)}"
            )

        response = yield request

        if response.status_code != 401:
            return

        # Rejected: refresh (or pick up a token another process stored) and
        # retry exactly once, only if we actually have a different token.
        new_token = await self._token(rejected=used if used is not None else "")
        if new_token is None or new_token.access_token == used:
            return
        logger.info(
            f"Server rejected the OAuth token for {self.server_url}; retrying with "
            f"fp={token_fingerprint(new_token.access_token)}"
        )
        request.headers["Authorization"] = new_token.get_auth_header()
        yield request


def _jsonrpc_request_id(request: httpx.Request) -> tuple[bool, Any]:
    """Return (is_jsonrpc_request, id) for a POSTed JSON-RPC request."""
    if request.method != "POST":
        return False, None
    try:
        payload = json.loads(request.content)
    except Exception:
        return False, None
    if not isinstance(payload, dict) or "id" not in payload or "method" not in payload:
        return False, None
    return True, payload["id"]


def _parse_jsonrpc_body(body: bytes, content_type: str) -> dict[str, Any] | None:
    """Extract a JSON-RPC response message from a JSON or SSE body."""
    text = body.decode("utf-8", errors="replace")
    candidates: list[str] = []
    if content_type.startswith("text/event-stream"):
        candidates = [
            line[5:].strip() for line in text.splitlines() if line.startswith("data:")
        ]
    else:
        candidates = [text]
    for candidate in candidates:
        try:
            msg = json.loads(candidate)
        except Exception:
            continue
        if (
            isinstance(msg, dict)
            and msg.get("jsonrpc") == "2.0"
            and ("result" in msg or "error" in msg)
        ):
            return msg
    return None


def _redact(text: str, request: httpx.Request) -> str:
    """Never echo the bearer credential back to the caller."""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        secret = auth[7:].strip()
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


class ErrorBodyTransport(httpx.AsyncBaseTransport):
    """Keep the server's error text for JSON-RPC requests answered with >= 400."""

    def __init__(self, inner: httpx.AsyncBaseTransport | None = None) -> None:
        self._inner = inner or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        # 404 keeps its SDK meaning (session terminated / method not found)
        if response.status_code < 400 or response.status_code == 404:
            return response
        is_request, request_id = _jsonrpc_request_id(request)
        if not is_request:
            return response

        try:
            body = await response.aread()
        finally:
            await response.aclose()

        content_type = response.headers.get("content-type", "").lower()
        headers = [
            (k, v) for k, v in response.headers.multi_items() if k.lower() not in _DROP_HEADERS
        ]
        headers.append(("content-type", "application/json"))

        message = _parse_jsonrpc_body(body, content_type)
        if message is not None:
            if "result" in message:
                # A full JSON-RPC result (often isError: true) sent with an
                # error status: the SDK would drop it, so hand it over as 200.
                return httpx.Response(
                    200, headers=headers, content=json.dumps(message).encode(), request=request
                )
            # JSON-RPC error: the SDK already surfaces these at >= 400
            return httpx.Response(
                response.status_code,
                headers=headers,
                content=json.dumps(message).encode(),
                request=request,
            )

        text = _redact(body.decode("utf-8", errors="replace").strip(), request)
        if len(text) > ERROR_BODY_MAX_CHARS:
            text = text[:ERROR_BODY_MAX_CHARS] + "..."
        reason = response.reason_phrase or ""
        summary = f"HTTP {response.status_code}{(' ' + reason) if reason else ''}"
        error = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": _INTERNAL_ERROR,
                "message": f"{summary}: {text}" if text else summary,
            },
        }
        return httpx.Response(
            response.status_code,
            headers=headers,
            content=json.dumps(error).encode(),
            request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


def build_http_client(
    server_name: str,
    url: str,
    headers: dict[str, str],
    api_key: str | None,
    timeout: httpx.Timeout,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> httpx.AsyncClient:
    """Create the httpx client for an HTTP MCP server.

    Auth priority: an explicit Authorization header, then a static API key,
    then OAuth tokens from the shared store (re-read on every request).
    """
    headers = dict(headers)
    auth: httpx.Auth | None = None
    if "Authorization" not in headers:
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            logger.debug(f"Using static API key for '{server_name}'")
        else:
            auth = OAuthBearerAuth(url, client_id=client_id, client_secret=client_secret)
    return httpx.AsyncClient(
        headers=headers,
        auth=auth,
        timeout=timeout,
        transport=ErrorBodyTransport(),
    )
