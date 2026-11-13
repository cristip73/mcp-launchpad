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
   "Server returned an error response". ``McpHttpClient`` rewrites such
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
# Never buffer more than this of an error body
ERROR_BODY_MAX_BYTES = 64 * 1024

# JSON-RPC "internal error" code used for synthesized errors
_INTERNAL_ERROR = -32603

# Response headers that no longer describe a rewritten (decoded) body
_DROP_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "content-type"}


def token_fingerprint(access_token: str) -> str:
    """Short non-reversible id of a token, safe for logs."""
    return hashlib.sha256(access_token.encode()).hexdigest()[:10]


# Request extension listing every bearer this auth flow put on the request.
# The retry mutates the same request, so its final headers only show the
# last token; the redaction of error bodies needs all of them.
SENT_BEARERS_EXTENSION = "mcpl_sent_bearers"


def _set_bearer(request: httpx.Request, header_value: str) -> None:
    request.headers["Authorization"] = header_value
    sent = request.extensions.setdefault(SENT_BEARERS_EXTENSION, [])
    secret = header_value[7:].strip() if header_value.lower().startswith("bearer ") else ""
    if secret and secret not in sent:
        sent.append(secret)


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
            _set_bearer(request, token.get_auth_header())
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
        _set_bearer(request, new_token.get_auth_header())
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


def _bearer_secrets(response: httpx.Response) -> list[str]:
    """Every bearer credential sent for this response (incl. auth retries)."""
    secrets: list[str] = []
    for resp in [*response.history, response]:
        try:
            req = resp.request
        except RuntimeError:  # response without a request
            continue
        candidates = list(req.extensions.get(SENT_BEARERS_EXTENSION, []))
        auth = req.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            candidates.append(auth[7:].strip())
        for secret in candidates:
            if secret and secret not in secrets:
                secrets.append(secret)
    # Longest first, so a token containing another is fully redacted
    return sorted(secrets, key=len, reverse=True)


def _redact(text: str, secrets: list[str]) -> str:
    """Never echo a bearer credential back to the caller."""
    for secret in secrets:
        text = text.replace(secret, "[redacted]")
    return text


async def _read_bounded(response: httpx.Response, content_type: str) -> bytes:
    """Read an error body, at most ERROR_BODY_MAX_BYTES.

    An SSE body is parsed as it arrives and the read stops at the first
    JSON-RPC message, so a stream the server keeps open does not hang us.
    """
    buf = bytearray()
    is_sse = content_type.startswith("text/event-stream")
    async for chunk in response.aiter_bytes():
        buf += chunk
        if len(buf) >= ERROR_BODY_MAX_BYTES:
            break
        if is_sse and _parse_jsonrpc_body(bytes(buf), content_type) is not None:
            break
    return bytes(buf[:ERROR_BODY_MAX_BYTES])


async def rewrite_error_response(
    request: httpx.Request, response: httpx.Response
) -> httpx.Response:
    """Keep the server's error text for a JSON-RPC request answered with >= 400.

    Runs after auth handling, so a 401 has already been refreshed and retried
    (and a final 401 keeps its status for the OAuth-required check).
    """
    # 404 keeps its SDK meaning (session terminated / method not found)
    if response.status_code < 400 or response.status_code == 404:
        return response
    is_request, request_id = _jsonrpc_request_id(request)
    if not is_request:
        return response

    content_type = response.headers.get("content-type", "").lower()
    try:
        body = await _read_bounded(response, content_type)
    finally:
        await response.aclose()

    secrets = _bearer_secrets(response)
    headers = [
        (k, v) for k, v in response.headers.multi_items() if k.lower() not in _DROP_HEADERS
    ]
    headers.append(("content-type", "application/json"))

    def _reply(status: int, payload: dict[str, Any]) -> httpx.Response:
        content = _redact(json.dumps(payload), secrets).encode()
        return httpx.Response(status, headers=headers, content=content, request=request)

    message = _parse_jsonrpc_body(body, content_type)
    if message is not None and response.status_code != 401:
        if "result" in message:
            # A full JSON-RPC result (often isError: true) sent with an
            # error status: the SDK would drop it, so hand it over as 200.
            return _reply(200, message)
        # JSON-RPC error: the SDK already surfaces these at >= 400
        return _reply(response.status_code, message)
    if message is not None and "error" in message:
        return _reply(response.status_code, message)

    text = _redact(body.decode("utf-8", errors="replace").strip(), secrets)
    if len(text) > ERROR_BODY_MAX_CHARS:
        text = text[:ERROR_BODY_MAX_CHARS] + "..."
    reason = response.reason_phrase or ""
    summary = f"HTTP {response.status_code}{(' ' + reason) if reason else ''}"
    return _reply(
        response.status_code,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": _INTERNAL_ERROR,
                "message": f"{summary}: {text}" if text else summary,
            },
        },
    )


class McpHttpClient(httpx.AsyncClient):
    """httpx client that keeps server error text (see rewrite_error_response).

    Done in ``send`` rather than in a custom transport: a custom transport
    disables httpx's environment proxy routing, and ``send`` runs after the
    auth flow, so 401 refresh/retry still sees the original response.
    """

    async def send(
        self, request: httpx.Request, *, stream: bool = False, **kwargs: Any
    ) -> httpx.Response:
        # Always stream internally so an error body is read bounded (also for
        # plain .post() calls such as the connection preflight), then honour
        # the caller's buffering choice.
        response = await super().send(request, stream=True, **kwargs)
        response = await rewrite_error_response(request, response)
        if not stream:
            try:
                await response.aread()
            except BaseException:
                await response.aclose()
                raise
        return response


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
    return McpHttpClient(headers=headers, auth=auth, timeout=timeout)
