"""Short-lived OAuth tokens: per-request auth, locked refresh, error bodies.

Covers the three defects seen with the Storyblocks MCP server (10-minute
access tokens, no DCR, errors sent with an HTTP error status):

1. a long-lived session kept sending the token it connected with;
2. a configured (non-DCR) client was not stored at login, so refresh failed;
3. the server's error text was replaced by "Server returned an error response".
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcp_launchpad.http_client import McpHttpClient, OAuthBearerAuth, build_http_client
from mcp_launchpad.oauth import manager as manager_module
from mcp_launchpad.oauth.flow import OAuthFlow
from mcp_launchpad.oauth.manager import OAuthManager
from mcp_launchpad.oauth.store import TokenStore
from mcp_launchpad.oauth.tokens import ClientCredentials, TokenSet

SERVER_URL = "https://mcp.example.com/mcp"
ISSUER = "https://auth.example.com"


@pytest.fixture
def store(tmp_path: Path) -> TokenStore:
    # Fallback (machine-derived) key: never touch the real OS keychain in tests
    with patch(
        "mcp_launchpad.oauth.store.keyring.get_password",
        side_effect=Exception("no keyring in tests"),
    ):
        return TokenStore(store_dir=tmp_path / "oauth")


def _token(access: str, expires_in: int, refresh: str | None = "rt-1") -> TokenSet:
    now = datetime.now(timezone.utc)
    return TokenSet(
        access_token=access,
        token_type="Bearer",
        resource=SERVER_URL,
        refresh_token=refresh,
        expires_at=now + timedelta(seconds=expires_in),
        issued_at=now,
    )


def _oauth_config() -> MagicMock:
    cfg = MagicMock()
    cfg.auth_server_metadata.issuer = ISSUER
    cfg.resource_uri = SERVER_URL
    return cfg


@pytest.fixture
def manager(store: TokenStore) -> OAuthManager:
    m = OAuthManager(_store=store)
    m._oauth_configs[SERVER_URL] = _oauth_config()
    return m


def _refresh_mock(*access_tokens: str, delay: float = 0.0) -> AsyncMock:
    """A refresh_token() stand-in that hands out the given tokens in order."""
    queue = list(access_tokens)

    async def _refresh(metadata: Any, client: Any, rt: str, resource: str) -> dict[str, Any]:
        if delay:
            await asyncio.sleep(delay)
        return {"access_token": queue.pop(0), "expires_in": 600, "refresh_token": "rt-2"}

    return AsyncMock(side_effect=_refresh)


# ---------------------------------------------------------------------------
# Token store: read-modify-write under one lock, atomic 0600 files
# ---------------------------------------------------------------------------


class TestStoreWrites:
    def test_set_token_keeps_other_entries_and_0600(self, store: TokenStore) -> None:
        store.set_token("https://a.example.com", _token("a", 600))
        store.set_token("https://b.example.com", _token("b", 600))
        assert store.get_token("https://a.example.com").access_token == "a"
        assert store.get_token("https://b.example.com").access_token == "b"
        mode = stat.S_IMODE((store.store_dir / "tokens.json").stat().st_mode)
        assert mode == 0o600
        # No temp files left behind
        assert not [p for p in store.store_dir.iterdir() if p.name.endswith(".tmp")]

    def test_delete_missing_returns_false(self, store: TokenStore) -> None:
        assert store.delete_token("https://nope.example.com") is False
        assert store.delete_client("https://nope.example.com") is False


# ---------------------------------------------------------------------------
# Defect 2: configured client must be stored / usable for refresh
# ---------------------------------------------------------------------------


class TestConfiguredClient:
    @pytest.mark.asyncio
    async def test_login_with_configured_client_stores_it(self, store: TokenStore) -> None:
        flow = OAuthFlow(
            server_url=SERVER_URL,
            token_store=store,
            client_id="https://client.example.com/metadata.json",
            callback_port=47391,
        )
        callback = MagicMock()
        callback.redirect_uri = "http://localhost:47391/callback"
        callback.wait_for_callback = AsyncMock(
            return_value=MagicMock(
                is_success=lambda: True, state="fixed-state", code="the-code"
            )
        )
        cb_cm = MagicMock()
        cb_cm.__aenter__ = AsyncMock(return_value=callback)
        cb_cm.__aexit__ = AsyncMock(return_value=False)

        with (
            patch.object(OAuthFlow, "discover", AsyncMock(return_value=_oauth_config())),
            patch("mcp_launchpad.oauth.flow.LocalhostCallbackServer", return_value=cb_cm),
            patch("mcp_launchpad.oauth.flow.build_authorization_url", return_value="https://x"),
            patch("mcp_launchpad.oauth.flow.generate_state", return_value="fixed-state"),
            patch("mcp_launchpad.oauth.flow.webbrowser.open", return_value=True),
            patch(
                "mcp_launchpad.oauth.flow.exchange_code_for_tokens",
                AsyncMock(return_value={"access_token": "at", "expires_in": 600, "refresh_token": "rt"}),
            ),
        ):
            await flow.run()

        client = store.get_client(ISSUER)
        assert client is not None
        assert client.client_id == "https://client.example.com/metadata.json"
        assert client.redirect_uri == "http://localhost:47391/callback"

    @pytest.mark.asyncio
    async def test_refresh_falls_back_to_configured_client(
        self, store: TokenStore, manager: OAuthManager
    ) -> None:
        store.set_token(SERVER_URL, _token("old", -10))
        refresh = _refresh_mock("new")
        with patch.object(manager_module, "refresh_token", refresh):
            # Without a client anywhere, refresh cannot happen
            assert await manager.refresh_if_needed(SERVER_URL) is False
            refresh.assert_not_called()
            # With the configured client id it works, and the client is persisted
            assert await manager.refresh_if_needed(SERVER_URL, client_id="cid") is True
        assert refresh.await_count == 1
        assert refresh.await_args.args[1].client_id == "cid"
        assert store.get_token(SERVER_URL).access_token == "new"
        assert store.get_client(ISSUER).client_id == "cid"


# ---------------------------------------------------------------------------
# Defect 1: refresh before expiry, on 401, and pick up other processes' tokens
# ---------------------------------------------------------------------------


class TestFreshToken:
    @pytest.mark.asyncio
    async def test_valid_token_is_not_refreshed(self, store, manager) -> None:
        store.set_token(SERVER_URL, _token("live", 600))
        refresh = _refresh_mock("x")
        with patch.object(manager_module, "refresh_token", refresh):
            token = await manager.get_fresh_token(SERVER_URL)
        assert token.access_token == "live"
        refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_nearly_expired_token_is_refreshed(self, store, manager) -> None:
        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("old", 20))  # inside the 60 s buffer
        refresh = _refresh_mock("new")
        with patch.object(manager_module, "refresh_token", refresh):
            token = await manager.get_fresh_token(SERVER_URL)
        assert token.access_token == "new"
        assert store.get_token(SERVER_URL).refresh_token == "rt-2"

    @pytest.mark.asyncio
    async def test_rejected_token_forces_refresh(self, store, manager) -> None:
        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("revoked", 600))
        refresh = _refresh_mock("new")
        with patch.object(manager_module, "refresh_token", refresh):
            token = await manager.get_fresh_token(SERVER_URL, rejected_access_token="revoked")
        assert token.access_token == "new"

    @pytest.mark.asyncio
    async def test_rejected_token_but_store_already_newer(self, store, manager) -> None:
        """Another process refreshed: use its token, do not redeem again."""
        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("from-other-process", 600))
        refresh = _refresh_mock("x")
        with patch.object(manager_module, "refresh_token", refresh):
            token = await manager.get_fresh_token(SERVER_URL, rejected_access_token="mine-old")
        assert token.access_token == "from-other-process"
        refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_concurrent_refreshes_redeem_once(self, store, manager) -> None:
        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("old", -10))
        refresh = _refresh_mock("new-1", "new-2", "new-3", delay=0.2)
        with patch.object(manager_module, "refresh_token", refresh):
            tokens = await asyncio.gather(
                *(manager.get_fresh_token(SERVER_URL) for _ in range(3))
            )
        assert refresh.await_count == 1
        assert {t.access_token for t in tokens} == {"new-1"}

    @pytest.mark.asyncio
    async def test_waits_for_lock_held_by_other_process_then_rereads(
        self, store, manager
    ) -> None:
        """Simulates another process mid-refresh holding the refresh lock."""
        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("old", -10))
        lock_path = store.store_dir / manager_module.REFRESH_LOCK_FILE
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)  # separate fd = separate lock owner
        refresh = _refresh_mock("mine")
        try:
            with patch.object(manager_module, "refresh_token", refresh):
                task = asyncio.create_task(manager.get_fresh_token(SERVER_URL))
                await asyncio.sleep(0.3)
                assert not task.done()  # blocked on the lock
                # The "other process" finishes its refresh and releases the lock
                store.set_token(SERVER_URL, _token("theirs", 600))
                fcntl.flock(fd, fcntl.LOCK_UN)
                token = await asyncio.wait_for(task, 5)
        finally:
            os.close(fd)
        assert token.access_token == "theirs"
        refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_failed_refresh_returns_current_token(self, store, manager) -> None:
        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("old", -10))
        from mcp_launchpad.oauth.flow import TokenExchangeError

        with patch.object(
            manager_module, "refresh_token", AsyncMock(side_effect=TokenExchangeError("invalid_grant"))
        ):
            token = await manager.get_fresh_token(SERVER_URL)
            assert await manager.refresh_if_needed(SERVER_URL) is False
        assert token.access_token == "old"

    @pytest.mark.asyncio
    async def test_proactive_refresh_skips_when_other_process_refreshed(
        self, store, manager
    ) -> None:
        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("fresh", 3000))
        refresh = _refresh_mock("x")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await manager.refresh_proactively(SERVER_URL, min_remaining_seconds=600)
            refresh.assert_not_called()
            # Forced (CLI `mcpl auth refresh`) always redeems
            assert await manager.refresh_proactively(SERVER_URL)
        assert refresh.await_count == 1


# ---------------------------------------------------------------------------
# OAuthBearerAuth: header per request, one retry on 401
# ---------------------------------------------------------------------------


class TestBearerAuth:
    @pytest.mark.asyncio
    async def test_header_follows_the_store(self, store, manager) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("Authorization", ""))
            return httpx.Response(200, json={})

        store.set_token(SERVER_URL, _token("first", 600))
        auth = OAuthBearerAuth(SERVER_URL, manager=manager)
        async with httpx.AsyncClient(auth=auth, transport=httpx.MockTransport(handler)) as c:
            await c.post(SERVER_URL, json={})
            store.set_token(SERVER_URL, _token("second", 600))  # e.g. `mcpl auth refresh` elsewhere
            await c.post(SERVER_URL, json={})
        assert seen == ["Bearer first", "Bearer second"]

    @pytest.mark.asyncio
    async def test_401_refreshes_and_retries_once(self, store, manager) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("Authorization", "")
            seen.append(auth)
            if auth == "Bearer new":
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(401, json={"error": "invalid_token"})

        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("dead", 600))  # not expired by clock
        with patch.object(manager_module, "refresh_token", _refresh_mock("new")):
            auth = OAuthBearerAuth(SERVER_URL, manager=manager)
            async with httpx.AsyncClient(auth=auth, transport=httpx.MockTransport(handler)) as c:
                r = await c.post(SERVER_URL, json={})
        assert r.status_code == 200
        assert seen == ["Bearer dead", "Bearer new"]

    @pytest.mark.asyncio
    async def test_401_without_new_token_is_returned(self, store, manager) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(401, json={"error": "invalid_token"})

        store.set_token(SERVER_URL, _token("dead", 600, refresh=None))
        auth = OAuthBearerAuth(SERVER_URL, manager=manager)
        async with httpx.AsyncClient(auth=auth, transport=httpx.MockTransport(handler)) as c:
            r = await c.post(SERVER_URL, json={})
        assert r.status_code == 401
        assert calls == 1  # no retry loop

    def test_static_api_key_skips_oauth(self) -> None:
        client = build_http_client("s", SERVER_URL, {}, "key", httpx.Timeout(5))
        assert client.auth is None or not isinstance(client.auth, OAuthBearerAuth)
        assert client.headers["Authorization"] == "Bearer key"

    def test_explicit_header_skips_oauth(self) -> None:
        client = build_http_client("s", SERVER_URL, {"Authorization": "Token x"}, None, httpx.Timeout(5))
        assert not isinstance(client.auth, OAuthBearerAuth)

    def test_oauth_when_no_key(self) -> None:
        client = build_http_client("s", SERVER_URL, {}, None, httpx.Timeout(5), client_id="cid")
        assert isinstance(client.auth, OAuthBearerAuth)
        assert client.auth.client_id == "cid"
        assert "Authorization" not in client.headers


# ---------------------------------------------------------------------------
# Defect 3: keep the server's error text
# ---------------------------------------------------------------------------


def _rpc(method: str = "tools/call", rid: Any = 7) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": {}}


async def _send(handler, payload: Any, method: str = "POST", headers=None) -> httpx.Response:
    async with McpHttpClient(transport=httpx.MockTransport(handler), headers=headers or {}) as c:
        if method == "POST":
            return await c.post(SERVER_URL, json=payload)
        return await c.get(SERVER_URL)


class TestErrorBodyRewrite:
    @pytest.mark.asyncio
    async def test_text_error_becomes_jsonrpc_error(self) -> None:
        def handler(request):
            return httpx.Response(403, text="[not_entitled] This item isn't included on your current plan.")

        r = await _send(handler, _rpc())
        assert r.status_code == 403
        body = r.json()
        assert body["id"] == 7
        assert "HTTP 403" in body["error"]["message"]
        assert "not_entitled" in body["error"]["message"]

    @pytest.mark.asyncio
    async def test_jsonrpc_result_with_error_status_passes_as_200(self) -> None:
        result = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "nope"}], "isError": True}}

        def handler(request):
            return httpx.Response(400, json=result)

        r = await _send(handler, _rpc())
        assert r.status_code == 200
        assert r.json() == result

    @pytest.mark.asyncio
    async def test_sse_result_with_error_status_passes_as_200(self) -> None:
        result = {"jsonrpc": "2.0", "id": 7, "result": {"content": [], "isError": True}}

        def handler(request):
            return httpx.Response(
                403,
                headers={"content-type": "text/event-stream"},
                text=f"event: message\ndata: {json.dumps(result)}\n\n",
            )

        r = await _send(handler, _rpc())
        assert r.status_code == 200
        assert r.json() == result

    @pytest.mark.asyncio
    async def test_401_keeps_status_and_www_authenticate(self) -> None:
        def handler(request):
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": 'Bearer resource_metadata="x"'},
                json={"error": "invalid_token", "error_description": "Invalid or expired token"},
            )

        r = await _send(handler, _rpc("initialize", 0))
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"] == 'Bearer resource_metadata="x"'
        assert "Invalid or expired token" in r.json()["error"]["message"]

    @pytest.mark.asyncio
    async def test_bearer_token_is_redacted(self) -> None:
        def handler(request):
            return httpx.Response(500, text="bad token secret-abc in request")

        r = await _send(handler, _rpc(), headers={"Authorization": "Bearer secret-abc"})
        assert "secret-abc" not in r.text
        assert "[redacted]" in r.json()["error"]["message"]

    @pytest.mark.asyncio
    async def test_untouched_cases(self) -> None:
        def handler(request):
            return httpx.Response(404 if request.method == "POST" else 405, text="raw")

        # 404 keeps its SDK meaning
        assert (await _send(handler, _rpc())).text == "raw"
        # GET (SSE listen stream) untouched
        assert (await _send(handler, None, method="GET")).text == "raw"

        def handler2(request):
            return httpx.Response(500, text="raw")

        # notifications (no id) untouched
        assert (await _send(handler2, {"jsonrpc": "2.0", "method": "notifications/initialized"})).text == "raw"


# ---------------------------------------------------------------------------
# End to end through the MCP SDK client
# ---------------------------------------------------------------------------


def _mcp_server(tool_status: int, tool_body: str | None, accepted: dict[str, str] | None = None):
    """A tiny streamable-HTTP MCP server on a MockTransport.

    tool_body=None answers tools/call with a normal successful result.
    accepted["token"], if given, is the only bearer the server accepts.
    """

    seen_auth: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method != "POST":
            return httpx.Response(405)
        seen_auth.append(request.headers.get("Authorization", ""))
        if accepted and request.headers.get("Authorization") != f"Bearer {accepted['token']}":
            return httpx.Response(401, json={"error": "invalid_token"})
        msg = json.loads(request.content)
        if "id" not in msg:
            return httpx.Response(202)
        if msg["method"] == "initialize":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "protocolVersion": msg["params"]["protocolVersion"],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock", "version": "1"},
                    },
                },
            )
        if msg["method"] == "tools/list":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {"tools": [{"name": "x", "inputSchema": {"type": "object"}}]},
                },
            )
        if msg["method"] == "tools/call" and tool_body is not None:
            return httpx.Response(tool_status, text=tool_body)
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [], "isError": False}},
        )

    return handler, seen_auth


class TestThroughSdk:
    @pytest.mark.asyncio
    async def test_server_error_text_reaches_the_caller(self) -> None:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        handler, _ = _mcp_server(403, "[not_entitled] This item isn't included on your current plan.")
        client = McpHttpClient(transport=httpx.MockTransport(handler))
        async with client:
            async with streamable_http_client(SERVER_URL, http_client=client, terminate_on_close=False) as t:
                async with ClientSession(t[0], t[1]) as session:
                    await session.initialize()
                    with pytest.raises(Exception) as exc_info:
                        await session.call_tool("some_tool", {})
        assert "not_entitled" in str(exc_info.value)
        assert "Server returned an error response" not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_session_survives_token_rotation(self, store, manager) -> None:
        """Server stops accepting the token mid-session; next call refreshes, no reconnect."""
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        accepted = {"token": "t1"}
        handler, seen = _mcp_server(200, None, accepted=accepted)
        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("t1", 600))

        auth = OAuthBearerAuth(SERVER_URL, manager=manager)
        client = McpHttpClient(auth=auth, transport=httpx.MockTransport(handler))
        with patch.object(manager_module, "refresh_token", _refresh_mock("t2")):
            async with client:
                async with streamable_http_client(
                    SERVER_URL, http_client=client, terminate_on_close=False
                ) as t:
                    async with ClientSession(t[0], t[1]) as session:
                        await session.initialize()
                        await session.call_tool("x", {})
                        n_before = len(seen)
                        accepted["token"] = "t2"  # t1 still "valid" by the clock
                        result = await session.call_tool("x", {})
        assert getattr(result, "is_error", getattr(result, "isError", None)) is False
        assert seen[n_before:] == ["Bearer t1", "Bearer t2"]
        assert store.get_token(SERVER_URL).access_token == "t2"


# ---------------------------------------------------------------------------
# Review round 1 (Codex) regressions
# ---------------------------------------------------------------------------


class TestReviewRound1:
    @pytest.mark.asyncio
    async def test_lock_timeout_fails_closed(self, store, manager, monkeypatch) -> None:
        """B2: a lock held past the deadline must not lead to a second redemption."""
        monkeypatch.setattr(manager_module, "REFRESH_LOCK_TIMEOUT", 0.3)
        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("old", -10))
        fd = os.open(store.store_dir / manager_module.REFRESH_LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        refresh = _refresh_mock("x")
        try:
            with patch.object(manager_module, "refresh_token", refresh):
                token = await manager.get_fresh_token(SERVER_URL)
                assert await manager.refresh_proactively(SERVER_URL) is False
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        assert token.access_token == "old"
        refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_parsed_jsonrpc_bodies_are_redacted(self) -> None:
        """B3: a JSON-RPC result/error echoing the bearer is redacted too."""
        result = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "got secret-abc"}], "isError": True}}
        error = {"jsonrpc": "2.0", "id": 7, "error": {"code": -1, "message": "bad secret-abc"}}
        for status, body in ((400, result), (403, error)):
            r = await _send(lambda req, b=body, st=status: httpx.Response(st, json=b), _rpc(),
                            headers={"Authorization": "Bearer secret-abc"})
            assert "secret-abc" not in r.text
            assert "[redacted]" in r.text

    @pytest.mark.asyncio
    async def test_401_with_jsonrpc_result_still_triggers_refresh(self, store, manager) -> None:
        """B4: rewriting runs after auth, so the 401 is seen and retried."""
        seen: list[str] = []
        bad = {"jsonrpc": "2.0", "id": 7, "result": {"content": [], "isError": True}}
        good = {"jsonrpc": "2.0", "id": 7, "result": {"content": [], "isError": False}}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("Authorization", ""))
            if request.headers.get("Authorization") == "Bearer new":
                return httpx.Response(200, json=good)
            return httpx.Response(401, json=bad)

        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("dead", 600))
        with patch.object(manager_module, "refresh_token", _refresh_mock("new")):
            auth = OAuthBearerAuth(SERVER_URL, manager=manager)
            async with McpHttpClient(auth=auth, transport=httpx.MockTransport(handler)) as c:
                r = await c.post(SERVER_URL, json=_rpc())
        assert seen == ["Bearer dead", "Bearer new"]
        assert r.status_code == 200 and r.json() == good

    @pytest.mark.asyncio
    async def test_final_401_keeps_status_even_with_result_body(self) -> None:
        bad = {"jsonrpc": "2.0", "id": 7, "result": {"content": [], "isError": True}}
        r = await _send(lambda req: httpx.Response(401, json=bad), _rpc())
        assert r.status_code == 401
        assert "error" in r.json()

    def test_env_proxies_are_kept(self, monkeypatch) -> None:
        """B5: no custom transport, so httpx still mounts HTTPS_PROXY."""
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
        client = build_http_client("s", SERVER_URL, {}, None, httpx.Timeout(5))
        assert any("proxy" in repr(t).lower() or "proxy" in repr(vars(t)).lower()
                   for t in client._mounts.values() if t is not None)

    @pytest.mark.asyncio
    async def test_configured_client_beats_other_servers_stored_client(self, store, manager) -> None:
        """B6: another server's DCR client on the same issuer is not used for ours."""
        store.set_client(ISSUER, ClientCredentials("dcr-client-of-server-a"))
        store.set_token(SERVER_URL, _token("old", -10))
        refresh = _refresh_mock("new")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await manager.refresh_if_needed(SERVER_URL, client_id="configured-b")
        assert refresh.await_args.args[1].client_id == "configured-b"
        # Server A's stored client is left alone
        assert store.get_client(ISSUER).client_id == "dcr-client-of-server-a"

    @pytest.mark.asyncio
    async def test_sse_error_stream_left_open_does_not_hang(self) -> None:
        """M2: stop reading at the first JSON-RPC message."""
        result = {"jsonrpc": "2.0", "id": 7, "result": {"content": [], "isError": True}}

        class OpenStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield f"event: message\ndata: {json.dumps(result)}\n\n".encode()
                await asyncio.sleep(3600)  # server never closes
                yield b""

        def handler(request):
            return httpx.Response(403, headers={"content-type": "text/event-stream"}, stream=OpenStream())

        async def go() -> httpx.Response:
            # stream=True, as the MCP SDK sends (a plain post() reads to EOF first)
            async with McpHttpClient(transport=httpx.MockTransport(handler)) as c:
                return await c.send(c.build_request("POST", SERVER_URL, json=_rpc()), stream=True)

        r = await asyncio.wait_for(go(), 5)
        assert r.status_code == 200 and r.json() == result


# ---------------------------------------------------------------------------
# Review round 2 (Codex) regressions + extra coverage
# ---------------------------------------------------------------------------

RESOURCE_A = "https://a.example.com"
RESOURCE_B = SERVER_URL


class TestReviewRound2:
    @pytest.mark.asyncio
    async def test_bearer_sent_before_retry_is_redacted(self, store, manager) -> None:
        """R2-B1: the retry mutates the request; the first bearer must still be redacted."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.headers.get("Authorization") == "Bearer old-secret":
                return httpx.Response(401, json={"error": "invalid_token"})
            return httpx.Response(500, text="saw old-secret and new-secret")

        store.set_client(ISSUER, ClientCredentials("cid"))
        store.set_token(SERVER_URL, _token("old-secret", 600))
        with patch.object(manager_module, "refresh_token", _refresh_mock("new-secret")):
            auth = OAuthBearerAuth(SERVER_URL, manager=manager)
            async with McpHttpClient(auth=auth, transport=httpx.MockTransport(handler)) as c:
                r = await c.post(SERVER_URL, json=_rpc())
        assert "old-secret" not in r.text and "new-secret" not in r.text
        assert r.json()["error"]["message"].count("[redacted]") == 2

    @pytest.mark.asyncio
    async def test_configured_id_keeps_stored_secret_of_same_id(self, store, manager) -> None:
        """R2-B2: secret given at login (stdin/env) is reused for the same client id."""
        store.set_client(ISSUER, ClientCredentials("cid", "stored-secret"))
        store.set_token(SERVER_URL, _token("old", -10))
        refresh = _refresh_mock("new")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await manager.refresh_if_needed(SERVER_URL, client_id="cid")
        used = refresh.await_args.args[1]
        assert (used.client_id, used.client_secret) == ("cid", "stored-secret")

    @pytest.mark.asyncio
    async def test_secret_of_a_different_client_is_never_borrowed(self, store, manager) -> None:
        store.set_client(ISSUER, ClientCredentials("other", "others-secret"))
        store.set_token(SERVER_URL, _token("old", -10))
        refresh = _refresh_mock("new")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await manager.refresh_if_needed(SERVER_URL, client_id="cid")
        used = refresh.await_args.args[1]
        assert (used.client_id, used.client_secret) == ("cid", None)
        assert store.get_client(ISSUER).client_id == "other"  # untouched

    @pytest.mark.asyncio
    async def test_login_client_kept_per_resource_when_issuer_taken(self, store) -> None:
        """R2-B3: server A has a DCR client on the issuer; login B with client-B.

        B's client must survive (per resource) and be used for B's refresh even
        without config (e.g. the daemon's background loop); A keeps its client.
        """
        store.set_client(ISSUER, ClientCredentials("dcr-a"))
        flow = OAuthFlow(server_url=RESOURCE_B, token_store=store, client_id="client-b",
                         client_secret="secret-b")
        await _run_login(flow)
        assert store.get_client(ISSUER).client_id == "dcr-a"
        assert store.get_client_for_resource(RESOURCE_B).client_id == "client-b"

        m = OAuthManager(_store=store)
        cfg_a = _oauth_config()
        cfg_a.resource_uri = RESOURCE_A
        m._oauth_configs[RESOURCE_B] = _oauth_config()
        m._oauth_configs[RESOURCE_A] = cfg_a
        store.set_token(RESOURCE_B, _token("b-old", -10))
        store.set_token(RESOURCE_A, _token("a-old", -10))
        refresh = _refresh_mock("b-new", "a-new")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await m.refresh_if_needed(RESOURCE_B)  # no client_id passed
            assert await m.refresh_if_needed(RESOURCE_A)
        used_b, used_a = (call.args[1] for call in refresh.await_args_list)
        assert (used_b.client_id, used_b.client_secret) == ("client-b", "secret-b")
        assert used_a.client_id == "dcr-a"

    def test_set_client_if_compatible(self, store) -> None:
        """R2-M5: conditional issuer write is atomic and never clobbers another id."""
        assert store.set_client_if_compatible(ISSUER, ClientCredentials("x", "s1"))
        assert not store.set_client_if_compatible(ISSUER, ClientCredentials("x", "s2"))
        assert store.set_client_if_compatible(ISSUER, ClientCredentials("x", "s2"), replace_same_id=True)
        assert store.get_client(ISSUER).client_secret == "s2"
        assert not store.set_client_if_compatible(ISSUER, ClientCredentials("y"), replace_same_id=True)
        assert store.get_client(ISSUER).client_id == "x"

    def test_resource_entries_do_not_disturb_issuer_lookup(self, store) -> None:
        """Old mcpl reads clients by issuer only; the new resource entries sit beside them."""
        store.set_client(ISSUER, ClientCredentials("issuer-client"))
        store.set_client_for_resource(RESOURCE_B, ClientCredentials("resource-client"))
        assert store.get_client(ISSUER).client_id == "issuer-client"
        raw = store._read_encrypted_file("clients.json")
        assert set(raw) == {ISSUER, "resource:" + RESOURCE_B}
        assert all("client_id" in v for v in raw.values())  # old from_dict still parses all

    @pytest.mark.asyncio
    async def test_preflight_post_with_open_sse_error_does_not_hang(self) -> None:
        """R2-M4: plain .post() (stream=False) is read bounded too."""
        result = {"jsonrpc": "2.0", "id": 0, "result": {"content": [], "isError": True}}

        class OpenStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield f"event: message\ndata: {json.dumps(result)}\n\n".encode()
                await asyncio.sleep(3600)
                yield b""

        def handler(request):
            return httpx.Response(403, headers={"content-type": "text/event-stream"}, stream=OpenStream())

        async def go():
            async with McpHttpClient(transport=httpx.MockTransport(handler)) as c:
                return await c.post(SERVER_URL, json=_rpc("initialize", 0))

        r = await asyncio.wait_for(go(), 5)
        assert r.status_code == 200 and r.json() == result

    @pytest.mark.asyncio
    async def test_large_error_body_is_capped(self) -> None:
        def handler(request):
            return httpx.Response(500, text="x" * 500_000)

        r = await _send(handler, _rpc())
        msg = r.json()["error"]["message"]
        assert len(msg) < 1100 and msg.endswith("...")

    @pytest.mark.asyncio
    async def test_success_responses_untouched_both_modes(self) -> None:
        def handler(request):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 7, "result": {"ok": True}})

        async with McpHttpClient(transport=httpx.MockTransport(handler)) as c:
            r1 = await c.post(SERVER_URL, json=_rpc())
            r2 = await c.send(c.build_request("POST", SERVER_URL, json=_rpc()), stream=True)
            body2 = json.loads(await r2.aread())
        assert r1.json()["result"] == {"ok": True} and body2["result"] == {"ok": True}


async def _run_login(flow: OAuthFlow) -> None:
    callback = MagicMock()
    callback.redirect_uri = "http://localhost:47391/callback"
    callback.wait_for_callback = AsyncMock(
        return_value=MagicMock(is_success=lambda: True, state="fixed-state", code="the-code")
    )
    cb_cm = MagicMock()
    cb_cm.__aenter__ = AsyncMock(return_value=callback)
    cb_cm.__aexit__ = AsyncMock(return_value=False)
    cfg = _oauth_config()
    cfg.resource_uri = flow.server_url
    with (
        patch.object(OAuthFlow, "discover", AsyncMock(return_value=cfg)),
        patch("mcp_launchpad.oauth.flow.LocalhostCallbackServer", return_value=cb_cm),
        patch("mcp_launchpad.oauth.flow.build_authorization_url", return_value="https://x"),
        patch("mcp_launchpad.oauth.flow.generate_state", return_value="fixed-state"),
        patch("mcp_launchpad.oauth.flow.webbrowser.open", return_value=True),
        patch(
            "mcp_launchpad.oauth.flow.exchange_code_for_tokens",
            AsyncMock(return_value={"access_token": "at", "expires_in": 600, "refresh_token": "rt"}),
        ),
    ):
        await flow.run()


# ---------------------------------------------------------------------------
# Real cross-process concurrency: N processes refresh one expired token at once
# ---------------------------------------------------------------------------

_CHILD = r'''
import asyncio, json, os, sys, fcntl
from pathlib import Path
from unittest.mock import MagicMock, patch
store_dir, count_file, url, issuer = sys.argv[1:5]
with patch("mcp_launchpad.oauth.store.keyring.get_password", side_effect=Exception("no keyring")):
    from mcp_launchpad.oauth.store import TokenStore
    store = TokenStore(store_dir=Path(store_dir))
from mcp_launchpad.oauth import manager as mm
async def fake_refresh(md, client, rt, resource):
    with open(count_file, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX); f.write(rt + "\n"); f.flush(); fcntl.flock(f, fcntl.LOCK_UN)
    await asyncio.sleep(0.5)
    n = sum(1 for _ in open(count_file))
    return {"access_token": f"at-{n}", "expires_in": 600, "refresh_token": f"rt-{n + 1}"}
async def main():
    m = mm.OAuthManager(_store=store)
    cfg = MagicMock(); cfg.auth_server_metadata.issuer = issuer; cfg.resource_uri = url
    m._oauth_configs[url] = cfg
    with patch.object(mm, "refresh_token", fake_refresh):
        t = await m.get_fresh_token(url)
    print(json.dumps({"access": t.access_token, "rt": t.refresh_token}))
asyncio.run(main())
'''


def test_parallel_processes_redeem_refresh_token_once(store, tmp_path) -> None:
    import subprocess
    import sys

    store.set_client(ISSUER, ClientCredentials("cid"))
    store.set_token(SERVER_URL, _token("old", -10, refresh="rt-1"))
    count_file = tmp_path / "redeemed.txt"
    count_file.touch()
    script = tmp_path / "child.py"
    script.write_text(_CHILD)
    procs = [
        subprocess.Popen(
            [sys.executable, str(script), str(store.store_dir), str(count_file), SERVER_URL, ISSUER],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=tmp_path,
        )
        for _ in range(4)
    ]
    outs = []
    for p in procs:
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, err
        outs.append(json.loads(out.strip().splitlines()[-1]))
    redeemed = count_file.read_text().split()
    assert redeemed == ["rt-1"]  # the rotating refresh token was redeemed exactly once
    assert {o["access"] for o in outs} == {"at-1"}
    assert {o["rt"] for o in outs} == {"rt-2"}
    assert store.get_token(SERVER_URL).refresh_token == "rt-2"


# ---------------------------------------------------------------------------
# Daemon background refresh threshold (round 1, M1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_background_refresh_skips_freshly_issued_short_token(store) -> None:
    from mcp_launchpad import daemon as daemon_module

    m = OAuthManager(_store=store)
    m._oauth_configs[SERVER_URL] = _oauth_config()
    store.set_client(ISSUER, ClientCredentials("cid"))
    d = MagicMock()
    refresh = _refresh_mock("new")
    with (
        patch.object(daemon_module, "get_oauth_manager", return_value=m),
        patch.object(manager_module, "refresh_token", refresh),
    ):
        # 10-minute token issued just now: half-life threshold (300 s) not reached
        store.set_token(SERVER_URL, _token("fresh", 590))
        await daemon_module.Daemon._refresh_oauth_tokens_once(d)
        refresh.assert_not_called()
        # Same token with 4 minutes left: inside the threshold, refreshed once
        aging = _token("aging", 240)
        aging.issued_at = aging.expires_at - timedelta(seconds=600)  # lifetime 600, 4 min left
        store.set_token(SERVER_URL, aging)
        await daemon_module.Daemon._refresh_oauth_tokens_once(d)
    assert refresh.await_count == 1


# ---------------------------------------------------------------------------
# Review round 3 (Codex) regressions
# ---------------------------------------------------------------------------


class TestReviewRound3:
    @pytest.mark.asyncio
    async def test_login_waits_for_running_refresh_and_wins(self, store) -> None:
        """R3-B1: a refresh started with client A cannot overwrite login B's pair."""
        m = OAuthManager(_store=store)
        m._oauth_configs[SERVER_URL] = _oauth_config()
        store.set_client(ISSUER, ClientCredentials("client-a"))
        store.set_token(SERVER_URL, _token("a-old", -10, refresh="rt-a"))

        refresh_started = asyncio.Event()

        async def slow_refresh(md, client, rt, resource):
            refresh_started.set()
            await asyncio.sleep(0.5)
            return {"access_token": "a-new", "expires_in": 600, "refresh_token": "rt-a2"}

        with patch.object(manager_module, "refresh_token", slow_refresh):
            refresh_task = asyncio.create_task(m.get_fresh_token(SERVER_URL))
            await refresh_started.wait()
            flow = OAuthFlow(server_url=SERVER_URL, token_store=store, client_id="client-b")
            await _run_login(flow)  # publishes after the refresh released the lock
            await refresh_task

        tok = store.get_token(SERVER_URL)
        assert tok.access_token == "at" and tok.refresh_token == "rt"  # login's pair
        assert store.get_client_for_resource(SERVER_URL).client_id == "client-b"

    @pytest.mark.asyncio
    async def test_refresh_after_login_rereads_and_does_not_redeem(self, store) -> None:
        """R3-B1, other order: login first, then a refresh that read the old token."""
        m = OAuthManager(_store=store)
        m._oauth_configs[SERVER_URL] = _oauth_config()
        store.set_client(ISSUER, ClientCredentials("client-a"))
        store.set_token(SERVER_URL, _token("a-old", -10, refresh="rt-a"))
        refresh = _refresh_mock("should-not-happen")
        fd = os.open(store.store_dir / manager_module.REFRESH_LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)  # "login in progress" holds the lock
        try:
            with patch.object(manager_module, "refresh_token", refresh):
                task = asyncio.create_task(m.get_fresh_token(SERVER_URL))
                await asyncio.sleep(0.3)
                store.set_token(SERVER_URL, _token("b-login", 600, refresh="rt-b"))
                store.set_client_for_resource(SERVER_URL, ClientCredentials("client-b"))
                fcntl.flock(fd, fcntl.LOCK_UN)
                tok = await asyncio.wait_for(task, 5)
        finally:
            os.close(fd)
        assert tok.access_token == "b-login"
        refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_secretless_resource_record_does_not_mask_issuer_secret(self, store, manager) -> None:
        """R3-B2 (a)."""
        store.set_client_for_resource(SERVER_URL, ClientCredentials("cid"))
        store.set_client(ISSUER, ClientCredentials("cid", "issuer-secret"))
        store.set_token(SERVER_URL, _token("old", -10))
        refresh = _refresh_mock("new", "new2")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await manager.refresh_if_needed(SERVER_URL)  # no config
            assert await manager.refresh_proactively(SERVER_URL, client_id="cid")  # with config
        for call in refresh.await_args_list:
            assert call.args[1].client_secret == "issuer-secret"

    @pytest.mark.asyncio
    async def test_rotated_secret_reaches_every_record_of_the_client(self, store) -> None:
        """R3-B2 (b): a login with a new secret updates the other resources' records."""
        store.set_client_for_resource(RESOURCE_A, ClientCredentials("shared", "old-secret"), issuer=ISSUER)
        store.set_client(ISSUER, ClientCredentials("shared", "old-secret"))
        store.set_client_for_resource("https://other-client.example.com", ClientCredentials("other", "keep"))
        flow = OAuthFlow(server_url=RESOURCE_B, token_store=store, client_id="shared",
                         client_secret="new-secret")
        await _run_login(flow)
        assert store.get_client_for_resource(RESOURCE_A).client_secret == "new-secret"
        assert store.get_client(ISSUER).client_secret == "new-secret"
        assert store.get_client_for_resource("https://other-client.example.com").client_secret == "keep"

        # Background refresh of A (no config) now uses the new secret
        m = OAuthManager(_store=store)
        cfg_a = _oauth_config()
        cfg_a.resource_uri = RESOURCE_A
        m._oauth_configs[RESOURCE_A] = cfg_a
        store.set_token(RESOURCE_A, _token("a-old", -10))
        refresh = _refresh_mock("a-new")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await m.refresh_if_needed(RESOURCE_A)
        assert refresh.await_args.args[1].client_secret == "new-secret"

    @pytest.mark.asyncio
    async def test_configured_secret_is_propagated(self, store, manager) -> None:
        store.set_client_for_resource(SERVER_URL, ClientCredentials("cid", "stale"))
        store.set_token(SERVER_URL, _token("old", -10))
        with patch.object(manager_module, "refresh_token", _refresh_mock("new")):
            assert await manager.refresh_if_needed(SERVER_URL, client_id="cid", client_secret="fresh")
        assert store.get_client_for_resource(SERVER_URL).client_secret == "fresh"

    @pytest.mark.asyncio
    async def test_logout_revokes_with_the_resource_client_and_forgets_it(self, store, manager) -> None:
        """R3-M3."""
        store.set_client(ISSUER, ClientCredentials("client-a"))
        store.set_client_for_resource(SERVER_URL, ClientCredentials("client-b"))
        store.set_token(SERVER_URL, _token("b-at", 600, refresh="b-rt"))
        manager._oauth_configs[SERVER_URL].auth_server_metadata.supports_revocation.return_value = True
        revoke = AsyncMock(return_value=True)
        with patch.object(manager_module, "revoke_token", revoke):
            assert await manager.logout_async(SERVER_URL)
        assert [c.args[1].client_id for c in revoke.await_args_list] == ["client-b", "client-b"]
        assert store.get_client_for_resource(SERVER_URL) is None
        assert store.get_client(ISSUER).client_id == "client-a"
        assert store.get_token(SERVER_URL) is None



# ---------------------------------------------------------------------------
# Review round 4 (Codex) regressions
# ---------------------------------------------------------------------------

ISSUER_2 = "https://auth.other-vendor.example.com"


class TestReviewRound4:
    @pytest.mark.asyncio
    async def test_secret_propagation_never_crosses_issuers(self, store) -> None:
        """R4-B1: same client_id "mcpl" registered at two unrelated issuers."""
        store.set_client(ISSUER_2, ClientCredentials("mcpl", "secret-of-issuer-2"))
        store.set_client_for_resource(RESOURCE_A, ClientCredentials("mcpl", "secret-of-issuer-2"), issuer=ISSUER_2)
        flow = OAuthFlow(server_url=RESOURCE_B, token_store=store, client_id="mcpl",
                         client_secret="secret-of-issuer-1")
        await _run_login(flow)  # issuer of RESOURCE_B is ISSUER
        assert store.get_client(ISSUER).client_secret == "secret-of-issuer-1"
        assert store.get_client(ISSUER_2).client_secret == "secret-of-issuer-2"
        assert store.get_client_for_resource(RESOURCE_A).client_secret == "secret-of-issuer-2"

        # Issuer-2's server refreshes with its own secret
        m = OAuthManager(_store=store)
        cfg_a = _oauth_config()
        cfg_a.resource_uri = RESOURCE_A
        cfg_a.auth_server_metadata.issuer = ISSUER_2
        m._oauth_configs[RESOURCE_A] = cfg_a
        store.set_token(RESOURCE_A, _token("a-old", -10))
        refresh = _refresh_mock("a-new")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await m.refresh_if_needed(RESOURCE_A)
        assert refresh.await_args.args[1].client_secret == "secret-of-issuer-2"

    def test_records_with_unknown_issuer_are_not_propagated_into(self, store) -> None:
        store.set_client_for_resource(RESOURCE_A, ClientCredentials("mcpl", "legacy"))
        assert store.propagate_client_secret(ISSUER, "mcpl", "new") == 0
        assert store.get_client_for_resource(RESOURCE_A).client_secret == "legacy"

    @pytest.mark.asyncio
    async def test_resource_record_of_another_issuer_is_ignored(self, store, manager) -> None:
        store.set_client_for_resource(SERVER_URL, ClientCredentials("x", "foreign"), issuer=ISSUER_2)
        store.set_client(ISSUER, ClientCredentials("right-client", "right-secret"))
        store.set_token(SERVER_URL, _token("old", -10))
        refresh = _refresh_mock("new")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await manager.refresh_if_needed(SERVER_URL)
        used = refresh.await_args.args[1]
        assert (used.client_id, used.client_secret) == ("right-client", "right-secret")

    @pytest.mark.asyncio
    async def test_issuerless_record_is_upgraded_then_propagated(self, store, manager) -> None:
        """A record written by an earlier build (no issuer) gets it at refresh."""
        store.set_client_for_resource(SERVER_URL, ClientCredentials("cid", "stale"))
        store.set_token(SERVER_URL, _token("old", -10))
        with patch.object(manager_module, "refresh_token", _refresh_mock("new")):
            assert await manager.refresh_if_needed(SERVER_URL, client_id="cid", client_secret="fresh")
        assert store.get_issuer_for_resource_client(SERVER_URL) == ISSUER
        assert store.get_client_for_resource(SERVER_URL).client_secret == "fresh"


    @pytest.mark.asyncio
    async def test_unconfigured_refresh_upgrades_record_then_rotation_reaches_it(self, store) -> None:
        """Codex r5 minor: backfill also on the unconfigured (background) refresh path."""
        store.set_client_for_resource(RESOURCE_A, ClientCredentials("shared", "old-secret"))  # no issuer
        m = OAuthManager(_store=store)
        cfg_a = _oauth_config()
        cfg_a.resource_uri = RESOURCE_A
        m._oauth_configs[RESOURCE_A] = cfg_a
        store.set_token(RESOURCE_A, _token("a-old", -10))
        with patch.object(manager_module, "refresh_token", _refresh_mock("a-1")):
            assert await m.refresh_if_needed(RESOURCE_A)  # no client_id passed
        assert store.get_issuer_for_resource_client(RESOURCE_A) == ISSUER

        # Login on another resource of the same issuer rotates the shared secret
        flow = OAuthFlow(server_url=RESOURCE_B, token_store=store, client_id="shared",
                         client_secret="new-secret")
        await _run_login(flow)
        store.set_token(RESOURCE_A, _token("a-1", -10))
        refresh = _refresh_mock("a-2")
        with patch.object(manager_module, "refresh_token", refresh):
            assert await m.refresh_if_needed(RESOURCE_A)
        assert refresh.await_args.args[1].client_secret == "new-secret"
