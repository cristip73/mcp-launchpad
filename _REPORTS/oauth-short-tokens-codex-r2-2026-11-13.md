1. **BLOCKING — B3 still leaks the bearer used before an auth retry.** [http_client.py:169](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/http_client.py:169)  
   `OAuthBearerAuth` mutates the same request when retrying. Consequently, history and final responses both expose the **new** Authorization header; `_bearer_secrets()` loses the original token. Reproduced: requests send `old-secret`, then `new-secret`; the final error surfaces `old-secret [redacted]`.  
   **Fix:** capture bearer values per request before each attempt, or preserve separate request/header objects across retries.

2. **BLOCKING — Configured client IDs discard matching stored secrets.** [manager.py:526](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:526)  
   With `oauth_client_id` configured and the secret supplied during login through `--client-secret-stdin` or `MCPL_CLIENT_SECRET`, login stores the secret. Subsequent refresh passes the configured ID with `client_secret=None`; the new authoritative-client branch ignores the matching stored credentials and sends no secret, causing `invalid_client`. Confirmed with an in-memory mock.  
   **Fix:** when stored and configured client IDs match, retain the stored secret unless an explicit replacement is supplied. Never borrow credentials from a different client ID.

3. **BLOCKING — B6 loses credentials supplied only at login.** [flow.py:741](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/flow.py:741)  
   If issuer client A exists, `mcpl auth login B --client-id client-B` succeeds but does not persist client B. When B’s config has no client ID, later refresh uses A with B’s refresh token and fails. Reproduced through mocked login and refresh.  
   **Fix:** persist credentials associated with B’s token/resource, preserving issuer-only lookup as a legacy fallback. Also ensure background refresh selects B’s credentials; its current call supplies no configured client.

4. **MINOR — M2 remains unbounded for preflight requests and auth-retry responses.** [http_client.py:274](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/http_client.py:274)  
   Ordinary `.post()` calls use `stream=False`, so `super().send()` consumes the entire body before `_read_bounded()` runs. Both connection preflights use `.post()`. Reproduced: a complete SSE error followed by an open stream still waits for EOF. Large bodies remain unbounded on that path. httpx also reads intermediate 401 bodies before retrying.  
   **Fix:** obtain streamed responses internally, apply bounded rewriting, then honor the caller’s requested buffering behavior; bound intermediate retry-response reads too.

5. **MINOR — B6’s preservation check is not atomic across processes.** [flow.py:739](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/flow.py:739)  
   Login B can read no issuer client, then another process stores client A, then B’s unconditional `set_client()` overwrites A. The analogous check in [manager.py:527](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:527) can race with login too.  
   **Fix:** perform the conditional check and write inside one store mutation lock.

Accepted-finding status: **B2 fixed** for supported Unix systems; **B3 incomplete**; **B4 and B5 fixed**; **B6 incomplete**; **M1 fixed** for stable token lifetimes; **M2 partial**. B1 remains the acknowledged transition risk; I found no cheap reliable mitigation against unmodified old writers.

Validation: 11 selected HTTP/SDK tests and seven in-memory IPC tests passed. IPC wire format is unchanged. Store-writing tests were excluded to preserve read-only operation; no files changed.

FAIL