Reviewed through commit `c78d3d1`; excluded the concurrent working-tree edit to `daemon.py`. No files changed by this review.

## BLOCKING

1. **Mixed-version processes can still lose rotated refresh tokens.**  
   [manager.py:597](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:597), [store.py:338](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/store.py:338)  
   Old daemons ignore `refresh.lock`, so an old and new process can redeem the same rotating refresh token concurrently. Also, an old writer can read the entire store, pause, then overwrite a newer token for another server with its stale snapshot. Atomic replacement and the new read-modify-write lock cannot prevent that old writer’s lost update.  
   **Fix:** establish a migration that disables or upgrades old refresh/store writers before sharing rotating credentials. Keeping unmodified old writers active cannot provide the stated guarantee through this new lock alone.

2. **Refresh explicitly proceeds without mutual exclusion.**  
   [manager.py:453](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:453), [manager.py:438](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:438)  
   After 60 seconds, every waiter proceeds despite another process holding the lock. Discovery performs multiple requests, so a legitimate holder can exceed that deadline. Waiters can then redeem the same rotating refresh token. On Windows, the implementation provides neither cross-process nor in-process exclusion; two coroutines refresh concurrently.  
   **Fix:** fail closed on lock timeout—return the current token or report a retryable error without redeeming—and implement equivalent Windows locking. Both cases reproduced with in-memory mocks.

3. **Parsed JSON-RPC bodies bypass credential redaction.**  
   [http_client.py:200](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/http_client.py:200)  
   Both parsed-result and parsed-error branches return before `_redact`. For example, HTTP 400 containing a JSON-RPC result whose text echoes the bearer now reaches the caller verbatim after conversion to 200. SSE messages take the same path. This violates the token-output constraint.  
   **Fix:** redact known request credentials from every surfaced message, including parsed JSON-RPC string fields, before serialization. Reproduced with dummy credentials.

4. **Rewriting 401 results prevents OAuth refresh and retry.**  
   [http_client.py:202](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/http_client.py:202)  
   The transport runs before `OAuthBearerAuth` receives the response. A server returning HTTP 401 with a JSON-RPC `result` containing `isError: true` becomes HTTP 200, so auth never sees the rejection. The preflight also misses its OAuth-required check. Reproduced: only the initial token lookup occurred, with no retry.  
   **Fix:** preserve 401 through auth handling; perform result normalization afterward, or explicitly exclude 401 from status conversion.

5. **The custom transport disables environment proxy routing.**  
   [http_client.py:266](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/http_client.py:266)  
   In httpx 0.28, supplying `transport=` disables automatic environment-proxy mounts. Servers previously reached through `HTTPS_PROXY`, `HTTP_PROXY`, or `ALL_PROXY` now connect directly, breaking proxy-dependent installations and potentially bypassing intended routing. Confirmed by comparing client mounts.  
   **Fix:** preserve httpx’s proxy selection and wrap the selected transports, or implement response handling above the transport layer.

6. **Saving configured clients can break another server sharing the issuer.**  
   [flow.py:735](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/flow.py:735), [manager.py:518](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:518)  
   Suppose server A uses stored DCR client A. Logging into server B with configured client B under the same authorization-server issuer overwrites A’s client credentials. A’s next refresh sends its refresh token with client B and fails. The configured fallback does not help because an issuer entry already exists.  
   **Fix:** associate client credentials with the token/resource and client identity, retaining issuer-only lookup as a legacy fallback.

## MINOR

1. **Short tokens defeat the background refresh deduplication.**  
   [daemon.py:225](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/daemon.py:225), [manager.py:664](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:664)  
   A newly issued 600-second token immediately has less than 600 seconds remaining. Every waiting daemon therefore refreshes again after acquiring the lock.  
   **Fix:** cap the threshold below the token lifetime, or detect that the stored token changed while waiting.

2. **Error handling buffers the entire response before applying its output limit.**  
   [http_client.py:190](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/http_client.py:190)  
   A large error body consumes unbounded memory. An SSE error response that delivers its final JSON-RPC message but keeps the connection open never reaches the parser; it waits for EOF or timeout. The latter reproduced with a live mock stream.  
   **Fix:** bound error-body reads and parse SSE incrementally, stopping when the matching response arrives.

Seven existing transport/SDK tests passed when invoked directly without filesystem writes. Store-writing tests were not run. No IPC wire-format change or nested store-lock deadlock was found; SDK JSON request bodies are replayable. Legacy SSE paths remain unchanged and still use connection-time credentials.

FAIL