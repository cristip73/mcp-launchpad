Reviewed `6aee162..14b5068`, read-only. Two blocking findings remain.

1. **BLOCKING — Concurrent login and refresh can leave mismatched token/client records.**  
   [flow.py:730](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/flow.py:730), [flow.py:743](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/flow.py:743), [manager.py:598](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:598)

   Login publishes its token and resource client without acquiring the refresh lock. Reproduced with two coroutines: refresh starts using client A; login with client B completes; A’s refresh then completes and overwrites the token. The persistent state becomes **A’s refresh token + client B**, and subsequent background refresh fails with `invalid_grant`. Concurrent processes can produce the same outcome; interleaved logins can also split the pair.

   **Fix:** serialize login’s final token/client publication with refresh using the same cross-process lock. Publish both records while holding it; browser interaction can happen beforehand. Protect the resource-slot check/write in `_select_client` under this coordination too.

2. **BLOCKING — Resource entries can mask valid secrets for the same client ID.**  
   [manager.py:516](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:516), [manager.py:524](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:524)

   `_select_client` takes the first matching client, even if its secret is absent or stale. It also never updates an existing resource record when an explicit replacement secret is supplied.

   Reproduced both cases:
   - A resource entry without a secret suppresses a matching issuer entry containing the required secret.
   - After rotating a shared client’s secret and logging into another resource, the issuer contains the new secret, but the first resource continues selecting its old secret. Passing the replacement through config works for that call; background refresh still selects the old stored secret.

   **Fix:** search matching-ID candidates for a usable secret and synchronize stored credentials when an explicit replacement is supplied. Define consistent precedence for same-ID secret updates across resources.

3. **MINOR — Logout ignores the newly recorded resource client.**  
   [manager.py:756](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:756)

   With issuer client A and resource client B, `logout_async(B)` submits both B tokens for revocation using A’s credentials. Reproduced: both revocation calls received client A. An issuer enforcing client ownership rejects them; local deletion still reports success, leaving the server-side tokens valid.

   **Fix:** use the resource client with issuer fallback for revocation, matching refresh’s selection.

Accepted round-2 findings:

| Finding | Status |
|---|---|
| R2-B1: pre-retry bearer redaction | Fixed; both bearers retained, longest first. |
| R2-B2: matching stored secret | Fixed for the original case; incomplete for conflicting same-ID records, as above. |
| R2-B3: login-only client persistence | Fixed for ordinary login/background refresh; publication remains vulnerable to concurrency. |
| R2-M4: preflight buffering | Fixed for eligible JSON-RPC `.post()` error responses. Intermediate retry 401 reads remain unbounded; I accept the explicitly scoped operational risk. |
| R2-M5: conditional issuer write | Fixed: check and write share one exclusive lock. The new resource-slot check/write still needs coordination. |

IPC serialization and payloads are unchanged. Token serialization is unchanged; `resource:` client entries preserve the existing encrypted dictionary/value format and do not disrupt older issuer lookups. Older versions cannot use those mappings. The agreed old-process transition risk remains.

The custom request extension is safe through the inspected **httpx 0.28.1 / httpcore 1.0.9** pipeline: unknown extensions are not serialized as HTTP data. Verified through the real HTTP/1.1 transport with an in-memory network backend.

Validation: **23 direct HTTP/SDK/IPC tests and seven regressions using in-memory store/lock doubles passed**. The findings above were reproduced separately. Disk-writing and real multiprocess tests were not run. No files changed.

FAIL