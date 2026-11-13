Reviewed `14b5068..d3fbdfe` and the full `main...HEAD`, read-only. One new blocker.

1. **BLOCKING — Secret propagation crosses issuer boundaries.**  
   [store.py:589](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/store.py:589), invoked by [flow.py:751](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/flow.py:751) and [manager.py:510](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:510).

   OAuth client IDs are unique within an issuer, not globally. Suppose unrelated issuers A and B both register `client_id="mcpl"` with different secrets. Logging into A overwrites **both B’s issuer and resource secrets**. B’s next refresh sends A’s secret to B, exposing A’s credential and breaking B’s authentication. Reproduced through mocked login followed by refresh.

   **Fix:** scope propagation to `(issuer, client_id)`. Record issuer association on resource-client entries and update only records belonging to that issuer. Preserve legacy issuer keys and avoid propagating into resource entries whose issuer is unknown.

Round-3 status:

- **R3-B1:** Fixed when the lock is acquired. Browser authorization and code exchange precede acquisition; no nested acquisition or lock held across browser waiting found. The explicitly accepted timeout bypass remains.
- **R3-B2:** Original masking and stale-secret scenarios fixed. Propagation introduces the issuer-isolation blocker above.
- **R3-M3:** Fixed for the reported scenario: revocation selects the resource client and deletion removes its record.

No additional MINOR findings. IPC framing and payloads remain unchanged. Stored token serialization and encrypted dictionary format remain compatible with older readers; the previously acknowledged old-writer transition risk remains.

Validation: **44 OAuth/HTTP/SDK checks and 10 IPC checks passed**, including all six R3 regressions. Storage used in-memory doubles; coroutine contention exercised real Unix `flock` on a read-only file. Disk-writing and multiprocess tests were not run. No files changed.

FAIL