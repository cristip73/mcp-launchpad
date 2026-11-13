R4-B1 is fixed. No blocking findings.

- **MINOR — Legacy issuer upgrade is skipped without a configured client ID.** [manager.py:513](/Users/cristi/CODE/mcp-launchpad/mcp_launchpad/oauth/manager.py:513)

  The early return at line 511 bypasses the new migration. Reproduced: resource A has an issuerless record with the old secret; an unconfigured refresh succeeds but leaves its issuer unknown. Login to resource B rotates the same issuer/client’s secret; propagation skips A. A’s next refresh selects its stale secret and fails with `invalid_client`.

  **Fix:** perform the issuer check/backfill before the early return, under the existing refresh lock. Add an unconfigured-refresh → rotation regression. This affects records from the earlier unreleased build.

No additional concurrency, older-reader compatibility, or token-security findings. Changed writes retain the existing lock order; no double acquisition found.

Validation: all **4 R4 and 6 R3 regressions passed**, using in-memory storage and real Unix `flock` on a read-only file. Disk-writing and multiprocess tests were not run. No files changed.

PASS (no blocking findings)