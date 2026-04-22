# OAuth Persistence Fixes - Raport Implementare

**Data:** 2026-04-22
**Status:** implementat, testat, confirmat funcțional pe 4 zile (grain: login 18 apr → refresh reușit 22 apr fără re-login)

---

## De ce

Toate serverele HTTP cu OAuth (grain, slack, happyscribe) se de-autentificau la ~1h. Utilizatorul trebuia să facă `mcpl auth login` repetat, pe când Claude Code nativ pe aceleași servere ținea autentificarea săptămâni.

Investigația log-urilor Claude Code nativ a arătat că:
- Grain dă token de 1h + refresh_token la TOȚI clienții (nu doar la Claude Code)
- Claude Code nativ face refresh proactiv la fiecare reconectare → tokenul nu expiră niciodată
- mcpl ar fi trebuit să facă la fel, dar avea 3 bug-uri care împiedicau asta

## Ce s-a găsit (cauze root)

### Bug 1 - Refresh_token pierdut la refresh (CAUZA PRINCIPALĂ)
**Fișier:** `oauth/manager.py` - `refresh_if_needed()` și `refresh_proactively()`

Când serverul OAuth răspunde la un token refresh, multe servere (inclusiv grain) returnează doar un access_token nou, FĂRĂ un refresh_token nou. `TokenSet.from_token_response()` seta `refresh_token = None`. La următoarea expirare, mcpl nu mai avea refresh_token → 401 → re-login obligatoriu.

### Bug 2 - URL mismatch la token lookup
**Fișier:** `oauth/manager.py` - `get_auth_status()`, `refresh_if_needed()`, `refresh_proactively()`, `logout_async()`

Token-urile se stochează sub `resource_uri` (ex: `https://api.grain.com`), dar lookup-ul se făcea cu `server_url` (ex: `https://api.grain.com/_/mcp`). 4 metode foloseau `self._store.get_token(server_url)` (exact match) în loc de `self._lookup_token(server_url)` (cu fallback pe base URL). Rezultat: tokenul nu era găsit → "not authenticated" deși exista pe disc.

### Bug 3 - Token salvat sub URL greșit la refresh
**Fișier:** `oauth/manager.py` - `refresh_if_needed()` și `refresh_proactively()`

La refresh, noul token se salva sub `server_url` (parametrul funcției) în loc de `oauth_config.resource_uri` (cheia canonică din store). Asta crea intrări duplicate în token store, și la cleanup se putea pierde token-ul valid.

## Ce s-a implementat

### Fix 1 - Preservare refresh_token la refresh
```python
# În refresh_if_needed() și refresh_proactively():
new_token = TokenSet.from_token_response(token_response, ...)
if not new_token.has_refresh_token() and token.has_refresh_token():
    new_token.refresh_token = token.refresh_token
```

### Fix 2 - Lookup consistent cu fallback pe base URL
Înlocuit `self._store.get_token(server_url)` cu `self._lookup_token(server_url)` în toate cele 4 metode afectate.

### Fix 3 - Salvare sub resource_uri canonic
```python
store_key = oauth_config.resource_uri or server_url
self._store.set_token(store_key, new_token)
```

### Fix 4 - offline_access scope (revert la logica originală)
Inițial am forțat `offline_access` mereu. Slack a refuzat cu `invalid_scope_requested`. Revenire la logica condiționată: adaugă `offline_access` doar dacă serverul nu advertise scopes SAU include explicit `offline_access`. Adăugat logging clar la decizie.

### Fix 5 - Clasificare erori la refresh fail
`invalid_grant` → mesaj clar "refresh token revoked/expired, user must re-authenticate"

### Fix 6 - Logging detaliat OAuth
- La `build_authorization_url()`: ce scopes se cer, ce advertise serverul
- La `OAuthFlow.run()`: token primit - has_refresh_token, scope, lifetime
- La refresh: ce server, ce rezultat, dacă s-a preservat refresh_token

### Comenzi CLI noi

**`mcpl auth refresh <server>`** - refresh manual, util pentru debug. Arată dacă refresh funcționează, noul token (expires_at, has_refresh_token, scopes).

**`mcpl auth discover <server>`** - afișează metadata OAuth discovery: scopes_supported, endpoints, DCR/PKCE/revocation support. A fost esențial pentru diagnostic (a arătat că grain nu advertise scopes, Slack nu include offline_access).

**`mcpl auth status` îmbunătățit** - arată token lifetime original, sugerează `mcpl auth refresh` (nu re-login) dacă are refresh_token.

## Fișiere modificate

- `mcp_launchpad/oauth/flow.py` - offline_access condiționat, logging scopes + token response
- `mcp_launchpad/oauth/manager.py` - refresh_token preservation, _lookup_token consistent, resource_uri save, error classification, AuthStatus.token_lifetime_human
- `mcp_launchpad/cli.py` - `auth refresh`, `auth discover`, status îmbunătățit
- `mcp_launchpad/daemon.py` - proactive refresh task (commit anterior 43d406f)
- `tests/test_oauth_flow.py` - test actualizat pentru offline_access condiționat
- `.gitignore` - adăugat `.mcp.json` (conține secrete)

## Rezultate confirmate

| Server | Token lifetime | Refresh token | Testat |
|---|---|---|---|
| grain | 1h | Da | 4 zile fără re-login (18→22 apr) |
| happyscribe | 2h | Da | Refresh manual + auto funcțional |
| slack | 12h | Da | Login OK, client credentials issue la re-discover (de investigat) |

## Limitare rămasă - Slack client credentials

Slack nu suportă DCR - folosește client_id pre-configurat din `.mcp.json`. La refresh după mai multe zile, `get_client("https://slack.com")` returnează None fiindcă client credentials par să nu fie persistate corect sub issuer-ul Slack. Necesită investigare separată.
