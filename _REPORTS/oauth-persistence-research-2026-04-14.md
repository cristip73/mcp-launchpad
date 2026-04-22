# OAuth Persistence Research - de ce se de-autentifică grain la ~1h

**Data:** 2026-04-14
**Status:** doar research, zero modificări de cod
**Observat:** servere HTTP cu OAuth în mcpl (în special `grain`) par să ceară re-login la ~1 oră, în timp ce Claude Code nativ pe același server menține sesiunea ~1 săptămână.

---

## 1. Arhitectura actuală OAuth în mcpl

**Token storage** (`mcp_launchpad/oauth/store.py`):
- Criptare **Fernet** (AES-128-CBC + HMAC), cheie în OS Keyring
- Locație: `~/.cache/mcp-launchpad/oauth/` → `tokens.json` + `clients.json`
- `TokenSet` conține: `access_token`, `refresh_token` (opțional), `expires_at`, `issued_at`, `scope`

**Refresh flow** (`oauth/manager.py`):
- `refresh_if_needed()` - reactiv, doar dacă `token.is_expired()` cu buffer 30s (`oauth/tokens.py:40`)
- `refresh_proactively()` (commit `43d406f`, 2026-04-12) - preventiv chiar dacă validul
- Daemon background task (`daemon.py:195-226`) - rulează la `MCPL_OAUTH_REFRESH_INTERVAL=1200s` (20 min), refresh dacă expiry < 10 min

**Discovery OAuth** (`oauth/discovery.py`):
- RFC 9728 (Protected Resource Metadata) → RFC 8414 (Authorization Server Metadata)
- Dynamic Client Registration (DCR) dacă serverul suportă
- Cache per server URL în `OAuthManager._oauth_configs`

**401 handling** (`connection.py`):
- Pe 401 se aruncă `OAuthRequiredError` → CLI cere user să ruleze `mcpl auth login`

## 2. De ce expiră la ~1h - cauze probabile (ordonate după probabilitate)

### **#1 - grain nu emite `refresh_token` pentru mcpl (P~70%)**

`oauth/flow.py:223-228`: daemon adaugă `offline_access` la request-ul de authorization **doar dacă**:
- `scopes_supported` lipsește din server metadata, **SAU**
- Serverul declară explicit `offline_access` în `scopes_supported`

Dacă grain-ul expune `scopes_supported` dar **fără** `offline_access`, mcpl nu cere refresh token. Rezultat:
- `TokenSet.refresh_token = None`
- `has_refresh_token() = False`
- Task-ul de refresh proactiv sare peste grain (`manager.py:~480`: `if not token.has_refresh_token(): continue`)
- La expiry 3600s → 401 → re-login full prin browser

**De verificat:** `mcpl auth status grain` - arată dacă avem refresh_token. Sau inspectează direct fișierul criptat (prin logs la refresh, nu direct).

### **#2 - Refresh token cu lifetime scurt emis de grain (P~60%)**

Chiar dacă mcpl primește un refresh token, grain-ul poate emite refresh tokens cu TTL = 1h (legat de access_token lifetime). La expiry, refresh call-ul primește `invalid_grant` și se pierde definitiv.

`oauth/manager.py:455-457` (refresh reactiv) și `manager.py:506-508` (refresh proactiv): ambele fac doar `logger.warning()` pe `TokenExchangeError`, fără a distinge între "refresh token expirat" vs "altă eroare tranzitorie".

### **#3 - Scope `offline_access` nu e forțat prin config (P~50%)**

`ServerConfig.oauth_scopes` (`config.py:60`) există ca field, dar în `.mcp.json` din MG_CP secțiunea `grain` nu are scopes explicit:

```json
"grain": {
  "type": "http",
  "url": "https://api.grain.com/_/mcp"
}
```

Slack are configurare mai completă cu `oauth.clientId` și `callbackPort`, dar nici ea nu cere scopes. Asta înseamnă că totul depinde de ce răspunde serverul la discovery.

### **#4 - Daemon restart pierde in-memory state OAuth configs (P~35%)**

`OAuthManager._oauth_configs` e un dict in-memory. Dacă daemon-ul restartă (user rulează `mcpl session stop`, sau crash), discovery-ul se reface de la zero. Tokens din disc persistă, dar orice eroare la re-discovery (timeout, schimbare issuer) poate invalida fluxul.

### **#5 - Claude Code nativ folosește alt flow (P~sigur diferit)**

Claude Code nativ pentru MCP HTTP cu OAuth:
- Probabil cere explicit `offline_access`
- Stochează tokens în Keychain cu lifetime mult mai mare
- Sau are logică custom care re-obține refresh token periodic
- Rezultat: user-ul observă ~1 săptămână între re-login-uri

**Nu avem cod Claude Code nativ accesibil pentru comparație directă** - e inference bazat pe diferența observată de user.

## 3. Soluții propuse (ordonate după risc/complexitate)

### **S1. Debug logging îmbunătățit (RISK: zero, EFFORT: 15 min)** - TRIMITE ÎNAINTE DE ORICE
Trebuie să știm **care** cauză e reală. Adaugă în `manager.py:455-457` și `:506-508`:
- Log la nivel INFO: ce server, există refresh_token, cât timp a avut access_token, ce eroare exactă a venit de la auth server
- Log la save token: `scopes` primite, `expires_in`, `has_refresh_token`

Fără date concrete, orice fix e ghicire.

### **S2. Forțează `offline_access` la authorize (RISK: mic, EFFORT: 30 min)**
`oauth/flow.py:223-228`: în loc să adaugi `offline_access` conditional, adaugă-l mereu dacă user nu a configurat `oauth_scopes` explicit. Multe OAuth servers acceptă scope-uri necunoscute fără eroare; cei care nu, se poate whitelista în config per-server.

Alternativă: expune `--scopes` pe `mcpl auth login` pentru override per-login. Și câmp `oauth_scopes` în `.mcp.json` pentru override declarativ.

### **S3. Extinde buffer refresh proactiv (RISK: mic, EFFORT: 5 min)**
`daemon.py:214`: `timedelta(minutes=10)` → `timedelta(minutes=30)`. Refresh mai devreme = mai puține 401 rate. Trade-off: ceva mai multe HTTP calls, neglijabil.

### **S4. Retry + better error classification la refresh fail (RISK: mediu, EFFORT: 1h)**
`manager.py:455-457` / `:506-508`: distinge între:
- `invalid_grant` (refresh_token mort definitiv) → marchează serverul ca "needs re-login", notifică user clar
- `temporarily_unavailable` / network error → retry cu backoff
- `invalid_scope` → probabil trebuie re-descoperit metadata

Astăzi, orice eroare e tratată la fel (log warning), deci utilizatorul nu știe dacă trebuie `mcpl auth login` sau doar să aștepte.

### **S5. Persist refresh_token metadata separat (RISK: mediu, EFFORT: 2h)**
În `TokenSet` adaugă `refresh_token_issued_at` și `refresh_token_expires_at` (când e cunoscut). Permite daemon-ului să detecteze când refresh token-ul e aproape de expirare absolut (ex. 30 zile) și să notifice user-ul preventiv, în loc să-l prindă pe 401 mid-task.

### **S6. Heartbeat proactiv pe HTTP servers (RISK: mare, EFFORT: 3h)**
În plus față de refresh token: keep session warm prin tool calls periodice no-op (ex. `tools/list`) la 30 min. Similar cu cum Claude Code nativ menține conexiunea. Efect secundar: multe server-e MCP reset-ează "last active" state doar la tool calls reale, ceea ce ar putea expira sesiuni chiar dacă tokenul e valid.

## 4. Ordine de intervenție recomandată

1. **S1 (logging) PRIMA** - până nu știm exact de ce pică, orice altceva e ghicire. Rulează 1-2 zile normale de usage, citește log-urile, identifică pattern-ul real.
2. **S2 (offline_access)** dacă log-urile arată `refresh_token = None` pentru grain.
3. **S4 (error classification)** dacă log-urile arată `invalid_grant` frecvent - atunci problema e server-side și mcpl poate doar să notifice clar user-ul.
4. **S3 (buffer extins)** ca quick win general.
5. **S5, S6** - rezerva dacă cele de mai sus nu acoperă.

## 5. Întrebări deschise / de clarificat cu user

- Confirmă: grain e singurul care face asta, sau și slack / happyscribe?
- Când se întâmplă re-auth la 1h - e acces token expiry exact (3600s), sau e legat de `last_used` + idle timeout (diferit)?
- Pentru referință: care e experiența cu `mcpl auth status grain` imediat după login vs după 30 min (arată `refresh_token`?)
- Există log-uri existente din daemon (`~/.cache/mcp-launchpad/daemon.log` sau similar) din care putem extrage pattern-ul istoric fără să adăugăm logging nou?

---

## 6. Referințe cod

- `mcp_launchpad/oauth/manager.py:384-508` - refresh flow
- `mcp_launchpad/oauth/flow.py:223-228` - `offline_access` conditional
- `mcp_launchpad/oauth/tokens.py:40` - 30s buffer
- `mcp_launchpad/oauth/store.py:87-351` - Fernet storage
- `mcp_launchpad/oauth/discovery.py:467-613` - RFC 9728 / 8414
- `mcp_launchpad/daemon.py:51,195-226` - background refresh task
- `mcp_launchpad/connection.py` (caută `OAuthRequiredError`) - 401 handling
