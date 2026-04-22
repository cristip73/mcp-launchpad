# MCPL Deployment & Usage in MG_CP

**Data:** 2026-04-14
**Scope:** Cum e deployat MCP Launchpad în vault-ul MG_CP, de ce a fost creat, ce rezolvă.

---

## 1. Contextul / De unde a venit nevoia

Claude Code pornește **fiecare MCP server ca proces separat per chat**. În setup-ul real din MG_CP (Kilostop) cu 20+ servere MCP și 40+ sesiuni paralele, rezultatul a fost:

- **~294 procese MCP simultan**, ~808 MB RAM
- Procese orfane acumulate după închiderea chat-urilor
- **Subagenți și scheduled tasks nu puteau accesa MCP-uri disabled** - limitare arhitecturală a Claude Code care forța alegerea între (a) consum masiv de resurse cu MCPs enabled, sau (b) pierderea accesului din automatizări când erau disabled

Sursă: `MG_CP/WORKBENCH/20260402 MCP LAUNCHPAD FORK/EXECUTIVE SUMMARY MCPL.md`

## 2. Ce rezolvă mcpl

Un singur proces daemon partajat între toate chat-urile. Pornire lazy per-server la primul call, disconnect automat când idle, OAuth tokens persistate central.

**Beneficii măsurate:**
- De la 294 → ~100 procese (o instanță per server, shared)
- Subagents/scheduled tasks pot invoca tools prin CLI (`mcpl call`) fără a fi blocați de enable/disable per chat
- OAuth tokens într-un singur loc → nu repetă login-ul per chat

**Trade-off acceptat:** agentul nu mai are tool calls native type-safe. În schimb rulează prin Bash: `mcpl inspect <server> <tool>` → `mcpl call <server> <tool> ...`.

## 3. Arhitectura (recap tehnic)

- **CLI** (`cli.py`, Click) - comenzi: `search`, `list`, `call`, `inspect`, `verify`, `session`, `auth`, `config`
- **Daemon** (`daemon.py`) - proces long-running, IPC via Unix socket (`~/.cache/mcp-launchpad/daemon.sock`), conectează servere lazy, deconectează idle (default 600s), refresh OAuth proactiv (20 min, commit `43d406f`)
- **ConnectionManager** (`connection.py`) - abstracție peste stdio / HTTP Streamable / SSE
- **OAuthManager** (`oauth/manager.py`) - OAuth 2.1 + PKCE, DCR, tokens criptate Fernet cu cheie din OS Keyring, stocate în `~/.cache/mcp-launchpad/oauth/`
- **Config loading** (`config.py`) - citește `.mcp.json` (prio: `./.mcp.json` → `./mcp.json` → `./.claude/mcp.json` → `~/.claude/mcp.json`), suportă `${VAR}` expansion

## 4. Cum e deployat în MG_CP (5 pași)

Sursă: `MG_CP/WORKBENCH/20260402 MCP LAUNCHPAD FORK/GHID MCPL DEPLOYMENT.md`

1. **Install:** `uv tool install https://github.com/cristip73/mcp-launchpad.git`
2. **Consolidare config:** toate serverele MCP în `.mcp.json` la root-ul vault-ului (22 servere)
3. **Verificare:** `mcpl verify` → testează toate conexiunile, `mcpl list <server>` confirmă tool-urile
4. **OAuth setup:** `mcpl auth login <server>` pentru serverele HTTP cu OAuth (Slack, Grain, HappyScribe)
5. **Registry rule:** `.claude/rules/mcpl-registry-A.md` listează cele 22 servere cu nr. tools + key tools; inclus în `CLAUDE.md` ca `@.claude/rules/mcpl-registry-A.md`

**Fișierele care ajung în acest repo pentru testare** (gitignored, au secrete):
- `/.mcp.json` - copie din MG_CP
- `/.claude/rules/mcpl-registry-A.md` - copie din MG_CP

## 5. Workflow obligatoriu pentru agent

Din `mcpl-registry-A.md:13-21`:

> **INTOTDEAUNA** rulează `mcpl inspect <server> <tool>` înainte de primul `mcpl call` pe un tool. NU ghici parametri - inspect îți dă schema exactă.

Flux:
1. Identifică serverul din registry (22 grupuri cu key tools)
2. `mcpl inspect <server> <tool>` → schema completă, required/optional
3. `mcpl call <server> <tool> --param1 val1 --param2 val2` (sau JSON pentru nested)

Pentru servere lente (gpt5-server: 1-30 min), registry marchează `run_in_background: true`.

## 6. Cele 22 servere MCP active în MG_CP

Total ~370+ tools distribuite în:

| Categorie | Servere |
|---|---|
| AI & Search | gpt5-server, exa, mcp-server-firecrawl |
| Browser & Scraping | chrome-devtools, firecrawl |
| Meetings & Transcripts | grain (HTTP+OAuth), happyscribe (HTTP) |
| Notes & KB | dynalist, roam-research, smart-connections |
| Messaging | whatsapp, telegram-mcp (74 tools), slack (HTTP+OAuth) |
| Marketing Analytics | google-ads (13), meta-ads (34), ga4-analytics, analytics-mcp, google-search-console (20) |
| CRM | ghl-mcp-local, liveagent |
| Video | youtube, tubepilot (48) |
| Ads Write | google-ads-write (63) |

Majoritatea sunt stdio locale (node/uv/uvx/npx) cu env vars pentru API keys. Serverele HTTP (grain, slack, happyscribe) folosesc OAuth prin mcpl daemon.

## 7. Limitări cunoscute (sursă MG_CP notes)

- **Cold start OAuth:** primul call pe server HTTP poate dura 10-30s (lazy connect + token check). Următoarele sunt instant.
- **Re-auth frecvent pe grain / HTTP servers cu OAuth** - *subiectul raportului de research paralel* (`oauth-persistence-research-2026-04-14.md`)
- **Output truncation** default 40k chars, save integral în `/tmp/mcpl/` când se trunchiază
- **Rebuild flow** după modificări: `pkill -f "mcp_launchpad.daemon" && uv tool install . --force --reinstall`
- **google-ads-write** a avut stale refresh token care necesita re-login manual

## 8. Intent strategic

MCPL e o "pluging platform" care decuplează **descoperirea** de tools de **procesele** care le execută. În Claude Code nativ, aceste două sunt legate (tool loaded = process running). MCPL le separă: tools sunt cunoscute prin registry static + `mcpl search`, procesele pornesc la nevoie.

Consecință importantă pentru sesiunile MG_CP: orice subagent care știe Bash poate accesa orice tool MCP, fără a consuma context tokens pentru încărcarea schemei completă la startup (evitând "context bloat" de la 400+ tools).
