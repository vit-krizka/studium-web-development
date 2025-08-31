# Studijní plán — Using Web Protocols
*(podle: Philip Ackermann — Full Stack Web Development: The Comprehensive Guide)*

> Cíl celého kurzu: osvojit si principy webových protokolů (zejména HTTP/1.1, HTTP/2 a HTTP/3), umět číst i skládat zprávy, bezpečně je provozovat, testovat a ladit, a volit vhodné komunikační vzory pro real‑time aplikace.

---

## Jak s plánem pracovat
- Každý **BLOK** obsahuje: *Cíl*, *Teorie* a *Praxe* (konkrétní úkoly).  
- Potřebné nástroje: Chrome/Edge DevTools, `curl` (>= 8), `httpie`, Node.js (>= 20) + Express, Postman/Insomnia (volitelně), `jq`, `mitmproxy` (volitelně).

---

# BLOK 1: Základy HTTP
**Cíl:** Rozumět principu komunikace klient–server, stavbě HTTP zpráv a rozdílům mezi verzemi protokolu.

### 5.1.1 Requests and Responses
**Teorie:**
- **Model klient–server** a bezstavovost HTTP (co je „stav“ a kde se drží — klient, server, middlewares).
- **Síťový kontext:** TCP/UDP, TLS, handshake, role portů (80/443), NAT a reverzní proxy.
- **DNS a URL/URI:** rozklad URL (schéma, host, port, path, query, fragment), percent‑encoding, relativní vs. absolutní odkazy.
- **HTTP verze:** 0.9 → 1.0 → **1.1** (keep‑alive, pipelining) → **HTTP/2** (multiplexing, HPACK) → **HTTP/3 (QUIC)**.
- **Životní cyklus požadavku:** od kliknutí v prohlížeči přes DNS → TLS → request → response → cache → render.
- **Bezpečnostní model prohlížeče:** Same‑Origin Policy (SOP) v kostce.

**Praxe:**
- V DevTools → **Network** sledujte jednotlivé požadavky, uložte **HAR** a identifikujte DNS/TLS/Waiting (TTFB).
- `curl -v https://example.org` a rozlišit TCP/TLS handshake, request line, response line a hlavičky.

### 5.1.2 Structure of HTTP Requests
**Teorie:**
- **Start‑line:** metoda, *request‑target* (origin‑form, absolute‑form, authority‑form, asterisk‑form), verze.
- **Hlavičky (fields):** end‑to‑end vs. hop‑by‑hop; `Connection` a proč skrývá hop‑by‑hop pole.
- **Tělo a kódování:** `Content-Type`, `Content-Length` vs. `Transfer-Encoding: chunked`, **content negotiation**.
- **Vlastnosti metod:** *safe*, *idempotent*, *cacheable*.

**Praxe:**
```bash
# GET (origin-form)
curl -v https://httpbin.org/get

# POST JSON (negociace obsahu)
curl -v https://httpbin.org/post \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"hello":"world"}'
```

### 5.1.3 Structure of HTTP Responses
**Teorie:**
- **Status line:** verze + kód + důvodová fráze.
- **Tělo vs. absence těla** (např. 204, 304, HEAD).
- **Streamování** a `Transfer-Encoding: chunked`.
- **Obsahové kódování:** `Content-Encoding` (gzip, br), `Content-Language`, `Content-Disposition` (download).

**Praxe:**
```bash
curl -i -v https://httpbin.org/gzip --compressed
```

---

# BLOK 2: Hlavičky, metody, kódy
**Cíl:** Umět číst i sestavovat HTTP dotazy s běžnými i pokročilými parametry, včetně cache a CORS.

### 5.1.4 Headers
**Teorie:**
- **Klíčové hlavičky:** `Content-Type`, `Accept`, `Authorization`, `Cookie`, `User-Agent`, `Host`, `Referer`, `Origin`.
- **Autentizace:** `WWW-Authenticate`, `Authorization: Basic/Bearer`, základy OAuth 2.0 / OIDC (Bearer token).
- **Cache a podmíněné požadavky:** `Cache-Control`, `Etag`/`If-None-Match`, `Last-Modified`/`If-Modified-Since`, `Vary`.
- **Lokalizace a komprese:** `Accept-Language`, `Accept-Encoding`.
- **CORS:** `Access-Control-Allow-*`, preflight (`OPTIONS`), rozdíl **SOP vs. CORS**.
- **Rozsahové požadavky:** `Range`/`Content-Range` (206 Partial Content).
- **Problémové odpovědi:** `application/problem+json` (strukturované chyby).

**Praxe:**
```bash
# Vlastní hlavička a cache
curl -i https://httpbin.org/etag/xyz -H "If-None-Match: \"xyz\""

# CORS preflight simulace
curl -i -X OPTIONS https://example.org/api \
  -H "Origin: https://foo.test" \
  -H "Access-Control-Request-Method: PUT"
```

### 5.1.5 Methods
**Teorie:**
- **Metody:** GET, HEAD, POST, PUT, PATCH (JSON Patch vs. Merge Patch), DELETE, OPTIONS, TRACE.
- **Vlastnosti:** bezpečnost, idempotence, cacheovatelnost; **Idempotency‑Key** pro opakovatelné POSTy.
- **Sémantika vs. transport:** REST vs. RPC; JSON‑RPC, gRPC (HTTP/2), GraphQL (over HTTP).

**Praxe: Mini REST API (Node/Express)**
```js
// server.mjs
import express from "express";
const app = express();
app.use(express.json());

app.get("/items", (req, res) => res.json([{id:1,name:"foo"}]));
app.post("/items", (req, res) => res.status(201).json({id:2, ...req.body}));
app.put("/items/2", (req, res) => res.json({id:2, ...req.body}));
app.patch("/items/2", (req, res) => res.json({id:2, ...req.body, patched:true}));
app.delete("/items/2", (req, res) => res.status(204).end());
app.options("/items", (req,res)=> res.set("Allow","GET,POST,OPTIONS").end());

app.listen(3000, ()=> console.log("http://localhost:3000"));
```

**Testování metod:**
```bash
http :3000/items
http POST :3000/items name=bar
http PUT  :3000/items/2 name=baz
http PATCH :3000/items/2 patched:=true
http DELETE :3000/items/2 -v
```

### 5.1.6 Status Codes
**Teorie:**
- **Skupiny 1xx–5xx**, nejčastější kódy:  
  - 200/201/202/204, 206; 301/302/303/307/308; 304; 400/401/403/404/405/409/410/415/422/429; 500/501/502/503/504.
- **Redirect sémantika:** rozdíl 301/308 (metoda zachována) vs. 302/303/307.
- **Dostupnost a spolehlivost:** retry‑able chyby vs. non‑retry‑able; `Retry-After`.

**Praxe:**
- Vytvořte na API cesty pro 404/405/409/415/429 a ověřte chování klientů (curl, prohlížeč).

---

# BLOK 3: Obsah, cookies a příkazy
**Cíl:** Umět pracovat s daty, relací (session) a nástroji příkazové řádky.

### 5.1.7 MIME Types
**Teorie:**
- **Běžné typy:** `text/html`, `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, `text/event-stream`.
- **Parametry typu:** `charset=utf-8`; rozdíl **Content-Type** × **Content-Encoding**.
- **Uploady a formuláře:** hranice `boundary` v `multipart`, velké soubory, integrita (hash).
- **Streaming:** NDJSON, chunked přenos, backpressure.

**Praxe:**
```bash
# JSON request + JSON response
curl -s https://httpbin.org/anything \
  -H "Content-Type: application/json" \
  -d '{"a":1}' | jq .
```

### 5.1.8 Cookies
**Teorie:**
- **Atributy:** `Domain`, `Path`, `Expires`/`Max-Age`, `Secure`, `HttpOnly`, **SameSite** (Lax/Strict/None).
- **Session vs. persistentní cookies**, **CSRF** a opatření (SameSite, tokeny), **CSP** (Content-Security-Policy) v kostce.
- **Alternativy:** token‑based auth (JWT v `Authorization: Bearer`), úskalí ukládání tokenů v prohlížeči.

**Praxe (Express session):**
```js
import session from "express-session";
app.use(session({ secret: "s3cr3t", resave:false, saveUninitialized:false, cookie:{ httpOnly:true, sameSite:"lax", secure:false }}));
app.get("/login", (req,res)=>{ req.session.user="alice"; res.json({ok:true}); });
app.get("/me",   (req,res)=> res.json({user:req.session.user ?? null}));
```

### 5.1.9 Executing HTTP from the Command Line
**Praxe (intenzivní cvičení):**
```bash
# Hlavičky
curl -i https://httpbin.org/headers -H "X-Trace-ID: abc123"

# Autentizace
curl -u user:pass https://httpbin.org/basic-auth/user/pass
curl -H "Authorization: Bearer <token>" https://httpbin.org/bearer

# Cookies (uložit / poslat)
curl -c cookies.txt https://httpbin.org/cookies/set?theme=dark
curl -b cookies.txt https://httpbin.org/cookies

# Form-URL-encoded a multipart
curl -d "a=1&b=2" https://httpbin.org/post
curl -F "file=@README.md" https://httpbin.org/post

# HTTP/2 a komprese
curl --http2 --compressed -I https://example.org
```

### 5.1.10 Web Security Basics

**Teorie:**
- **Same-Origin Policy (SOP):**
  - Definice „origin“ (schéma + doména + port).
  - Omezení přístupu JavaScriptu k datům z jiných originů.
  - Výjimky: `document.domain`, `postMessage`, iframy se sandboxem.
- **CORS (Cross-Origin Resource Sharing):**
  - Hlavičky: `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`.
  - Preflight request (OPTIONS).
- **CSRF (Cross-Site Request Forgery):**
  - Princip: zneužití přihlášeného uživatele k nechtěné akci.
  - Ochrana: SameSite cookies, CSRF tokeny, kontrola hlavičky `Referer`.
- **XSS (Cross-Site Scripting):**
  - Uložení nebo vložení škodlivého JavaScriptu do stránky.
  - Ochrana: escaping, CSP (Content-Security-Policy).
- **Bezpečné cookies a storage:**
  - Atributy: `HttpOnly`, `Secure`, `SameSite`.
  - Rizika ukládání tokenů v localStorage/sessionStorage.

**Praxe:**
```bash
# Ověření CORS
curl -i https://httpbin.org/get -H "Origin: https://evil.com"

# Test CSRF tokenu
curl -i -X POST https://example.com/transfer \
     -H "Cookie: session=abc123" \
     -d "amount=100" \
     -H "X-CSRF-Token: <token>"

# Ukázka XSS ve formuláři (teoreticky)
<input type="text" value="<script>alert('XSS')</script>">

# CSP hlavička
Content-Security-Policy: default-src 'self'; script-src 'self'
```

---

# BLOK 4: Obousměrná komunikace
**Cíl:** Umět vytvořit aplikaci, která reaguje v reálném čase a zvolit vhodný komunikační vzor.

### 5.2.1 Polling and Long Polling
**Teorie:**
- **Polling** vs. **long polling**: latence, náklady, škálování; timeouts, jitter, exponential backoff.
- **Konzistence dat:** verzování (cursor/`since_id`), deduplikace, idempotence.

**Praxe:**
- Mini „notifikace“: klient opakovaně dotazuje `/updates?since=<cursor>`; server vrací 204 pokud nic nového.

### 5.2.2 Server‑Sent Events (SSE)
**Teorie:**
- Jednosměrný proud od serveru: `Content-Type: text/event-stream`, pole `event:`, `data:`, `id:`, `retry:`.
- **Reconnect** a pozice (`Last-Event-ID`), proxy/timeouts, keep‑alive ping.
- Kdy volit SSE vs. WebSocket vs. polling.

**Praxe (Express SSE):**
```js
app.get("/stream", (req,res)=>{
  res.setHeader("Content-Type","text/event-stream");
  res.setHeader("Cache-Control","no-cache");
  res.flushHeaders();
  const iv = setInterval(()=>{
    res.write(`event: tick\ndata: ${Date.now()}\n\n`);
  }, 1000);
  req.on("close", ()=> clearInterval(iv));
});
```

### 5.2.3 WebSockets
**Teorie:**
- **Handshake:** `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key/Accept`.
- Full‑duplex, rámce, ping/pong, **backpressure**; subprotokoly (např. `graphql-ws`).
- **Provozní realita:** load balancery, sticky sessions, TLS terminace, limity počtu spojení.
- **Alternativy:** gRPC streaming (HTTP/2), WebTransport (QUIC, experimentální).

**Praxe:**
- Jednoduchý chat (např. `ws` v Node.js nebo Socket.IO). Přidejte heartbeat, reconnect a limit délky zprávy.

---

## DOPORUČENÁ ROZŠÍŘENÍ (BLOK 5 – volitelné)
### Bezpečnost & spolehlivost
- **HTTPS/TLS:** certifikační řetěz, OCSP stapling, HSTS, PFS.
- **Rate limiting** (`429`, `Retry-After`), **timeout budget**, **circuit breaker**, **hedging** požadavků.
- **Headers pro bezpečnost:** `CSP`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.

### Výkon & cache
- CDN a reverse proxy (Nginx), `Cache-Control` a `Surrogate-Control`, invalidace, `stale-while-revalidate`.
- **ETag** vs. `Last-Modified`, `Vary` na jazyk/encoding/autorizaci.

### Observabilita
- Strukturované logy, **Correlation/Trace‑ID**, OpenTelemetry, export do Jaeger/Tempo.
- **Problem Details** (`application/problem+json`) jako standard pro chyby API.

---

## Praktické dovednosti – výstu py (checklisty)
**Po BLOKU 1 umím:**
- [ ] Přečíst start‑line/hlavičky/tělo v DevTools a `curl -v`.
- [ ] Vysvětlit rozdíly HTTP/1.1 vs. HTTP/2 vs. HTTP/3.
- [ ] Vytvořit HAR a interpretovat TTFB/LCP (základně).

**Po BLOKU 2 umím:**
- [ ] Použít `Etag`/`If-None-Match`, rozlišit `301/302/307/308`.
- [ ] Vyřešit CORS preflight a nastavit `Vary`.
- [ ] Rozlišit `PUT` vs. `PATCH` a navrhnout idempotentní API.

**Po BLOKU 3 umím:**
- [ ] Správně zvolit `Content-Type`/`Content-Encoding`.
- [ ] Bezpečně nastavit cookie (`HttpOnly`, `Secure`, `SameSite`).
- [ ] Odeslat formulář/multipart upload přes `curl` a zpracovat na serveru.

**Po BLOKU 4 umím:**
- [ ] Implementovat long polling se správným timeoutem a backoffem.
- [ ] Spustit SSE stream s heartbeatem a obnovením po výpadku.
- [ ] Napsat jednoduchý WebSocket chat a řešit ping/pong.

---

## Doporučená cvičení „end‑to‑end“
1. **Mini API + klient:** Napište API (Express) s CRUD, ETag, 429 rate‑limit, CORS. Klientem testujte přes `httpie` a Postman.
2. **Streaming feed:** Implementujte SSE ticker, klient se automaticky připojuje po výpadku a loguje `Last-Event-ID`.
3. **Upload velkého souboru:** Multipart upload s ověřením checksumu a stavovou obnovou (resume) — navrhněte protokol.
4. **Observabilita:** Zaveďte Correlation‑ID (např. `X-Request-ID`) a dohledatelný průchod logy skrz reverse proxy.

---

## Shrnutí
Tento plán postupně kultivuje schopnost číst, psát a provozovat HTTP ve výrobní kvalitě: od základních requestů v DevTools přes správu hlaviček a cache, až po real‑time kanály (SSE/WebSockets) a provozní témata (bezpečnost, výkon, observabilita).
