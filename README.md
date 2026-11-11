# APP(1)

## NAME

**app** -- Go command-line HTTP/2 client for solving `nosql.ru` Proof-of-Work challenges without a JavaScript engine.

## SYNOPSIS

```text
./app --url <URL> [--cookie <file>] [--outcookie <file>] [--out <file>] [--outheader <file>] [--stdoutheaders]
```

## DESCRIPTION

`app` fetches the target URL, detects redirects to the `botcheck/challenge.php` verification page, solves the SHA-256 Proof-of-Work challenge natively in Go (`crypto/sha256`), emulates a randomized browser/canvas fingerprint, submits the verification payload to `verify.php`, stores resulting cookies, and retrieves the final target page.

Network connections prefer **IPv6** and **HTTP/2**, automatically falling back to **IPv4** and **HTTP/1.1** when the former are unavailable.

---

## 1. BUILD

Requirements: **Go 1.24+** (standard library only, zero external dependencies).

Build the `app` binary on Linux (Ubuntu / Debian):

```bash
go build -o app .
```

Optional static build without CGO:

```bash
CGO_ENABLED=0 go build -o app .
```

Run unit and local integration tests:

```bash
go test -v ./...
```

---

## 2. OPTIONS

Only `--url` is required. All other options are optional.

`--url URL`
: Target HTTP/HTTPS URL to fetch (required). Example: `https://nosql.ru/forum/forum.php?fid=8`.

`--cookie FILE`
: Path to load initial cookies from before making the first request. File format is flat `key=value` lines (no domain, path, or expiration attributes). If the server accepts these cookies (e.g., a valid `q_botcheck_pass`), no Proof-of-Work challenge is issued and the page loads directly.

`--outcookie FILE`
: Path to save resulting cookies (`key=value` per line) after obtaining the target page (either following Proof-of-Work verification and redirect, or directly when input cookies are already valid). Cookies deleted by the server (`Max-Age=0` or past `expires`) are omitted.

`--out FILE`
: Path to write the final HTTP response body (automatically decompressed if `Content-Encoding: gzip` is used).

`--outheader FILE`
: Path to write the status line and HTTP headers of the final response.

`--stdoutheaders`
: Print all outgoing request headers and incoming response headers across the full request/redirect/verification chain to `stdout` without bodies. Each request is preceded by a timestamp formatted as `year-mon-day hour:min:sec.millisec`.

### Cookie File Format

```text
key1=value1
key2=value2
```

### Examples

Full run saving cookies, response headers, and body:

```bash
./app --url https://nosql.ru/forum/forum.php?fid=8 --outcookie cookies.txt --out page.html --outheader headers.txt
```

Subsequent run reusing saved cookies with header tracing:

```bash
./app --url https://nosql.ru/forum/forum.php?fid=8 --cookie cookies.txt --outcookie cookies.txt --out page.html --stdoutheaders
```

Minimal invocation:

```bash
./app --url https://nosql.ru/forum/forum.php?fid=8
```

---

## 3. PROOF-OF-WORK SYSTEM

The browser gate on `nosql.ru` (`botcheck`) operates in four stages:

1. **Initial Request and Ticket Redirect (`302 Found`)**
   When no valid `q_botcheck_pass` cookie is present, `GET /forum/forum.php?fid=8` returns `HTTP 302` with `Location: botcheck/challenge.php?ticket=<payload>.<sig>`.
   The `<payload>` (Base64URL-encoded JSON protected by an HMAC signature `<sig>`) at this stage contains only `return_url`, `server_score` (server-side HTTP header trust score, 0--100), `nonce`, and `exp` (120-second TTL).
   **Why HTTP header inspection alone is insufficient:** the PoW parameters (`challenge_seed` and `difficulty`) are not present in the `Location` ticket; they are generated only on the subsequent request inside the HTML/JS body.

2. **Challenge Delivery (`GET /forum/botcheck/challenge.php?ticket=...`)**
   The server validates the initial ticket signature, generates a random 16-hex-character `challenge_seed` and `difficulty` (typically `4`), and serves an HTML page embedding JS constants:
   - `const TICKET = "<payload>.<sig>";` (updated signed ticket whose JSON payload also duplicates `challenge_seed` and `difficulty`);
   - `const SEED = "...";` (challenge seed string);
   - `const DIFFICULTY = 4;` (required number of leading `'0'` hex characters in the SHA-256 digest);
   - `const VERIFY_URL = "verify.php";` (relative verification endpoint).

3. **Proof-of-Work Computation**
   The client iterates integer `nonce = 0, 1, 2, ...` until the lowercase hexadecimal digest

   ```text
   SHA-256("<SEED>:<nonce>")
   ```

   begins with `DIFFICULTY` `'0'` characters (`4 * DIFFICULTY` leading zero bits; `65,536` hashes on average for `DIFFICULTY = 4`). No JS VM is required; this client computes it natively in Go using `crypto/sha256`.

4. **Verification (`POST /forum/botcheck/verify.php`) and Pass Cookie**
   The client submits a JSON payload to `verify.php`:
   - PoW solution: `ticket`, `pow_nonce`, `pow_hash`, `elapsed_ms`;
   - Browser environment signals: `webdriver` (`false`), `canvas` (browser JS draws text onto `<canvas>` and calls `toDataURL()`), `screen`, `lang`, `tz_offset`, `has_plugins`. The server evaluates these alongside `server_score` to decide whether to grant access or fall back to an interactive captcha.
   - **Fingerprint randomization in this tool:** instead of performing real canvas rendering, each run generates a cheap randomized `data:image/png;base64,...` string (an 8-byte PNG signature followed by random bytes via `math/rand/v2`), paired with randomized `screen`, `lang` / `Accept-Language`, `tz_offset`, `has_plugins`, and `User-Agent`.

   Upon verification, the server sets the signed pass cookie `q_botcheck_pass=<exp_b64>.<sig>` (`Max-Age=43200`, 12 hours) and returns:

   ```json
   {"action":"redirect","url":"http://nosql.ru/forum/forum.php?fid=8"}
   ```

   Following this URL (including the `301` upgrade from `http://` to `https://`) with `q_botcheck_pass` and forum session cookies yields `HTTP 200 OK` with the target page content.
