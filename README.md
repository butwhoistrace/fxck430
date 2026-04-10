
<h1 align="center">FCK403</h1>
<p align="center">
  <b>Smash through 403 Forbidden.</b><br>
  Go · zero dependencies · 480+ techniques · 11 modules · baseline fingerprinting
</p>

<p align="center">
  <code>go install github.com/butwhoistrace/fck403@latest</code>
</p>

---

## Quick Start

```bash
fck403 https://target.com admin                    # run all modules
fck403 https://target.com admin -m paths,headers   # pick modules
fck403 https://target.com admin -s                 # only show bypasses
```

## Features

- **Baseline fingerprinting** — fingerprints the target (403), a random 404, and the root page before scanning. Compares every response by status + size + body hash to eliminate false positives
- **Smart classification** — distinguishes real bypasses from anomalies (TRACE reflections, 400/405 responses) and false positives (root page served instead of admin)
- **11 attack modules** — methods, path manipulation, IP spoofing, URL rewrite abuse, user-agent spoofing, referer tricks, host confusion, hop-by-hop abuse, protocol switching, port/proto headers, misc
- **Per-segment path manipulation** — multi-segment paths like `api/v1/dashboard` get traversal/encoding tricks injected at every segment boundary
- **Header combinations** — tests multi-header attacks (XFF + X-Real-IP + Client-IP together), not just individual headers
- **Body content matching** — `--match "dashboard"` highlights responses containing specific content
- **Rate limiting** — `-d 100` adds 100ms delay between requests to evade WAF rate limits
- **Redirect following** — `-L` follows 301/302 chains to confirm if redirects lead to actual content
- **Retry on failure** — automatic single retry with 500ms backoff on network errors
- **Real protocol switching** — separate HTTP transports for HTTP/1.0, HTTP/1.1, and HTTP/2
- **Zero dependencies** — pure Go stdlib, single binary

## Modules

```
fck403 --list

  methods    HTTP methods + overrides + Accept/CT/Encoding/Lang   (48 req)
  paths      Path manipulation, encoding, case, traversal         (47+ req)
  headers    IP spoofing: 22 headers x 15 IPs + combos           (335 req)
  rewrite    X-Original-URL, X-Rewrite-URL, X-Forwarded-Prefix    (9 req)
  ua         Googlebot, Bingbot, Yandex, Facebook, curl            (9 req)
  referer    Referer header spoofing                                (6 req)
  host       Host header manipulation + confusion attacks           (8 req)
  hopbyhop   Hop-by-hop header abuse via Connection                (11 req)
  protocol   HTTP/1.0, HTTP/1.1, HTTP/2 (real protocol switch)     (3 req)
  port       X-Forwarded-Proto, X-Forwarded-Port                    (6 req)
  misc       Wayback Machine, direct IP, API version fuzzing     (varies)
```

Pick one: `-m headers` · pick several: `-m methods,paths,ua` · or run all (default).

## Flags

```
Target & Scan                    Output & Filter
─────────────                    ───────────────
-u   target URL                  -o   text/json/csv
-p   target path                 -s   show only bypasses
-t   threads        (10)         -v   verbose (show anomalies, FPs)
-T   timeout        (10s)        --match  highlight body regex matches
-d   delay in ms    (0)          --no-color  disable ANSI colors

Network                          Modules
───────                          ───────
-x   proxy URL (Burp etc.)       -m   module list (default: all)
-c   cookie string               --list  show available modules
-H   custom header
-L   follow redirects
```

## Usage Examples

```bash
# Basic scan — run everything against /admin
fck403 https://target.com admin

# Only path + header tricks, show bypasses only
fck403 https://target.com admin -m paths,headers -s

# Through Burp proxy with 50ms rate limit
fck403 https://target.com admin -x http://127.0.0.1:8080 -d 50

# Follow redirects to confirm XFF IP spoofing bypasses
fck403 https://target.com admin -m headers -L -s

# Search for "dashboard" in response bodies
fck403 https://target.com admin --match "dashboard"

# Multi-segment path with JSON output
fck403 https://target.com api/v1/dashboard -o json

# Pipe-friendly output (no colors)
fck403 https://target.com admin -s --no-color | grep PATH

# Verbose mode — see anomalies and false positives
fck403 https://target.com admin -v
```

## How It Works

1. **Fingerprint** — sends 3 baseline requests: the target path (expects 403), a random non-existent path (expects 404), and the root page. Records status code, body size, and MD5 hash for each
2. **Scan** — fires 480+ requests across all enabled modules using concurrent goroutines with semaphore-based throttling
3. **Classify** — compares each response against the 3 fingerprints:
   - Matches baseline/404/root fingerprint → **false positive** (filtered)
   - 403/401 → **blocked**
   - 400/405/TRACE-200 → **anomaly** (not a real bypass)
   - 3xx → **redirect** (worth investigating)
   - Everything else → **bypass** (highlighted green)
4. **Report** — summary with bypass count, redirect targets, anomaly breakdown, and optional JSON/CSV export

## Disclaimer

Authorized testing only. Only use this tool on systems you have explicit permission to test.

## Credits

[iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403) · [HackTricks](https://book.hacktricks.xyz) · [Vidoc](https://blog.vidocsecurity.com) · [PortSwigger](https://portswigger.net/research)
