<p align="center">
<pre>
                                                              ███████╗ ██████╗██╗  ██╗██╗  ██╗ ██████╗ ██████╗ 
                                                              ██╔════╝██╔════╝██║ ██╔╝██║  ██║██╔═══██╗╚════██╗
                                                              █████╗  ██║     █████╔╝ ███████║██║   ██║ █████╔╝
                                                              ██╔══╝  ██║     ██╔═██╗ ╚════██║██║   ██║ ╚═══██╗
                                                              ██║     ╚██████╗██║  ██╗     ██║╚██████╔╝██████╔╝
                                                              ╚═╝      ╚═════╝╚═╝  ╚═╝     ╚═╝ ╚═════╝ ╚═════╝
</pre>
</p>

<h3 align="center">Smash through 403 Forbidden.</h3>

<p align="center">
  <img src="https://img.shields.io/badge/go-1.22+-00ADD8?style=flat&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/dependencies-zero-success" alt="Zero deps">
  <img src="https://img.shields.io/badge/techniques-480+-blueviolet" alt="480+ techniques">
  <img src="https://img.shields.io/badge/version-3.0-blue" alt="v3.0">
</p>

---

## Install

```
go install github.com/butwhoistrace/fck403@latest
```

Or clone and build:

```bash
git clone https://github.com/butwhoistrace/fck403.git
cd fck403 && go build -o fck403 .
```

---

## Usage

```bash
fck403 <url> <path> [flags]
fck403 -u <url> -p <path> [flags]
```

```bash
fck403 https://target.com admin                           # all modules, full scan
fck403 https://target.com admin -m paths,headers -s       # selected modules, bypasses only
fck403 https://target.com admin -d 100 -L                 # 100ms delay + follow redirects
fck403 https://target.com api/v1/dashboard -o json        # multi-segment path, JSON output
fck403 https://target.com admin --match "admin|dashboard" # highlight body content matches
fck403 https://target.com admin -s --no-color | grep PATH # pipe-friendly, no ANSI
fck403 https://target.com admin -x http://127.0.0.1:8080  # through Burp
fck403 --list                                             # show all modules
```

---

## What It Does

Give it a URL that returns **403 Forbidden**. It fires **480+ requests** across 11 attack modules — different methods, path encodings, spoofed headers, protocol tricks — and shows you what gets through.

Before scanning, it **fingerprints 3 baseline responses** (the 403 page, a random 404, and the root page) by status code, body size, and MD5 hash. Every scan result is compared against these fingerprints to **eliminate false positives** automatically.

Results are classified into 5 categories:

| Color | Category | Meaning |
|:---:|---|---|
| **Green** | **Bypass** | Different response from baseline — real access |
| **Cyan** | **Anomaly** | 400/405/TRACE — server quirk, not a real bypass |
| **Yellow** | **Redirect** | 301/302 — worth following up with `-L` |
| **Red** | **Blocked** | 403/401 — wall held |
| **Gray** | **False positive** | Response matches baseline/404/root fingerprint |

---

## Modules

```
  methods    HTTP methods + overrides + Accept/CT/Encoding/Lang   48 req
  paths      Path normalization, encoding, case, traversal       47+ req
  headers    IP spoofing: 22 headers × 15 IPs + combos          335 req
  rewrite    X-Original-URL, X-Rewrite-URL, X-Forwarded-Prefix    9 req
  ua         Googlebot, Bingbot, Yandex, Facebook, curl            9 req
  referer    Referer header spoofing                                6 req
  host       Host header manipulation + confusion attacks           8 req
  hopbyhop   Hop-by-hop header abuse via Connection                11 req
  protocol   HTTP/1.0, HTTP/1.1, HTTP/2 (real protocol switch)     3 req
  port       X-Forwarded-Proto, X-Forwarded-Port                    6 req
  misc       Wayback Machine, direct IP, API version fuzzing    varies
```

Pick one `-m headers` · pick several `-m methods,paths,ua` · or run all (default).

---

## Flags

| Flag | Description | Default |
|---|---|---|
| `-u` | Target URL | — |
| `-p` | Target path | — |
| `-t` | Threads | `10` |
| `-T` | Timeout (seconds) | `10` |
| `-d` | Delay between requests (ms) | `0` |
| `-m` | Modules (comma-separated or `all`) | `all` |
| `-o` | Output format: `text` / `json` / `csv` | `text` |
| `-x` | Proxy URL (e.g. Burp) | — |
| `-c` | Cookie string | — |
| `-H` | Custom header (`Key: Value`) | — |
| `-L` | Follow redirects | `false` |
| `-s` | Show only bypasses | `false` |
| `-v` | Verbose (show anomalies + false positives) | `false` |
| `--match` | Highlight responses where body matches regex | — |
| `--no-color` | Disable ANSI color output | `false` |
| `--list` | List available modules and exit | — |

> **Note:** URL and path can also be passed as positional arguments:
> `fck403 https://target.com admin` is the same as `fck403 -u https://target.com -p admin`

---

## Example Output

```
  Target:   https://example.com/intra/dashboard
  Threads:  10
  Timeout:  10s
  Delay:    100ms
  Modules:  methods, paths, headers, rewrite, ua, referer, host, hopbyhop, protocol, port, misc

  Fingerprinting baseline...
  Baseline:  [403] 1247 B  (target response)
  NotFound:  [404]  853 B  (random path)
  RootPage:  [200] 4821 B  (root / response)

  CODE     SIZE   TIME   CATEGORY          TECHNIQUE
  ──────────────────────────────────────────────────────────

  [1/11] Path Manipulation
  [403]    1247 B   0.19s  PATH             https://example.com/%2e/intra/dashboard
  [200]    8432 B   0.18s  PATH             https://example.com/intra/dashboard/
  [200]    8432 B   0.21s  PATH             https://example.com/intra/dashboard/.
  [200]    8432 B   0.19s  PATH             https://example.com//intra/dashboard//
  ...

  RESULTS
  ──────────────────────────────────────────────────────────
  Total:       481
  Bypassed:    6
  Anomalies:   3   (400/405/TRACE — not real bypasses)
  Redirects:   1
  Blocked:     439
  False pos:   2   (matched baseline/404/root)
  Errors:      30

  SMASHED THROUGH:
  ──────────────────────────────────────────────────────────
  [200]    8432 B  PATH   https://example.com/intra/dashboard/
  [200]    8432 B  PATH   https://example.com/intra/dashboard/.
  [200]    8432 B  PATH   https://example.com//intra/dashboard//
  [200]    8432 B  PATH   https://example.com/./intra/dashboard/./
  [200]    8432 B  PATH   https://example.com/intra;/dashboard
  [200]    8432 B  PATH   https://example.com/intra/dAshboard

  REDIRECTS (worth checking):
  [302]       0 B  IP-HEADER  -H 'X-Forwarded-For: 10.0.0.1' -> /intra/dashboard/
```

---

## How Baseline Fingerprinting Works

Most 403 bypass tools report everything that isn't 403 as a "bypass" — including TRACE reflections, error pages, and the site's homepage being served instead of the blocked content. This creates noise.

FCK403 solves this by taking **3 fingerprints before scanning**:

| Fingerprint | What it catches |
|---|---|
| **Baseline** (target → 403) | Custom error pages that return 200 with the same blocked content |
| **NotFound** (random path → 404) | Soft-404 catch-all pages, SPAs returning 200 for everything |
| **RootPage** (/ → 200) | Rewrite headers that get ignored and just serve the homepage |

Each fingerprint stores **status code + body size + MD5 body hash**. If a scan response matches any fingerprint exactly, it's classified as a **false positive** and filtered from the bypass list.

When FCK403 says **"0 bypasses found"**, it means zero. Not "zero real ones but here's 5 fake ones".

---

## Disclaimer

**Authorized testing only.** Only use this tool on systems you have explicit permission to test.

---

## Credits

[iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403) · [HackTricks](https://book.hacktricks.xyz) · [Vidoc](https://blog.vidocsecurity.com) · [PortSwigger](https://portswigger.net/research)
