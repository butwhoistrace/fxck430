
<h1 align="center">FCK403</h1>
<p align="center">
  <b>Smash through 403 Forbidden.</b><br>
  Go · zero dependencies · 300+ techniques · 11 attack vectors · module selector
</p>

---

### Install

```
go install github.com/butwhoistrace/fck403@latest
```

### Use

```bash
fck403 https://target.com admin                              # run everything
fck403 https://target.com admin -m methods,paths             # pick modules
fck403 https://target.com admin -m headers -s                # headers only, show bypasses only
fck403 -u https://target.com -p admin -o json                # save results as json
fck403 -u https://target.com -p admin -x http://127.0.0.1:8080  # through burp
fck403 --list                                                # show all modules
```

### Modules

```
fck403 --list

  methods    HTTP methods + overrides + Accept/CT        (30 req)
  paths      URL encoding, case, extensions, traversal   (47 req)
  headers    IP spoofing: 22 headers x 10 IPs           (220 req)
  rewrite    X-Original-URL, X-Rewrite-URL, X-Fwd-Prefix (9 req)
  ua         Googlebot, Bingbot, Yandex, Facebook         (9 req)
  referer    Referer spoofing                              (6 req)
  host       Host header manipulation + confusion          (8 req)
  hopbyhop   Strip security headers via Connection        (11 req)
  protocol   HTTP/1.0, 1.1, 2 (real protocol switch)      (3 req)
  port       X-Forwarded-Proto, X-Forwarded-Port           (6 req)
  misc       Wayback, direct IP, API version fuzzing    (varies)
```

Pick one: `-m headers` · pick several: `-m methods,paths,ua` · or run all (default).

### Flags

```
-u   target URL          -c   cookie            -m   modules (default: all)
-p   target path         -H   custom header     -s   show only bypasses
-t   threads (10)        -o   text/json/csv     -v   verbose
-T   timeout (10s)       -x   proxy URL         --list  show modules
```

### How it works

Give it a URL that returns 403. It fires requests with different methods, path encodings, spoofed headers, and protocol tricks. Everything that doesn't come back as 403 gets highlighted as a bypass.

### Disclaimer

Authorized testing only.

### Credits

[iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403) · [HackTricks](https://book.hacktricks.xyz) · [Vidoc](https://blog.vidocsecurity.com) · [PortSwigger](https://portswigger.net/research)
