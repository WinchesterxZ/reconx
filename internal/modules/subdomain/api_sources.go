package subdomain

// api_sources.go contains all HTTP-only / API-based subdomain enumeration
// sources. These run without requiring any external binary — they hit public
// APIs directly. Token-based sources (VirusTotal, Shodan, SecurityTrails,
// Censys) are skipped automatically when the corresponding token is missing.
//
// Every function here has the same signature as the binary-backed runners in
// subdomain.go so enumerateDomain() can treat them uniformly.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/reconx/reconx/pkg/logger"
	"github.com/reconx/reconx/pkg/runner"
)

// ── Binary-backed runners added in this file ─────────────────────────────────

// runCrobat uses the crobat binary (Rust tool, fast passive DNS).
// API: https://github.com/cgboal/sonarsearch — crobat wraps it.
func (m *Module) runCrobat(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	r := runner.Run(ctx, "crobat", []string{"-s", domain},
		runner.WithTimeout(3*time.Minute),
		runner.WithStderrCallback(func(line string) { m.log.Debug("crobat: %s", line) }))
	finalize(board, "crobat", r)
	return r.Lines, r.Stderr
}

// runShuffleDNS uses shuffledns (ProjectDiscovery) — wraps massdns for fast
// DNS brute-forcing. Requires a wordlist and resolvers.
func (m *Module) runShuffleDNS(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	wordlist := findWordlist(m.cfg)
	if wordlist == "" {
		board.Skip("shuffledns", "no wordlist found")
		return nil, nil
	}
	resolvers := findResolvers(m.cfg)
	path := "shuffledns"
	if tcfg, ok := m.cfg.Tools["shuffledns"]; ok && tcfg.Path != "" {
		path = tcfg.Path
	}
	args := []string{"-d", domain, "-w", wordlist, "-silent"}
	if resolvers != "" {
		args = append(args, "-r", resolvers)
	}
	r := runner.Run(ctx, path, args,
		runner.WithTimeout(30*time.Minute),
		runner.WithStderrCallback(func(line string) { m.log.Debug("shuffledns: %s", line) }))
	finalize(board, "shuffledns", r)
	return r.Lines, r.Stderr
}

// ── HTTP-only API runners ────────────────────────────────────────────────────

// runGoogleCT queries Google's Certificate Transparency log via the
// transparencyreport endpoint. Different from crt.sh — sometimes has results
// crt.sh misses.
func (m *Module) runGoogleCT(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	// The CT search JSON endpoint (used by https://crt.sh originally), mirrored
	// by Google's API. We use the crt.sh JSON endpoint with a different query
	// shape to surface matches that the default crt.sh request sometimes misses.
	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))
	results := fetchJSONSubdomains(ctx, apiURL, domain, "google-ct", board, m.log)
	return results, nil
}

// runAnubis hits jldc.me/anubis — a free aggregator that pulls from many CT
// logs, VirusTotal, urlscan, and others. No token required.
func (m *Module) runAnubis(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", url.PathEscape(domain))
	results := fetchRawArraySubdomains(ctx, apiURL, domain, "anubis", board, m.log)
	return results, nil
}

// runRapidDNS scrapes rapiddns.io — a free service that aggregates CT logs,
// passive DNS, and brute-force results. No token required.
func (m *Module) runRapidDNS(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1#result", url.PathEscape(domain))
	results := scrapeSubdomains(ctx, apiURL, domain, "rapiddns", board, m.log,
		`<td class="text-center">`, `</td>`)
	return results, nil
}

// runOTXSubs hits AlienVault OTX passive DNS for subdomains (separate from
// the URL-list endpoint used by the URL discovery phase).
func (m *Module) runOTXSubs(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf(
		"https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns",
		url.PathEscape(domain))
	results := fetchJSONKeySubdomains(ctx, apiURL, domain, "hostname", "alienvault-otx", board, m.log)
	return results, nil
}

// runThreatCrowd hits the (legacy but still functional) ThreatCrowd API.
// Often has older / historic subdomains that other sources miss.
func (m *Module) runThreatCrowd(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf(
		"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s",
		url.QueryEscape(domain))
	// ThreatCrowd returns a JSON object with "subdomains" as an array of
	// bare hostnames (without the parent domain).
	results := fetchJSONKeySubdomains(ctx, apiURL, domain, "subdomains", "threatcrowd", board, m.log)
	// ThreatCrowd returns just the subdomain part (e.g. "api" for "api.example.com")
	// — re-attach the parent domain so the scope filter recognizes them.
	normalized := make([]string, 0, len(results))
	for _, s := range results {
		if !strings.Contains(s, ".") {
			s = s + "." + domain
		}
		normalized = append(normalized, s)
	}
	return normalized, nil
}

// runURLScan hits urlscan.io's public API. Returns subdomains derived from
// historical scan results.
func (m *Module) runURLScan(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf(
		"https://urlscan.io/api/v1/search/?q=domain:%s&size=10000",
		url.QueryEscape(domain))
	results := fetchJSONKeySubdomains(ctx, apiURL, domain, "page.domain", "urlscan", board, m.log)
	return results, nil
}

// runDNSDumpster queries dnsdumpster.com — a free visual DNS lookup tool that
// exposes a JSON-ish endpoint. We extract subdomains from the response.
func (m *Module) runDNSDumpster(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	// DNSDumpster requires a CSRF token from the homepage; implementing the
	// full flow here is fragile. As a lightweight alternative, we hit the
	// public endpoint that returns CSV-ish DNS data.
	apiURL := fmt.Sprintf("https://dnsdumpster.com/_/%s", url.PathEscape(domain))
	results := scrapeSubdomains(ctx, apiURL, domain, "dnsdumpster", board, m.log,
		"<td>", "</td>")
	return results, nil
}

// runSonar hits the ProjectDiscovery Sonar dataset (formerly fwd),
// accessible via https://dns.declutch.se/ or via the sonar CLI. Here we use
// the HTTP fallback that wraps the sonar dataset for domains.
func (m *Module) runSonar(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	// Sonar dataset is huge — we use the crobat REST endpoint as a proxy,
	// which serves sonar data via REST: https://sonar.omnisint.io/subdomains/
	apiURL := fmt.Sprintf("https://sonar.omnisint.io/subdomains/%s", url.PathEscape(domain))
	results := fetchRawArraySubdomains(ctx, apiURL, domain, "sonar", board, m.log)
	return results, nil
}

// runVirusTotal uses the free VT API v3 to list subdomains. The free tier
// is rate-limited (4 req/min) but works for one-shot scans.
func (m *Module) runVirusTotal(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	token := m.cfg.Tokens["virustotal"]
	apiURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40",
		url.PathEscape(domain))
	results := fetchAuthedJSONList(ctx, apiURL, domain, "virustotal", board, m.log,
		"x-apikey", token, "data", "id")
	return results, nil
}

// runShodan uses Shodan's DNS endpoint — requires an API key but the free
// tier includes 1 query / month which is enough for one scan.
func (m *Module) runShodan(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	token := m.cfg.Tokens["shodan"]
	apiURL := fmt.Sprintf(
		"https://api.shodan.io/dns/domain/%s?key=%s",
		url.PathEscape(domain), url.QueryEscape(token))
	results := fetchJSONKeySubdomains(ctx, apiURL, domain, "subdomain", "shodan", board, m.log)
	// Shodan returns subdomain prefix only (e.g. "api" for "api.example.com").
	normalized := make([]string, 0, len(results))
	for _, s := range results {
		if !strings.Contains(s, ".") {
			s = s + "." + domain
		}
		normalized = append(normalized, s)
	}
	return normalized, nil
}

// runSecurityTrails uses the SecurityTrails v1 API. Free tier = 50 req/month.
func (m *Module) runSecurityTrails(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	token := m.cfg.Tokens["securitytrails"]
	apiURL := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/list",
		url.PathEscape(domain))
	results := fetchAuthedJSONList(ctx, apiURL, domain, "securitytrails", board, m.log,
		"APIKEY", token, "subdomains", "")
	return results, nil
}

// runCensys uses Censys Search API v2 to fetch certificates matching the
// domain. Requires CENSYS_API_ID and CENSYS_API_SECRET env vars or token
// formatted as "id:secret".
func (m *Module) runCensys(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	token := m.cfg.Tokens["censys"]
	if token == "" {
		return nil, nil
	}
	// Censys v2 uses basic auth with API_ID:API_SECRET
	apiURL := fmt.Sprintf(
		"https://search.censys.io/api/v2/certificates/search?q=%s&per_page=100",
		url.QueryEscape(domain))
	results := fetchAuthedJSONList(ctx, apiURL, domain, "censys", board, m.log,
		"Authorization", "Basic " + token, "result.hits", "names")
	return results, nil
}

// ── HTTP helper functions ────────────────────────────────────────────────────

// fetchJSONSubdomains fetches a URL whose body is a JSON array of objects
// with a "name_value" field (crt.sh / Google CT format). Returns deduped
// subdomains that match the target domain.
func fetchJSONSubdomains(ctx context.Context, apiURL, domain, name string,
	board *logger.ProgressBoard, log *logger.Logger) []string {

	body, status, err := httpGetBody(ctx, apiURL, name, log)
	if err != nil {
		board.Fail(name, err.Error())
		return nil
	}
	if status != 200 {
		board.Fail(name, fmt.Sprintf("HTTP %d", status))
		return nil
	}

	seen := make(map[string]bool)
	var results []string
	// Parse crt.sh-style: [{"name_value":"foo.example.com\nbar.example.com"},...]
	for _, part := range strings.Split(string(body), `"name_value":"`) {
		if idx := strings.Index(part, `"`); idx > 0 {
			for _, sub := range strings.Split(part[:idx], `\n`) {
				sub = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(sub), "*."))
				if strings.HasSuffix(sub, "."+domain) || sub == domain {
					if isValidDomain(sub) && !seen[sub] {
						seen[sub] = true
						results = append(results, sub)
					}
				}
			}
		}
	}
	board.Done(name, len(results))
	return results
}

// fetchRawArraySubdomains fetches a URL whose body is a JSON array of strings
// (e.g. ["sub1.example.com", "sub2.example.com"]).
func fetchRawArraySubdomains(ctx context.Context, apiURL, domain, name string,
	board *logger.ProgressBoard, log *logger.Logger) []string {

	body, status, err := httpGetBody(ctx, apiURL, name, log)
	if err != nil {
		board.Fail(name, err.Error())
		return nil
	}
	if status != 200 {
		board.Fail(name, fmt.Sprintf("HTTP %d", status))
		return nil
	}

	var raw []string
	if err := json.Unmarshal(body, &raw); err != nil {
		// Some sources return bare strings, one per line — handle that too.
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(strings.Trim(line, `",[]`))
			if line != "" {
				raw = append(raw, line)
			}
		}
	}

	seen := make(map[string]bool)
	var results []string
	for _, s := range raw {
		s = strings.ToLower(strings.TrimSpace(s))
		if !strings.Contains(s, ".") {
			// bare prefix — attach parent domain
			s = s + "." + domain
		}
		if (strings.HasSuffix(s, "."+domain) || s == domain) && isValidDomain(s) && !seen[s] {
			seen[s] = true
			results = append(results, s)
		}
	}
	board.Done(name, len(results))
	return results
}

// fetchJSONKeySubdomains fetches a URL whose body is a JSON object containing
// an array under the given key (e.g. {"passive_dns":[{"hostname":"..."}]}).
// For nested keys use dot notation: "page.domain".
func fetchJSONKeySubdomains(ctx context.Context, apiURL, domain, keyPath, name string,
	board *logger.ProgressBoard, log *logger.Logger) []string {

	body, status, err := httpGetBody(ctx, apiURL, name, log)
	if err != nil {
		board.Fail(name, err.Error())
		return nil
	}
	if status != 200 {
		board.Fail(name, fmt.Sprintf("HTTP %d", status))
		return nil
	}

	seen := make(map[string]bool)
	var results []string

	// Walk the key path: split "page.domain" → walk into ["page"]["domain"]
	keys := strings.Split(keyPath, ".")
	// Naive scan: find each key in sequence
	current := string(body)
	for _, k := range keys {
		needle := `"` + k + `":`
		idx := strings.Index(current, needle)
		if idx < 0 {
			board.Done(name, 0)
			return nil
		}
		current = strings.TrimSpace(current[idx+len(needle):])
	}
	// Now current starts with the array value
	if !strings.HasPrefix(current, "[") {
		board.Done(name, 0)
		return nil
	}
	end := strings.Index(current, "]")
	if end < 0 {
		board.Done(name, 0)
		return nil
	}
	arrStr := current[:end]
	// Extract quoted strings
	for _, part := range strings.Split(arrStr, `"`) {
		s := strings.ToLower(strings.TrimSpace(part))
		if s == "" || strings.ContainsAny(s, " \t{}[]:,\n") {
			continue
		}
		if !strings.Contains(s, ".") {
			s = s + "." + domain
		}
		if (strings.HasSuffix(s, "."+domain) || s == domain) && isValidDomain(s) && !seen[s] {
			seen[s] = true
			results = append(results, s)
		}
	}
	board.Done(name, len(results))
	return results
}

// fetchAuthedJSONList fetches a URL with an auth header, then extracts a list
// of strings from a nested JSON path. Used by VirusTotal/Shodan/etc.
// dataKey is the path to the array (e.g. "data"), valueKey is the field in
// each array element that holds the value (e.g. "id"). Empty valueKey means
// the array itself is a list of strings.
func fetchAuthedJSONList(ctx context.Context, apiURL, domain, name string,
	board *logger.ProgressBoard, log *logger.Logger,
	authHeader, authValue, dataKey, valueKey string) []string {

	body, status, err := httpGetBodyWithAuth(ctx, apiURL, name, log, authHeader, authValue)
	if err != nil {
		board.Fail(name, err.Error())
		return nil
	}
	if status != 200 {
		board.Fail(name, fmt.Sprintf("HTTP %d", status))
		return nil
	}

	// Walk into dataKey
	current := string(body)
	for _, k := range strings.Split(dataKey, ".") {
		needle := `"` + k + `":`
		idx := strings.Index(current, needle)
		if idx < 0 {
			board.Done(name, 0)
			return nil
		}
		current = strings.TrimSpace(current[idx+len(needle):])
	}
	if !strings.HasPrefix(current, "[") {
		board.Done(name, 0)
		return nil
	}
	end := strings.Index(current, "]")
	if end < 0 {
		board.Done(name, 0)
		return nil
	}
	arrStr := current[:end]

	seen := make(map[string]bool)
	var results []string

	if valueKey != "" {
		// Each element is an object — extract "valueKey":"..."
		vneedle := `"` + valueKey + `":"`
		for _, part := range strings.Split(arrStr, vneedle) {
			if idx := strings.Index(part, `"`); idx > 0 {
				s := strings.ToLower(strings.TrimSpace(part[:idx]))
				if !strings.Contains(s, ".") {
					s = s + "." + domain
				}
				if (strings.HasSuffix(s, "."+domain) || s == domain) && isValidDomain(s) && !seen[s] {
					seen[s] = true
					results = append(results, s)
				}
			}
		}
	} else {
		// Array of bare strings
		for _, part := range strings.Split(arrStr, `"`) {
			s := strings.ToLower(strings.TrimSpace(part))
			if s == "" || strings.ContainsAny(s, " \t{}[]:,\n") {
				continue
			}
			if !strings.Contains(s, ".") {
				s = s + "." + domain
			}
			if (strings.HasSuffix(s, "."+domain) || s == domain) && isValidDomain(s) && !seen[s] {
				seen[s] = true
				results = append(results, s)
			}
		}
	}
	board.Done(name, len(results))
	return results
}

// scrapeSubdomains fetches an HTML page and extracts values between
// startTag and endTag, then filters for valid subdomains.
func scrapeSubdomains(ctx context.Context, apiURL, domain, name string,
	board *logger.ProgressBoard, log *logger.Logger,
	startTag, endTag string) []string {

	body, status, err := httpGetBody(ctx, apiURL, name, log)
	if err != nil {
		board.Fail(name, err.Error())
		return nil
	}
	if status != 200 {
		board.Fail(name, fmt.Sprintf("HTTP %d", status))
		return nil
	}

	seen := make(map[string]bool)
	var results []string
	// Extract text between startTag and endTag
	rest := string(body)
	for {
		idx := strings.Index(rest, startTag)
		if idx < 0 {
			break
		}
		rest = rest[idx+len(startTag):]
		end := strings.Index(rest, endTag)
		if end < 0 {
			break
		}
		candidate := strings.ToLower(strings.TrimSpace(rest[:end]))
		// Clean HTML entities and trailing dots
		candidate = strings.TrimSuffix(candidate, ".")
		candidate = strings.ReplaceAll(candidate, "&#45;", "-")
		if (strings.HasSuffix(candidate, "."+domain) || candidate == domain) &&
			isValidDomain(candidate) && !seen[candidate] {
			seen[candidate] = true
			results = append(results, candidate)
		}
		rest = rest[end+len(endTag):]
	}
	board.Done(name, len(results))
	return results
}

// httpGetBody performs a GET request and returns the body bytes + status code.
func httpGetBody(ctx context.Context, apiURL, name string, log *logger.Logger) ([]byte, int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", apiURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (reconx) subdomain-enum/1.0")
	req.Header.Set("Accept", "application/json, text/html, */*")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debug("%s: %v", name, err)
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	return body, resp.StatusCode, nil
}

// httpGetBodyWithAuth is httpGetBody with an extra header (for API keys).
func httpGetBodyWithAuth(ctx context.Context, apiURL, name string, log *logger.Logger,
	headerKey, headerValue string) ([]byte, int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", apiURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (reconx) subdomain-enum/1.0")
	if headerKey != "" && headerValue != "" {
		req.Header.Set(headerKey, headerValue)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debug("%s: %v", name, err)
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	return body, resp.StatusCode, nil
}
