package secdast

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Hit is one check that fired on one response.
type Hit struct {
	// Check is the row's ID (the finding's rule id).
	Check string `json:"check"`
	// Path is the origin-relative path the evidence comes from.
	Path string `json:"path"`
	// Key tells two hits of one check on one path apart (a cookie or a
	// header name, a signature); "" when the check fires once per path.
	Key string `json:"key,omitempty"`
	// Evidence states facts (status, header names, byte counts), never a
	// response body.
	Evidence string `json:"evidence"`
}

// Check is one row of the passive check table.
type Check struct {
	// ID is the finding rule id ("dast.<area>.<name>").
	ID         string
	Title      string
	Severity   policy.FindingSeverity
	Confidence policy.FindingConfidence
	CWE        []string
	// Message and FixHint are the finding's text (never the server's).
	Message string
	FixHint string
	eval    func(c *evalCtx) []Hit
}

// evalCtx is what every row reads: the target and the answers by probe.
type evalCtx struct {
	t    Target
	byID map[string]Response
	all  []Response
}

func (c *evalCtx) page() (Response, bool) {
	r, ok := c.byID[ProbePage]
	return r, ok && r.Err == ""
}

// Checks is the table, in report order. Section 14.9's set: security
// headers, cookie flags, CORS reflection, /.git/HEAD, /.env, directory
// listings, exposed source maps, framework debug pages, server banners.
//
//nolint:gocyclo // one row per check, each with its own small Fires closure; complexity tracks the table's length, not logic depth.
func Checks() []Check {
	return []Check{
		{
			ID: "dast.headers.csp-missing", Title: "No Content-Security-Policy",
			Severity: policy.FindingSeverityLow, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-693"},
			Message: "The page is served without a Content-Security-Policy header, so the browser has no policy limiting where scripts may load from; a cross-site scripting bug runs with no second line of defence.",
			FixHint: "Send a Content-Security-Policy header (start with default-src 'self' and a script-src that names your script hosts); a Report-Only header alone does not enforce anything.",
			eval:    pageHTMLHeaderMissing("content-security-policy", "no Content-Security-Policy header"),
		},
		{
			ID: "dast.headers.nosniff-missing", Title: "No X-Content-Type-Options: nosniff",
			Severity: policy.FindingSeverityLow, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-693"},
			Message: "The page is served without X-Content-Type-Options: nosniff, so a browser may guess a response's type and run content it should have treated as data.",
			FixHint: "Send X-Content-Type-Options: nosniff on every response.",
			eval: func(c *evalCtx) []Hit {
				p, ok := c.page()
				if !ok || !ok2xx(p) || strings.EqualFold(strings.TrimSpace(p.Header.Get("x-content-type-options")), "nosniff") {
					return nil
				}
				return []Hit{{Path: p.Path, Evidence: pageFact(p) + ": no X-Content-Type-Options: nosniff"}}
			},
		},
		{
			ID: "dast.headers.framing-missing", Title: "Page can be framed by any site",
			Severity: policy.FindingSeverityLow, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-1021"},
			Message: "The page sets neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive, so any site can load it in a frame (clickjacking).",
			FixHint: "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY or SAMEORIGIN).",
			eval: func(c *evalCtx) []Hit {
				p, ok := c.page()
				if !ok || !ok2xx(p) || !isHTML(p) {
					return nil
				}
				xfo := strings.ToUpper(strings.TrimSpace(p.Header.Get("x-frame-options")))
				if xfo == "DENY" || xfo == "SAMEORIGIN" || cspHas(p, "frame-ancestors") {
					return nil
				}
				return []Hit{{Path: p.Path, Evidence: pageFact(p) + ": no X-Frame-Options and no frame-ancestors"}}
			},
		},
		{
			ID: "dast.headers.hsts-missing", Title: "No Strict-Transport-Security over HTTPS",
			Severity: policy.FindingSeverityInfo, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-319"},
			Message: "The HTTPS page is served without Strict-Transport-Security, so a browser that first reaches the site over plain HTTP is not told to stay on HTTPS. Browsers ignore it for localhost; this matters for the deployed build.",
			FixHint: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains from the production HTTPS server.",
			eval: func(c *evalCtx) []Hit {
				p, ok := c.page()
				if !ok || !c.t.HTTPS() || !ok2xx(p) || p.Header.Has("strict-transport-security") {
					return nil
				}
				return []Hit{{Path: p.Path, Evidence: pageFact(p) + ": no Strict-Transport-Security header"}}
			},
		},
		{
			ID: "dast.headers.referrer-policy-missing", Title: "No Referrer-Policy",
			Severity: policy.FindingSeverityInfo, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-200"},
			Message: "The page sets no Referrer-Policy, so the browser's default decides how much of the page URL (paths, query tokens) other sites receive.",
			FixHint: "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
			eval:    pageHTMLHeaderMissing("referrer-policy", "no Referrer-Policy header"),
		},
		{
			ID: "dast.cookies.httponly-missing", Title: "Cookie readable by scripts",
			Severity: policy.FindingSeverityLow, Confidence: policy.FindingConfidenceMedium, CWE: []string{"CWE-1004"},
			Message: "A cookie is set without HttpOnly, so any script on the page, an injected one included, can read it. Session and authentication cookies should never be readable by scripts.",
			FixHint: "Set HttpOnly on session and authentication cookies (a CSRF token cookie a script must read is the usual exception and is not reported).",
			eval: cookieRule(func(c *evalCtx, ck cookie) (string, bool) {
				if ck.httpOnly || ck.csrfLike() {
					return "", false
				}
				return "no HttpOnly", true
			}),
		},
		{
			ID: "dast.cookies.secure-missing", Title: "Cookie without Secure over HTTPS",
			Severity: policy.FindingSeverityLow, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-614"},
			Message: "An HTTPS response sets a cookie without Secure, so the browser would also send it over plain HTTP.",
			FixHint: "Set Secure on every cookie the HTTPS site sets.",
			eval: cookieRule(func(c *evalCtx, ck cookie) (string, bool) {
				if !c.t.HTTPS() || ck.secure {
					return "", false
				}
				return "no Secure", true
			}),
		},
		{
			ID: "dast.cookies.samesite-missing", Title: "Cookie without a SameSite policy",
			Severity: policy.FindingSeverityLow, Confidence: policy.FindingConfidenceMedium, CWE: []string{"CWE-1275"},
			Message: "A cookie is set without a SameSite attribute (or with SameSite=None but without Secure), so its cross-site behaviour is left to each browser's default and cross-site request forgery is easier.",
			FixHint: "Set SameSite=Lax (or Strict) on session cookies; SameSite=None needs Secure.",
			eval: cookieRule(func(_ *evalCtx, ck cookie) (string, bool) {
				switch {
				case ck.sameSite == "":
					return "no SameSite", true
				case ck.sameSite == "none" && !ck.secure:
					return "SameSite=None without Secure", true
				}
				return "", false
			}),
		},
		{
			ID: "dast.cors.origin-reflected-credentials", Title: "CORS reflects any origin, with credentials",
			Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-942"},
			Message: "The server echoed a foreign Origin in Access-Control-Allow-Origin and allowed credentials, so any website the developer or a user visits can read this server's authenticated responses.",
			FixHint: "Allow only a fixed list of trusted origins; never copy the request's Origin into Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true.",
			eval:    corsRule(func(acao string, creds bool) bool { return acao == CanaryOrigin && creds }),
		},
		{
			ID: "dast.cors.origin-reflected", Title: "CORS reflects any origin",
			Severity: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-942"},
			Message: "The server echoed a foreign Origin in Access-Control-Allow-Origin, so any website can read this server's responses to anonymous requests.",
			FixHint: "Allow only a fixed list of trusted origins instead of copying the request's Origin header.",
			eval:    corsRule(func(acao string, creds bool) bool { return acao == CanaryOrigin && !creds }),
		},
		{
			ID: "dast.cors.wildcard-credentials", Title: "CORS wildcard with credentials",
			Severity: policy.FindingSeverityLow, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-942"},
			Message: "The server answers Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Browsers refuse that pair, so it fails today, and it is often 'fixed' by reflecting the Origin, which is the dangerous form.",
			FixHint: "Either drop credentials for the public wildcard or list the trusted origins explicitly.",
			eval:    corsRule(func(acao string, creds bool) bool { return acao == "*" && creds }),
		},
		{
			ID: "dast.exposed.git", Title: "Git metadata served (/.git/HEAD)",
			Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-538"},
			Message: "The server serves the repository's .git directory: /.git/HEAD answered with a Git ref. Anyone who can reach the server can usually download the whole history, secrets ever committed included.",
			FixHint: "Do not serve the project directory itself; serve only the build output, or deny every path under /.git.",
			eval: func(c *evalCtx) []Hit {
				r, ok := c.byID[ProbeGitHead]
				if !ok || r.Err != "" || r.Status != 200 || isHTML(r) {
					return nil
				}
				b := strings.TrimSpace(string(r.Body))
				if !strings.HasPrefix(b, "ref: refs/") && !isHexID(b) {
					return nil
				}
				return []Hit{{Path: r.Path, Evidence: fmt.Sprintf("GET %s (%d, %d bytes): a Git HEAD ref", r.Path, r.Status, len(r.Body))}}
			},
		},
		{
			ID: "dast.exposed.env", Title: "Environment file served (/.env)",
			Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-538"},
			Message: "The server serves /.env, a file of NAME=value lines that usually holds API keys and database passwords. Its contents were not read into this finding.",
			FixHint: "Do not serve the project directory; move secrets out of the web root and rotate every value the file held.",
			eval: func(c *evalCtx) []Hit {
				r, ok := c.byID[ProbeEnv]
				if !ok || r.Err != "" || r.Status != 200 || isHTML(r) {
					return nil
				}
				n := envLines(r.Body)
				if n == 0 {
					return nil
				}
				return []Hit{{Path: r.Path, Evidence: fmt.Sprintf("GET %s (%d, %d bytes): %d NAME=value lines (values not read)", r.Path, r.Status, len(r.Body), n)}}
			},
		},
		{
			ID: "dast.listing.directory", Title: "Directory listing",
			Severity: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceMedium, CWE: []string{"CWE-548"},
			Message: "A response is a generated directory listing, so every file under that directory can be found and fetched, ones never linked from the app included.",
			FixHint: "Turn directory listings off (autoindex off, serve-index removed, python -m http.server only for throwaway use).",
			eval: func(c *evalCtx) []Hit {
				var out []Hit
				for _, r := range c.all {
					if r.Err != "" || r.Status != 200 || !isHTML(r) {
						continue
					}
					if sig := matchSignature(r.Body, listingSignatures); sig != "" {
						out = append(out, Hit{Path: r.Path, Key: sig, Evidence: fmt.Sprintf("GET %s (%d): %s", r.Path, r.Status, sig)})
					}
				}
				return out
			},
		},
		{
			ID: "dast.exposed.sourcemap", Title: "Source map served",
			Severity: policy.FindingSeverityLow, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-540"},
			Message: "A script's source map is served, which gives anyone the original source layout and often the source itself. Normal for a development server; make sure the production build does not publish it.",
			FixHint: "Build production bundles without public source maps (or with hidden source maps uploaded only to your error tracker).",
			eval: func(c *evalCtx) []Hit {
				var out []Hit
				for _, r := range c.all {
					if !strings.HasPrefix(r.RequestID, probeMap) || r.Err != "" || r.Status != 200 {
						continue
					}
					b := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(r.Body), []byte(")]}'")))
					if !bytes.HasPrefix(b, []byte("{")) || !bytes.Contains(b, []byte(`"mappings"`)) || !bytes.Contains(b, []byte(`"sources"`)) {
						continue
					}
					ev := fmt.Sprintf("GET %s (%d, %d bytes): a source map", r.Path, r.Status, len(r.Body))
					if bytes.Contains(b, []byte(`"sourcesContent"`)) {
						ev += " with the sources embedded"
					}
					out = append(out, Hit{Path: r.Path, Evidence: ev})
				}
				return out
			},
		},
		{
			ID: "dast.debug.page", Title: "Framework debug page",
			Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceMedium, CWE: []string{"CWE-489", "CWE-215"},
			Message: "A response is a framework's debug or developer error page, which shows stack traces, settings and sometimes an interactive console. Expected while developing; it must never be on in a build anyone else can reach.",
			FixHint: "Turn the framework's debug mode off outside local development (DEBUG = False, APP_DEBUG=false, NODE_ENV=production, ASPNETCORE_ENVIRONMENT=Production, display_errors off).",
			eval: func(c *evalCtx) []Hit {
				var out []Hit
				for _, r := range c.all {
					if r.Err != "" || strings.HasPrefix(r.RequestID, probeMap) || strings.HasPrefix(r.RequestID, probeScript) {
						continue
					}
					if sig := matchSignature(r.Body, debugSignatures); sig != "" {
						out = append(out, Hit{Path: r.Path, Key: sig, Evidence: fmt.Sprintf("GET %s (%d): %s", r.Path, r.Status, sig)})
					}
				}
				return out
			},
		},
		{
			ID: "dast.banner.version", Title: "Server software and version disclosed",
			Severity: policy.FindingSeverityInfo, Confidence: policy.FindingConfidenceHigh, CWE: []string{"CWE-200"},
			Message: "A response header names the server software or framework, with a version where shown, which tells an attacker which known vulnerabilities to try.",
			FixHint: "Remove X-Powered-By and the framework version headers, and send a Server header without a version (server_tokens off, app.disable('x-powered-by')).",
			eval: func(c *evalCtx) []Hit {
				p, ok := c.page()
				if !ok {
					return nil
				}
				var out []Hit
				for _, name := range bannerHeaders {
					v := strings.TrimSpace(p.Header.Get(name))
					if v == "" || (name == "server" && !hasDigit(v)) {
						continue
					}
					out = append(out, Hit{Path: p.Path, Key: name, Evidence: fmt.Sprintf("GET %s: %s: %s", p.Path, canonicalName(name), clip(v, 80))})
				}
				return out
			},
		},
	}
}

// Evaluate runs every row over the answers, in table order.
func Evaluate(t Target, rs []Response) []Hit {
	c := &evalCtx{t: t, byID: map[string]Response{}, all: rs}
	for _, r := range rs {
		c.byID[r.RequestID] = r
	}
	out := []Hit{}
	for _, row := range Checks() {
		for _, h := range row.eval(c) {
			h.Check = row.ID
			out = append(out, h)
		}
	}
	return out
}

// CheckByID returns the row with id.
func CheckByID(id string) (Check, bool) {
	for _, c := range Checks() {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}

// --- shared row helpers --------------------------------------------------

func ok2xx(r Response) bool { return r.Status >= 200 && r.Status <= 299 }

// isHTML reads the Content-Type, then sniffs the first bytes.
func isHTML(r Response) bool {
	ct := strings.ToLower(r.Header.Get("content-type"))
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml") {
		return true
	}
	if ct != "" && !strings.HasPrefix(ct, "text/plain") {
		return false
	}
	head := bytes.ToLower(bytes.TrimSpace(r.Body))
	if len(head) > 512 {
		head = head[:512]
	}
	return bytes.HasPrefix(head, []byte("<!doctype html")) || bytes.HasPrefix(head, []byte("<html")) || bytes.Contains(head, []byte("<head")) || bytes.Contains(head, []byte("<body"))
}

func pageFact(p Response) string {
	ct := p.Header.Get("content-type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if ct == "" {
		ct = "no content type"
	}
	return fmt.Sprintf("GET %s (%d, %s)", p.Path, p.Status, clip(strings.TrimSpace(ct), 64))
}

func pageHTMLHeaderMissing(name, fact string) func(c *evalCtx) []Hit {
	return func(c *evalCtx) []Hit {
		p, ok := c.page()
		if !ok || !ok2xx(p) || !isHTML(p) || p.Header.Has(name) {
			return nil
		}
		return []Hit{{Path: p.Path, Evidence: pageFact(p) + ": " + fact}}
	}
}

func cspHas(r Response, directive string) bool {
	for _, v := range r.Header.Values("content-security-policy") {
		for _, part := range strings.Split(v, ";") {
			if f := strings.Fields(part); len(f) > 0 && strings.EqualFold(f[0], directive) {
				return true
			}
		}
	}
	return false
}

func corsRule(fires func(acao string, creds bool) bool) func(c *evalCtx) []Hit {
	return func(c *evalCtx) []Hit {
		p, ok := c.page()
		if !ok {
			return nil
		}
		acao := strings.TrimSpace(p.Header.Get("access-control-allow-origin"))
		creds := strings.EqualFold(strings.TrimSpace(p.Header.Get("access-control-allow-credentials")), "true")
		if acao == "" || !fires(acao, creds) {
			return nil
		}
		ev := fmt.Sprintf("GET %s with Origin: %s answered Access-Control-Allow-Origin: %s", p.Path, CanaryOrigin, clip(acao, 80))
		if creds {
			ev += " and Access-Control-Allow-Credentials: true"
		}
		return []Hit{{Path: p.Path, Evidence: ev}}
	}
}

// cookie is one Set-Cookie header's name and attributes (the value is
// never kept).
type cookie struct {
	name     string
	httpOnly bool
	secure   bool
	sameSite string // lower case, "" when absent
}

func (c cookie) csrfLike() bool {
	n := strings.ToLower(c.name)
	return strings.Contains(n, "csrf") || strings.Contains(n, "xsrf")
}

func parseSetCookie(v string) (cookie, bool) {
	parts := strings.Split(v, ";")
	name, _, ok := strings.Cut(parts[0], "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return cookie{}, false
	}
	ck := cookie{name: clip(name, 64)}
	for _, a := range parts[1:] {
		k, val, _ := strings.Cut(strings.TrimSpace(a), "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "httponly":
			ck.httpOnly = true
		case "secure":
			ck.secure = true
		case "samesite":
			ck.sameSite = strings.ToLower(strings.TrimSpace(val))
		}
	}
	return ck, true
}

// cookieRule reports each cookie (by name, once per run) that fires.
func cookieRule(fires func(c *evalCtx, ck cookie) (string, bool)) func(c *evalCtx) []Hit {
	return func(c *evalCtx) []Hit {
		var out []Hit
		seen := map[string]bool{}
		for _, r := range c.all {
			if r.Err != "" {
				continue
			}
			for _, v := range r.Header.Values("set-cookie") {
				ck, ok := parseSetCookie(v)
				if !ok || seen[ck.name] {
					continue
				}
				fact, hit := fires(c, ck)
				if !hit {
					continue
				}
				seen[ck.name] = true
				out = append(out, Hit{Path: r.Path, Key: ck.name, Evidence: fmt.Sprintf("GET %s set cookie %q: %s", r.Path, ck.name, fact)})
			}
		}
		return out
	}
}

// signature is one fixed text a page carries, and the name reported.
type signature struct {
	name string
	re   *regexp.Regexp
}

func matchSignature(body []byte, sigs []signature) string {
	for _, s := range sigs {
		if s.re.Match(body) {
			return s.name
		}
	}
	return ""
}

var listingSignatures = []signature{
	{"an \"Index of /\" listing (Apache, nginx autoindex)", regexp.MustCompile(`(?i)<title>\s*Index of /`)},
	{"a \"Directory listing for /\" page (Python http.server)", regexp.MustCompile(`(?i)<title>\s*Directory listing for /`)},
	{"a \"listing directory\" page (serve-index)", regexp.MustCompile(`(?i)<title>\s*listing directory /`)},
	{"an \"Index of /\" heading", regexp.MustCompile(`(?i)<h1>\s*Index of /`)},
}

var debugSignatures = []signature{
	{"the Django debug page (DEBUG = True)", regexp.MustCompile(`You're seeing this error because you have <code>DEBUG = True</code>`)},
	{"the Werkzeug debugger", regexp.MustCompile(`(?i)Werkzeug Debugger|The debugger caught an exception in your WSGI application`)},
	{"the Rails development error page", regexp.MustCompile(`Action Controller: Exception caught`)},
	{"the ASP.NET Core developer exception page", regexp.MustCompile(`An unhandled exception occurred while processing the request\.`)},
	{"the ASP.NET error page with details", regexp.MustCompile(`Server Error in '/[^']*' Application`)},
	{"an Express stack trace", regexp.MustCompile(`at Layer\.handle \[as handle_request\]`)},
	{"the Whoops error page (Laravel and other PHP frameworks)", regexp.MustCompile(`Whoops! There was an error\.`)},
	{"PHP errors shown in the page (display_errors on)", regexp.MustCompile(`<b>(?:Fatal error|Parse error|Warning|Notice|Deprecated)</b>:.{0,400}? on line <b>\d+</b>`)},
}

// bannerHeaders are the version-disclosing headers, in report order.
var bannerHeaders = []string{"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"}

func canonicalName(lower string) string {
	parts := strings.Split(lower, "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}

var envLine = regexp.MustCompile(`^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=`)

// envLines counts NAME=value lines; a body that is mostly something else
// (an HTML fallback page, JSON) counts zero.
func envLines(body []byte) int {
	n, other := 0, 0
	for _, line := range strings.Split(string(body), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if envLine.MatchString(l) {
			n++
		} else {
			other++
		}
	}
	if n == 0 || other > n {
		return 0
	}
	return n
}

func isHexID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func hasDigit(s string) bool { return strings.ContainsAny(s, "0123456789") }

// clip cuts s to n bytes on a rune boundary and drops control characters.
func clip(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+len(string(r)) > n {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
