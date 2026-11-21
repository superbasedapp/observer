package secdast

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// The fixed probe ids, in request order.
const (
	ProbePage     = "page"
	ProbeGitHead  = "git-head"
	ProbeEnv      = "env"
	ProbeNotFound = "not-found"
	probeScript   = "script-"
	probeMap      = "map-"
)

// Request is one GET the run asks the lane to make. Only the fields below
// can vary: the lane sends no body, no cookie, no credential and a fixed
// User-Agent, to the target's origin only.
type Request struct {
	// ID names the probe (ProbePage, "script-1", ...).
	ID string
	// Path is origin-relative ("/" first), with its query.
	Path string
	// Origin, when set, is sent as the Origin header (CanaryOrigin on the
	// page probe).
	Origin string
}

// Header is a response's headers keyed by lower-case name.
type Header map[string][]string

// Get is the first value of name ("" when absent).
func (h Header) Get(name string) string {
	if v := h[strings.ToLower(name)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Values are every value of name.
func (h Header) Values(name string) []string { return h[strings.ToLower(name)] }

// Has reports whether name is present at all.
func (h Header) Has(name string) bool { _, ok := h[strings.ToLower(name)]; return ok }

// Response is what the lane read for one Request.
type Response struct {
	// RequestID is the Request's ID.
	RequestID string
	// Path is the origin-relative path finally answered (after same-origin
	// redirects).
	Path   string
	Status int
	Header Header
	// Body is at most MaxBodyBytes; Truncated says more was not read.
	Body      []byte
	Truncated bool
	// OffOriginRedirect is set when the server redirected off the origin:
	// the redirect was not followed and this response is the redirect.
	OffOriginRedirect bool
	// Err is a transport failure (refused dial, timeout, TLS), "" on an
	// answer. A refusal of the loopback rule reads here too.
	Err string
}

// Fetch is the lane seam: one Request in, one Response out. The production
// Fetch is internal/secdastnet; tests pass a table.
type Fetch func(ctx context.Context, req Request) Response

// The run outcomes. A run that could not read the page reports no finding
// and never reads as clean.
const (
	// OutcomeComplete: every probe was answered.
	OutcomeComplete = "complete"
	// OutcomePartial: the page was answered, some probe failed.
	OutcomePartial = "partial"
	// OutcomeUnreachable: the page itself was not answered; nothing was
	// checked.
	OutcomeUnreachable = "unreachable"
)

// ProbeError is one probe that got no answer.
type ProbeError struct {
	Probe string `json:"probe"`
	Path  string `json:"path"`
	Error string `json:"error"`
}

// Report is one run.
type Report struct {
	Target   string       `json:"target"`
	Outcome  string       `json:"outcome"`
	Requests int          `json:"requests"`
	Errors   []ProbeError `json:"errors,omitempty"`
	Hits     []Hit        `json:"hits"`
	// Checks is how many check rows ran (len(Checks) on a reachable
	// target, 0 when unreachable).
	Checks int `json:"checks"`
	// Responses are kept for the caller's tests and are not serialized.
	Responses []Response `json:"-"`
}

// Run makes the probes through fetch, in order, never more than
// MaxRequests, and evaluates the check table over the answers. notFound is
// a caller-chosen random token for the 404 probe (the package draws no
// randomness of its own). The run stops early when ctx ends.
func Run(ctx context.Context, t Target, notFound string, fetch Fetch) Report {
	rep := Report{Target: t.String(), Hits: []Hit{}}
	do := func(req Request) (Response, bool) {
		if rep.Requests >= MaxRequests || ctx.Err() != nil {
			return Response{}, false
		}
		rep.Requests++
		r := fetch(ctx, req)
		r.RequestID = req.ID
		if r.Path == "" {
			r.Path = req.Path
		}
		if r.Err != "" {
			rep.Errors = append(rep.Errors, ProbeError{Probe: req.ID, Path: req.Path, Error: r.Err})
		}
		rep.Responses = append(rep.Responses, r)
		return r, r.Err == ""
	}
	page, ok := do(Request{ID: ProbePage, Path: t.Page(), Origin: CanaryOrigin})
	if !ok {
		rep.Outcome = OutcomeUnreachable
		return rep
	}
	for _, req := range []Request{
		{ID: ProbeGitHead, Path: "/.git/HEAD"},
		{ID: ProbeEnv, Path: "/.env"},
		{ID: ProbeNotFound, Path: "/observer-dast-" + sanitizeToken(notFound)},
	} {
		do(req)
	}
	for i, p := range ScriptPaths(t, page) {
		script, ok := do(Request{ID: probeScript + strconv.Itoa(i+1), Path: p})
		if !ok {
			continue
		}
		if mp, ok := SourceMapPath(t, script); ok {
			do(Request{ID: probeMap + strconv.Itoa(i+1), Path: mp})
		}
	}
	rep.Outcome = OutcomeComplete
	if len(rep.Errors) > 0 || ctx.Err() != nil {
		rep.Outcome = OutcomePartial
	}
	rep.Hits = Evaluate(t, rep.Responses)
	rep.Checks = len(Checks())
	return rep
}

// sanitizeToken keeps a 404 token to [a-z0-9], at most 32 characters, so
// the probe path is always plain.
func sanitizeToken(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
		if b.Len() >= 32 {
			break
		}
	}
	if b.Len() == 0 {
		return "404"
	}
	return b.String()
}

// scriptSrc finds the src of a <script> element (either quote, or none).
var scriptSrc = regexp.MustCompile(`(?is)<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)

// ScriptPaths are the same-origin scripts an HTML page references, in page
// order, without duplicates, at most MaxScripts.
func ScriptPaths(t Target, page Response) []string {
	if page.Status < 200 || page.Status > 299 || !isHTML(page) {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range scriptSrc.FindAllSubmatch(page.Body, -1) {
		ref := string(m[1]) + string(m[2]) + string(m[3])
		p, ok := t.SameOrigin(page.Path, ref)
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) == MaxScripts {
			break
		}
	}
	return out
}

// mapComment is a JavaScript source map comment (//# or the old //@).
var mapComment = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*$`)

// SourceMapPath is the same-origin source map a script names: the SourceMap
// (or X-SourceMap) header first, else the last sourceMappingURL comment. A
// data: URI (an inline map) is not a request.
func SourceMapPath(t Target, script Response) (string, bool) {
	if script.Status < 200 || script.Status > 299 {
		return "", false
	}
	ref := script.Header.Get("sourcemap")
	if ref == "" {
		ref = script.Header.Get("x-sourcemap")
	}
	if ref == "" && !script.Truncated {
		body := strings.TrimRight(string(script.Body), " \t\r\n;")
		if i := strings.LastIndexByte(body, '\n'); i >= 0 {
			body = body[i+1:]
		}
		if m := mapComment.FindStringSubmatch(body); m != nil {
			ref = m[1]
		}
	}
	if ref == "" || strings.HasPrefix(strings.ToLower(ref), "data:") {
		return "", false
	}
	return t.SameOrigin(script.Path, ref)
}
