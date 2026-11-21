package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// launch_hold.go holds an agent's launch for a human (lane cli-2 fixes-1,
// the plans orchestrator's ruling on audit M2; the operator's decision is
// "ask on each launch"). Every dashboard route whose write starts an agent
// or a harness of agents is a row of agentLaunchRoutes; reg wraps exactly
// those (holdAgentLaunch). When such a write's caller is attributed to an
// agent (Options.LaunchCaller, the daemon's ancestry walk), the launch is
// not started: the daemon's store (Options.PendingLaunches) keeps an action
// that replays this exact request (method, path, headers, body), and the
// caller gets 202 with the hold. A human confirms it once, before it expires,
// on the Terminals page (POST /api/terminal/pending/<id>/confirm) or with
// `observer terminals confirm <id>`; the replay then records the agent as
// the run's initiator. The table's completeness against every registered
// route is pinned (TestEveryLaunchRouteIsHeldAndAsked), and so is its
// agreement with guard rule R-168's route table.

// maxHeldBody bounds the request body a hold keeps (a launch body is a few
// hundred bytes; a benchmark spec is capped at 256 KiB by its handler).
const maxHeldBody = 512 << 10

// sessionLaunchPath is the per-session launch routes' path: a continue
// (/api/session/<id>/launch) and a resume (/api/session/<id>/resume).
var sessionLaunchPath = regexp.MustCompile(`^/api/session/[^/]+/(?:launch|resume)$`)

// agentLaunchRoute is one dashboard route whose write starts an agent or a
// harness of agents.
type agentLaunchRoute struct {
	// pattern is the registered mux pattern.
	pattern string
	// path narrows the route to the request paths that launch (a prefix
	// pattern serves other sub-routes too).
	path func(p string) bool
	// body, when set, narrows the row to a body that starts something.
	body func(body []byte) bool
	// what names the launch for the human who confirms it.
	what string
}

func pathIs(want string) func(string) bool { return func(p string) bool { return p == want } }

// agentLaunchRoutes is THE table of launch routes (one row per route).
var agentLaunchRoutes = []agentLaunchRoute{
	{pattern: "/api/terminal/launch", path: pathIs("/api/terminal/launch"), what: "New Terminal launch"},
	{pattern: "/api/arena/runs", path: pathIs("/api/arena/runs"), what: "Agent Arena run (one agent per candidate)"},
	{pattern: "/api/session/", path: sessionLaunchPath.MatchString, what: "session continue or resume"},
	{pattern: "/api/tools/launch", path: pathIs("/api/tools/launch"), what: "Tools card launch (a terminal window running the agent)"},
	{pattern: "/api/security/fix/launch", path: pathIs("/api/security/fix/launch"), what: "Fix with an agent (Code security findings)"},
	{pattern: "/api/security/assessments/launch", path: pathIs("/api/security/assessments/launch"), what: "Security assessment (an agent assesses a project)"},
	{pattern: "/api/security/assessments/fix", path: pathIs("/api/security/assessments/fix"), what: "Fix a security assessment item (an agent edits the project)"},
	{pattern: "/api/benchmarks/run", path: pathIs("/api/benchmarks/run"), body: benchmarkSpendBody, what: "Benchmarks spend run (drives agent harnesses)"},
}

// sandboxLineRoutes are the launch routes whose held card says whether the
// launch is sandboxed (a body without a true sandbox member reads
// "unsandboxed"): the routes that start one agent in a project folder. The
// rows that run a harness of agents (the arena, the benchmark) carry no such
// line.
var sandboxLineRoutes = map[string]bool{
	"/api/terminal/launch":             true,
	"/api/session/":                    true,
	"/api/tools/launch":                true,
	"/api/security/fix/launch":         true,
	"/api/security/assessments/launch": true,
	"/api/security/assessments/fix":    true,
}

// routeChosenSandbox are the launch routes that decide the sandbox themselves
// for some bodies: the answer says the route will run this body's launch in a
// sandbox whatever its sandbox member says (a security assessment kind that
// runs only in one; the dialog sends no sandbox member for it). The held card
// reads it, so a launch the route will sandbox is never shown as "unsandboxed:
// runs on this machine with your access".
var routeChosenSandbox = map[string]func(body []byte) bool{
	"/api/security/assessments/launch": securityAssessBodySandboxed,
}

// heldSandboxed says a held launch will run in a sandbox: its own sandbox
// member is true, or its route sandboxes it itself.
func heldSandboxed(row agentLaunchRoute, body []byte, member bool) bool {
	if member {
		return true
	}
	chosen, ok := routeChosenSandbox[row.pattern]
	return ok && chosen(body)
}

// heldExtra is what a route adds to its hold beyond the body's own members.
type heldExtra struct {
	// Details are rows only the server can compute, shown before the body's
	// members (the card's first rows are Observer's, never the agent's).
	Details []dashapi.PendingLaunchDetail
	// Body, when set, is the body the confirm replays in place of the agent's
	// own, and the card shows its members. A route sets it to pin what the
	// card showed (a digest the confirm must still match).
	Body []byte
	// Refuse, when set, answers the request in the route's own words and holds
	// nothing: the launch could not run as asked.
	Refuse func(w http.ResponseWriter)
}

// heldExtras are the routes whose hold computes more than the body's members:
// the fix of an assessment item shows the exact prompt the confirm would start
// and pins its digest into the replayed body (W6b-B1, M2).
var heldExtras = map[string]func(s *Server, r *http.Request, body []byte) heldExtra{
	"/api/security/assessments/fix": (*Server).securityAssessFixHeld,
}

// benchmarkSpendBody reports whether a benchmark run body asks to spend
// (a dry run starts no harness). An undecodable body counts as a spend.
func benchmarkSpendBody(body []byte) bool {
	var b struct {
		ConfirmSpend json.RawMessage `json:"confirm_spend"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return true
	}
	v := strings.TrimSpace(string(b.ConfirmSpend))
	return v != "" && v != "false" && v != "null"
}

// launchRouteFor returns the table row of a registered pattern.
func launchRouteFor(pattern string) (agentLaunchRoute, bool) {
	for _, r := range agentLaunchRoutes {
		if r.pattern == pattern {
			return r, true
		}
	}
	return agentLaunchRoute{}, false
}

// heldReplayKey marks a request the daemon replays for a confirmed hold;
// it carries the origin the hold recorded.
type heldReplayKey struct{}

type heldReplay struct{ initiator, parent string }

// replayOrigin returns the held origin of a confirmed replay.
func replayOrigin(ctx context.Context) (heldReplay, bool) {
	h, ok := ctx.Value(heldReplayKey{}).(heldReplay)
	return h, ok
}

// holdAgentLaunch wraps a launch route's handler: an agent's write is held
// for a human, anything else passes unchanged. A pattern that is not a
// launch route is returned as it is.
func (s *Server) holdAgentLaunch(pattern string, h http.HandlerFunc) http.HandlerFunc {
	row, ok := launchRouteFor(pattern)
	if !ok {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !row.path(r.URL.Path) {
			h(w, r)
			return
		}
		if _, replay := replayOrigin(r.Context()); replay {
			h(w, r) // a confirmed hold: run it
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxHeldBody+1))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) > maxHeldBody {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if row.body != nil && !row.body(body) {
			h(w, r)
			return
		}
		initiator, parent := s.launchOrigin(r)
		if initiator != dashapi.InitiatorAgent {
			h(w, r)
			return
		}
		// One decode, one truth (fixes-3, audit M2): the handler's
		// encoding/json decode matches member names without regard to case
		// and keeps the last, so a body that names a member twice under that
		// folding could run other than its card reads. It is refused, never
		// held.
		if name, dup := foldedDuplicateMember(body); dup {
			writePendingError(w, http.StatusBadRequest, dashapi.PendingCodeDuplicateMember,
				"an agent asked for this launch, and its body names "+strconv.Quote(name)+" more than once (member names are matched without regard to case, the way the launch handler reads them), so what it would run cannot be shown for a confirm; nothing was held or started. Send each member once.")
			return
		}
		s.holdForHuman(w, r, row, body, h, initiator, parent)
	}
}

// holdForHuman records the hold and answers 202.
func (s *Server) holdForHuman(w http.ResponseWriter, r *http.Request, row agentLaunchRoute, body []byte, h http.HandlerFunc, initiator, parent string) {
	if s.opts.PendingLaunches == nil {
		writePendingError(w, http.StatusForbidden, dashapi.PendingCodeConfirmRefused,
			"an agent asked for this launch and it needs a human's confirm, but this dashboard has no launch hold; start the run yourself")
		return
	}
	// A route that computes more than the body shows (the fix of an assessment
	// item) answers, pins the body the confirm replays, and leads the card with
	// rows of its own. It runs before the hold, on a request the hold may still
	// refuse as full; a route bounds its own work (see its hook).
	var extra heldExtra
	if hook, ok := heldExtras[row.pattern]; ok {
		extra = hook(s, r, body)
		if extra.Refuse != nil {
			extra.Refuse(w)
			return
		}
		if extra.Body != nil {
			body = extra.Body
		}
	}
	method, target, header, remote := r.Method, r.URL.String(), r.Header.Clone(), r.RemoteAddr
	local := r.Context().Value(http.LocalAddrContextKey)
	start := func(ctx context.Context) (dashapi.PendingLaunchResult, error) {
		ctx = context.WithValue(ctx, heldReplayKey{}, heldReplay{initiator: initiator, parent: parent})
		if a, ok := local.(net.Addr); ok {
			ctx = context.WithValue(ctx, http.LocalAddrContextKey, a)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body)) //nolint:gosec // G704: builds the held request for an in-process replay through the route handler h, never sent over the network
		if err != nil {
			return dashapi.PendingLaunchResult{}, err
		}
		req.Header, req.RemoteAddr = header, remote
		rec := &captureWriter{header: http.Header{}}
		h(rec, req)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		return dashapi.PendingLaunchResult{Status: rec.status, ContentType: rec.header.Get("Content-Type"), Body: rec.buf.Bytes()}, nil
	}
	p := heldSummary(row, r.URL.Path, body)
	p.Details = append(append([]dashapi.PendingLaunchDetail(nil), extra.Details...), p.Details...)
	p.Front, p.Initiator, p.ParentSessionID = "dashboard", initiator, parent
	held, err := s.opts.PendingLaunches.Hold(p, start)
	if err != nil {
		var pe *dashapi.PendingLaunchError
		if errors.As(err, &pe) && pe.Code == dashapi.PendingCodeTooMany {
			writePendingError(w, http.StatusTooManyRequests, pe.Code, pe.Message)
			return
		}
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    dashapi.PendingCodeConfirmRequired,
		"message": "an agent asked for this launch; it waits for a human to confirm it on the Terminals page or with `observer terminals confirm " + held.ID + "`",
		"pending": held,
	})
}

// heldSummary is what a human sees about a held dashboard launch: the
// route's name and the request's own tool, project and sandbox fields.
func heldSummary(row agentLaunchRoute, path string, body []byte) dashapi.PendingLaunch {
	var b struct {
		Tool        string `json:"tool"`
		ProjectRoot string `json:"project_root"`
		Sandbox     bool   `json:"sandbox"`
		Backend     string `json:"backend"`
	}
	_ = json.Unmarshal(body, &b)
	p := dashapi.PendingLaunch{Tool: b.Tool, Project: b.ProjectRoot}
	if heldSandboxed(row, body, b.Sandbox) {
		p.Sandbox = "auto"
		if b.Backend != "" {
			p.Sandbox = b.Backend
		}
	}
	p.What = row.what
	if strings.HasPrefix(path, "/api/session/") {
		p.What += " of session " + strings.Split(strings.TrimPrefix(path, "/api/session/"), "/")[0]
	}
	if p.Tool != "" {
		p.What += ": " + p.Tool
	}
	p.Details = heldDetails(row, path, body)
	return p
}

// maxDetailValue bounds one detail's shown value (a prompt can be long);
// a longer value says it was cut.
const maxDetailValue = 300

// unsandboxedDetail is the sandbox detail of a launch that runs on the host.
const unsandboxedDetail = "unsandboxed: runs on this machine with your access"

// maskedDetail is the shown value of a secret-looking member.
const maskedDetail = scrub.Redacted + " (a secret-looking member, not shown; the confirm sends it as given)"

// heldDetails is every field a held dashboard request is bound to (lane
// cli-2 fixes-2, audit M-B): the request path's own operands, then every
// top-level member of the body, in the body's order, so nothing the replay
// sends is left off the confirm card. A few members are read for the human
// (the sandbox, the sign-in copy, a GUI launch); every other member is
// shown as sent. A body that is not one JSON object is shown whole.
func heldDetails(row agentLaunchRoute, path string, body []byte) []dashapi.PendingLaunchDetail {
	var out []dashapi.PendingLaunchDetail
	if rest, ok := strings.CutPrefix(path, "/api/session/"); ok {
		id, verb, _ := strings.Cut(rest, "/")
		out = append(out, dashapi.PendingLaunchDetail{Label: "session", Value: id}, dashapi.PendingLaunchDetail{Label: "action", Value: verb})
	}
	members, ok := orderedMembers(body)
	if !ok {
		if t := strings.TrimSpace(string(body)); t != "" {
			out = append(out, dashapi.PendingLaunchDetail{Label: "body", Value: clampDetailValue(scrub.MaskCertainSecrets(t)), Warn: true})
		}
		return out
	}
	sandboxed := false
	for _, m := range members {
		d := dashapi.PendingLaunchDetail{Label: m.key, Value: clampDetailValue(scrub.MaskCertainSecrets(m.value))}
		if m.items != nil {
			// A list says how many of its items it cut (fixes-3, audit
			// L2): a long candidates list must not hide one silently.
			items := make([]string, len(m.items))
			for i, it := range m.items {
				items[i] = scrub.MaskCertainSecrets(it)
			}
			var cut bool
			d.Value, cut = clampListValue(items)
			d.Warn = d.Warn || cut
		}
		// A member is read by the name the handler's decode matches it
		// to (fixes-3, audit M2): "SANDBOX" sets the sandbox field too.
		switch readMemberName(m.key) {
		case "sandbox":
			sandboxed = m.value == "true"
			continue // said once, below, in words
		case "sign_in_seed":
			if m.value == "true" {
				d.Value, d.Warn = "copies your sign-in for this tool into the box", true
			}
		case "kind":
			if m.value == "gui" {
				d.Value = "gui: opens a desktop app"
			}
		case "workspace_remote", "confirm_spend", "allow_unpriced":
			d.Warn = true
		case "tier_relax":
			// A wider sandbox network for this run (plan section 13.9).
			d.Warn = m.value == "true"
		case "relaxations":
			// Guard rules lifted for this run (plan section 13.5).
			d.Warn = len(m.items) > 0 || (m.value != "" && m.value != "[]" && m.value != "null")
		}
		// A secret-looking member's value is masked (fixes-3, audit L3);
		// the confirm sends it as given.
		if scrub.SecretName(m.key) {
			d.Value, d.Warn = maskedDetail, true
		}
		out = append(out, d)
	}
	if sandboxLineRoutes[row.pattern] {
		if heldSandboxed(row, body, sandboxed) {
			out = append([]dashapi.PendingLaunchDetail{{Label: "sandbox", Value: "sandboxed"}}, out...)
		} else {
			out = append([]dashapi.PendingLaunchDetail{{Label: "sandbox", Value: unsandboxedDetail, Warn: true}}, out...)
		}
	}
	return out
}

// readMembers are the body members heldDetails reads for the human, keyed
// by their folded name (jsonFoldKey).
var readMembers = func() map[string]string {
	out := map[string]string{}
	for _, n := range []string{"sandbox", "sign_in_seed", "kind", "workspace_remote", "confirm_spend", "allow_unpriced", "relaxations", "tier_relax"} {
		out[jsonFoldKey(n)] = n
	}
	return out
}()

// readMemberName is the read member a body member name decodes into, ""
// when it is none of them.
func readMemberName(key string) string { return readMembers[jsonFoldKey(key)] }

// jsonFoldKey folds a JSON member name the way encoding/json matches it to
// a struct field (its foldName: an ASCII letter upper-cased, any other rune
// replaced by the smallest rune of its unicode.SimpleFold orbit), so two
// names fold equal exactly when the launch handlers' decode treats them as
// the same field ("sandbox", "SANDBOX", and "ſandbox" with a long s).
func jsonFoldKey(k string) string {
	var b strings.Builder
	b.Grow(len(k))
	for _, r := range k {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
			continue
		}
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				r = next
				break
			}
			r = next
		}
		b.WriteRune(r)
	}
	return b.String()
}

// foldedDuplicateMember reports the first member name, at any depth of
// body, that an object names twice under jsonFoldKey. encoding/json keeps
// the last of them, so a card that showed the first would mislead. A body
// that is not valid JSON has none (it is shown whole).
func foldedDuplicateMember(body []byte) (string, bool) {
	type frame struct {
		obj       bool
		expectKey bool
		keys      map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.obj && top.expectKey {
			name, _ := tok.(string)
			folded := jsonFoldKey(name)
			if top.keys[folded] {
				return name, true
			}
			top.keys[folded], top.expectKey = true, false
			continue
		}
		if top != nil && top.obj {
			top.expectKey = true // after this value, a name
		}
		if d, ok := tok.(json.Delim); ok {
			stack = append(stack, &frame{obj: d == '{', expectKey: d == '{', keys: map[string]bool{}})
		}
	}
}

type bodyMember struct {
	key, value string
	// items are an array member's elements, each as compact JSON; nil for
	// any other member.
	items []string
}

// orderedMembers decodes a JSON object's top-level members in order: a
// string member's value unquoted, any other member as compact JSON, and
// an array member's elements as well.
func orderedMembers(body []byte) ([]bodyMember, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var out []bodyMember
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		v := string(raw)
		var str string
		if json.Unmarshal(raw, &str) == nil {
			v = str
		} else {
			var buf bytes.Buffer
			if json.Compact(&buf, raw) == nil {
				v = buf.String()
			}
		}
		m := bodyMember{key: key, value: v}
		var elems []json.RawMessage
		if json.Unmarshal(raw, &elems) == nil {
			m.items = make([]string, 0, len(elems))
			for _, e := range elems {
				var buf bytes.Buffer
				if json.Compact(&buf, e) != nil {
					buf.Reset()
					buf.Write(e)
				}
				m.items = append(m.items, buf.String())
			}
		}
		out = append(out, m)
	}
	return out, true
}

// clampListValue shows a list's items whole while they fit in
// maxDetailValue, then says how many it cut (fixes-3, audit L2); cut is
// true when it cut any.
func clampListValue(items []string) (v string, cut bool) {
	whole := "[" + strings.Join(items, ",") + "]"
	if len(whole) <= maxDetailValue {
		return whole, false
	}
	var b strings.Builder
	b.WriteByte('[')
	shown := 0
	for _, it := range items {
		sep := 0
		if shown > 0 {
			sep = 1
		}
		if b.Len()+sep+len(it) > maxDetailValue {
			break
		}
		if shown > 0 {
			b.WriteByte(',')
		}
		b.WriteString(it)
		shown++
	}
	if shown == 0 {
		// The first item alone is too long: shown cut, and counted cut.
		b.WriteString(cutOnRune(items[0], maxDetailValue))
		b.WriteString("...")
	}
	fmt.Fprintf(&b, ", ...] (%d of %d items cut; the confirm sends all %d)", len(items)-shown, len(items), len(items))
	return b.String(), true
}

// cutOnRune is v cut to at most n bytes on a rune boundary.
func cutOnRune(v string, n int) string {
	if len(v) <= n {
		return v
	}
	i := n
	for i > 0 && !utf8.RuneStart(v[i]) {
		i--
	}
	return v[:i]
}

// clampDetailValue cuts a long value on a rune boundary and says so.
func clampDetailValue(v string) string {
	if len(v) <= maxDetailValue {
		return v
	}
	return cutOnRune(v, maxDetailValue) + "... (cut; the confirm sends it whole)"
}

// captureWriter records a replayed handler's answer.
type captureWriter struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func (c *captureWriter) Header() http.Header { return c.header }
func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.buf.Write(b)
}

// writePendingError writes a coded refusal.
func writePendingError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": code})
}

// handleTerminalPending serves the held launches: GET /api/terminal/pending
// lists them; POST /api/terminal/pending/<id>/confirm starts one (refused
// for a caller attributed to an agent; a caller inside a box never gets
// here, the caller check refuses it first); POST .../<id>/reject drops one.
func (s *Server) handleTerminalPending(w http.ResponseWriter, r *http.Request) {
	if s.opts.PendingLaunches == nil {
		writeJSON(w, map[string]any{"pending": []dashapi.PendingLaunch{}, "enabled": false})
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/terminal/pending"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		list := s.opts.PendingLaunches.List()
		if list == nil {
			list = []dashapi.PendingLaunch{}
		}
		writeJSON(w, map[string]any{"pending": list, "enabled": true})
		return
	}
	id, verb, ok := strings.Cut(rest, "/")
	if !ok || id == "" || (verb != "confirm" && verb != "reject") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	if verb == "reject" {
		p, err := s.opts.PendingLaunches.Reject(id)
		if err != nil {
			writePendingFailure(w, err)
			return
		}
		writeJSON(w, map[string]any{"rejected": p})
		return
	}
	initiator, _ := s.launchOrigin(r)
	p, res, err := s.opts.PendingLaunches.Confirm(r.Context(), id, initiator)
	if err != nil {
		writePendingFailure(w, err)
		return
	}
	s.recordManageAudit(r, "launch_confirm", "pending="+p.ID+" what="+p.What+" initiator="+p.Initiator)
	ct := res.ContentType
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	if res.Status == 0 {
		res.Status = http.StatusOK
	}
	w.WriteHeader(res.Status)
	_, _ = w.Write(res.Body)
}

// pendingFailureStatus maps a pending refusal code onto its HTTP status.
var pendingFailureStatus = map[string]int{
	dashapi.PendingCodeNotFound:       http.StatusNotFound,
	dashapi.PendingCodeConfirmRefused: http.StatusForbidden,
	dashapi.PendingCodeTooMany:        http.StatusTooManyRequests,
}

func writePendingFailure(w http.ResponseWriter, err error) {
	var pe *dashapi.PendingLaunchError
	if errors.As(err, &pe) {
		status, ok := pendingFailureStatus[pe.Code]
		if !ok {
			status = http.StatusConflict
		}
		writePendingError(w, status, pe.Code, pe.Message)
		return
	}
	writeErr(w, err)
}
