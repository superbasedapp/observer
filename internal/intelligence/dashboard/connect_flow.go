package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

// connect_flow.go is the dashboard half of "Sign in and connect this
// machine" (Getting started v2, shared contract B and D). The Get started
// panel on Overview, the top bar's Sign in button and Settings > Account all
// start the SAME flow:
//
//   - POST /api/connect/start {"team": "<slug>"|""} spawns
//     `observer connect --json --no-browser [--config <path>] [team]` as a
//     child of the running binary, the way backfill_run.go spawns
//     `observer backfill`. The child is the CLI a human types; this package
//     links nothing from the cloud lane and makes no network call itself
//     (tests/invariant/cloud_egress_test.go keeps pinning that).
//   - GET /api/connect/progress answers the latest state, folded from the
//     child's JSON lines by the ordered table connectLineRules.
//   - POST /api/connect/cancel stops a running child.
//
// One child at a time: a second start while one runs returns the current
// state (200), never a second child. The child is bounded by the connect
// request's expiry (expires_in from its waiting line when present, else the
// contract's 900 s) plus a short grace, so a request nobody approves cannot
// pin the slot. The last finished state is kept in memory until the next
// start, so the page can still read the connected target's online address
// after the child has exited (a daemon restart forgets it; the page then
// derives the address from the enrolment).
//
// The browser opens approve_url itself: the child runs with --no-browser,
// because a daemon-spawned browser can land on the wrong desktop (a service
// account, the WSL side), and the page that asked is the one the person is
// looking at.

// The connect progress states. The first two and the last three are this
// file's own; the rest are contract B's lines.
const (
	connectStateIdle         = "idle"
	connectStateStarting     = "starting"
	connectStateWaiting      = "waiting_approval"
	connectStateApproved     = "approved"
	connectStateAttaching    = "attaching"
	connectStateConnected    = "connected"
	connectStateSignedInOnly = "signed_in_only"
	connectStateError        = "error"
	connectStateCanceled     = "canceled"
	connectStateExpired      = "expired"
)

// connectDefaultExpiry is the connect request's lifetime when the child's
// waiting line does not say (contract A: expires_in 900).
const connectDefaultExpiry = 900 * time.Second

// connectExpiryGrace lets the child report its own "expired" line before the
// daemon stops it.
const connectExpiryGrace = 30 * time.Second

// connectMaxExpiry caps a child-reported expires_in, so a bad line cannot
// hold the slot for hours.
const connectMaxExpiry = time.Hour

// connectTailMax bounds the child's kept stderr to roughly the last 2 KB,
// the same discipline as the cloud login and sync runs.
const connectTailMax = 2048

// ConnectTarget is where an approved request connects this machine: the
// account's personal dashboard or one of its teams (contract A).
type ConnectTarget struct {
	OrgID       string `json:"org_id,omitempty"`
	Slug        string `json:"slug,omitempty"`
	Kind        string `json:"kind,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	ShareLevel  string `json:"share_level,omitempty"`
}

// ConnectProgress is GET /api/connect/progress (and the start and cancel
// responses): the latest state of the one connect child.
type ConnectProgress struct {
	State   string `json:"state"`
	Running bool   `json:"running"`
	// Team is the slug the flow was started for ("" for the personal
	// dashboard or the browser's own choice).
	Team string `json:"team,omitempty"`
	// ApproveURL is the browser approval page; VerifyURL and UserCode are
	// the code-entry fallback for a machine with no browser.
	ApproveURL string `json:"approve_url,omitempty"`
	VerifyURL  string `json:"verify_url,omitempty"`
	UserCode   string `json:"user_code,omitempty"`
	// ExpiresAt is when the daemon stops waiting for approval.
	ExpiresAt string         `json:"expires_at,omitempty"`
	Target    *ConnectTarget `json:"target,omitempty"`
	// DisplayName, Kind and OnlineURL are set once connected. OnlineURL is
	// for buttons only; a personal dashboard's address is never printed.
	DisplayName string `json:"display_name,omitempty"`
	Kind        string `json:"kind,omitempty"`
	OnlineURL   string `json:"online_url,omitempty"`
	// Code and Message describe an error, a cancel or an expiry.
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

// connectLine is one JSON line `observer connect --json` prints (contract B).
// ExpiresIn is optional (an addition this lane asked for); absent means the
// contract's 900 s.
type connectLine struct {
	State       string         `json:"state"`
	ApproveURL  string         `json:"approve_url"`
	VerifyURL   string         `json:"verify_url"`
	UserCode    string         `json:"user_code"`
	ExpiresIn   int            `json:"expires_in"`
	Target      *ConnectTarget `json:"target"`
	DisplayName string         `json:"display_name"`
	Kind        string         `json:"kind"`
	OnlineURL   string         `json:"online_url"`
	Code        string         `json:"code"`
	Message     string         `json:"message"`
}

// connectLineRule folds one contract-B state into the progress.
type connectLineRule struct {
	state    string
	terminal bool
	apply    func(p *ConnectProgress, l connectLine)
}

// connectLineRules is the ordered table of the child's states; a line whose
// state is not here is ignored (a newer CLI may say more).
var connectLineRules = []connectLineRule{
	{state: connectStateWaiting, apply: func(p *ConnectProgress, l connectLine) {
		p.ApproveURL = safeConnectURL(l.ApproveURL)
		p.VerifyURL = safeConnectURL(l.VerifyURL)
		p.UserCode = cleanUserCode(l.UserCode)
	}},
	{state: connectStateApproved, apply: func(p *ConnectProgress, l connectLine) {
		if t := cleanConnectTarget(l.Target); t != nil {
			p.Target = t
		}
	}},
	{state: connectStateAttaching},
	{state: connectStateConnected, terminal: true, apply: func(p *ConnectProgress, l connectLine) {
		p.DisplayName = cleanConnectText(l.DisplayName, 120)
		p.Kind = cleanConnectKind(l.Kind)
		if p.Target != nil {
			if p.DisplayName == "" {
				p.DisplayName = p.Target.DisplayName
			}
			if p.Kind == "" {
				p.Kind = p.Target.Kind
			}
		}
		p.OnlineURL = safeConnectURL(l.OnlineURL)
	}},
	{state: connectStateSignedInOnly, terminal: true},
	{state: connectStateError, terminal: true, apply: func(p *ConnectProgress, l connectLine) {
		p.Code = cleanConnectText(l.Code, 64)
		p.Message = cleanConnectText(l.Message, 400)
		if p.Message == "" {
			p.Message = "Connecting did not finish."
		}
	}},
}

// connectTerminal reports whether state ends the flow.
func connectTerminal(state string) bool {
	switch state {
	case connectStateCanceled, connectStateExpired:
		return true
	}
	for _, r := range connectLineRules {
		if r.state == state {
			return r.terminal
		}
	}
	return false
}

// applyConnectLine folds one output line into p. ok is false for a line
// that is not a contract-B JSON object or names an unknown state (p is then
// returned unchanged). expiresIn is the waiting line's expires_in, 0 when
// absent. A line after a terminal state never moves the progress.
func applyConnectLine(p ConnectProgress, raw []byte) (next ConnectProgress, expiresIn time.Duration, ok bool) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || raw[0] != '{' || connectTerminal(p.State) {
		return p, 0, false
	}
	var l connectLine
	if err := json.Unmarshal(raw, &l); err != nil {
		return p, 0, false
	}
	for _, r := range connectLineRules {
		if r.state != l.State {
			continue
		}
		next = p
		next.State = r.state
		if r.apply != nil {
			r.apply(&next, l)
		}
		if r.state == connectStateWaiting && l.ExpiresIn > 0 {
			expiresIn = time.Duration(l.ExpiresIn) * time.Second
			if expiresIn > connectMaxExpiry {
				expiresIn = connectMaxExpiry
			}
		}
		return next, expiresIn, true
	}
	return p, 0, false
}

// safeConnectURL keeps an address the page may open: https, or http on a
// loopback host (a local test server). Anything else (javascript:, a
// relative path, a malformed URL) is dropped.
func safeConnectURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return ""
	}
	switch u.Scheme {
	case "https":
		return u.String()
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return u.String()
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return u.String()
		}
	}
	return ""
}

// userCodeRe is the shape of a code-entry code (KTRW-4821).
var userCodeRe = regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{1,15}$`)

func cleanUserCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !userCodeRe.MatchString(s) {
		return ""
	}
	return s
}

// cleanConnectKind keeps the two target kinds contract A names.
func cleanConnectKind(s string) string {
	switch s {
	case "personal", "team":
		return s
	}
	return ""
}

// cleanShareLevel keeps the two share levels contract A names.
func cleanShareLevel(s string) string {
	switch s {
	case "summary", "full":
		return s
	}
	return ""
}

// cleanConnectText trims, drops control characters and clips to max runes.
func cleanConnectText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

func cleanConnectTarget(t *ConnectTarget) *ConnectTarget {
	if t == nil {
		return nil
	}
	out := &ConnectTarget{
		OrgID:       cleanConnectText(t.OrgID, 128),
		Slug:        cleanConnectText(t.Slug, 64),
		Kind:        cleanConnectKind(t.Kind),
		DisplayName: cleanConnectText(t.DisplayName, 120),
		ShareLevel:  cleanShareLevel(t.ShareLevel),
	}
	return out
}

// teamSlugRe is a team slug: lowercase letters, digits and inner hyphens.
// It can never start with "-", so the slug can never be read as a flag.
var teamSlugRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

// normalizeTeamSlug trims and lowercases a requested team; "" is the
// personal dashboard (or the browser's own choice). ok is false for
// anything that is not a slug.
func normalizeTeamSlug(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", true
	}
	return s, teamSlugRe.MatchString(s)
}

// connectArgs is the child's argv after the binary.
// flags are extra connect flags (connectReconsentFlag), placed before the
// team argument.
func connectArgs(configPath, team string, flags ...string) []string {
	args := []string{"connect", "--json", "--no-browser"}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	args = append(args, flags...)
	if team != "" {
		args = append(args, team)
	}
	return args
}

// connectReconsentFlag is the child's flag for a re-consent run: re-attach
// this machine to the destination it already has so its owner can accept
// the grant that destination now offers (`observer connect --reconsent`,
// attachrule row 10; budget enforce consistency 2026-11-19).
const connectReconsentFlag = "--reconsent"

// --- refusals -------------------------------------------------------------

// connectFacts is what the start route checks before it spawns anything.
type connectFacts struct {
	enrolled bool
	orgName  string
	locked   bool
	// reconsent is a re-consent run: it needs a connection, never refuses one.
	reconsent bool
}

// connectRefusal is one reason the flow does not start.
type connectRefusal struct {
	name    string
	when    func(f connectFacts) bool
	code    string
	message func(f connectFacts) string
}

// connectRefusals is the ordered table: the first match refuses with 409.
//
// A machine that is already connected is refused rather than switched: the
// Get started panel only offers Connect while the machine is not connected,
// and moving a connected machine (above all one an organization manages)
// needs the old destination named, which `observer connect` asks for on a
// terminal. Disconnect first in Settings > Account, then connect again.
var connectRefusals = []connectRefusal{
	{
		name: "locked",
		when: func(f connectFacts) bool { return f.locked },
		code: "locked",
		message: func(connectFacts) string {
			return "Your company's settings choose where this machine sends data, so it cannot be connected from here."
		},
	},
	{
		name: "already_connected",
		when: func(f connectFacts) bool { return f.enrolled && !f.reconsent },
		code: "already_connected",
		message: func(f connectFacts) string {
			name := strings.TrimSpace(f.orgName)
			if name == "" {
				name = "a dashboard"
			}
			return "This machine is already connected to " + name + ". Disconnect it in Settings > Account first."
		},
	},
	{
		name: "reconsent_not_connected",
		when: func(f connectFacts) bool { return f.reconsent && !f.enrolled },
		code: "not_connected",
		message: func(connectFacts) string {
			return "This machine is not connected, so there is nothing to review again. Connect it in Settings > Account."
		},
	},
}

// decideConnectRefusal walks connectRefusals; nil means start.
func decideConnectRefusal(f connectFacts) *connectRefusal {
	for i := range connectRefusals {
		if connectRefusals[i].when(f) {
			return &connectRefusals[i]
		}
	}
	return nil
}

// connectFactsOf reads the facts through the seams the status routes
// already use: the enrolment (a local read) and the front door's lock.
func (s *Server) connectFactsOf(ctx context.Context) connectFacts {
	var f connectFacts
	f.enrolled, f.orgName = s.orgEnrolled(ctx)
	if s.opts.ConnectStatus != nil {
		f.locked = s.opts.ConnectStatus(ctx, s.connectIdentity()).Locked
	}
	return f
}

// --- the one child ------------------------------------------------------

// connectExecFn runs `<observer> <args...>`, handing every stdout line to
// onLine and stderr to errOut, and returns the exit code. Tests inject a
// fake through connectFlow.exec.
type connectExecFn func(ctx context.Context, args []string, onLine func([]byte), errOut io.Writer) (int, error)

// connectFlow owns the in-memory state of the one connect child. The zero
// value is ready to use.
type connectFlow struct {
	mu  sync.Mutex
	run *connectRun
	// exec and now are seams; nil means realExecConnect and time.Now.
	exec connectExecFn
	now  func() time.Time
}

// connectRun is one start's state, guarded by connectFlow.mu.
type connectRun struct {
	progress ConnectProgress
	running  bool
	canceled bool
	expired  bool
	cancel   context.CancelFunc
	timer    *time.Timer
	tail     []byte
}

func (f *connectFlow) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// snapshot returns the current progress (idle when nothing has run).
func (f *connectFlow) snapshot() ConnectProgress {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.run == nil {
		return ConnectProgress{State: connectStateIdle}
	}
	return f.run.progress
}

// start spawns the child unless one runs; started is false when the
// current run was returned instead.
func (f *connectFlow) start(configPath, team string, flags ...string) (p ConnectProgress, started bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.run != nil && f.run.running {
		return f.run.progress, false
	}
	now := f.clock().UTC()
	ctx, cancel := context.WithCancel(context.Background())
	run := &connectRun{
		running: true,
		cancel:  cancel,
		progress: ConnectProgress{
			State:     connectStateStarting,
			Running:   true,
			Team:      team,
			StartedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(connectDefaultExpiry).Format(time.RFC3339),
		},
	}
	run.timer = time.AfterFunc(connectDefaultExpiry+connectExpiryGrace, func() { f.expire(run) })
	f.run = run
	execFn := f.exec
	if execFn == nil {
		execFn = realExecConnect
	}
	args := connectArgs(configPath, team, flags...)
	go func() {
		code, err := execFn(ctx, args, func(line []byte) { f.onLine(run, line) }, connectTailWriter{f: f, run: run})
		f.finish(run, code, err)
	}()
	return run.progress, true
}

// onLine folds one stdout line into the run.
func (f *connectFlow) onLine(run *connectRun, line []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.run != run || !run.running {
		return
	}
	next, expiresIn, ok := applyConnectLine(run.progress, line)
	if !ok {
		return
	}
	if expiresIn > 0 {
		next.ExpiresAt = f.clock().UTC().Add(expiresIn).Format(time.RFC3339)
		run.timer.Reset(expiresIn + connectExpiryGrace)
	}
	next.Running = true
	run.progress = next
}

// expire stops a run nobody approved in time.
func (f *connectFlow) expire(run *connectRun) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !run.running {
		return
	}
	run.expired = true
	run.cancel()
}

// stop cancels the running child, if any, and returns the progress.
func (f *connectFlow) stop() (ConnectProgress, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.run == nil || !f.run.running {
		if f.run == nil {
			return ConnectProgress{State: connectStateIdle}, false
		}
		return f.run.progress, false
	}
	f.run.canceled = true
	f.run.cancel()
	return f.run.progress, true
}

// connectExitRule decides the final state when the child exits.
type connectExitRule struct {
	name  string
	when  func(run *connectRun) bool
	apply func(p *ConnectProgress, run *connectRun, code int, err error)
}

// connectExitRules is the ordered table walked when the child exits: a
// terminal line the child printed wins, then the daemon's own cancel and
// expiry, then a plain exit with no terminal line, which is an error.
var connectExitRules = []connectExitRule{
	{
		name:  "child_reported_end",
		when:  func(run *connectRun) bool { return connectTerminal(run.progress.State) },
		apply: func(*ConnectProgress, *connectRun, int, error) {},
	},
	{
		name: "canceled",
		when: func(run *connectRun) bool { return run.canceled },
		apply: func(p *ConnectProgress, _ *connectRun, _ int, _ error) {
			p.State, p.Code, p.Message = connectStateCanceled, "canceled", "Stopped. Nothing was connected."
		},
	},
	{
		name: "expired",
		when: func(run *connectRun) bool { return run.expired },
		apply: func(p *ConnectProgress, _ *connectRun, _ int, _ error) {
			p.State, p.Code, p.Message = connectStateExpired, "expired", "The request expired before it was approved. Start again for a new code."
		},
	},
	{
		name: "exited_without_end",
		when: func(*connectRun) bool { return true },
		apply: func(p *ConnectProgress, run *connectRun, code int, err error) {
			p.State, p.Code = connectStateError, "exited"
			msg := lastLine(run.tail)
			if msg == "" && err != nil {
				msg = err.Error()
			}
			if msg == "" {
				msg = fmt.Sprintf("observer connect stopped before it finished (exit %d).", code)
			}
			p.Message = cleanConnectText(msg, 400)
		},
	},
}

// finish records the child's exit.
func (f *connectFlow) finish(run *connectRun, code int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	run.running = false
	run.timer.Stop()
	run.cancel()
	for _, r := range connectExitRules {
		if r.when(run) {
			r.apply(&run.progress, run, code, err)
			break
		}
	}
	run.progress.Running = false
	run.progress.FinishedAt = f.clock().UTC().Format(time.RFC3339)
}

// connectTailWriter keeps the last connectTailMax bytes of the child's
// stderr on its run.
type connectTailWriter struct {
	f   *connectFlow
	run *connectRun
}

func (w connectTailWriter) Write(p []byte) (int, error) {
	w.f.mu.Lock()
	defer w.f.mu.Unlock()
	w.run.tail = append(w.run.tail, p...)
	if over := len(w.run.tail) - connectTailMax; over > 0 {
		w.run.tail = append([]byte(nil), w.run.tail[over:]...)
	}
	return len(p), nil
}

// lastLine is the last non-empty line of b.
func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

// realExecConnect runs the running binary with args, scanning stdout line by
// line (the JSON lines must never be interleaved with stderr) and copying
// stderr to errOut. ctx bounds the child.
func realExecConnect(ctx context.Context, args []string, onLine func([]byte), errOut io.Writer) (int, error) {
	binary, err := osExecutable()
	if err != nil {
		return 0, fmt.Errorf("locate observer binary: %w", err)
	}
	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // G204: argv is connectArgs: fixed flags, the daemon's own config path and a slug validated by teamSlugRe.
	cmd.Stderr = errOut
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start observer connect: %w", err)
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		onLine(sc.Bytes())
	}
	// A line longer than the buffer stops the scan; drain the rest so the
	// child never blocks on a full pipe.
	_, _ = io.Copy(io.Discard, stdout)
	runErr := cmd.Wait()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		runErr = nil // the exit code says it; the tail says why
	}
	return code, runErr
}

// --- routes ---------------------------------------------------------------

// handleConnectStart serves POST /api/connect/start: confirm token, a valid
// team slug (or none), the refusal table, then one child.
func (s *Server) handleConnectStart(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req struct {
		Team string `json:"team"`
		// Reconsent re-attaches this machine to its current destination
		// (connectReconsentFlag); it takes no team.
		Reconsent bool `json:"reconsent"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	team, ok := normalizeTeamSlug(req.Team)
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error":   "bad_team",
			"message": "That is not a team name. Use the short name from your team's invite, like acme-dev.",
		})
		return
	}
	if req.Reconsent && team != "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error":   "bad_team",
			"message": "Reviewing your connection again keeps its dashboard; it takes no team name.",
		})
		return
	}
	var flags []string
	if req.Reconsent {
		flags = append(flags, connectReconsentFlag)
	}
	// A run already in flight is returned as it is (one child at a time),
	// even when it has just connected this machine.
	if cur := s.connectFlow.snapshot(); !cur.Running {
		facts := s.connectFactsOf(r.Context())
		facts.reconsent = req.Reconsent
		if ref := decideConnectRefusal(facts); ref != nil {
			writeJSONStatus(w, http.StatusConflict, map[string]string{
				"error":   ref.code,
				"message": ref.message(facts),
			})
			return
		}
	}
	p, started := s.connectFlow.start(s.opts.ConfigPath, team, flags...)
	if started {
		detail := "target=personal_or_choice"
		if req.Reconsent {
			detail = "reconsent=current_destination"
		}
		if team != "" {
			detail = "team=" + team
		}
		s.recordManageAudit(r, "connect_start", detail)
	}
	writeJSON(w, p)
}

// handleConnectProgress serves GET /api/connect/progress.
func (s *Server) handleConnectProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.connectFlow.snapshot())
}

// handleConnectCancel serves POST /api/connect/cancel: stops the running
// child (the final state lands on the next progress read).
func (s *Server) handleConnectCancel(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	p, stopped := s.connectFlow.stop()
	if stopped {
		s.recordManageAudit(r, "connect_cancel", "")
	}
	writeJSON(w, p)
}
