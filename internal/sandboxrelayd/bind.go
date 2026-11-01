package sandboxrelayd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// bind.go binds a validated request to its run before anything runs it
// (plans decision log P-026, lane sbx-p2b): the box can only speak for its
// own run, so it must not be able to steer the host hook into another
// repository, another project's session or a flood of host children. Every
// check is a row of bindChecks, walked top down; the first refusal answers
// the request with that row's sandboxrelay.Refusal (never a silent drop).

// SessionOwner returns the project root the node already records for a
// session id ("" when the node does not know the session).
type SessionOwner func(ctx context.Context, sessionID string) (string, error)

// RunRate is the per-run token bucket: Requests per second refill with a
// burst of Burst, and Bytes per second of payload with a burst of
// BurstBytes. Zero fields take DefaultRunRate's.
type RunRate struct {
	Requests   float64
	Burst      float64
	Bytes      float64
	BurstBytes float64
}

// DefaultRunRate bounds one box: every request starts a host hook child of
// about 80 ms, and a busy agent sends two or three hook events per tool
// call, so 20 a second with a burst of 100 leaves room for real work while
// one box cannot keep the host busy; 4 MiB a second of payload with a 64
// MiB burst bounds what one box adds to the database.
var DefaultRunRate = RunRate{Requests: 20, Burst: 100, Bytes: 4 << 20, BurstBytes: 64 << 20}

// DefaultMaxSessions caps the distinct session ids one run may speak for.
const DefaultMaxSessions = 256

func (r RunRate) withDefaults() RunRate {
	d := DefaultRunRate
	if r.Requests > 0 {
		d.Requests = r.Requests
	}
	if r.Burst > 0 {
		d.Burst = r.Burst
	}
	if r.Bytes > 0 {
		d.Bytes = r.Bytes
	}
	if r.BurstBytes > 0 {
		d.BurstBytes = r.BurstBytes
	}
	return d
}

// bucket is a two-dimension token bucket (requests and bytes). It starts
// full.
type bucket struct {
	mu      sync.Mutex
	rate    RunRate
	reqs    float64
	bytes   float64
	last    time.Time
	started bool
}

// take spends one request and n bytes at now, or reports false (spending
// nothing) when either dimension is short.
func (b *bucket) take(now time.Time, n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.started {
		b.reqs, b.bytes, b.last, b.started = b.rate.Burst, b.rate.BurstBytes, now, true
	}
	if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.reqs = min(b.rate.Burst, b.reqs+dt*b.rate.Requests)
		b.bytes = min(b.rate.BurstBytes, b.bytes+dt*b.rate.Bytes)
		b.last = now
	}
	if b.reqs < 1 || b.bytes < float64(n) {
		return false
	}
	b.reqs--
	b.bytes -= float64(n)
	return true
}

// Payload keys the binding reads. A hook decodes a payload into structs,
// where encoding/json matches a key without regard to case, so the binding
// matches the same way (strings.EqualFold) and checks EVERY key that would
// match, so a duplicate spelling cannot slip one value past it. The keys
// are bound wherever they sit in the payload, nested objects included
// (P-032), except under a tool operand (payloadOperandKeys).
var (
	// payloadDirKeys name a working directory the host hook attributes
	// rows and project state to (grounded: every cwd-like key a hook
	// receiver decodes, internal/hook and internal/adapter).
	payloadDirKeys = []string{"cwd", "new_cwd", "old_cwd", "previous_cwd", "workspaceRoot", "workspace_roots"}
	// payloadSessionKeys name a session the host hook writes rows under or
	// links rows to (the identity keys of internal/hook/hookshape.go, and
	// the parent session a sub-agent event names).
	payloadSessionKeys = []string{
		"session_id", "sessionId", "conversation_id", "conversationId",
		"parent_session_id", "parentSessionId", "parent_conversation_id", "parentConversationId",
	}
	// payloadFileKeys name a file the host hook reads (a transcript tail,
	// the login snapshot beside a transcript store): each must lie under
	// the run's roots. The confined reader refuses anything else anyway;
	// binding it first answers with a refusal instead of a silent miss.
	payloadFileKeys = []string{"transcript_path", "transcriptPath", "agent_transcript_path", "agentTranscriptPath"}
	// payloadOperandKeys hold a tool call's own operands and results: paths
	// and ids the agent works on inside the box, never a host read or a
	// row identity, so the binding does not look inside them (a Read of
	// /usr/include is a legitimate tool call).
	payloadOperandKeys = []string{
		"tool_input", "toolInput", "tool_response", "toolResponse", "tool_output", "toolOutput",
		"tool_result", "toolResult", "tool_call", "toolCall", "arguments", "params",
	}
)

// Bounds of the payload walk: a payload nested deeper, or with more
// values, than any hook sends is refused rather than half read.
const (
	maxPayloadDepth = 64
	maxPayloadNodes = 50000
)

// payloadFacts are the identity facts a payload claims.
type payloadFacts struct {
	dirs     []string
	sessions []string
	files    []string
	// bad is set when a directory or file value is not a clean absolute
	// path, or the payload is past the walk's bounds.
	bad bool
	// syn is the path syntax the payload's paths are read in: the host's,
	// which is the box's (sandboxrelay/paths.go; a POSIX-only check refused
	// every Windows payload, Windows 11 Pro run 3).
	syn sandboxrelay.PathSyntax
}

// readPayloadFacts reads the first JSON value of a payload the way the most
// lenient hook reader does (a BOM trimmed, a json.Decoder that ignores what
// follows the first value). A payload that is not a JSON object claims
// nothing. Paths are read in syn.
func readPayloadFacts(stdin []byte, syn sandboxrelay.PathSyntax) payloadFacts {
	out := payloadFacts{syn: syn}
	body := bytes.TrimPrefix(stdin, []byte{0xEF, 0xBB, 0xBF})
	var raw json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&raw); err != nil {
		return out
	}
	if first := firstByte(raw); first != '{' {
		return out
	}
	nodes := 0
	walkPayload(raw, 0, &nodes, &out)
	return out
}

// walkPayload collects the facts of one JSON value and everything nested
// in it.
func walkPayload(raw json.RawMessage, depth int, nodes *int, out *payloadFacts) {
	*nodes++
	if depth > maxPayloadDepth || *nodes > maxPayloadNodes {
		out.bad = true
		return
	}
	switch firstByte(raw) {
	case '{':
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return
		}
		for k, v := range m {
			switch {
			case keyMatches(k, payloadOperandKeys):
			case keyMatches(k, payloadDirKeys):
				out.addPaths(stringValues(v), &out.dirs)
			case keyMatches(k, payloadFileKeys):
				out.addPaths(expandHome(stringValues(v)), &out.files)
			case keyMatches(k, payloadSessionKeys):
				for _, s := range stringValues(v) {
					if s != "" {
						out.sessions = append(out.sessions, s)
					}
				}
			default:
				walkPayload(v, depth+1, nodes, out)
			}
		}
	case '[':
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil {
			return
		}
		for _, v := range arr {
			walkPayload(v, depth+1, nodes, out)
		}
	}
}

// addPaths appends the clean absolute paths of vs (in the facts' syntax,
// a trailing separator dropped) to dst and marks the facts bad for any
// other non-empty value.
func (f *payloadFacts) addPaths(vs []string, dst *[]string) {
	for _, v := range vs {
		if v == "" {
			continue
		}
		c, ok := f.syn.Clean(v)
		if !ok {
			f.bad = true
			continue
		}
		*dst = append(*dst, c)
	}
}

// expandHome turns a leading "~/" into this user's home, the way the one
// hook reader that accepts it does (the agy transcript reader); the box
// sees the host home at the same path.
func expandHome(vs []string) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return vs
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		if strings.HasPrefix(v, "~/") {
			v = filepath.Join(home, v[2:])
		}
		out[i] = v
	}
	return out
}

// firstByte is the first non-space byte of a JSON value.
func firstByte(raw json.RawMessage) byte {
	t := bytes.TrimLeft(raw, " \t\r\n")
	if len(t) == 0 {
		return 0
	}
	return t[0]
}

func keyMatches(k string, keys []string) bool {
	for _, want := range keys {
		if strings.EqualFold(k, want) {
			return true
		}
	}
	return false
}

// stringValues returns a string value, or the strings of an array value.
func stringValues(raw json.RawMessage) []string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	return nil
}

// RootsContain reports whether path lies under one of roots once every
// symlink in both is resolved (sandbox plan section 5.2: attribution comes
// from the host's launch facts, never a path the box reports, so a link the
// box planted cannot point the host elsewhere). A path or root that cannot
// be resolved is contained in nothing.
func RootsContain(roots []string, path string) bool {
	rp := resolvePath(path)
	if rp == "" {
		return false
	}
	for _, r := range roots {
		if r == "" || !filepath.IsAbs(r) {
			continue
		}
		rr := resolvePath(r)
		if rr != "" && within(rp, rr) {
			return true
		}
	}
	return false
}

// ConfinedContains returns RootsContain over roots, for hookctx.Channel.
func ConfinedContains(roots []string) func(string) bool {
	rs := cleanRoots(roots)
	return func(p string) bool { return RootsContain(rs, p) }
}

// resolvePath resolves every symlink in the absolute path p. The missing
// tail of a path that does not exist yet is kept as written (a component
// that does not exist cannot be a link), but a component that exists and
// cannot be resolved (a dangling link, an unreadable directory) makes the
// whole path unresolvable ("").
func resolvePath(p string) string {
	if !filepath.IsAbs(p) || strings.ContainsRune(p, 0) {
		return ""
	}
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		return ""
	}
	parent := filepath.Dir(p)
	if parent == p {
		return ""
	}
	rp := resolvePath(parent)
	if rp == "" {
		return ""
	}
	return filepath.Join(rp, filepath.Base(p))
}

// within reports whether p equals root or lies under it (clean absolute
// paths of this host: a Windows host compares with its own separator and
// case-insensitively, sandboxrelay/paths.go).
func within(p, root string) bool { return sandboxrelay.HostPaths().Within(p, root) }

// bindInput is what one binding check reads.
type bindInput struct {
	d     *Daemon
	st    *RunState
	run   RunRecord
	req   sandboxrelay.HookRequest
	facts payloadFacts
	now   time.Time
}

// bindCheck is one row of the binding table: check returns the refusal,
// or "" when the request passes the row.
type bindCheck struct {
	name  string
	check func(ctx context.Context, in bindInput) sandboxrelay.Refusal
}

// bindChecks is the binding table, walked top down. The rate row runs
// first so a flood spends nothing else; the replay row before any lookup;
// the session claim last, so a request refused by an earlier row claims
// nothing.
var bindChecks = []bindCheck{
	{
		name: "the run's request and byte rate",
		check: func(_ context.Context, in bindInput) sandboxrelay.Refusal {
			if !in.st.rate.take(in.now, len(in.req.Stdin)) {
				return sandboxrelay.RefusedRate
			}
			return ""
		},
	},
	{
		name: "a replay is never a gate event",
		check: func(_ context.Context, in bindInput) sandboxrelay.Refusal {
			if in.req.Replay && (in.req.Kind != sandboxrelay.KindHook || in.d.Gated == nil || in.d.Gated(in.req)) {
				return sandboxrelay.RefusedReplay
			}
			return ""
		},
	},
	{
		name: "the payload's working directories lie in the run",
		check: func(_ context.Context, in bindInput) sandboxrelay.Refusal {
			if in.facts.bad {
				return sandboxrelay.RefusedPath
			}
			allowed := runDirs(in.run)
			for _, d := range in.facts.dirs {
				if !RootsContain(allowed, d) {
					return sandboxrelay.RefusedPath
				}
			}
			return ""
		},
	},
	{
		name: "the payload's files lie under the run's roots",
		check: func(_ context.Context, in bindInput) sandboxrelay.Refusal {
			allowed := append(runDirs(in.run), in.run.Roots...)
			for _, f := range in.facts.files {
				if !RootsContain(allowed, f) {
					return sandboxrelay.RefusedPath
				}
			}
			return ""
		},
	},
	{
		name: "the payload's sessions are not another project's",
		check: func(ctx context.Context, in bindInput) sandboxrelay.Refusal {
			for _, id := range in.facts.sessions {
				if !in.d.sessionMayBind(ctx, in.run, id) {
					return sandboxrelay.RefusedSession
				}
			}
			return ""
		},
	},
	{
		name: "the payload's sessions are claimed by this run, within its cap",
		check: func(_ context.Context, in bindInput) sandboxrelay.Refusal {
			return in.d.claimSessions(in.st, in.run.RunID, in.facts.sessions)
		},
	},
}

// runDirs are the directories a payload's working directory may name: the
// run's workspace and its project root. Narrower than the read roots on
// purpose: a tool state dir can sit inside another repository (a home
// directory kept in git), and a working directory there would attribute
// rows to it.
func runDirs(run RunRecord) []string {
	var out []string
	for _, d := range []string{run.WorkspaceDir, run.ProjectRoot} {
		if d != "" && filepath.IsAbs(d) {
			out = append(out, d)
		}
	}
	return out
}

// sessionMayBind reports whether run may speak for session id: not claimed
// by another live run, and, when the node already records it, recorded
// under a project inside the run's directories (a box may resume its own
// project's session, never another project's). A claim whose run has ended
// (its run record is gone) is released here, so a later box may resume a
// session an earlier box spoke for (plans decision log P-032). A recorded
// root inside a managed clone of the run's project counts as the project
// (CloneOrigin), so a clone run's session can be resumed by a later run of
// the same project.
func (d *Daemon) sessionMayBind(ctx context.Context, run RunRecord, id string) bool {
	d.mu.Lock()
	owner, claimed := d.sessions[id]
	d.mu.Unlock()
	if claimed && owner != run.RunID {
		if d.runLive(owner) {
			return false
		}
		d.endGone(owner)
	}
	if claimed && owner == run.RunID {
		return true
	}
	if d.SessionOwner == nil {
		return true
	}
	root, err := d.SessionOwner(ctx, id)
	if err != nil {
		return false
	}
	if root == "" || RootsContain(runDirs(run), root) {
		return true
	}
	if d.CloneOrigin == nil {
		return false
	}
	origin := d.CloneOrigin(root)
	return origin != "" && RootsContain(runDirs(run), origin)
}

// runLive reports whether runID's run is still on: it has a run record and
// its helper's liveness lock does not say the helper is gone (alive.go).
// Only a record that is certainly absent, or a lock file nobody holds, ends
// the run: a record that cannot be read for any other reason keeps its
// claims (fail closed).
func (d *Daemon) runLive(runID string) bool {
	if helperOf(d.ObserverDir, runID) == helperGone {
		return false
	}
	_, err := ReadRun(d.ObserverDir, runID)
	return !errors.Is(err, ErrNoRecord)
}

// endGone ends a run runLive found over: a helper that died leaves its
// record and lock file, which go first, so nothing can speak for the run
// again; then EndRun releases what the daemon holds.
func (d *Daemon) endGone(runID string) {
	if helperOf(d.ObserverDir, runID) == helperGone {
		rec, rerr := ReadRun(d.ObserverDir, runID)
		if RemoveRun(d.ObserverDir, runID) == nil {
			_ = os.Remove(alivePath(d.ObserverDir, runID))
			if rerr == nil {
				d.notifyPruned([]RunRecord{rec})
			}
		}
	}
	d.EndRun(runID)
}

// notifyPruned hands each record a sweep removed to OnPruned.
func (d *Daemon) notifyPruned(pruned []RunRecord) {
	if d.OnPruned == nil {
		return
	}
	for _, rec := range pruned {
		d.OnPruned(rec)
	}
}

// EndRun releases everything the daemon holds for runID: its handler state
// and every session it spoke for. The host helper removes a run's record
// when the run ends; the daemon calls EndRun when it sees the record gone
// (on a claim another run wants, and on its sweep). Idempotent.
func (d *Daemon) EndRun(runID string) {
	d.mu.Lock()
	st := d.runs[runID]
	var rec RunRecord
	if st != nil {
		rec = st.run
	}
	delete(d.runs, runID)
	for id, owner := range d.sessions {
		if owner == runID {
			delete(d.sessions, id)
		}
	}
	d.mu.Unlock()
	if st == nil || d.OnRunEnd == nil {
		return
	}
	// After the run's last health delivery, so a write in flight cannot
	// leave state behind for a run that is gone.
	if st.health.end(rec, d.OnRunEnd) {
		d.OnRunEnd(rec)
	}
}

// Sweep ends every run the daemon holds state for whose record is gone or
// whose helper died (a helper killed with SIGKILL cannot remove its record;
// its liveness lock says it is gone), and returns how many it ended. It
// also removes the records of dead helpers the daemon holds no state for.
func (d *Daemon) Sweep() int {
	pruned, _ := PruneDeadRunRecords(d.ObserverDir)
	d.notifyPruned(pruned)
	d.mu.Lock()
	ids := make([]string, 0, len(d.runs))
	for id := range d.runs {
		ids = append(ids, id)
	}
	d.mu.Unlock()
	n := 0
	for _, id := range ids {
		if !d.runLive(id) {
			d.endGone(id)
			n++
		}
	}
	return n
}

// claimSessions records ids as spoken for by runID, within the run's cap,
// under one lock (two runs racing for one new id: exactly one claims it).
// It claims nothing when it refuses.
func (d *Daemon) claimSessions(st *RunState, runID string, ids []string) sandboxrelay.Refusal {
	if len(ids) == 0 {
		return ""
	}
	limit := d.MaxSessions
	if limit <= 0 {
		limit = DefaultMaxSessions
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessions == nil {
		d.sessions = map[string]string{}
	}
	fresh := 0
	for _, id := range ids {
		if owner, ok := d.sessions[id]; ok {
			if owner != runID {
				return sandboxrelay.RefusedSession
			}
			continue
		}
		fresh++
	}
	if st.sessionCount+fresh > limit {
		return sandboxrelay.RefusedSessionCap
	}
	for _, id := range ids {
		if _, ok := d.sessions[id]; !ok {
			d.sessions[id] = runID
			st.sessionCount++
		}
	}
	return ""
}

// bind walks bindChecks for one request and returns the first refusal.
func (d *Daemon) bind(ctx context.Context, st *RunState, run RunRecord, req sandboxrelay.HookRequest, facts payloadFacts) (sandboxrelay.Refusal, string) {
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	in := bindInput{d: d, st: st, run: run, req: req, facts: facts, now: now}
	for _, c := range bindChecks {
		if r := c.check(ctx, in); r != "" {
			return r, c.name
		}
	}
	return "", ""
}
