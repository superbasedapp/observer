package proxyroute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proxyauth"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// hold.go: the route hold of a safe restart (SR-12, lane sr-restart).
//
// The daemon IS the proxy, so stopping it while an AI tool is routed through
// it gives that tool ConnectionRefused (CLAUDE.md, "never stop the daemon
// while the proxy route is active"). A safe restart takes off the routes that
// reach THIS proxy first, restarts, and puts back exactly those routes once
// the new proxy serves. Nothing else is written.
//
// Which routes the hold takes off is a table (holdRules) over one inspected
// row of the route inspection table (routeInspectors, the per-tool route
// rows). The removal is the row's own Leave remover (routeShapes), the same
// edit leaving an organization makes. The put-back has two rungs:
//
//  1. the file exactly as it was, when nothing else wrote it since the
//     removal (the bytes are compared right before the rename), so every
//     byte, comment and key order comes back;
//  2. otherwise the row's own writer (the one `observer init` and route
//     maintenance call), run only when the route is still off and the file
//     is still there, with the route-provenance record put back exactly as
//     it was (or dropped again when there was none), so who wrote the route
//     does not change.
//
// Before a route is taken off, the removal and the rung-2 put-back are
// rehearsed on a private scratch copy of the file (holdcheck.go), and the
// route is taken off only when the put-back would give back every setting the
// file had (Codex's remover deletes the whole provider table while its writer
// writes four keys of it, so a table holding the developer's own keys stays
// on). Rung 2 runs only while the writer's route keys are still exactly what
// the removal left (their digest is journaled), so a value the removal itself
// leaves (Qwen Code's default host) is never mistaken for a route set during
// the restart, and a key someone did change is never overwritten.
//
// The hold journal (RouteHoldFileName, 0600 beside route-provenance.json) is
// written before a route is removed and holds no file bytes and no whole-file
// digest: only which routes are off, the value each removal left at the route
// key and the digest of the writer's route keys. A hold an interrupted run
// left behind is put back by the next `observer service restart` or `start`,
// or by the daemon itself once its proxy on that port serves
// (ReleasePendingRoutes), and is never lost. A verb's whole run, and every
// read-modify-write of the journal, holds the route hold lock (holdlock.go).

// RouteHoldFileName is the hold journal, kept in the registrar home's
// .observer directory beside the route-provenance file. proxyroute is its one
// owner.
const RouteHoldFileName = "route-hold.json"

// routeHoldVersion is the journal schema version. Version 2 added Left and
// LeftState; a version-1 entry (no LeftState) is put back the cautious way
// (only onto a route key that reads empty, without Force).
const routeHoldVersion = 2

// HoldAction is what the hold does about one inspected route.
type HoldAction string

const (
	// HoldSkip: the route does not reach this proxy (another host, another
	// port, an inactive provider, no route at all). Not reported.
	HoldSkip HoldAction = "skip"
	// HoldKeep: the route reaches this proxy but stays on; Reason says why.
	HoldKeep HoldAction = "keep"
	// HoldTakeOff: the route is taken off for the restart and put back after.
	HoldTakeOff HoldAction = "take_off"
)

// HoldReason is why the hold chose its action. A closed vocabulary, one per
// holdRules row.
type HoldReason string

// The hold reasons.
const (
	HoldReasonNotThisProxy HoldReason = "not_this_proxy"
	// HoldReasonOrgRoute: the organization wrote the route (enrolment or the
	// managed daemon). A safe restart never touches it: the organization's
	// integrity probe would read a missing route as a removal.
	HoldReasonOrgRoute HoldReason = "org_route"
	// HoldReasonProviderLane: a third-party provider lane route. Its
	// original provider host lives in the organization's record.
	HoldReasonProviderLane HoldReason = "provider_lane"
	// HoldReasonNoRemover: no Leave remover knows this route's file shape.
	HoldReasonNoRemover HoldReason = "no_remover"
	// HoldReasonNotWriterValue: the route is not exactly what the row's
	// writer writes, so it could not be written back the same way if the
	// file changed during the restart.
	HoldReasonNotWriterValue HoldReason = "not_writer_value"
	// HoldReasonNotExact: the rehearsal (holdcheck.go) found that putting
	// the route back with the writer would not give back every setting of
	// the file (a key of the developer's own in the table the removal
	// deletes, a comment, a value the writer would change), or it could not
	// run.
	HoldReasonNotExact HoldReason = "not_exact"
	// HoldReasonRouted: the route reaches this proxy and can be taken off
	// and put back exactly.
	HoldReasonRouted HoldReason = "routed"
)

// holdInput is everything the decision needs for one inspected route.
type holdInput struct {
	// Status is the inspected route, active provider applied.
	Status RouteStatus
	// Port is this daemon's proxy port.
	Port int
	// OrgOwned: the route's provenance record was written by the
	// organization (routeprov.OrgOwned).
	OrgOwned bool
	// Removable: a Leave remover exists for the row (routeShapes).
	Removable bool
	// WriterAgrees: a dry run of the row's writer, in the route's own client
	// token form, says it would write exactly this route (already set, no
	// key added).
	WriterAgrees bool
	// Exact: the rehearsal of the removal and the writer's put-back on a
	// scratch copy gave back every setting of the file.
	Exact bool
}

type holdRule struct {
	match  func(in holdInput) bool
	action HoldAction
	reason HoldReason
}

// holdRules is the hold table, walked top-down; the first match wins. One
// test case per row (hold_test.go).
var holdRules = []holdRule{
	{func(in holdInput) bool { return in.Status.State != RouteOurs || in.Status.Port != in.Port }, HoldSkip, HoldReasonNotThisProxy},
	{func(in holdInput) bool { return in.OrgOwned }, HoldKeep, HoldReasonOrgRoute},
	{func(in holdInput) bool { return in.Status.Lane }, HoldKeep, HoldReasonProviderLane},
	{func(in holdInput) bool { return !in.Removable }, HoldKeep, HoldReasonNoRemover},
	{func(in holdInput) bool { return !in.WriterAgrees }, HoldKeep, HoldReasonNotWriterValue},
	{func(in holdInput) bool { return !in.Exact }, HoldKeep, HoldReasonNotExact},
	{func(holdInput) bool { return true }, HoldTakeOff, HoldReasonRouted},
}

// decideHold walks holdRules for one route.
func decideHold(in holdInput) (HoldAction, HoldReason) {
	for _, r := range holdRules {
		if r.match(in) {
			return r.action, r.reason
		}
	}
	return HoldSkip, HoldReasonNotThisProxy
}

// HoldReasonText is the plain-language reason a route stays on.
func HoldReasonText(r HoldReason) string {
	switch r {
	case HoldReasonOrgRoute:
		return "your organization wrote this route, so a restart leaves it as it is"
	case HoldReasonProviderLane:
		return "it is a provider lane route your organization maintains"
	case HoldReasonNoRemover:
		return "Observer cannot take this route off and put it back"
	case HoldReasonNotWriterValue:
		return "it is not the exact value Observer writes for this tool, so it could not be put back the same way"
	case HoldReasonNotExact:
		return "putting it back after the restart could change or lose a setting beside it (such as your own keys or comments in the same table), so it stays on"
	case HoldReasonRouted:
		return "it reaches this proxy"
	default:
		return string(r)
	}
}

// HeldRoute is one route the hold took off: a journal entry.
type HeldRoute struct {
	Tool       string `json:"tool"`
	ConfigPath string `json:"config_path"`
	// Value is the route taken off. It can carry the proxy client token, so
	// the journal is 0600 like route-provenance.json and the value is never
	// printed (proxyauth.Redact).
	Value string `json:"value"`
	// Record is the route-provenance record as it was before the hold (nil
	// when there was none), so a put-back by the writer leaves the record
	// exactly as it found it.
	Record *routeprov.Record `json:"record,omitempty"`
	// HeldAt is when the route was taken off (RFC 3339, UTC).
	HeldAt string `json:"held_at"`
	// Left is the value the removal left at the route key ("" when it
	// deleted the key). Qwen Code's removal sets model.baseUrl back to the
	// provider's default host rather than deleting it, so that value is the
	// route being off, not a route set during the restart. It is the
	// writer's own default or the host the route replaced, never a
	// credential.
	Left string `json:"left,omitempty"`
	// LeftState is routeKeyState (the SHA-256 of the writer's route keys)
	// of the file the removal left. While the file still has it, nothing but
	// the hold changed those keys, so rung 2 may undo exactly the removal's
	// edits (the writer runs with Force: Codex's prior provider, which the
	// removal selected again, is switched back). "" on a version-1 entry.
	LeftState string `json:"left_state,omitempty"`

	// before is the file as it was, and afterSHA256 the digest of the file
	// the removal left, for the exact put-back (rung 1). In memory only:
	// the journal never holds file bytes, which can carry provider keys, or
	// a digest of the whole file.
	before      []byte
	afterSHA256 string
}

// RouteHold is the hold journal: the routes that are off.
type RouteHold struct {
	Version int `json:"version"`
	// Port is the proxy port the routes reach.
	Port   int         `json:"port"`
	Routes []HeldRoute `json:"routes"`
}

// Empty reports whether no route is held.
func (h RouteHold) Empty() bool { return len(h.Routes) == 0 }

// HoldResult is what the hold did, or would do, about one route that
// reaches this proxy.
type HoldResult struct {
	Tool       string
	ConfigPath string
	Action     HoldAction
	Reason     HoldReason
	// TakenOff is set when the route was removed (never on a dry run).
	TakenOff bool
	// Err is a removal that failed; the route is still on.
	Err error
}

// RouteHoldPath is where this registrar keeps the hold journal.
func (r *Registrar) RouteHoldPath() string {
	return filepath.Join(r.opts.HomeDir, ".observer", RouteHoldFileName)
}

// PendingRouteHold reads the hold journal: the routes an earlier hold took
// off and has not put back yet (an interrupted restart, or `observer service
// stop`). A missing journal is an empty hold. It takes no lock: a caller that
// acts on it holds the route hold lock (LockRouteHold) first.
func (r *Registrar) PendingRouteHold() (RouteHold, error) {
	h, err := readRouteHold(r.RouteHoldPath())
	if h.Port <= 0 {
		h.Port = r.opts.ProxyPort
	}
	return h, err
}

// PendingRouteHoldAt is PendingRouteHold for the home at homeDir ("" = this
// account's home), for a reader with no proxy port of its own (`observer
// doctor`). Read-only.
func PendingRouteHoldAt(homeDir string) (RouteHold, error) {
	if homeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return RouteHold{}, fmt.Errorf("proxyroute.PendingRouteHoldAt: %w", err)
		}
		homeDir = home
	}
	return readRouteHold(filepath.Join(homeDir, ".observer", RouteHoldFileName))
}

// readRouteHold reads the journal at path (missing = empty).
func readRouteHold(path string) (RouteHold, error) {
	h := RouteHold{Version: routeHoldVersion}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return h, fmt.Errorf("proxyroute.readRouteHold: %w", err)
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return h, fmt.Errorf("proxyroute.readRouteHold: parse %s: %w", path, err)
	}
	return h, nil
}

// saveRouteHold writes the journal (0600), or removes it when nothing is
// held.
func (r *Registrar) saveRouteHold(h RouteHold) error {
	path := r.RouteHoldPath()
	if err := testwriteguard.Check("write", path); err != nil {
		return fmt.Errorf("proxyroute.saveRouteHold: %w", err)
	}
	if h.Empty() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("proxyroute.saveRouteHold: remove: %w", err)
		}
		return nil
	}
	h.Version = routeHoldVersion
	body, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return fmt.Errorf("proxyroute.saveRouteHold: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("proxyroute.saveRouteHold: mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("proxyroute.saveRouteHold: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("proxyroute.saveRouteHold: rename: %w", err)
	}
	return nil
}

// HoldRoutes takes off every route that reaches this registrar's proxy port
// and can be put back exactly (holdRules), journaling each one before it is
// removed. On a dry-run registrar it only decides. It returns the hold (the routes now
// off, including any an interrupted earlier hold left off) and one result per
// route that reaches the proxy. An unreadable journal or provenance file is
// an error and nothing is removed: the routes that are off could not be
// told apart, or the records could not be put back. Another process holding
// the route hold lock is ErrRouteHoldBusy, and nothing is removed. A later
// error (the journal could not be saved) returns the routes already off in
// the hold, so the caller can put them back.
func (r *Registrar) HoldRoutes() (RouteHold, []HoldResult, error) {
	if !r.opts.DryRun {
		unlock, err := r.holdLockForWrite()
		if err != nil {
			return RouteHold{}, nil, err
		}
		defer unlock()
	}
	pending, err := r.PendingRouteHold()
	if err != nil {
		return RouteHold{}, nil, err
	}
	// The early refusals return an empty hold: nothing was taken off, and
	// a caller must never put back routes held for another port onto this
	// one.
	prov, err := loadProvenance(r.ProvenancePath())
	if err != nil {
		return RouteHold{}, nil, err
	}
	port := r.opts.ProxyPort
	if !pending.Empty() && pending.Port != port {
		return RouteHold{}, nil, fmt.Errorf("proxyroute.HoldRoutes: an earlier hold took routes off for port %d, not %d; put them back first", pending.Port, port)
	}
	hold := RouteHold{Version: routeHoldVersion, Port: port}
	e := r.inspectEnv()
	view := provenanceView{file: &prov}
	var results []HoldResult
	for _, ri := range routeInspectors() {
		st := ApplyActiveProvider([]RouteStatus{inspectOne(ri, e, nil, view)})[0]
		rec := prov.Find(ri.tool, st.ConfigPath)
		in := holdInput{Status: st, Port: port}
		if st.State == RouteOurs && st.Port == port {
			shape, ok := shapeFor(ri.tool)
			in.Removable = ok && shape.remove != nil && shape.keys != nil
			in.OrgOwned = rec != nil && routeprov.OrgOwned(rec.Writer)
			in.WriterAgrees = r.writerAgrees(ri, e, st.ConfigPath, rec)
			if in.Removable && in.WriterAgrees && !in.OrgOwned && !st.Lane {
				in.Exact = r.rehearseCurrent(ri, st.ConfigPath, rec) == nil
			}
		}
		action, reason := decideHold(in)
		if action == HoldSkip {
			continue
		}
		res := HoldResult{Tool: ri.tool, ConfigPath: st.ConfigPath, Action: action, Reason: reason}
		if action == HoldTakeOff && !r.opts.DryRun {
			hr, terr := r.takeOff(ri, st.ConfigPath, rec, &hold, pending)
			if terr != nil {
				res.Err = terr
			} else {
				res.TakenOff = true
				hold.Routes = append(hold.Routes, hr)
			}
		}
		results = append(results, res)
	}
	// Routes an interrupted hold left off stay held (they were not seen as
	// routed above, so they were not taken again).
	hold.Routes = append(hold.Routes, notIn(pending.Routes, hold.Routes)...)
	if !r.opts.DryRun {
		if err := r.saveRouteHold(hold); err != nil {
			return hold, results, err
		}
	}
	return hold, results, nil
}

// writerAgrees dry-runs the row's writer in the route's own client token
// form and reports whether it would write exactly the route found: already
// set, nothing added. Then a put-back by the writer (rung 2) writes the same
// value the hold took off.
func (r *Registrar) writerAgrees(ri routeInspector, e inspectEnv, path string, rec *routeprov.Record) bool {
	shape, ok := shapeFor(ri.tool)
	if !ok || ri.write == nil {
		return false
	}
	cur, present, err := shape.read(path, rec)
	if err != nil || !present {
		return false
	}
	// The value must be exactly what the writer writes at this port (a
	// loopback route the writer merely tolerates, such as another spelling,
	// is not), and the writer must have nothing to add to the file.
	want := routeprov.Record{Tool: ri.tool, ConfigPath: path}
	if rec != nil {
		want = *rec
	}
	if !ownRouteAt(ri.tool, want, cur, r.opts.ProxyPort) {
		return false
	}
	dry, err := NewRegistrar(RegisterOptions{
		ProxyPort: r.opts.ProxyPort, HomeDir: e.home, DryRun: true, Getenv: e.getenv,
		ClientToken: proxyauth.TokenOf(cur),
	})
	if err != nil {
		return false
	}
	res := ri.write(dry)
	return res.Error == nil && res.AlreadySet && !res.Added && !res.GatewayHintsAdded && !res.ConfigMissing
}

// removalRecord is the record a removal of the route at path with value cur
// uses: the provenance record when there is one, with the value found.
func removalRecord(tool, path, cur string, rec *routeprov.Record) routeprov.Record {
	rm := routeprov.Record{Tool: tool, ConfigPath: path}
	if rec != nil {
		rm = *rec
	}
	rm.Value = cur
	return rm
}

// rehearseCurrent rehearses the hold of the route at path as the file is now
// (for the decision and the dry run; takeOff rehearses again on the bytes it
// reads under the settings-file lock).
func (r *Registrar) rehearseCurrent(ri routeInspector, path string, rec *routeprov.Record) error {
	shape, _ := shapeFor(ri.tool)
	before, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cur, present, err := shape.read(path, rec)
	if err != nil || !present {
		return errors.New("proxyroute: the route is not set")
	}
	_, err = r.rehearsePutBack(ri, rec, removalRecord(ri.tool, path, cur, rec), before)
	return err
}

// takeOff journals and removes one route through its Leave remover, under
// the settings-file lock when the registrar has one. It rehearses the
// removal and the put-back on the exact bytes it read (holdcheck.go) and
// removes nothing when the rehearsal fails. It keeps the file as it was for
// rung 1 only when the removal started from exactly those bytes (the file it
// left is the rehearsal's), so rung 1 can never undo a write another program
// made in between.
func (r *Registrar) takeOff(ri routeInspector, path string, rec *routeprov.Record, hold *RouteHold, pending RouteHold) (HeldRoute, error) {
	tool := ri.tool
	shape, _ := shapeFor(tool)
	if r.opts.Lock != nil {
		unlock, err := r.opts.Lock(path)
		if err != nil {
			return HeldRoute{}, fmt.Errorf("proxyroute.takeOff: lock: %w", err)
		}
		defer unlock()
	}
	before, err := os.ReadFile(path)
	if err != nil {
		return HeldRoute{}, fmt.Errorf("proxyroute.takeOff: read: %w", err)
	}
	cur, present, err := shape.read(path, rec)
	if err != nil {
		return HeldRoute{}, err
	}
	if !present {
		return HeldRoute{}, fmt.Errorf("proxyroute.takeOff: the %s route is no longer set", tool)
	}
	rm := removalRecord(tool, path, cur, rec)
	reh, err := r.rehearsePutBack(ri, rec, rm, before)
	if err != nil {
		return HeldRoute{}, fmt.Errorf("proxyroute.takeOff: the %s route stays on: %w", tool, err)
	}
	hr := HeldRoute{Tool: tool, ConfigPath: path, Value: cur, HeldAt: time.Now().UTC().Format(time.RFC3339), Left: reh.left, LeftState: reh.leftState}
	if rec != nil {
		snap := *rec
		hr.Record = &snap
	}
	// Journal first: a run killed after the removal still knows the route
	// is off.
	if err := r.saveRouteHold(journalOf(hold, pending, hr)); err != nil {
		return HeldRoute{}, err
	}
	if err := shape.remove(path, rm); err != nil {
		// The route stays on; the journal must not claim it is off.
		_ = r.saveRouteHold(journalOf(hold, pending))
		return HeldRoute{}, err
	}
	after, aerr := os.ReadFile(path)
	if aerr == nil && bytes.Equal(after, reh.after) {
		sum := sha256.Sum256(after)
		hr.before, hr.afterSHA256 = before, hex.EncodeToString(sum[:])
	}
	// The journal holds what the removal really left at the route keys
	// (the rehearsal's state unless another program wrote the file in
	// between).
	if st, serr := routeKeyState(path, shape.keys(rec)); serr == nil && st != hr.LeftState {
		hr.LeftState = st
		hr.Left, _, _ = shape.read(path, rec)
		_ = r.saveRouteHold(journalOf(hold, pending, hr))
	}
	return hr, nil
}

// journalOf is the journal while a hold is in progress: the routes held so
// far, then extra, then the routes an interrupted hold left off that are not
// held again.
func journalOf(hold *RouteHold, pending RouteHold, extra ...HeldRoute) RouteHold {
	held := append(append([]HeldRoute(nil), hold.Routes...), extra...)
	return RouteHold{Version: routeHoldVersion, Port: hold.Port, Routes: append(held, notIn(pending.Routes, held)...)}
}

// notIn returns the routes of from whose tool and file are not in held.
func notIn(from, held []HeldRoute) []HeldRoute {
	var out []HeldRoute
	for _, p := range from {
		dup := false
		for _, h := range held {
			if h.Tool == p.Tool && h.ConfigPath == p.ConfigPath {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, p)
		}
	}
	return out
}

// ReleaseOutcome is what the release did for one held route.
type ReleaseOutcome string

// The release outcomes.
const (
	// ReleaseRestored: the file was put back exactly as it was.
	ReleaseRestored ReleaseOutcome = "restored"
	// ReleaseRewritten: the file changed during the restart, so the row's
	// writer wrote the same route again and its provenance record was put
	// back as it was.
	ReleaseRewritten ReleaseOutcome = "rewritten"
	// ReleaseRewrittenDiffers: the writer wrote the route again, but what
	// the file now holds is not the value taken off.
	ReleaseRewrittenDiffers ReleaseOutcome = "rewritten_differs"
	// ReleaseSetMeanwhile: a route was set again in the file during the
	// restart (by you or a tool); it is left as it is.
	ReleaseSetMeanwhile ReleaseOutcome = "set_meanwhile"
	// ReleaseChangedMeanwhile: the route is still off, but another of the
	// keys its writer owns changed during the restart (Codex's
	// model_provider, a Qwen Code provider entry), so the writer is not run
	// over that change; the route stays off and is not held any more.
	ReleaseChangedMeanwhile ReleaseOutcome = "changed_meanwhile"
	// ReleaseConfigGone: the config file is gone; nothing is created.
	ReleaseConfigGone ReleaseOutcome = "config_gone"
	// ReleaseFailed: the route could not be put back; it stays held in the
	// journal for the next release.
	ReleaseFailed ReleaseOutcome = "failed"
)

// ReleaseResult is one held route's put-back.
type ReleaseResult struct {
	Tool       string
	ConfigPath string
	Outcome    ReleaseOutcome
	Err        error
}

// ReleaseRoutes puts back every route of h (rung 1, else rung 2; see the
// file comment) and then, reading the journal again under the route hold
// lock, drops from it the routes it put back and keeps (or adds) the ones it
// could not (the journal is removed when none is left). It never writes a
// route the hold did not take off, and never creates a config file that is
// gone. Another process holding the lock is one failed result
// (ErrRouteHoldBusy) and nothing is changed.
func (r *Registrar) ReleaseRoutes(h RouteHold) []ReleaseResult {
	unlock, err := r.holdLockForWrite()
	if err != nil {
		return []ReleaseResult{{Outcome: ReleaseFailed, Err: err}}
	}
	defer unlock()
	var out []ReleaseResult
	var failed, done []HeldRoute
	for _, hr := range h.Routes {
		res := r.releaseOne(h.Port, hr)
		if res.Outcome == ReleaseFailed {
			failed = append(failed, hr)
		} else {
			done = append(done, hr)
		}
		out = append(out, res)
	}
	cur, err := readRouteHold(r.RouteHoldPath())
	if err != nil {
		return append(out, ReleaseResult{Outcome: ReleaseFailed, Err: err})
	}
	port := cur.Port
	if cur.Empty() || port <= 0 {
		port = h.Port
	}
	left := notIn(cur.Routes, done)
	left = append(left, notIn(failed, left)...)
	if err := r.saveRouteHold(RouteHold{Version: routeHoldVersion, Port: port, Routes: left}); err != nil {
		out = append(out, ReleaseResult{Outcome: ReleaseFailed, Err: err})
	}
	return out
}

// ReleasePendingRoutes is the put-back of a hold an earlier run left (an
// interrupted or timed-out restart, `observer service stop`), for the daemon
// whose proxy on this registrar's port now serves, and for `observer service
// start` where no service manager runs the daemon. Under the route hold lock
// it reads the journal and puts back its routes when they are for this port.
// It returns the journal as read (pending.Port says which port it is for; a
// hold for another port is left alone and not released), the results, and
// ErrRouteHoldBusy when another process holds the lock (that process owns
// the put-back).
func (r *Registrar) ReleasePendingRoutes() (RouteHold, []ReleaseResult, error) {
	unlock, err := r.holdLockForWrite()
	if err != nil {
		return RouteHold{}, nil, err
	}
	defer unlock()
	pending, err := r.PendingRouteHold()
	if err != nil {
		return pending, nil, err
	}
	if pending.Empty() || pending.Port != r.opts.ProxyPort {
		return pending, nil, nil
	}
	return pending, r.ReleaseRoutes(pending), nil
}

// releaseOne puts back one held route.
func (r *Registrar) releaseOne(port int, hr HeldRoute) ReleaseResult {
	res := ReleaseResult{Tool: hr.Tool, ConfigPath: hr.ConfigPath}
	if hr.before != nil && hr.afterSHA256 != "" {
		done, err := r.restoreBytes(hr)
		if err != nil {
			res.Outcome, res.Err = ReleaseFailed, err
			return res
		}
		if done {
			res.Outcome = ReleaseRestored
			return res
		}
	}
	shape, ok := shapeFor(hr.Tool)
	ri := inspectorFor(hr.Tool)
	if !ok || ri.write == nil {
		res.Outcome, res.Err = ReleaseFailed, fmt.Errorf("proxyroute.ReleaseRoutes: no writer for %s", hr.Tool)
		return res
	}
	if _, err := os.Stat(hr.ConfigPath); errors.Is(err, os.ErrNotExist) {
		res.Outcome = ReleaseConfigGone
		return res
	}
	cur, present, err := shape.read(hr.ConfigPath, hr.Record)
	if err != nil {
		res.Outcome, res.Err = ReleaseFailed, err
		return res
	}
	force := false
	switch {
	case hr.LeftState != "" && shape.keys != nil:
		state, serr := routeKeyState(hr.ConfigPath, shape.keys(hr.Record))
		if serr != nil {
			res.Outcome, res.Err = ReleaseFailed, serr
			return res
		}
		if state != hr.LeftState {
			// Someone changed a key the writer owns: never write over it.
			res.Outcome = ReleaseChangedMeanwhile
			if present && cur != hr.Left {
				res.Outcome = ReleaseSetMeanwhile
			}
			return res
		}
		// Every route key is exactly as the removal left it, so Force only
		// undoes the removal's own edits (Codex's prior provider, which the
		// removal selected again, is switched back), and the rehearsal
		// proved the writer gives back the settings the removal took.
		force = true
	case present && cur != "":
		// A version-1 entry: no state to compare, so only a route key that
		// reads empty is written, without Force.
		res.Outcome = ReleaseSetMeanwhile
		return res
	}
	reg, err := NewRegistrar(RegisterOptions{
		ProxyPort: port, HomeDir: r.opts.HomeDir, Getenv: r.opts.Getenv, Lock: r.opts.Lock,
		ClientToken: proxyauth.TokenOf(hr.Value), Writer: recordWriter(hr.Record),
		Force: force,
	})
	if err != nil {
		res.Outcome, res.Err = ReleaseFailed, err
		return res
	}
	w := ri.write(reg)
	if w.Error != nil {
		res.Outcome, res.Err = ReleaseFailed, w.Error
		return res
	}
	if err := r.restoreRecord(hr); err != nil {
		res.Err = err
	}
	res.Outcome = ReleaseRewritten
	if now, _, rerr := shape.read(hr.ConfigPath, hr.Record); rerr != nil || now != hr.Value {
		res.Outcome = ReleaseRewrittenDiffers
	}
	return res
}

// restoreBytes puts the file back exactly as it was when it still holds
// exactly what the removal left (compared again right before the rename).
// It reports false, with no error, when the file changed since.
func (r *Registrar) restoreBytes(hr HeldRoute) (bool, error) {
	if r.opts.Lock != nil {
		unlock, err := r.opts.Lock(hr.ConfigPath)
		if err != nil {
			return false, fmt.Errorf("proxyroute.restoreBytes: lock: %w", err)
		}
		defer unlock()
	}
	unchanged := func() error {
		sum, err := fileSHA256(hr.ConfigPath)
		if err != nil {
			return err
		}
		if sum != hr.afterSHA256 {
			return errFileChanged
		}
		return nil
	}
	if err := unchanged(); err != nil {
		return false, nil //nolint:nilerr // a changed or gone file falls through to the writer rung
	}
	err := writeFileKeepModeIf(hr.ConfigPath, hr.before, unchanged)
	if errors.Is(err, errFileChanged) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("proxyroute.restoreBytes: %w", err)
	}
	return true, nil
}

// fileSHA256 is the hex SHA-256 of the file at path.
func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// errFileChanged marks a file another writer changed since the removal.
var errFileChanged = errors.New("proxyroute: the file changed since the route was taken off")

// restoreRecord puts the route's provenance record back exactly as it was
// before the hold, or drops the one the writer just added when there was
// none.
func (r *Registrar) restoreRecord(hr HeldRoute) error {
	path := r.ProvenancePath()
	f, err := loadProvenance(path)
	if err != nil {
		return err
	}
	cur := f.Find(hr.Tool, hr.ConfigPath)
	switch {
	case hr.Record == nil && cur == nil:
		return nil
	case hr.Record == nil:
		f.Drop(hr.Tool, hr.ConfigPath)
	case cur == nil:
		f.Records = append(f.Records, *hr.Record)
	default:
		*cur = *hr.Record
	}
	return saveProvenance(path, f)
}

// recordWriter is the writer a put-back records with (the record is put back
// as it was afterwards, so this only matters if that fails).
func recordWriter(rec *routeprov.Record) routeprov.Writer {
	if rec == nil {
		return ""
	}
	return rec.Writer
}
