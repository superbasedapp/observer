//go:build linux && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_cred_local_linux.go is credential injection's half inside a LOCAL
// run's Linux host helper (lane N3, SBX-NET-2), wired into the helper's
// lane seams (sandbox_helpers_credlane_linux.go). Only a run whose helper
// serves the model-proxy forward gets a lane: the bwrap and oci-runc rows
// on the proxy_only tier, and on the internet tier only with the
// provider-host block on. The process_lite (Landlock) row and every run on
// the host tier get none (no --proxy-addr reaches the helper, so there is
// no forward to stamp), nor does an internet-tier run without the block
// (the helper cannot tell that the tool's model traffic uses the forward).
// Before the box starts, the helper
// mints the run's sentinel and relay token and writes the run's injection
// record (custody host_bound, lane local, hashes only); the box env gets
// a sentinel in place of each bound provider's key variable, only where the
// launching env already carried one (never added, so a subscription login
// is not moved onto key billing); the helper's model-proxy forward stamps the run
// and its token on every request (the hosted path's two headers, a
// box-sent value replaced); and the proxy's injector swaps the sentinel
// only when every row of sandboxcred.Decide holds, the local rows
// included. The token lives only in this helper's memory.

func init() {
	localCredBoxEnvHook = credLocalBoxEnv
	localCredStampHook = credLocalStamp
	localCredEndHook = credLocalEnd
	localCredReopenHook = credLocalReopen
}

// credLocalTTL bounds a local run's record. The real bound is the run's
// liveness lock (the "local helper gone" row), which a helper killed with
// SIGKILL loses at once.
const credLocalTTL = 7 * 24 * time.Hour

// credLocalLane is one local run's lane in this helper: the providers it
// binds, their sentinels (only in the helper that opened the lane; a
// re-opened lane has none, the box already holds them) and its token.
type credLocalLane struct {
	observerDir string
	providers   []string
	sentinels   []credSentinel
	token       string
}

// sentinelMap is the lane's sentinels by provider.
func (l *credLocalLane) sentinelMap() map[string]string {
	out := make(map[string]string, len(l.sentinels))
	for _, s := range l.sentinels {
		out[s.provider] = s.sentinel
	}
	return out
}

// credLocalLanes holds this helper's lanes (run id -> *credLocalLane).
var credLocalLanes sync.Map

// credLocalBoxEnv sets up the run's lane and returns env with each bound
// provider's sentinel in place of that provider's key variable and every
// other credential variable (sandboxcred.BoxEnvSet's table) dropped; env is
// returned unchanged when the component is off or the run cannot be served
// (no relay run, no proxy forward, model traffic not known to use the
// forward, a tool with no injectable provider, no bound provider:
// sandboxcred.BindLocal), so the run is exactly as before.
func credLocalBoxEnv(h sandbox.HostArgs, env []string) []string {
	lane := credLocalOpen(h, env)
	if lane == nil || len(lane.sentinels) == 0 {
		return env
	}
	for _, s := range lane.sentinels {
		p, ok := sandboxcred.ProviderFor(s.provider)
		if !ok || s.sentinel == "" || !credEnvHasKey(env, p.KeyEnv) {
			return env
		}
	}
	// Each bound key variable holds only its sentinel; every other variable
	// the credential table classes is dropped (F-005), named on the record.
	out, _ := sandboxcred.BoxEnvSet(lane.sentinelMap(), env)
	return out
}

// credEnvNames are env's variable names that carry a value.
func credEnvNames(env []string) []string {
	var out []string
	for _, kv := range env {
		if name, v, ok := strings.Cut(kv, "="); ok && v != "" {
			out = append(out, name)
		}
	}
	return out
}

// credEnvHasKey reports whether env carries a non-empty name variable.
// Only such a variable is replaced: adding one would move a tool signed
// in with a subscription (an OAuth login) onto API-key billing.
func credEnvHasKey(env []string, name string) bool {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, name+"="); ok && v != "" {
			return true
		}
	}
	return false
}

// credLocalRouted reports whether the run's model traffic is known to go
// through the proxy forward, read from the helper's own flags (the helper
// is not told whether the launch is proxy-routed): with no egress gateway
// (proxy_only) the forward is the box's only route out, and with the
// gateway's provider-host block on a direct provider request is refused.
// An internet-tier run without the block may reach the provider directly,
// where a sentinel would be refused (401).
func credLocalRouted(h sandbox.HostArgs) bool {
	return !h.Gateway || h.ProviderBlock
}

// credLocalOpen mints and records the run's lane (nil: no lane).
func credLocalOpen(h sandbox.HostArgs, env []string) *credLocalLane {
	if h.RelayRun == "" || h.ProxyAddr == "" || h.ObserverDir == "" || h.SockDir == "" || !credLocalRouted(h) {
		return nil
	}
	if v, ok := credLocalLanes.Load(h.RelayRun); ok {
		return v.(*credLocalLane)
	}
	// The forward is served only when the proxy answered at start; with
	// no forward there is nothing to stamp, so no sentinel either.
	if fi, err := os.Lstat(filepath.Join(h.SockDir, sandbox.ProxySocketName)); err != nil || fi.Mode().Type() != fs.ModeSocket {
		return nil
	}
	if !credActive(context.Background()) {
		return nil
	}
	run, err := sandboxrelayd.ReadRun(h.ObserverDir, h.RelayRun)
	if err != nil {
		return nil
	}
	candidates := credToolProviders(run.Tool)
	names := credEnvNames(env)
	// A candidate whose key variable the launching env carries: only then
	// is there something to replace (and a stored-key list worth reading).
	var withKey []string
	for _, id := range candidates {
		if p, ok := sandboxcred.ProviderFor(id); ok && credEnvHasKey(env, p.KeyEnv) {
			withKey = append(withKey, id)
		}
	}
	if len(withKey) == 0 {
		return nil
	}
	ids, perr := credReadProviders(h.ObserverDir)
	if perr != nil {
		// Selected, a key variable to replace, but the list of stored
		// keys cannot be read: no lane, said out loud (audit FU3-A4).
		slog.Default().Warn("terminal_sandbox: credential injection is selected but the list of stored provider keys cannot be read; this run gets no injection and its box keeps the launching key variables",
			"run", h.RelayRun, "providers", strings.Join(withKey, ","), "err", perr)
		return nil
	}
	bound := sandboxcred.BindLocal(sandboxcred.LocalBindFacts{Candidates: candidates, Stored: ids, EnvNames: names})
	if len(bound) == 0 {
		return nil
	}
	sentinels := make([]credSentinel, 0, len(bound))
	for _, id := range bound {
		s, err := sandboxcred.MintSentinel(rand.Reader, id)
		if err != nil {
			return nil
		}
		sentinels = append(sentinels, credSentinel{provider: id, sentinel: s})
	}
	token, err := sandboxcred.MintToken(rand.Reader)
	if err != nil {
		return nil
	}
	now := credNow()
	lane := &credLocalLane{observerDir: h.ObserverDir, providers: bound, sentinels: sentinels, token: token}
	_, dropped := sandboxcred.BoxEnvSet(lane.sentinelMap(), env)
	rec := credNewRecord(h.RelayRun, vocab.CustodyHostBound, sentinels)
	rec.Lane, rec.TokenHash = sandboxcred.LaneLocal, sandboxcred.Hash(token)
	rec.DroppedEnv, rec.CreatedAt, rec.Expires = dropped, now, now.Add(credLocalTTL)
	if credWriteRecord(h.ObserverDir, rec) != nil {
		return nil
	}
	credLocalLanes.Store(h.RelayRun, lane)
	return lane
}

// credLocalReopenRule is one row of the re-open table: when refuses holds,
// the lane stays closed with reason (a fixed text naming no value).
type credLocalReopenRule struct {
	refuses func(h sandbox.HostArgs, rec credRunRecord) bool
	reason  func(rec credRunRecord) string
}

// credLocalReopenRules are walked top-down for a re-adopted run whose
// record says lane local (F-004): the same facts credLocalOpen required at
// launch, read again, since the user may have removed the key or turned
// the component off while the run's helper was gone.
var credLocalReopenRules = []credLocalReopenRule{
	{
		refuses: func(_ sandbox.HostArgs, rec credRunRecord) bool {
			return string(rec.Custody) != sandboxcred.CustodyLocal
		},
		reason: func(credRunRecord) string { return "the run's injection record is not a local run's" },
	},
	{
		refuses: func(_ sandbox.HostArgs, rec credRunRecord) bool { return !credNow().Before(rec.Expires) },
		reason:  func(credRunRecord) string { return "the run's injection record has expired" },
	},
	{
		refuses: func(h sandbox.HostArgs, _ credRunRecord) bool { return h.ProxyAddr == "" || !credLocalRouted(h) },
		reason:  func(credRunRecord) string { return "the run's model traffic no longer goes through the proxy forward" },
	},
	{
		refuses: func(sandbox.HostArgs, credRunRecord) bool { return !credActive(context.Background()) },
		reason: func(credRunRecord) string {
			return "credential injection (" + credentialsComponent + ") is not selected"
		},
	},
	{
		refuses: func(h sandbox.HostArgs, _ credRunRecord) bool {
			_, err := credReadProviders(h.ObserverDir)
			return err != nil
		},
		reason: func(credRunRecord) string {
			return "the list of stored provider keys cannot be read"
		},
	},
	{
		refuses: func(h sandbox.HostArgs, rec credRunRecord) bool { return credLocalMissingKey(h.ObserverDir, rec) != "" },
		reason: func(rec credRunRecord) string {
			if ps := rec.providers(); len(ps) == 1 {
				return "no " + ps[0] + " key is stored for injection; add yours with `observer sandbox credentials add " + ps[0] + "`"
			}
			return "a key the run's lane binds (" + strings.Join(rec.providers(), ", ") + ") is no longer stored for injection; add it with `observer sandbox credentials add <provider>`"
		},
	},
}

// credLocalMissingKey is the first provider the record binds whose key is
// no longer stored ("" when every one is).
func credLocalMissingKey(observerDir string, rec credRunRecord) string {
	for _, id := range rec.providers() {
		if !credKeyStored(observerDir, id) {
			return id
		}
	}
	return ""
}

// credLocalReopen re-opens a re-adopted run's lane (F-004): the box still
// holds the sentinel its first helper put in its env, and the record still
// holds that sentinel's hash, so this helper mints its own relay token,
// records its hash on the record (the sentinel hash kept) and stamps the
// run on its forward again. It returns "" when the lane is open, or when
// the run has no local record (it never had injection; the forward stays
// the raw pipe as before), and otherwise why it stays closed.
func credLocalReopen(h sandbox.HostArgs) string {
	if h.RelayRun == "" || h.ObserverDir == "" {
		return ""
	}
	rec, err := credReadRecord(h.ObserverDir, h.RelayRun)
	if err != nil {
		return credLocalReopenNoRecord(h, err)
	}
	if rec.Lane != sandboxcred.LaneLocal {
		return ""
	}
	if _, ok := credLocalLanes.Load(h.RelayRun); ok {
		return ""
	}
	for _, rule := range credLocalReopenRules {
		if rule.refuses(h, rec) {
			return rule.reason(rec)
		}
	}
	token, err := sandboxcred.MintToken(rand.Reader)
	if err != nil {
		return "a relay token could not be minted"
	}
	rec.TokenHash = sandboxcred.Hash(token)
	if credWriteRecord(h.ObserverDir, rec) != nil {
		return "the run's injection record could not be written"
	}
	// No sentinel in this helper: the box already holds it, and this
	// helper builds no box env.
	credLocalLanes.Store(h.RelayRun, &credLocalLane{observerDir: h.ObserverDir, providers: rec.providers(), token: token})
	return ""
}

// credLocalReopenNoRecord is the note for a re-adopted run with no
// readable injection record (audit FU3-A5). A record that exists but is
// refused is always named. An absent record is named only when the run
// could have had a lane (the component is selected now, the run's tool has
// an injectable provider and its model traffic goes through the forward): a run
// launched with injection whose first helper ended normally has lost its
// record, and the helper cannot tell that from a run launched without
// injection, so the note says both. Any other run gets no note.
func credLocalReopenNoRecord(h sandbox.HostArgs, err error) string {
	if !errors.Is(err, fs.ErrNotExist) {
		return "the run's injection record cannot be read (" + err.Error() + ")"
	}
	if h.ProxyAddr == "" || !credLocalRouted(h) || !credActive(context.Background()) {
		return ""
	}
	run, rerr := sandboxrelayd.ReadRun(h.ObserverDir, h.RelayRun)
	if rerr != nil || len(credToolProviders(run.Tool)) == 0 {
		return ""
	}
	return "this run has no injection record (it is removed when the run's first helper ends normally); if it was launched with credential injection it cannot be restored"
}

// credLocalStamp is the run's stamp: the run header and the run's relay
// token, each replacing whatever the box sent (nil: no lane).
func credLocalStamp(runID string) func(http.Header) {
	v, ok := credLocalLanes.Load(runID)
	if !ok {
		return nil
	}
	token := v.(*credLocalLane).token
	return func(h http.Header) {
		h.Set(vocab.RelayRunHeader, runID)
		h.Set(sandboxcred.TokenHeader, token)
	}
}

// credLocalEnd ends the run's lane: its record (and its kept fresh
// session ids, credFreshPath) is removed, unless another helper has since
// written its own (a different token hash).
func credLocalEnd(runID string) {
	v, ok := credLocalLanes.LoadAndDelete(runID)
	if !ok {
		return
	}
	lane := v.(*credLocalLane)
	rec, err := credReadRecord(lane.observerDir, runID)
	if err != nil || rec.TokenHash != sandboxcred.Hash(lane.token) {
		return
	}
	_ = os.Remove(credRunPath(lane.observerDir, runID))
	_ = os.Remove(credFreshPath(lane.observerDir, runID))
}
