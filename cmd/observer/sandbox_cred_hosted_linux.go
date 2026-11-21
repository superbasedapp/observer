//go:build linux && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_cred_hosted_linux.go is credential injection's half inside the
// hosted host helper: the run's setup, teardown, box environment and relay
// token stamp, wired into the helper's hooks (sandbox_cred_seam_linux.go).
// That helper runs only on Linux (terminal_sandbox_hosted_host.go), so this
// half is compiled only there (WINFIX4 lint: unused on Windows and macOS).
// The keystore, the run records, the proxy's injector and the verbs stay in
// sandbox_cred.go on every platform.

func init() {
	hostedCredSetupHook = credSetup
	hostedCredTeardownHook = credTeardown
	hostedCredEnvHook = credEnv
	hostedCredInBoxKeysHook = credInBoxKeys
	hostedCredStampHook = credStamp
	hostedCredIsSentinelHook = sandboxcred.IsSentinel
}

// credOtherHomeRelay reports whether the proxy itself puts a credential on
// the box's requests (homeRelayServedAtHome: the org gateway route), which
// serves home_relay with no stored key. The box still gets a sentinel, so
// its tool starts (FX3 item 5, F-L3P4-4).
var credOtherHomeRelay = func() bool {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()})
	return err == nil && homeRelayServedAtHome(cfg)
}

// credKeyPoolSet reports whether a routing key pool is configured, for the
// refusal's words: a pool never serves home_relay.
var credKeyPoolSet = func() bool {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()})
	return err == nil && len(cfg.Routing.KeyPool) > 0
}

// credSetup mints the run's sentinel for home_relay custody, or applies the
// provider_injected rules (sandbox_cred_broker.go).
func credSetup(ctx context.Context, plan hostedPlanFile) error {
	if !credActive(ctx) {
		return nil
	}
	switch vocab.KeyCustody(plan.Custody) {
	case vocab.CustodyHomeRelay:
		return credSetupHomeRelay(plan)
	case vocab.CustodyProviderInjected:
		return credSetupProviderInjected(ctx, plan)
	}
	return nil
}

// credSetupHomeRelay binds the run's providers (sandboxcred.BindProviders
// over the tool's injectable providers, from its capability row) and mints
// one sentinel per bound provider, each for that provider's own key
// variable (gap H2: a run used to bind exactly one provider, so only a
// vendor-locked tool could use injection).
func credSetupHomeRelay(plan hostedPlanFile) error {
	candidates := credToolProviders(plan.Tool)
	unsat := func(why string) error {
		if credKeyPoolSet() {
			why += " (the routing key pool does not serve home_relay: it only rotates keys a request already carries)"
		}
		return fmt.Errorf("%s: key custody home_relay: %s", verdictHostedCustody, why)
	}
	served := credOtherHomeRelay()
	if len(candidates) == 0 {
		if served {
			return nil // the org gateway serves; no key variable injection knows
		}
		return unsat("the tool's model requests do not reach a provider credential injection serves")
	}
	ids, perr := credReadProviders(plan.ObserverDir)
	if perr != nil && !served {
		return unsat("the list of stored provider keys cannot be read (" + perr.Error() + "); remove it and add your keys again with `observer sandbox credentials add <provider>`")
	}
	// Whoever serves the key at home, the box gets a sentinel in each bound
	// provider's key variable, so the tool starts (F-L3P4-4): the injector
	// swaps a stored key for it, or the org gateway route replaces it with
	// the org's virtual key.
	bound := sandboxcred.BindProviders(sandboxcred.BindFacts{Candidates: candidates, Stored: ids, OrgRoute: served})
	if len(bound) == 0 {
		if served {
			return nil // the org gateway serves; no stored key to bind
		}
		if len(candidates) == 1 {
			return unsat("no " + candidates[0] + " key is stored for injection; add yours with `observer sandbox credentials add " + candidates[0] + "`")
		}
		return unsat("no key of the tool's providers (" + strings.Join(candidates, ", ") + ") is stored for injection; add yours with `observer sandbox credentials add <provider>`")
	}
	sentinels := make([]credSentinel, 0, len(bound))
	for _, id := range bound {
		s, err := sandboxcred.MintSentinel(rand.Reader, id)
		if err != nil {
			return err
		}
		sentinels = append(sentinels, credSentinel{provider: id, sentinel: s})
	}
	now := credNow()
	rec := credNewRecord(plan.RunID, vocab.CustodyHomeRelay, sentinels)
	rec.CreatedAt, rec.Expires = now, now.Add(time.Duration(plan.TimeoutMinutes)*time.Minute+10*time.Minute)
	if err := credWriteRecord(plan.ObserverDir, rec); err != nil {
		return fmt.Errorf("the run's injection record: %w", err)
	}
	credStates.Store(plan.RunID, &credState{observerDir: plan.ObserverDir, sentinels: sentinels})
	return nil
}

// credSentinel is one bound provider's sentinel, held in clear only in the
// host helper that minted it.
type credSentinel struct {
	provider string
	sentinel string
}

// credNewRecord is a run's record for its bound sentinels: version 1 for
// one provider (the shape every run had before), version 2 for several.
func credNewRecord(runID string, custody vocab.KeyCustody, sentinels []credSentinel) credRunRecord {
	rec := credRunRecord{RunID: runID, Custody: custody}
	if len(sentinels) == 1 {
		rec.V, rec.Provider, rec.SentinelHash = credRecordVersion, sentinels[0].provider, sandboxcred.Hash(sentinels[0].sentinel)
		return rec
	}
	rec.V = credRecordVersionSet
	for _, s := range sentinels {
		rec.Bindings = append(rec.Bindings, credBinding{Provider: s.provider, SentinelHash: sandboxcred.Hash(s.sentinel)})
	}
	return rec
}

// credTeardown removes the run's record (and, for provider_injected, the
// broker rule) and verifies it is gone.
func credTeardown(plan hostedPlanFile) {
	credStates.Delete(plan.RunID)
	credInBoxCache.Delete(plan.RunID)
	if vocab.KeyCustody(plan.Custody) == vocab.CustodyProviderInjected {
		credTeardownProviderInjected(plan)
	}
	p := credRunPath(plan.ObserverDir, plan.RunID)
	_ = os.Remove(p)
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		slog.Default().Warn("terminal_sandbox: the run's credential record could not be removed", "run", plan.RunID)
	}
}

// credEnv puts each bound provider's sentinel in that provider's key
// variable.
func credEnv(plan hostedPlanFile, env map[string]string) {
	v, ok := credStates.Load(plan.RunID)
	if !ok {
		return
	}
	for _, s := range v.(*credState).sentinels {
		if p, ok := sandboxcred.ProviderFor(s.provider); ok && s.sentinel != "" {
			env[p.KeyEnv] = s.sentinel
		}
	}
}

// credInBoxKeys fills, for an in_box_api_key run, each API-key variable the
// daemon's environment left empty from the key the person stored, for the
// providers the run's tool can use (gap H3). The stored keys are read once
// per run (credInBoxCache) and only while the component is on; a provider
// whose variable the environment already sets is left as it is.
func credInBoxKeys(plan hostedPlanFile, env map[string]string) {
	if vocab.KeyCustody(plan.Custody) != vocab.CustodyInBoxAPIKey {
		return
	}
	for name, val := range credInBoxValues(plan) {
		if env[name] == "" {
			env[name] = val
		}
	}
}

// credInBoxCache holds each run's stored-key fill (run id -> map), so the
// keystore is opened once per run, not on every agentEnv.
var credInBoxCache sync.Map

// credInBoxValues reads the run's stored keys into the variables they fill
// (name -> key), for the providers the tool can use whose variables the
// daemon's environment lacks.
func credInBoxValues(plan hostedPlanFile) map[string]string {
	if v, ok := credInBoxCache.Load(plan.RunID); ok {
		return v.(map[string]string)
	}
	out := map[string]string{}
	if credActive(context.Background()) && plan.ObserverDir != "" {
		usable := sandboxcred.UsableProviders(hostedToolRoute(plan.Tool))
		var keys keystore.Store
		for _, id := range sandboxcred.Intersect(usable, credStoredProviders(plan.ObserverDir)) {
			p, _ := sandboxcred.ProviderFor(id)
			if credEnvHasAny(p.InBoxEnv) {
				continue
			}
			if keys == nil {
				keys = credKeysFn(plan.ObserverDir)
			}
			if k, err := keys.Get(sandboxcred.KeyName(id)); err == nil && k != "" {
				out[p.KeyEnv] = k
			}
		}
	}
	v, _ := credInBoxCache.LoadOrStore(plan.RunID, out)
	return v.(map[string]string)
}

// credEnvHasAny reports whether the daemon's environment sets any of names.
func credEnvHasAny(names []string) bool {
	for _, n := range names {
		if v, ok := hostedLookupEnv(n); ok && v != "" {
			return true
		}
	}
	return false
}

// credStamp stamps the run's relay token on a relayed model request; a
// token the box sent is always removed. The token is minted at the first
// request of this helper (so a re-adopting helper mints its own) and its
// hash recorded on the run's record, once, under the run's lock.
func credStamp(h http.Header, runID string) {
	h.Del(sandboxcred.TokenHeader)
	st := credStateFor(runID)
	if st == nil {
		return
	}
	if tok := st.relayToken(runID); tok != "" {
		h.Set(sandboxcred.TokenHeader, tok)
	}
}

// credStateFor is the run's state in this helper: the one setup stored, or,
// for a helper that did not run the setup (a re-adoption), one made once
// from the run's record. A run with no record is remembered as absent, so a
// helper whose run has no injection (the component off) reads the config
// once per run, not on every request.
func credStateFor(runID string) *credState {
	if v, ok := credStates.Load(runID); ok {
		if st := v.(*credState); !st.absent {
			return st
		}
		return nil
	}
	obs := credObserverDir()
	st := &credState{observerDir: obs}
	if _, err := credReadRecord(obs, runID); err != nil {
		st.absent = true
	}
	v, _ := credStates.LoadOrStore(runID, st)
	if got := v.(*credState); !got.absent {
		return got
	}
	return nil
}

// relayToken returns the run's relay token, minting it and recording its
// hash on the run's record the first time ("" when either step fails; the
// next request tries again).
func (st *credState) relayToken(runID string) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.token != "" {
		return st.token
	}
	rec, err := credReadRecord(st.observerDir, runID)
	if err != nil {
		return ""
	}
	tok, err := sandboxcred.MintToken(rand.Reader)
	if err != nil {
		return ""
	}
	rec.TokenHash = sandboxcred.Hash(tok)
	if credWriteRecord(st.observerDir, rec) != nil {
		return ""
	}
	st.token = tok
	return tok
}

// credWriteRecord writes a run's record whole (0600, renamed into place).
func credWriteRecord(observerDir string, rec credRunRecord) error {
	dir := credRunsDir(observerDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+rec.RunID+".*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp.Name(), 0o600)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
		return werr
	}
	return os.Rename(tmp.Name(), credRunPath(observerDir, rec.RunID))
}

// credState is the host helper's own per-run state: the sentinels it put in
// the box (one per bound provider) and the relay token it stamps (never
// written anywhere in clear). Each relayed connection has its own server,
// so concurrent first requests reach credStamp together: mu makes the
// token's mint and its hash on the run's record one step, so the two can
// never differ (audit F1).
type credState struct {
	observerDir string
	sentinels   []credSentinel
	// absent: this helper found no record for the run, so nothing is
	// stamped and no config is read again for it (audit F6).
	absent bool

	mu    sync.Mutex
	token string
}

// credStates holds the helper's runs (run id -> *credState).
var credStates sync.Map

// credToolProviders are the providers credential injection may bind for a
// tool, from its capability row (hostedToolRoute), never its name.
func credToolProviders(tool string) []string {
	return sandboxcred.InjectableProviders(hostedToolRoute(tool))
}

// credToolProvider is the tool's one injectable provider ("" when it has
// none or several): the provider_injected broker rule names one.
func credToolProvider(tool string) string {
	if ps := credToolProviders(tool); len(ps) == 1 {
		return ps[0]
	}
	return ""
}

// credKeyStored reports whether the user's key for provider is stored,
// from the ids-only list the add and remove verbs keep (credMarkProvider),
// never by reading the key (F-010 A6): no key bytes enter a host helper's
// memory and no keychain prompt is raised for a presence check. A key
// removed behind the verbs' back reads as stored; the daemon's injector
// then finds no key (match row no_key) and the sentinel is refused, fail
// closed.
func credKeyStored(observerDir, provider string) bool {
	stored, err := credKeyPresence(observerDir, provider)
	return stored && err == nil
}

// credKeyPresence is credKeyStored that also says when the list exists but
// cannot be read (refused: not an owner-only file of this user, or not
// JSON), so a caller can refuse loudly rather than read it as "no key"
// (audit FU3-A4). An absent list is no error: no key was ever added.
func credKeyPresence(observerDir, provider string) (bool, error) {
	if observerDir == "" || provider == "" {
		return false, nil
	}
	ids, err := credReadProviders(observerDir)
	if err != nil {
		return false, err
	}
	return slices.Contains(ids, provider), nil
}
