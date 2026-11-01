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
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
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
	hostedCredStampHook = credStamp
}

// credOtherHomeRelay reports whether a key the proxy adds itself is
// configured (a routing key pool or the org gateway route), which serves
// home_relay without injection.
var credOtherHomeRelay = func() bool {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()})
	return err == nil && (len(cfg.Routing.KeyPool) > 0 || cfg.Proxy.OrgRoute.Mode != "")
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

func credSetupHomeRelay(plan hostedPlanFile) error {
	provider := credToolProvider(plan.Tool)
	unsat := func(why string) error {
		if credOtherHomeRelay() {
			return nil // the pool or the org gateway serves the custody
		}
		return fmt.Errorf("%s: key custody home_relay: %s", verdictHostedCustody, why)
	}
	if provider == "" {
		return unsat("the tool's model provider is not one credential injection serves")
	}
	if !credKeyStored(plan.ObserverDir, provider) {
		return unsat("no " + provider + " key is stored for injection; add yours with `observer sandbox credentials add " + provider + "` or in Terminals > Settings")
	}
	sentinel, err := sandboxcred.MintSentinel(rand.Reader, provider)
	if err != nil {
		return err
	}
	now := credNow()
	rec := credRunRecord{
		V: credRecordVersion, RunID: plan.RunID, Provider: provider, Custody: vocab.CustodyHomeRelay,
		SentinelHash: sandboxcred.Hash(sentinel), CreatedAt: now,
		Expires: now.Add(time.Duration(plan.TimeoutMinutes)*time.Minute + 10*time.Minute),
	}
	if err := credWriteRecord(plan.ObserverDir, rec); err != nil {
		return fmt.Errorf("the run's injection record: %w", err)
	}
	credStates.Store(plan.RunID, &credState{observerDir: plan.ObserverDir, provider: provider, sentinel: sentinel})
	return nil
}

// credTeardown removes the run's record (and, for provider_injected, the
// broker rule) and verifies it is gone.
func credTeardown(plan hostedPlanFile) {
	credStates.Delete(plan.RunID)
	if vocab.KeyCustody(plan.Custody) == vocab.CustodyProviderInjected {
		credTeardownProviderInjected(plan)
	}
	p := credRunPath(plan.ObserverDir, plan.RunID)
	_ = os.Remove(p)
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		slog.Default().Warn("terminal_sandbox: the run's credential record could not be removed", "run", plan.RunID)
	}
}

// credEnv puts the run's sentinel in its tool's key variable.
func credEnv(plan hostedPlanFile, env map[string]string) {
	v, ok := credStates.Load(plan.RunID)
	if !ok {
		return
	}
	st := v.(*credState)
	if p, ok := sandboxcred.ProviderFor(st.provider); ok && st.sentinel != "" {
		env[p.KeyEnv] = st.sentinel
	}
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

// credState is the host helper's own per-run state: the sentinel it put in
// the box and the relay token it stamps (never written anywhere in clear).
// Each relayed connection has its own server, so concurrent first requests
// reach credStamp together: mu makes the token's mint and its hash on the
// run's record one step, so the two can never differ (audit F1).
type credState struct {
	observerDir string
	provider    string
	sentinel    string
	// absent: this helper found no record for the run, so nothing is
	// stamped and no config is read again for it (audit F6).
	absent bool

	mu    sync.Mutex
	token string
}

// credStates holds the helper's runs (run id -> *credState).
var credStates sync.Map

// credToolProvider is the one provider a tool's model catalogue names.
func credToolProvider(tool string) string {
	spec, _ := integration.For(tool)
	return sandboxcred.ProviderForTool(spec.Model.Catalog.Kind == integration.ModelCatalogVendor, spec.Model.Catalog.Providers)
}

// credKeyStored reports whether the user's key for provider is stored.
func credKeyStored(observerDir, provider string) bool {
	if observerDir == "" || provider == "" {
		return false
	}
	v, err := credKeysFn(observerDir).Get(sandboxcred.KeyName(provider))
	return err == nil && v != ""
}
