//go:build !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_cred.go is credential injection for sandboxed runs (sandbox plan
// v2 sections 7.2 and 7.3, gap G24, lane GATES-SBX), behind the opt-in
// component terminals.sandbox.credentials. The user adds their own
// provider key (the CLI or the dashboard, never an agent: guard rule R-165
// covers the verb and the route), stored in the OS keychain under service
// sbo-sandbox-cred-v1. For a hosted run with custody home_relay the box
// gets a per-run sentinel in its tool's key variable; the home side of the
// run's relay stamps a per-run relay token on each relayed model request;
// and the daemon's proxy swaps the sentinel for the key only when every row
// of internal/sandboxcred's match table holds. The decisions are pure
// (internal/sandboxcred); this file holds the keystore, the run records,
// the hooks and the verbs.
//
// Local runs (bwrap, oci) get no injection in this release: their model
// requests reach the proxy through a plain socket forward that carries no
// host-side run identity (recorded in docs and the ledger, SBX-NET-2).

func init() {
	hostedCredReady = credReady
	hostedCredConsentLine = credConsentLine
	hostedCredNotReady = credNotReady
	sandboxSubcommands = append(sandboxSubcommands, newSandboxCredentialsCmd)
	gatesSandboxRouteFuncs = append(gatesSandboxRouteFuncs, credDashboardRoutes)
}

// credActive reports whether the component is selected (a test seam).
var credActive = func(ctx context.Context) bool {
	return sandboxFeatureActive(ctx, daemonConfigPath(), credentialsComponent)
}

// credObserverDir is the observer dir the records live under (a test
// seam): the daemon's own, from its config.
var credObserverDir = func() string {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()})
	if err != nil {
		return ""
	}
	return sandboxObserverDirFor(cfg)
}

// credKeysFn opens the keystore of the user's provider keys (a test seam).
var credKeysFn = func(observerDir string) keystore.Store {
	return keystore.Open(sandboxcred.KeystoreService, filepath.Join(observerDir, "sandbox-cred", "keys"), slog.Default())
}

// credProviderHost is the model host a provider's real key may be sent to
// (a test seam: a test points it at its fake upstream).
var credProviderHost = func(p sandboxcred.Provider) string { return p.Host }

// credNow is the clock (a test seam).
var credNow = func() time.Time { return time.Now().UTC() }

// credRunRecord is one run's injection record: hashes only, never the
// sentinel, the token or the key.
type credRunRecord struct {
	V            int              `json:"v"`
	RunID        string           `json:"run_id"`
	Provider     string           `json:"provider"`
	Custody      vocab.KeyCustody `json:"custody"`
	SentinelHash string           `json:"sentinel_hash"`
	TokenHash    string           `json:"token_hash,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
	Expires      time.Time        `json:"expires"`
}

const credRecordVersion = 1

// credRunsDir is where the run records live.
func credRunsDir(observerDir string) string {
	return filepath.Join(observerDir, "sandbox-cred", "runs")
}

func credRunPath(observerDir, runID string) string {
	return filepath.Join(credRunsDir(observerDir), runID+".json")
}

// credReadRecord reads a run's record, owner-checked and without
// following a link.
func credReadRecord(observerDir, runID string) (credRunRecord, error) {
	if !vocab.ValidRelayRunID(runID) || observerDir == "" {
		return credRunRecord{}, errors.New("no record")
	}
	b, err := credReadOwned(credRunPath(observerDir, runID))
	if err != nil {
		return credRunRecord{}, err
	}
	var rec credRunRecord
	if err := json.Unmarshal(b, &rec); err != nil || rec.V != credRecordVersion || rec.RunID != runID {
		return credRunRecord{}, errors.New("record refused")
	}
	return rec, nil
}

// credReadOwned reads a small owner-only regular file of this user, never
// through a link.
func credReadOwned(p string) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 64<<10 || fi.Mode().Perm()&0o077 != 0 || !ownedByMe(fi) {
		return nil, errors.New("not an owner-only file of this user")
	}
	return os.ReadFile(p) //nolint:gosec // G304: a fixed name under the daemon's own observer dir, checked above
}

// credReady is newHostedDriver's homeRelayOK addition: the component is on,
// the proxy that swaps the sentinel is in this build, and at least one
// provider key is stored. The run's own provider is checked by the helper's
// setup (credSetup), which refuses custody_unsatisfiable when its tool's
// provider has no key.
func credReady(full config.Config) bool {
	if !credSelected(full) || !credProxyBuilt {
		return false
	}
	return len(credStoredProviders(sandboxObserverDirFor(full))) > 0
}

// credSelected reports whether full selects the component (a test seam).
var credSelected = func(full config.Config) bool {
	return sandboxFeatureSelected(componentSnapshotForConfig(full), credentialsComponent)
}

// credProxyBuilt: the capture proxy, which swaps the sentinel for the key,
// is in this build (sandbox_cred_proxy.go sets it). Without it nothing could
// swap the key, so credReady is false and a home_relay launch is refused up
// front naming why, instead of a later bare 401 from the provider (audit
// F10).
var credProxyBuilt bool

// credNotReady names why injection cannot serve home_relay although the
// component is selected.
func credNotReady(full config.Config) string {
	if !credSelected(full) || credProxyBuilt {
		return ""
	}
	return "credential injection (" + credentialsComponent + ") is selected, but this build has no capture proxy (built with sbo_omit_capture_proxy), which is what swaps the box's sentinel for your key"
}

// credConsentLine is the consent screen's credential line while the
// component is on: injection's own disclosure for home_relay (audit F8).
// provider_injected is not offered, so its text is never shown yet.
func credConsentLine(ctx context.Context, custody, vendor, capture string) (string, bool) {
	if custody != string(vocab.CustodyHomeRelay) || !credActive(ctx) {
		return "", false
	}
	return sandboxcred.Disclosure(custody, vendor, capture), true
}

// credProvidersFile lists the providers that have a key (ids only, never a
// key), so a driver build can answer credReady without opening the
// keychain.
func credProvidersFile(observerDir string) string {
	return filepath.Join(observerDir, "sandbox-cred", "providers.json")
}

// credStoredProviders reads the list (empty when absent or unreadable).
func credStoredProviders(observerDir string) []string {
	b, err := credReadOwned(credProvidersFile(observerDir))
	if err != nil {
		return nil
	}
	var ids []string
	if json.Unmarshal(b, &ids) != nil {
		return nil
	}
	return ids
}

// credMarkProvider records that provider has a key (or no longer has one).
func credMarkProvider(observerDir, provider string, stored bool) error {
	var out []string
	for _, id := range credStoredProviders(observerDir) {
		if id != provider {
			out = append(out, id)
		}
	}
	if stored {
		out = append(out, provider)
	}
	dir := filepath.Dir(credProvidersFile(observerDir))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(out)
	tmp, err := os.CreateTemp(dir, ".providers.*.tmp")
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
	return os.Rename(tmp.Name(), credProvidersFile(observerDir))
}

// credInjector is the daemon's proxy.CredentialInjector.
type credInjector struct {
	observerDir string
	mu          sync.Mutex
	keys        map[string]credCachedKey
}

type credCachedKey struct {
	key string
	at  time.Time
}

// credKeyTTL bounds how long a key read from the keystore is kept in the
// daemon's memory.
const credKeyTTL = time.Minute

func (i *credInjector) key(provider string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	if c, ok := i.keys[provider]; ok && credNow().Sub(c.at) < credKeyTTL {
		return c.key
	}
	v, err := credKeysFn(i.observerDir).Get(sandboxcred.KeyName(provider))
	if err != nil {
		v = ""
	}
	if i.keys == nil {
		i.keys = map[string]credCachedKey{}
	}
	i.keys[provider] = credCachedKey{key: v, at: credNow()}
	return v
}

// decide judges one relayed request through sandboxcred.Decide and returns
// the header to set and its value (ok false: leave the request untouched).
func (i *credInjector) decide(runID, token, host, xAPIKey, authorization, googKey string) (string, string, bool) {
	rec, err := credReadRecord(i.observerDir, runID)
	facts := sandboxcred.RunFacts{Found: err == nil}
	var p sandboxcred.Provider
	if err == nil {
		_, rerr := sandboxrelayd.ReadRun(i.observerDir, runID)
		facts.Live = rerr == nil && credNow().Before(rec.Expires) && rec.Custody == vocab.CustodyHomeRelay
		facts.Provider, facts.SentinelHash, facts.TokenHash = rec.Provider, rec.SentinelHash, rec.TokenHash
		p, _ = sandboxcred.ProviderFor(rec.Provider)
	}
	if p.ID != "" && strings.EqualFold(host, credProviderHost(p)) {
		host = p.Host
	}
	req := sandboxcred.Request{RunID: runID, Token: token, Host: host, XAPIKey: xAPIKey, Authorization: authorization, GoogKey: googKey}
	key := ""
	if facts.Found && facts.Live {
		key = i.key(rec.Provider)
		facts.KeyStored = key != ""
	}
	d := sandboxcred.Decide(req, facts)
	if !d.Inject {
		return "", "", false
	}
	return d.Auth.Header(), d.Auth.Value(key), true
}
