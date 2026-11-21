//go:build !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
// gets a per-run sentinel in the key variable of each provider it binds (gap
// H2: every provider its tool can use whose key is stored); the home side of the
// run's relay stamps a per-run relay token on each relayed model request;
// and the daemon's proxy swaps the sentinel for the key only when every row
// of internal/sandboxcred's match table holds. The decisions are pure
// (internal/sandboxcred); this file holds the keystore, the run records,
// the hooks and the verbs.
//
// Local runs (bwrap and oci-runc on the proxy_only tier, or on the
// internet tier with the provider-host block; lane N3) get the same
// injection (process_lite and any host-tier run get none): their host helper stamps the run on its model-proxy forward
// (sandbox_helpers_credlane_linux.go, sandbox_cred_local_linux.go), and the
// run's record carries lane "local", judged by the match table's local
// rows.

func init() {
	hostedCredConsentLine = credConsentLine
	hostedCredInBoxStored = credInBoxStored
	hostedCredFacts = func(full config.Config) (bool, bool, []string) {
		return credSelected(full), credProxyBuilt, credStoredProviders(sandboxObserverDirFor(full))
	}
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

// credHelperLive reports whether a run's host helper still holds the run's
// liveness lock (a test seam).
var credHelperLive = sandboxrelayd.RunLive

// credRunRecord is one run's injection record: hashes only, never the
// sentinel, the token or the key. A run that binds one provider writes the
// version 1 shape every run had before (Provider, SentinelHash), byte for
// byte; a run that binds several (gap H2) writes version 2, whose Bindings
// list each provider with its own sentinel's hash and leave Provider and
// SentinelHash empty. A reader before version 2 refuses a version 2 record
// (no injection, fail closed).
type credRunRecord struct {
	V            int              `json:"v"`
	RunID        string           `json:"run_id"`
	Provider     string           `json:"provider"`
	Custody      vocab.KeyCustody `json:"custody"`
	SentinelHash string           `json:"sentinel_hash"`
	Bindings     []credBinding    `json:"bindings,omitempty"`
	TokenHash    string           `json:"token_hash,omitempty"`
	// Lane is how the run's requests reach the proxy ("" hosted, "local"
	// for a local run's host helper; lane N3).
	Lane sandboxcred.Lane `json:"lane,omitempty"`
	// DroppedEnv names the credential variables a local run's box env did
	// not get (names only, never a value; F-005).
	DroppedEnv []string  `json:"dropped_env,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	Expires    time.Time `json:"expires"`
}

// credBinding is one bound provider of a version 2 record.
type credBinding struct {
	Provider     string `json:"provider"`
	SentinelHash string `json:"sentinel_hash"`
}

// The record versions: 1 binds one provider, 2 several.
const (
	credRecordVersion    = 1
	credRecordVersionSet = 2
)

// bindings are the record's bound providers with their sentinel hashes.
func (rec credRunRecord) bindings() []sandboxcred.Binding {
	if rec.V == credRecordVersion {
		return []sandboxcred.Binding{{Provider: rec.Provider, SentinelHash: rec.SentinelHash}}
	}
	out := make([]sandboxcred.Binding, 0, len(rec.Bindings))
	for _, b := range rec.Bindings {
		out = append(out, sandboxcred.Binding{Provider: b.Provider, SentinelHash: b.SentinelHash})
	}
	return out
}

// providers are the record's bound provider ids.
func (rec credRunRecord) providers() []string {
	var out []string
	for _, b := range rec.bindings() {
		out = append(out, b.Provider)
	}
	return out
}

// credRecordShapeOK checks a record's version against its shape: version 1
// carries no Bindings, version 2 carries two or more, each a provider the
// table knows, each once, and leaves the version 1 fields empty.
func credRecordShapeOK(rec credRunRecord) bool {
	switch rec.V {
	case credRecordVersion:
		return len(rec.Bindings) == 0
	case credRecordVersionSet:
		if rec.Provider != "" || rec.SentinelHash != "" || len(rec.Bindings) < 2 {
			return false
		}
		seen := map[string]bool{}
		for _, b := range rec.Bindings {
			if _, ok := sandboxcred.ProviderFor(b.Provider); !ok || seen[b.Provider] || b.SentinelHash == "" {
				return false
			}
			seen[b.Provider] = true
		}
		return true
	}
	return false
}

// credRunsDir is where the run records live.
func credRunsDir(observerDir string) string {
	return filepath.Join(observerDir, "sandbox-cred", "runs")
}

func credRunPath(observerDir, runID string) string {
	return filepath.Join(credRunsDir(observerDir), runID+".json")
}

// credFreshDir holds each injected local run's kept fresh session ids
// (ids only), beside its injection record. The relay daemon is its one
// writer (credFreshStore.AddFresh); the run's host helper removes the
// run's file with the record at the run's end (credLocalEnd), and a file
// left by a helper killed outright stays with its record for the run's
// re-adoption, as the record does.
func credFreshDir(observerDir string) string {
	return filepath.Join(observerDir, "sandbox-cred", "fresh")
}

func credFreshPath(observerDir, runID string) string {
	return filepath.Join(credFreshDir(observerDir), runID+".json")
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
	if err := json.Unmarshal(b, &rec); err != nil || !credRecordShapeOK(rec) || rec.RunID != runID {
		return credRunRecord{}, errors.New("record refused")
	}
	return rec, nil
}

// credReadOwned reads a small owner-only regular file of this user, never
// through a link.
func credReadOwned(p string) ([]byte, error) {
	fi, err := os.Lstat(p) //nolint:gosec // G703: false positive; the run's own credential record path, only lstat'd before the owner and type checks
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 64<<10 || fi.Mode().Perm()&0o077 != 0 || !ownedByMe(fi) {
		return nil, errors.New("not an owner-only file of this user")
	}
	return os.ReadFile(p) //nolint:gosec // G304: a fixed name under the daemon's own observer dir, checked above
}

// credReady reports whether injection can serve home_relay node-wide: the
// component is on, the proxy that swaps the sentinel is in this build, and
// at least one provider key is stored. The hosted driver asks the same
// question through sandboxcred.HomeKey over hostedCredFacts, and asks it
// per tool at Create; the helper's setup (credSetup) still refuses
// custody_unsatisfiable when none of its tool's providers has a key.
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
// component is on: injection's own disclosure for home_relay (audit F8),
// naming each stored key a run can bind (gap H2). provider_injected is not
// offered, so its text is never shown yet.
func credConsentLine(ctx context.Context, custody, vendor, capture string) (string, bool) {
	if custody != string(vocab.CustodyHomeRelay) || !credActive(ctx) {
		return "", false
	}
	return sandboxcred.Disclosure(custody, vendor, capture, credStoredProviders(credObserverDir())...), true
}

// credInBoxStored are the providers whose stored key an in-box custody may
// put in a box where the daemon's environment has none (gap H3): the stored
// ones while the component is on, none otherwise.
func credInBoxStored(ctx context.Context) []string {
	if !credActive(ctx) {
		return nil
	}
	return credStoredProviders(credObserverDir())
}

// credProvidersFile lists the providers that have a key (ids only, never a
// key), so a driver build can answer credReady without opening the
// keychain.
func credProvidersFile(observerDir string) string {
	return filepath.Join(observerDir, "sandbox-cred", "providers.json")
}

// credStoredProviders reads the list (empty when absent or unreadable).
func credStoredProviders(observerDir string) []string {
	ids, _ := credReadProviders(observerDir)
	return ids
}

// credReadProviders reads the list, telling an absent list (no key was
// ever added: nil, nil) from one that exists but is refused or unreadable
// (an error naming why; audit FU3-A4).
func credReadProviders(observerDir string) ([]string, error) {
	b, err := credReadOwned(credProvidersFile(observerDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", credProvidersFile(observerDir), err)
	}
	var ids []string
	if err := json.Unmarshal(b, &ids); err != nil {
		return nil, fmt.Errorf("%s: %w", credProvidersFile(observerDir), err)
	}
	return ids, nil
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
	if err == nil {
		_, rerr := sandboxrelayd.ReadRun(i.observerDir, runID)
		// A hosted record must be home_relay; a local record's custody
		// and its helper are judged by the match table's local rows.
		facts.Live = rerr == nil && credNow().Before(rec.Expires) && (rec.Lane == sandboxcred.LaneLocal || rec.Custody == vocab.CustodyHomeRelay)
		facts.Bindings, facts.TokenHash = rec.bindings(), rec.TokenHash
		facts.Lane, facts.Custody = rec.Lane, string(rec.Custody)
		if rec.Lane == sandboxcred.LaneLocal {
			facts.HelperLive = credHelperLive(i.observerDir, runID)
		}
		// The test seam's upstream stands for a bound provider's host.
		for _, b := range facts.Bindings {
			if p, ok := sandboxcred.ProviderFor(b.Provider); ok && strings.EqualFold(host, credProviderHost(p)) {
				host = p.Host
				break
			}
		}
	}
	req := sandboxcred.Request{RunID: runID, Token: token, Host: host, XAPIKey: xAPIKey, Authorization: authorization, GoogKey: googKey}
	// Only the key of the one provider the request is judged against is
	// read: its destination's, within the run's bound set.
	key, provider := "", ""
	if facts.Found && facts.Live {
		provider = sandboxcred.SelectBinding(req, facts).Provider
		if _, ok := sandboxcred.ProviderFor(provider); ok {
			key = i.key(provider)
		}
		facts.KeyStored = key != ""
	}
	d := sandboxcred.Decide(req, facts)
	if !d.Inject || d.Provider != provider {
		return "", "", false
	}
	return d.Auth.Header(), d.Auth.Value(key), true
}
