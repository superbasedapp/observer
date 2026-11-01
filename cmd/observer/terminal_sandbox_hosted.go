//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_hosted.go is the shared remote core of the three hosted
// sandbox drivers (sandbox plan v2 section 13 P7, lane SBX-P7): E2B, Modal
// and Vercel Sandbox differ only in their wire client
// (internal/sandboxremote/{e2b,modal,vercel}), which each vendor's own
// build-tagged file registers (registerHostedVendor); this file holds what
// they share and never names a vendor.
//
// What it guarantees (each pinned by a test in terminal_sandbox_hosted_test.go):
//   - nothing calls a vendor, reads a credential value, uploads or starts a
//     timer before a user action: the probe reads only local facts (the
//     config, the env var's presence, a connected marker, the consent and
//     ledger files) and never builds a client (invariant I6);
//   - a credential is read at use time, from the keystore first (one
//     service per vendor) and the vendor's environment variables second,
//     and is sent only to the endpoint it is bound to (SBX-GOV-4);
//   - consent, the spend ledger and the teardown records are node-local,
//     owner-only files under ~/.observer/sandbox-hosted.

func init() {
	sandboxHelperFuncs[hostedHostVerb] = runHostedHost
	// Every rebuild starts with no hosted row listed; a hosted driver's build
	// sets it again (newHostedDriver), so a driver that became inactive
	// leaves AllowRemote false (the SBX-P7 merge's audit finding 8).
	sandboxDriversRebuildHooks = append(sandboxDriversRebuildHooks, func() { hostedListed.Store(false) })
}

// hostedListed records whether a hosted row is in the local backends, as
// the hosted drivers last saw the config (set when a driver is built).
var hostedListed atomic.Bool

// sandboxRemoteAllowed is the selection table's Floors.AllowRemote (S7):
// true only while a hosted row is in the local backends and no org floor
// sets allow_remote = false.
func sandboxRemoteAllowed(orgForbids bool) bool {
	return !orgForbids && hostedListed.Load()
}

// recordHostedListed updates hostedListed from the local config.
func recordHostedListed(cfg config.TerminalSandboxConfig) {
	listed := false
	for _, id := range sandboxEnabledBackends(cfg) {
		if row, ok := sandboxbackend.Get(id); ok && row.Iso.Location == vocab.LocationRemote {
			listed = true
		}
	}
	hostedListed.Store(listed)
}

// sandboxRequestCustody is the key custody a selection request carries for
// row: a hosted row's is [terminal.sandbox.hosted].key_custody, a local
// row's is the bound tool state (host_bound).
func sandboxRequestCustody(cfg config.TerminalSandboxConfig, row sandboxbackend.Capability) vocab.KeyCustody {
	if row.Iso.Location == vocab.LocationRemote {
		return vocab.KeyCustody(cfg.Hosted.KeyCustody)
	}
	return vocab.CustodyHostBound
}

// hostedCredentialInReach reports whether the agent in a hosted box holds a
// reusable model credential (capture rule C4): every custody but home_relay.
func hostedCredentialInReach(custody vocab.KeyCustody) bool {
	return custody != vocab.CustodyHomeRelay
}

// ---- node-local state under ~/.observer/sandbox-hosted ----------------------

// hostedStateDir is the hosted drivers' node-local directory.
func hostedStateDir(observerDir string) string { return filepath.Join(observerDir, "sandbox-hosted") }

// hostedProviderDir is one provider's directory.
func hostedProviderDir(observerDir, provider string) string {
	return filepath.Join(hostedStateDir(observerDir), provider)
}

// hostedFileMu serialises this process's reads and writes of the state
// files (the daemon's dashboard actions and its runs); hostedWithState adds
// the cross-process lock.
var hostedFileMu sync.Mutex

// hostedLockName is the state directory's cross-process lock file.
const hostedLockName = ".lock"

// hostedWithState runs fn holding this process's mutex and an exclusive lock
// on the state directory's lock file (lockFileExclusive: flock on unix,
// LockFileEx on Windows). Every run's sandbox-hosted-host helper is its own
// process, so the mutex alone let two launches lose a reservation and a
// settle overwrite another run's (the SBX-P7 merge's audit finding 3). With
// create false and no state directory yet there is nothing to read, so fn
// runs under the mutex only and nothing is created.
func hostedWithState(observerDir string, create bool, fn func() error) error {
	hostedFileMu.Lock()
	defer hostedFileMu.Unlock()
	dir := hostedStateDir(observerDir)
	if !create {
		if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
			return fn()
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, hostedLockName), os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the lock file under ~/.observer/sandbox-hosted the daemon builds
	if err != nil {
		return fmt.Errorf("terminal_sandbox: open the hosted state lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := lockFileExclusive(f); err != nil {
		return fmt.Errorf("terminal_sandbox: lock the hosted state: %w", err)
	}
	defer func() { _ = unlockFile(f) }()
	return fn()
}

// hostedMaxStateFile caps one state file read.
const hostedMaxStateFile = 4 << 20

// hostedReadOwned reads an owner-only state file: no symlink, a regular
// file, not readable or writable by group or others (on unix), capped.
func hostedReadOwned(p string) ([]byte, error) {
	fi, err := os.Lstat(p) //nolint:gosec // G703: a path under ~/.observer/sandbox-hosted the daemon builds, never request input
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %v); remove it", p, fi.Mode().Perm())
	}
	if fi.Size() > hostedMaxStateFile {
		return nil, fmt.Errorf("%s is over %d bytes", p, hostedMaxStateFile)
	}
	return os.ReadFile(p) //nolint:gosec // G304: a state file under the observer dir, lstat-checked above
}

// hostedWriteOwned writes v as JSON through a fresh 0600 temporary file and a
// rename, under a 0700 directory.
func hostedWriteOwned(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_ = tmp.Chmod(0o600)
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	return os.Rename(name, p)
}

// hostedConsentPath is a provider's consent record.
func hostedConsentPath(observerDir, provider string) string {
	return filepath.Join(hostedProviderDir(observerDir, provider), "consent.json")
}

// hostedLoadConsent reads a provider's consent record (nil when none or
// unreadable: an unreadable record is no consent).
func hostedLoadConsent(observerDir, provider string) *sandboxremote.ConsentRecord {
	var out *sandboxremote.ConsentRecord
	_ = hostedWithState(observerDir, false, func() error {
		b, err := hostedReadOwned(hostedConsentPath(observerDir, provider))
		if err != nil {
			return nil
		}
		if rec, err := sandboxremote.DecodeConsent(b); err == nil {
			out = &rec
		}
		return nil
	})
	return out
}

// hostedSaveConsent records the user's agreement.
func hostedSaveConsent(observerDir string, rec sandboxremote.ConsentRecord) error {
	return hostedWithState(observerDir, true, func() error {
		return hostedWriteOwned(hostedConsentPath(observerDir, rec.Facts.Provider), rec)
	})
}

// hostedRevokeConsent removes a provider's consent record.
func hostedRevokeConsent(observerDir, provider string) error {
	return hostedWithState(observerDir, false, func() error {
		err := os.Remove(hostedConsentPath(observerDir, provider))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	})
}

// hostedLedgerPath is the spend ledger (all providers).
func hostedLedgerPath(observerDir string) string {
	return filepath.Join(hostedStateDir(observerDir), "ledger.json")
}

// hostedLedgerKeepDays is how many days of the ledger are kept.
const hostedLedgerKeepDays = 31

// hostedUpdateLedger reads, changes and writes the ledger under the
// cross-process lock (hostedWithState).
func hostedUpdateLedger(observerDir string, now time.Time, change func(l *sandboxremote.Ledger) error) error {
	return hostedWithState(observerDir, true, func() error {
		var l sandboxremote.Ledger
		if b, err := hostedReadOwned(hostedLedgerPath(observerDir)); err == nil {
			if err := json.Unmarshal(b, &l); err != nil {
				return fmt.Errorf("terminal_sandbox: the hosted spend ledger does not parse (%w); it is never ignored, fix or remove %s", err, hostedLedgerPath(observerDir))
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		l.Prune(now, hostedLedgerKeepDays)
		if err := change(&l); err != nil {
			return err
		}
		return hostedWriteOwned(hostedLedgerPath(observerDir), l)
	})
}

// hostedLedgerUsed is the box-minutes counted today for provider (a ledger
// that does not parse counts as the whole cap: never more spend on doubt).
func hostedLedgerUsed(observerDir, provider string, now time.Time, daily int) int {
	used := daily
	_ = hostedUpdateLedger(observerDir, now, func(l *sandboxremote.Ledger) error {
		used = l.Used(provider, sandboxremote.DayOf(now))
		return errors.New("read only")
	})
	return used
}

// hostedRunsDir holds the teardown records.
func hostedRunsDir(observerDir string) string {
	return filepath.Join(hostedStateDir(observerDir), "runs")
}

// hostedRecordPath is one run's teardown record.
func hostedRecordPath(observerDir, runID string) string {
	return filepath.Join(hostedRunsDir(observerDir), runID+".json")
}

// hostedSaveRecord writes a teardown record (before every vendor call that
// changes the box, so a killed process leaves the truth behind).
func hostedSaveRecord(observerDir string, rec sandboxremote.Record) error {
	return hostedWithState(observerDir, true, func() error {
		return hostedWriteOwned(hostedRecordPath(observerDir, rec.RunID), rec)
	})
}

// hostedRemoveRecord removes a record the vendor confirmed gone, with the
// per-box secret files it names.
func hostedRemoveRecord(observerDir string, rec sandboxremote.Record) error {
	if !rec.Removable() {
		return fmt.Errorf("terminal_sandbox: the record of run %s is %s; it is removed only after the provider confirms the box is gone", rec.RunID, rec.State)
	}
	return hostedWithState(observerDir, false, func() error {
		// The reason a staged diff did not come home outlives the record.
		if rec.DiffError != "" {
			if err := hostedKeepDiffErrorLocked(observerDir, rec, time.Now()); err != nil {
				return err
			}
		}
		for _, f := range rec.SecretFiles {
			if filepath.Dir(f) == hostedSecretsDir(observerDir) {
				_ = os.Remove(f)
			}
		}
		err := os.Remove(hostedRecordPath(observerDir, rec.RunID))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	})
}

// hostedDiffErrorsPath holds the kept diff-error lines
// (sandboxremote.DiffErrorLine).
func hostedDiffErrorsPath(observerDir string) string {
	return filepath.Join(hostedStateDir(observerDir), "diff-errors.json")
}

// hostedKeepDiffErrorLocked appends rec's diff error to the kept lines; the
// caller holds the state lock.
func hostedKeepDiffErrorLocked(observerDir string, rec sandboxremote.Record, now time.Time) error {
	var lines []sandboxremote.DiffErrorLine
	if b, err := hostedReadOwned(hostedDiffErrorsPath(observerDir)); err == nil {
		if json.Unmarshal(b, &lines) != nil {
			lines = nil // an unreadable file is replaced, never trusted
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return hostedWriteOwned(hostedDiffErrorsPath(observerDir), sandboxremote.KeepDiffError(lines, rec, now))
}

// hostedLoadDiffErrors reads the kept diff-error lines, oldest first.
func hostedLoadDiffErrors(observerDir string) []sandboxremote.DiffErrorLine {
	var lines []sandboxremote.DiffErrorLine
	_ = hostedWithState(observerDir, false, func() error {
		b, err := hostedReadOwned(hostedDiffErrorsPath(observerDir))
		if err == nil {
			_ = json.Unmarshal(b, &lines)
		}
		return nil
	})
	return lines
}

// hostedLoadRecords reads every teardown record (an unreadable one is
// skipped; doctor names it).
func hostedLoadRecords(observerDir string) []sandboxremote.Record {
	var out []sandboxremote.Record
	_ = hostedWithState(observerDir, false, func() error {
		entries, err := os.ReadDir(hostedRunsDir(observerDir))
		if err != nil {
			return nil
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			b, err := hostedReadOwned(filepath.Join(hostedRunsDir(observerDir), e.Name()))
			if err != nil {
				continue
			}
			var rec sandboxremote.Record
			if json.Unmarshal(b, &rec) == nil && rec.RunID+".json" == e.Name() {
				out = append(out, rec)
			}
		}
		return nil
	})
	return out
}

// hostedSecretsDir holds per-box secrets (an E2B envd access token).
func hostedSecretsDir(observerDir string) string {
	return filepath.Join(hostedStateDir(observerDir), "secrets")
}

// hostedSaveBoxSecret writes a per-box secret owner-only and returns its
// path (deleted with the run's record).
func hostedSaveBoxSecret(observerDir, runID, value string) (string, error) {
	dir := hostedSecretsDir(observerDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, runID+".token")
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// hostedKeeperKeyPath is where a guest PTY keeper's key is kept at home
// (owner-only, beside the per-box secrets, deleted with the run's record;
// never in the box record).
func hostedKeeperKeyPath(observerDir, runID string) string {
	return filepath.Join(hostedSecretsDir(observerDir), runID+".keeper")
}

// hostedSaveKeeperKey writes a keeper key owner-only (SBX-UPD audit finding 2).
func hostedSaveKeeperKey(observerDir, runID string, key []byte) error {
	dir := hostedSecretsDir(observerDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(hostedKeeperKeyPath(observerDir, runID), []byte(hex.EncodeToString(key)), 0o600)
}

// hostedReadKeeperKey reads the keeper key a run's helper kept.
func hostedReadKeeperKey(observerDir, runID string) ([]byte, error) {
	b, err := os.ReadFile(hostedKeeperKeyPath(observerDir, runID)) //nolint:gosec // G304: the run's own key file under the state dir
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) < 16 {
		return nil, errors.New("the keeper key file is damaged")
	}
	return key, nil
}

// ---- credentials ------------------------------------------------------------

// hostedKeystoreOpen opens a vendor's keystore (a variable so tests never
// touch the real OS keychain).
var hostedKeystoreOpen = func(service, dir string) keystore.Store {
	return keystore.Open(service, dir, slog.Default())
}

// hostedLookupEnv reads the vendor's environment variables (a variable for
// tests).
var hostedLookupEnv = os.LookupEnv

// hostedCredDir is the keystore's file fallback directory.
func hostedCredDir(observerDir string) string {
	return filepath.Join(hostedStateDir(observerDir), "cred")
}

// hostedConnectedMarker records that a credential was connected through the
// keystore (no value; it lets the panel and the probe show presence without
// opening the keychain).
func hostedConnectedMarker(observerDir, provider string) string {
	return filepath.Join(hostedProviderDir(observerDir, provider), "connected")
}

// hostedCredentialSource says where a credential would come from, without
// reading any value or opening the keychain: "keystore", "env" or "".
func hostedCredentialSource(observerDir string, v sandboxremote.Vendor) string {
	if _, err := os.Lstat(hostedConnectedMarker(observerDir, v.ID)); err == nil {
		return sandboxremote.SourceKeystore
	}
	for _, n := range v.EnvCredential {
		if s, ok := hostedLookupEnv(n); !ok || strings.TrimSpace(s) == "" {
			return ""
		}
	}
	return sandboxremote.SourceEnv
}

// hostedResolveCredential reads the credential at use time: the keystore
// first, then the vendor's environment variables. It is called only from a
// user action (a launch, the leftover list's confirm, a connect check).
func hostedResolveCredential(observerDir string, v sandboxremote.Vendor) (sandboxremote.Credential, error) {
	if _, err := os.Lstat(hostedConnectedMarker(observerDir, v.ID)); err == nil {
		ks := hostedKeystoreOpen(v.KeystoreService, hostedCredDir(observerDir))
		raw, err := ks.Get(sandboxremote.KeystoreName)
		switch {
		case err == nil:
			c, derr := sandboxremote.DecodeStored(v.ID, []byte(raw))
			if derr != nil {
				return sandboxremote.Credential{}, derr
			}
			if !c.Complete(v) {
				return sandboxremote.Credential{}, fmt.Errorf("%w: the stored %s credential is incomplete; reconnect it", sandboxremote.ErrCredentialMissing, v.Name)
			}
			return c, nil
		case !errors.Is(err, keystore.ErrNotFound):
			return sandboxremote.Credential{}, fmt.Errorf("%w: the %s credential could not be read from the keychain: %w", sandboxremote.ErrCredentialMissing, v.Name, err)
		}
	}
	if c, ok := sandboxremote.CredentialFromEnv(v, hostedLookupEnv); ok {
		return c, nil
	}
	return sandboxremote.Credential{}, fmt.Errorf("%w: no %s credential: connect one in Terminals > Settings > Hosted sandboxes, or set %s", sandboxremote.ErrCredentialMissing, v.Name, strings.Join(v.EnvCredential, " and "))
}

// hostedConnectCredential stores a credential in the keystore, bound to
// endpoint, and writes the connected marker.
func hostedConnectCredential(observerDir string, v sandboxremote.Vendor, fields map[string]string, endpoint, spki string) error {
	c := sandboxremote.Credential{Provider: v.ID, Fields: fields, Endpoint: endpoint, Source: sandboxremote.SourceKeystore, SPKISHA256: spki}
	if !c.Complete(v) {
		return fmt.Errorf("terminal_sandbox: a %s credential needs %s", v.Name, strings.Join(v.EnvCredential, ", "))
	}
	b, err := sandboxremote.EncodeStored(c)
	if err != nil {
		return err
	}
	ks := hostedKeystoreOpen(v.KeystoreService, hostedCredDir(observerDir))
	if err := ks.Set(sandboxremote.KeystoreName, string(b)); err != nil {
		return fmt.Errorf("terminal_sandbox: store the %s credential: %w", v.Name, err)
	}
	if err := os.MkdirAll(hostedProviderDir(observerDir, v.ID), 0o700); err != nil {
		return err
	}
	return os.WriteFile(hostedConnectedMarker(observerDir, v.ID), []byte("1\n"), 0o600)
}

// hostedDisconnectCredential removes the stored credential and the marker.
func hostedDisconnectCredential(observerDir string, v sandboxremote.Vendor) error {
	ks := hostedKeystoreOpen(v.KeystoreService, hostedCredDir(observerDir))
	if err := ks.Delete(sandboxremote.KeystoreName); err != nil {
		return err
	}
	err := os.Remove(hostedConnectedMarker(observerDir, v.ID))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// ---- the vendor registry ---------------------------------------------------

// hostedClientFactory builds a vendor's wire client over one credential and
// endpoint. Called only from a user action.
type hostedClientFactory func(cred sandboxremote.Credential, endpoint string) (sandboxremote.Client, error)

// hostedVendorReg is one vendor driver's registration.
type hostedVendorReg struct {
	vendor    string
	component string
	newClient hostedClientFactory
}

// hostedVendorRegs are the registered vendor drivers (vendor id ->
// registration), filled from each vendor file's init.
var hostedVendorRegs = map[string]hostedVendorReg{}

// registerHostedVendor registers a vendor driver with the sandbox runtime.
// It is called from init only.
func registerHostedVendor(reg hostedVendorReg) {
	hostedVendorRegs[reg.vendor] = reg
	registerSandboxDriver(sandboxDriverReg{
		backend: reg.vendor, component: reg.component,
		build: func(r *sandboxRuntime, full config.Config) sandboxDriver {
			return newHostedDriver(r, full, reg)
		},
	})
}

// hostedVendorConfig returns a vendor's per-provider table.
// hostedResolve is the region and API endpoint a provider table names: its
// configured endpoint (E2B only; an org-published one may leave the
// vendor's domain, SBX-GOV-2) or its region's own (lane SBX-UPD).
func hostedResolve(v sandboxremote.Vendor, pc config.TerminalSandboxHostedProviderConfig) (region, endpoint string, ok bool) {
	return v.ResolveEndpoint(pc.Region, pc.Endpoint, pc.OrgPublished)
}

// hostedResolveRefusal says why hostedResolve refused a provider table.
func hostedResolveRefusal(v sandboxremote.Vendor, pc config.TerminalSandboxHostedProviderConfig) string {
	if pc.Endpoint != "" {
		return fmt.Sprintf("the endpoint %q is not on %s's own domain (%s); an endpoint elsewhere reaches a node only as one your organization publishes", pc.Endpoint, v.Name, strings.Join(v.Domains, ", "))
	}
	return fmt.Sprintf("region %q is not one %s documents", pc.Region, v.Name)
}

func hostedVendorConfig(c config.TerminalSandboxHostedConfig, vendor string) config.TerminalSandboxHostedProviderConfig {
	switch vendor {
	case sandboxremote.VendorE2B:
		return c.E2B
	case sandboxremote.VendorModal:
		return c.Modal
	case sandboxremote.VendorVercel:
		return c.Vercel
	}
	return config.TerminalSandboxHostedProviderConfig{}
}

// ---- the probe (local only, invariant I6) -----------------------------------

// The hosted probe verdicts (section 4.7; the copy keys a surface renders).
const (
	verdictHostedRegionUnknown     = "region_unknown"
	verdictHostedCredentialMissing = "credential_missing" //nolint:gosec // G101: a verdict copy key, not a credential
	verdictHostedBoxBinary         = "box_binary_unavailable"
	verdictHostedMemoryImages      = "memory_images_refused"
)

// hostedProbeFacts are the local facts a hosted probe reads (a seam so a
// test feeds them).
type hostedProbeFacts struct {
	listed       bool
	host         sandboxbackend.HostKind
	credential   string
	consentFacts *sandboxremote.ConsentFacts
	usedToday    int
	boxBinaryErr error
	// consentChange is the consent verdict of a recorded consent that no
	// longer matches ("" when none is recorded or it matches).
	consentChange string
}

// hostedProbeLadder decides a hosted row's probe verdict from local facts
// only, walked top-down (CLAUDE.md rule 5). It never calls the vendor.
func hostedProbeLadder(v sandboxremote.Vendor, cfg config.TerminalSandboxHostedConfig, f hostedProbeFacts) sandboxselect.Probe {
	row, _ := sandboxbackend.Get(v.ID)
	p := sandboxselect.Probe{Compiled: true, Version: row.Control.Pins.RequiredMin, Sources: []string{"live"}}
	pc := hostedVendorConfig(cfg, v.ID)
	_, _, regionOK := hostedResolve(v, pc)
	rules := []struct {
		verdict string
		fails   func() (bool, string)
	}{
		{sandboxselect.VerdictDisabledByConfig, func() (bool, string) {
			return !f.listed, v.ID + " is not in [terminal.sandbox].backends"
		}},
		{sandboxselect.VerdictUnsupportedPlatform, func() (bool, string) {
			return !row.RunsOn(f.host), "the hosted drivers run their host services on a Linux or WSL2 daemon only"
		}},
		{verdictHostedRegionUnknown, func() (bool, string) {
			return !regionOK, "region " + pc.Region + " is not one " + v.Name + " documents (" + strings.Join(v.Regions.Known, ", ") + ")"
		}},
		{verdictHostedMemoryImages, func() (bool, string) {
			return cfg.MemoryImages == "refuse" && v.MemoryImages.AutoPauseExists && !v.MemoryImages.CanDisable,
				v.Name + " can take a memory image of a live box and memory_images = refuse"
		}},
		{verdictHostedCredentialMissing, func() (bool, string) {
			return f.credential == "", "no " + v.Name + " credential: connect one in Terminals > Settings > Hosted sandboxes, or set " + strings.Join(v.EnvCredential, " and ")
		}},
		{verdictHostedBoxBinary, func() (bool, string) {
			if f.boxBinaryErr == nil {
				return false, ""
			}
			return true, f.boxBinaryErr.Error()
		}},
		{sandboxremote.VerdictDailyCapReached, func() (bool, string) {
			_, err := sandboxremote.PlanTimeout(cfg.MaxRunMinutes, cfg.DailyBoxMinutes, f.usedToday)
			if err == nil {
				return false, ""
			}
			return true, err.Error()
		}},
	}
	for _, r := range rules {
		if bad, why := r.fails(); bad {
			p.Verdict, p.Reason = r.verdict, why
			return p
		}
	}
	p.Verdict = sandboxselect.VerdictAvailable
	// Consent is judged against the facts that do not depend on the launch
	// (provider, endpoint, region, custody, box binary, memory images and
	// the caps); the scope, tier and capture are checked again at Create.
	p.ConsentRecorded = f.consentFacts != nil
	if !p.ConsentRecorded {
		p.ConsentChange = f.consentChange
	}
	return p
}

// hostedBoxBinaryCheck says whether an in-box observer is available: a
// configured box_binary that is an executable regular file, else the
// running binary when it is a Linux binary (the box architecture is checked
// at launch, against what the box reports).
func hostedBoxBinaryCheck(pc config.TerminalSandboxHostedProviderConfig, observerBin string) error {
	if b := strings.TrimSpace(pc.BoxBinary); b != "" {
		fi, err := os.Stat(b)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("box_binary %s is not an executable file", b)
		}
		return nil
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this observer is a %s binary; set [terminal.sandbox.hosted.<provider>].box_binary to a Linux observer of this version", runtime.GOOS)
	}
	if observerBin == "" {
		return errors.New("the running observer binary is unknown")
	}
	return nil
}

// hostedDriver is one hosted vendor's lifecycle service over a sandbox
// runtime.
type hostedDriver struct {
	r      *sandboxRuntime
	cfg    config.TerminalSandboxHostedConfig
	vendor sandboxremote.Vendor
	reg    hostedVendorReg
	now    func() time.Time
	// homeRelayOK: a key the proxy adds itself is configured (a routing key
	// pool or the org AI Gateway route), so home_relay custody can work.
	homeRelayOK bool
	// homeRelayNote names why credential injection cannot serve home_relay
	// on this node although it is selected (audit F10); "" otherwise.
	homeRelayNote string
}

// newHostedDriver builds a hosted driver; nothing is probed, read or dialled
// here.
func newHostedDriver(r *sandboxRuntime, full config.Config, reg hostedVendorReg) sandboxDriver {
	v, _ := sandboxremote.VendorFor(reg.vendor)
	recordHostedListed(full.Terminal.Sandbox)
	return &hostedDriver{
		r: r, cfg: full.Terminal.Sandbox.Hosted, vendor: v, reg: reg, now: time.Now,
		homeRelayOK:   len(full.Routing.KeyPool) > 0 || full.Proxy.OrgRoute.Mode != "" || hostedCredReadyFor(full),
		homeRelayNote: hostedCredNotReadyFor(full),
	}
}

// listed reports whether the row is among the enabled backends.
func (d *hostedDriver) listed() bool {
	return slices.Contains(sandboxEnabledBackends(d.r.cfg), d.vendor.ID)
}

// consentFactsStatic are the consent facts that do not depend on a launch.
func (d *hostedDriver) consentFactsStatic() (sandboxremote.ConsentFacts, bool) {
	pc := hostedVendorConfig(d.cfg, d.vendor.ID)
	region, endpoint, ok := hostedResolve(d.vendor, pc)
	if !ok {
		return sandboxremote.ConsentFacts{}, false
	}
	return sandboxremote.ConsentFacts{
		Provider: d.vendor.ID, Endpoint: endpoint, Region: region, Custody: d.cfg.KeyCustody,
		BoxBinary: hostedBoxBinaryLabel(pc), MemoryImages: d.cfg.MemoryImages,
		MaxRunMinutes: d.cfg.MaxRunMinutes, DailyBoxMinutes: d.cfg.DailyBoxMinutes,
	}, true
}

// hostedBoxBinaryLabel names the in-box observer on the consent screen. A
// box_binary's version is not read on this machine (the file is a Linux
// binary run only in the box), so the screen says it is unchecked and names
// the version the box must report, never this binary's version as that
// file's (live run 2, finding N3).
func hostedBoxBinaryLabel(pc config.TerminalSandboxHostedProviderConfig) string {
	if b := strings.TrimSpace(pc.BoxBinary); b != "" {
		return "observer from box_binary " + b + " (its version is unchecked here; the box refuses it unless it reports " + version + ")"
	}
	return "observer " + version + " (this running Linux binary)"
}

// probe reads local facts only (never the vendor, never a credential
// value).
func (d *hostedDriver) probe(context.Context) sandboxselect.Probe {
	f := hostedProbeFacts{listed: d.listed(), host: sandboxHostKind()}
	if !f.listed {
		return hostedProbeLadder(d.vendor, d.cfg, f)
	}
	f.credential = hostedCredentialSource(d.r.observerDir, d.vendor)
	f.usedToday = hostedLedgerUsed(d.r.observerDir, d.vendor.ID, d.now(), d.cfg.DailyBoxMinutes)
	f.boxBinaryErr = hostedBoxBinaryCheck(hostedVendorConfig(d.cfg, d.vendor.ID), d.r.observerBin)
	if static, ok := d.consentFactsStatic(); ok {
		if rec := hostedLoadConsent(d.r.observerDir, d.vendor.ID); rec != nil {
			if v := hostedStaticConsentVerdict(*rec, static); v == sandboxremote.ConsentOK {
				f.consentFacts = &rec.Facts
			} else {
				f.consentChange = v
			}
		}
	}
	return hostedProbeLadder(d.vendor, d.cfg, f)
}

// hostedStaticConsentVerdict is the consent verdict against the
// launch-independent facts: ConsentOK, or the one naming what changed.
func hostedStaticConsentVerdict(rec sandboxremote.ConsentRecord, static sandboxremote.ConsentFacts) string {
	static.Tier, static.Capture, static.ScopeKey = rec.Facts.Tier, rec.Facts.Capture, rec.Facts.ScopeKey
	return sandboxremote.CheckConsent(&rec, static)
}

// version is the row's client contract version.
func (d *hostedDriver) version() string {
	row, _ := sandboxbackend.Get(d.vendor.ID)
	return row.Control.Pins.RequiredMin
}

// sandboxRequestRegion is the region a selection request carries for a
// hosted row (the region the run would record, S7b); "" for a local row.
func sandboxRequestRegion(cfg config.TerminalSandboxConfig, backend string) string {
	v, ok := sandboxremote.VendorFor(backend)
	if !ok {
		return ""
	}
	r, _, _ := hostedResolve(v, hostedVendorConfig(cfg.Hosted, backend))
	return r
}
