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
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxkey"
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
		return hostedSelectionCustody(vocab.KeyCustody(cfg.Hosted.KeyCustody), row)
	}
	return vocab.CustodyHostBound
}

// hostedSelectionCustody is the custody a selection request with no tool
// carries for a hosted row (decision SBXD-1): an explicit value as set; auto
// is resolved per tool only at the launch, so here it reads as the custody
// it can fall back to, the strictest for capture: in_box_api_key where the
// row offers it, home_relay where the row keeps every key home.
func hostedSelectionCustody(c vocab.KeyCustody, row sandboxbackend.Capability) vocab.KeyCustody {
	if c != vocab.CustodyAuto {
		return c
	}
	if hostedRowRefusesInBox(row) {
		return vocab.CustodyHomeRelay
	}
	return vocab.CustodyInBoxAPIKey
}

// hostedRowRefusesInBox reports whether a hosted row keeps every model key
// on this machine: its capability row offers no in-box custody.
func hostedRowRefusesInBox(row sandboxbackend.Capability) bool {
	return !slices.Contains(row.Net.KeyCustody, vocab.CustodyInBoxAPIKey)
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
// A keychain entry already gone still removes the marker, so a provider never
// reads as connected with nothing behind it.
func hostedDisconnectCredential(observerDir string, v sandboxremote.Vendor) error {
	ks := hostedKeystoreOpen(v.KeystoreService, hostedCredDir(observerDir))
	if err := ks.Delete(sandboxremote.KeystoreName); err != nil && !errors.Is(err, keystore.ErrNotFound) {
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
	// The optional hooks of a vendor whose row's capability flags ask for
	// more than the shared core does (lane G4, the org-hosted row; nil for
	// the three file-API vendors, which keep the core's own behaviour):
	//   - mintSource builds the run's token source for a MintedCredential
	//     vendor (the core then reads no keystore and no environment);
	//   - localProbe adds the row's own local probe rows (no network call,
	//     invariant I6), walked before the shared ladder's;
	//   - endRun takes the run's end branch (hold, return and delete, or end
	//     without a return) in place of the shared teardown, and reports
	//     whether it did.
	mintSource func(ctx context.Context, plan hostedPlanFile) (sandboxremote.CredentialSource, error)
	localProbe func(d *hostedDriver) (verdict, reason string)
	endRun     func(ctx context.Context, r *hostedRun) bool
	//   - resumeBox names the held box a launch in this process takes over
	//     ("" for a fresh box), and resumeArgs is the agent's native resume
	//     tail for a session id (nil for a fresh session in the kept box).
	resumeBox  func() string
	resumeArgs func(tool, sessionID string) []string
	//   - cloneSpec is the box-side clone of a remote_clone delivery: the
	//     exact argv and environment and the token purpose it is sent
	//     under (nil: the vendor has no box-side clone);
	//   - runCap is the vendor's own lower cap of a box's run minutes (the
	//     organization's max_run_minutes; 0 for none), applied as
	//     min(local, vendor) at launch.
	cloneSpec func(url string) (argv []string, env map[string]string, purpose string)
	runCap    func(d *hostedDriver) int
	//   - authVersion is the row's authenticated version source (FX1 item 1,
	//     live finding F-L3-5): the version and true only when it was read
	//     from an authenticated identity (for the org row, the org's signed
	//     managed body); "" and false otherwise. A row that pins
	//     RequireAuthenticatedVersion needs one, or selection rule S2b
	//     refuses every launch. nil keeps the row's client contract version,
	//     unauthenticated (E2B, Modal and Vercel do not pin the flag).
	authVersion func(d *hostedDriver) (version string, ok bool)
	//   - dailyQuota is the vendor's own per-member daily box-minutes quota
	//     (for the org row, the organization's daily_box_minutes_per_member
	//     from its verified body; 0 for none), shown on the consent screen
	//     under the machine's own cap. nil: the vendor publishes none.
	dailyQuota func(c config.TerminalSandboxHostedConfig) int
	//   - cloneRepositories lists the repositories a clone-remote launch on
	//     the row may name (for the org row, the organization's published
	//     clone_repositories), for the clone consent's picker (FX3 item 3).
	//     nil: the row offers no box-side clone list.
	cloneRepositories func(c config.TerminalSandboxHostedConfig) []string
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
	for _, row := range hostedVendorConfigTable {
		if row.vendor == vendor {
			return row.read(c)
		}
	}
	return config.TerminalSandboxHostedProviderConfig{}
}

// hostedVendorConfigTable maps a vendor id to its provider table in
// [terminal.sandbox.hosted] (a table, not a switch on the vendor id; lane
// G4). A driver whose table is composed from the verified managed body
// appends its own row from its file's init.
var hostedVendorConfigTable = []hostedVendorConfigRow{
	{sandboxremote.VendorE2B, func(c config.TerminalSandboxHostedConfig) config.TerminalSandboxHostedProviderConfig { return c.E2B }},
	{sandboxremote.VendorModal, func(c config.TerminalSandboxHostedConfig) config.TerminalSandboxHostedProviderConfig { return c.Modal }},
	{sandboxremote.VendorVercel, func(c config.TerminalSandboxHostedConfig) config.TerminalSandboxHostedProviderConfig { return c.Vercel }},
	{sandboxremote.VendorDockerSandboxes, func(c config.TerminalSandboxHostedConfig) config.TerminalSandboxHostedProviderConfig { return c.Docker }},
	{sandboxremote.VendorInstaBox, func(c config.TerminalSandboxHostedConfig) config.TerminalSandboxHostedProviderConfig {
		return c.InstaBox
	}},
	{sandboxremote.VendorDaytona, func(c config.TerminalSandboxHostedConfig) config.TerminalSandboxHostedProviderConfig {
		return c.Daytona
	}},
}

// hostedVendorConfigRow is one row of hostedVendorConfigTable; a driver
// whose provider table is composed elsewhere appends its own from init.
type hostedVendorConfigRow = struct {
	vendor string
	read   func(config.TerminalSandboxHostedConfig) config.TerminalSandboxHostedProviderConfig
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
	// version and versionAuthenticated are the row's version as its driver
	// read it ("" keeps the client contract version, unauthenticated).
	version              string
	versionAuthenticated bool
	// homeKey is the node-wide answer to whether a run's model key can
	// reach the agent under the configured custody (sandboxkey.HomeKey);
	// nil when it can.
	homeKey *sandboxkey.HomeKeyVerdict
}

// hostedProbeLadder decides a hosted row's probe verdict from local facts
// only, walked top-down (CLAUDE.md rule 5). It never calls the vendor.
func hostedProbeLadder(v sandboxremote.Vendor, cfg config.TerminalSandboxHostedConfig, f hostedProbeFacts) sandboxselect.Probe {
	row, _ := sandboxbackend.Get(v.ID)
	p := sandboxselect.Probe{Compiled: true, Version: row.Control.Pins.RequiredMin, Sources: []string{"live"}}
	if f.version != "" {
		p.Version, p.VersionAuthenticated = f.version, f.versionAuthenticated
	}
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
		// The model key's custody, before Start (audit
		// hosted-sandbox-key-custody-2026-11-18): a custody nothing on this
		// node can serve refuses every launch, so the row is not offered as
		// ready and the setup checklist's model key step reads missing.
		{sandboxselect.VerdictCustodyUnsatisfiable, func() (bool, string) {
			if f.homeKey == nil {
				return false, ""
			}
			return true, f.homeKey.Message
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
	if pc.BoxBinaryInImage {
		return nil // the box image carries it; the box checks its version at launch
	}
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
	// homeRelayOK: a key the proxy adds itself is configured (the org AI
	// Gateway route, homeRelayServedAtHome) or credential injection is
	// ready, so home_relay custody can work (the org row's probe reads it).
	homeRelayOK bool
	// homeKey are the node's facts about how a run's model key reaches the
	// agent (hostedHomeKeyFacts); the probe judges them node-wide and
	// Create per tool, through the one table (sandboxkey.HomeKey).
	homeKey sandboxkey.HomeKeyFacts
	// full is the config the driver was built from, so the key facts are
	// read again on each question (a key stored after the build counts at
	// once: the dialog's paste field re-reads the probe).
	full *config.Config
}

// homeRelayServedAtHome reports whether the proxy itself puts a credential
// on a request that carries none of the user's: the org AI Gateway route,
// which strips every credential header and attaches the org's virtual key.
// A routing key pool does not: it only rotates among keys a request already
// presented (internal/proxy keypool.go's membership guard), so a box with no
// key gets none from it (FX3 item 5, live finding F-L3P4-4).
func homeRelayServedAtHome(full config.Config) bool {
	return full.Proxy.OrgRoute.Mode != ""
}

// newHostedDriver builds a hosted driver; nothing is probed, read or dialled
// here.
func newHostedDriver(r *sandboxRuntime, full config.Config, reg hostedVendorReg) sandboxDriver {
	v, _ := sandboxremote.VendorFor(reg.vendor)
	recordHostedListed(full.Terminal.Sandbox)
	hk := hostedHomeKeyFacts(full)
	return &hostedDriver{
		r: r, cfg: full.Terminal.Sandbox.Hosted, vendor: v, reg: reg, now: time.Now,
		homeRelayOK: hostedHomeRelayServed(hk),
		homeKey:     hk,
		full:        &full,
	}
}

// homeKeyFacts are the node's key facts with the driver's own custody (the
// one Create reads) and its row's capability: a row that keeps every key
// on this machine resolves auto to home_relay (decision SBXD-1). The stored
// key list is read again (ids only, never a key), so a key stored after
// the driver was built counts at once.
func (d *hostedDriver) homeKeyFacts() sandboxkey.HomeKeyFacts {
	f := d.homeKey
	if hostedCredFacts != nil && d.full != nil {
		f.InjectionSelected, f.InjectionBuilt, f.StoredProviders = hostedCredFacts(*d.full)
	}
	f.Custody = d.cfg.KeyCustody
	f.InBoxRefused = hostedRowRefusesInBox(hostedRow(d.vendor.ID))
	return f
}

// hostedHomeKeyFacts are the node's facts about how a hosted run's model
// key reaches the agent: the configured custody, the org AI Gateway route,
// and what credential injection offers (read without opening a key).
func hostedHomeKeyFacts(full config.Config) sandboxkey.HomeKeyFacts {
	f := sandboxkey.HomeKeyFacts{
		Custody: full.Terminal.Sandbox.Hosted.KeyCustody, OrgRoute: homeRelayServedAtHome(full),
		InBoxEnvProviders: hostedInBoxEnvProviders(),
	}
	if hostedCredFacts != nil {
		f.InjectionSelected, f.InjectionBuilt, f.StoredProviders = hostedCredFacts(full)
	}
	return f
}

// hostedInBoxEnvProviders are the providers whose in-box API-key variable
// (sandboxkey.InBoxKeyEnv) is set in the daemon's environment (ids only;
// no value leaves this function), read through hostedLookupEnv. The hosted
// host helper inherits that environment, so this is what an in-box custody
// forwards (agentEnv).
func hostedInBoxEnvProviders() []string {
	var ids []string
	for _, n := range sandboxkey.InBoxKeyEnv() {
		if v, ok := hostedLookupEnv(n); ok && v != "" {
			ids = append(ids, sandboxkey.InBoxEnvProvider(n))
		}
	}
	return sandboxkey.Known(ids)
}

// hostedToolRoute is what a tool's capability row says about the providers
// its model requests use (sandboxkey.ToolRoute), read from the row, never
// its name: the vendor-locked catalogue, whether it has a proxy route, and
// the providers that route names (its covered built-in provider overrides,
// and the provider whose model host a route lane addresses). With neither
// named, RouteProviders stays nil: the registry says nothing about which
// providers the route carries.
func hostedToolRoute(tool string) sandboxkey.ToolRoute {
	spec, _ := integration.For(tool)
	t := sandboxkey.ToolRoute{
		VendorLocked: spec.Model.Catalog.Kind == integration.ModelCatalogVendor,
		Families:     spec.Model.Catalog.Providers,
		Routed:       spec.Proxy != nil,
	}
	if spec.Proxy == nil {
		return t
	}
	named := false
	var ids []string
	addHost := func(upstream string) {
		named = true
		if p, ok := sandboxkey.ProviderForHost(hostedUpstreamHost(upstream)); ok {
			ids = append(ids, p.ID)
		}
	}
	if l := spec.Proxy.Lane; l != nil && l.DefaultUpstream != "" {
		addHost(l.DefaultUpstream)
	}
	if spec.Proxy.CarriesProviders != nil {
		// The route sets one provider's base URL (opencode's
		// OPENAI_BASE_URL): only that provider's requests reach the proxy.
		named = true
		ids = append(ids, spec.Proxy.CarriesProviders...)
	}
	for _, o := range spec.Proxy.ProviderOverrides {
		if !o.Covered() {
			continue
		}
		named = true
		ids = append(ids, o.Provider)
	}
	if named {
		// Named but none the table knows is an empty set, not "unknown".
		t.RouteProviders = append([]string{}, sandboxkey.Known(ids)...)
	}
	return t
}

// hostedUpstreamHost is the host of an upstream root ("https://openrouter.ai"
// -> "openrouter.ai"; "" when it does not parse).
func hostedUpstreamHost(upstream string) string {
	u, err := url.Parse(upstream)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// hostedHomeRelayServed reports whether home_relay custody is served on
// the node whatever custody is configured (the org row's probe fact).
func hostedHomeRelayServed(f sandboxkey.HomeKeyFacts) bool {
	f.Custody, f.ForTool = string(vocab.CustodyHomeRelay), false
	return sandboxkey.HomeKey(f).OK
}

// hostedHomeKeyForTool completes the node's facts for one tool: the
// providers credential injection can bind for it and the providers whose
// keys it can use at all, read from the tool's own capability row
// (hostedToolRoute), never its name.
func hostedHomeKeyForTool(f sandboxkey.HomeKeyFacts, tool string) sandboxkey.HomeKeyFacts {
	r := hostedToolRoute(tool)
	f.ForTool = true
	f.ToolProviders = sandboxkey.InjectableProviders(r)
	f.ToolUsable = sandboxkey.UsableProviders(r)
	f.ToolName = integration.DisplayName(tool)
	return f
}

// hostedToolKeyFacts are hostedHomeKeyForTool's facts completed with the
// tool's own settings of [terminal.sandbox.hosted] (decisions SBXD-1 and
// SBXD-4): its per-tool custody and its opt-in in-box key sources, each
// only where the tool's registry row grounds it (never read from the
// files here: that happens only when a run starts).
func hostedToolKeyFacts(f sandboxkey.HomeKeyFacts, hc config.TerminalSandboxHostedConfig, tool string) sandboxkey.HomeKeyFacts {
	f = hostedHomeKeyForTool(f, tool)
	f.ToolCustody = hc.KeyCustodyByTool[tool]
	if row, ok := integration.SandboxSavedKeysFor(tool); ok && hc.ToolKeys[tool] && row.FileFor(runtime.GOOS) != "" {
		f.ToolSavedKeys, f.ToolSavedProviders = true, row.Providers()
	}
	if row, ok := integration.SandboxLoginSeedFor(tool); ok && hc.LoginSeed[tool] && !slices.Contains(row.KeychainOn, runtime.GOOS) {
		f.LoginSeed = true
	}
	return f
}

// hostedKeyFactsOf returns the node's key facts as a listed hosted driver
// among drivers holds them (every hosted driver reads the same config, so
// any listed one answers); ok false when no hosted row is listed.
func hostedKeyFactsOf(drivers map[string]sandboxDriver) (sandboxkey.HomeKeyFacts, bool) {
	f, _, ok := hostedKeyNodeOf(drivers)
	return f, ok
}

// hostedKeyNodeOf is hostedKeyFactsOf with the hosted block the per-tool
// facts are completed from. A listed row that offers an in-box custody is
// preferred, so the per-tool line describes the vendor rows; the org-hosted
// row, which keeps every key home, says its own refusal in its probe (R2)
// and at the launch.
func hostedKeyNodeOf(drivers map[string]sandboxDriver) (sandboxkey.HomeKeyFacts, config.TerminalSandboxHostedConfig, bool) {
	var found *hostedDriver
	for _, id := range slices.Sorted(maps.Keys(drivers)) {
		h, ok := drivers[id].(*hostedDriver)
		if !ok || !h.listed() {
			continue
		}
		if found == nil || (found.homeKeyFacts().InBoxRefused && !h.homeKeyFacts().InBoxRefused) {
			found = h
		}
	}
	if found == nil {
		return sandboxkey.HomeKeyFacts{}, config.TerminalSandboxHostedConfig{}, false
	}
	return found.homeKeyFacts(), found.cfg, true
}

// hostedKeyNotice is the per-tool line of the sandbox probe, said before
// Start: the refusal a hosted launch of tool would meet on its model key
// (blocking), or a line that does not block it (which custody the launch
// uses and why, which of the person's keys the agent gets, or that it
// starts with none); nil when there is nothing to say.
func hostedKeyNotice(f sandboxkey.HomeKeyFacts, tool string) *dashapi.SandboxKeyNotice {
	return hostedKeyNoticeFor(f, config.TerminalSandboxHostedConfig{}, tool)
}

// hostedKeyNoticeFor is hostedKeyNotice with the tool's own settings
// (hostedToolKeyFacts): the line also carries the resolved custody, the
// providers whose stored key would keep the key home (the dialog's paste
// field), and the tool's opt-in in-box sources when the key goes in the box.
func hostedKeyNoticeFor(f sandboxkey.HomeKeyFacts, hc config.TerminalSandboxHostedConfig, tool string) *dashapi.SandboxKeyNotice {
	tf := hostedToolKeyFacts(f, hc, tool)
	v := sandboxkey.HomeKey(tf)
	if v.OK && v.Message == "" {
		return nil
	}
	sev := dashapi.SandboxKeyBlocking
	if !v.Blocking() {
		sev = dashapi.SandboxKeyAdvisory
	}
	n := &dashapi.SandboxKeyNotice{Code: v.Code, Message: v.Message, Technical: v.Technical, Severity: sev, Custody: v.Resolution.Custody}
	for _, id := range sandboxkey.KeepHomeOffers(tf) {
		p, _ := sandboxkey.ProviderFor(id)
		n.KeepHome = append(n.KeepHome, dashapi.SandboxKeyProvider{ID: id, Label: p.KeyLabel})
	}
	if v.Resolution.Custody == string(vocab.CustodyInBoxAPIKey) {
		if _, ok := integration.SandboxSavedKeysFor(tool); ok {
			n.ToolKeys = &dashapi.SandboxKeySource{On: hc.ToolKeys[tool]}
		}
		if _, ok := integration.SandboxLoginSeedFor(tool); ok {
			n.LoginSeed = &dashapi.SandboxKeySource{On: hc.LoginSeed[tool]}
		}
	}
	return n
}

// hostedKeyCheck refuses a launch whose model key cannot reach the agent
// (S7d, the one table sandboxkey.HomeKey): a typed refusal with the plain
// sentence and the technical detail apart, so the dashboard shows the
// sentence and a link and a terminal prints both.
func hostedKeyCheck(f sandboxkey.HomeKeyFacts) error {
	v := sandboxkey.HomeKey(f)
	if v.OK {
		return nil
	}
	return &dashapi.SandboxStepRefusal{Code: verdictHostedCustody, Message: v.Message, Technical: v.Code + ": " + v.Technical}
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
	f := sandboxremote.ConsentFacts{
		Provider: d.vendor.ID, Endpoint: endpoint, Region: region, Custody: hostedConsentCustody(d.cfg),
		BoxBinary: hostedBoxBinaryLabel(pc), MemoryImages: d.cfg.MemoryImages,
		MaxRunMinutes: d.cfg.MaxRunMinutes, DailyBoxMinutes: d.cfg.DailyBoxMinutes,
	}
	hk := d.homeKeyFacts()
	f.InBoxKeys, f.ToolKeys, f.LoginSeed = hostedConsentKeyFacts(d.cfg, hk.InjectionSelected, hk.StoredProviders, hk.InBoxRefused)
	return f, true
}

// hostedConsentCustody is the consent's custody fact (decision SBXD-1): the
// node's key_custody ("auto" states the rule, not a per-tool answer, so a
// resolution that differs per tool needs no second consent), with every
// per-tool value after it, sorted ("auto; droid=in_box_api_key"). With no
// per-tool value it is exactly the node value, as every record had.
func hostedConsentCustody(hc config.TerminalSandboxHostedConfig) string {
	out := hc.KeyCustody
	tools := slices.Sorted(maps.Keys(hc.KeyCustodyByTool))
	if len(tools) == 0 {
		return out
	}
	parts := make([]string, 0, len(tools))
	for _, t := range tools {
		parts = append(parts, t+"="+hc.KeyCustodyByTool[t])
	}
	return out + "; " + strings.Join(parts, ",")
}

// hostedConsentKeyFacts are the consent's in-box key facts (decisions
// SBXD-3 and SBXD-4): the stored providers whose keys would enter the box
// (read only while the credentials component is selected, as the host
// helper reads them), and the tools opted in to their own saved keys and to
// a login seed. Each is bound only while the custody settings can put a key
// in the box (sandboxkey.MayPutKeyInBox), so under home_relay everywhere
// all three are empty and a stored key never reopens the consent.
func hostedConsentKeyFacts(hc config.TerminalSandboxHostedConfig, injectionSelected bool, stored []string, inBoxRefused bool) (inBoxKeys, toolKeys, loginSeed string) {
	if !sandboxkey.MayPutKeyInBox(hc.KeyCustody, hc.KeyCustodyByTool, inBoxRefused) {
		return "", "", ""
	}
	if injectionSelected {
		inBoxKeys = strings.Join(sandboxkey.Known(stored), ",")
	}
	on := func(m map[string]bool, grounded func(string) bool) string {
		var ids []string
		for _, t := range slices.Sorted(maps.Keys(m)) {
			if m[t] && grounded(t) {
				ids = append(ids, t)
			}
		}
		return strings.Join(ids, ",")
	}
	toolKeys = on(hc.ToolKeys, func(t string) bool { _, ok := integration.SandboxSavedKeysFor(t); return ok })
	loginSeed = on(hc.LoginSeed, func(t string) bool { _, ok := integration.SandboxLoginSeedFor(t); return ok })
	return inBoxKeys, toolKeys, loginSeed
}

// hostedBoxBinaryLabel names the in-box observer on the consent screen. A
// box_binary's version is not read on this machine (the file is a Linux
// binary run only in the box), so the screen says it is unchecked and names
// the version the box must report, never this binary's version as that
// file's (live run 2, finding N3).
func hostedBoxBinaryLabel(pc config.TerminalSandboxHostedProviderConfig) string {
	if pc.BoxBinaryInImage {
		return "observer from the box image (nothing is uploaded; the box refuses it unless it reports " + version + ")"
	}
	if b := strings.TrimSpace(pc.BoxBinary); b != "" {
		return "observer from box_binary " + b + " (its version is unchecked here; the box refuses it unless it reports " + version + ")"
	}
	return "observer " + version + " (this running Linux binary)"
}

// probe reads local facts only (never the vendor, never a credential
// value).
func (d *hostedDriver) probe(context.Context) sandboxselect.Probe {
	f := hostedProbeFacts{listed: d.listed(), host: sandboxHostKind()}
	f.version, f.versionAuthenticated = d.probeVersion()
	if d.reg.localProbe != nil {
		// The row's own local rows come first (the org-hosted row's R0: a
		// node not offered the row says so before anything else).
		if v, why := d.reg.localProbe(d); v != "" {
			return sandboxselect.Probe{Compiled: true, Version: f.version, VersionAuthenticated: f.versionAuthenticated, Sources: []string{"live"}, Verdict: v, Reason: why}
		}
	}
	if !f.listed {
		return hostedProbeLadder(d.vendor, d.cfg, f)
	}
	f.credential = hostedCredentialSource(d.r.observerDir, d.vendor)
	if d.vendor.MintedCredential {
		// No stored credential: every call carries a token the org mints at
		// launch (the local sign-in check is the row's own probe row R3).
		f.credential = sandboxremote.SourceMinted
	}
	f.usedToday = hostedLedgerUsed(d.r.observerDir, d.vendor.ID, d.now(), d.cfg.DailyBoxMinutes)
	f.boxBinaryErr = hostedBoxBinaryCheck(hostedVendorConfig(d.cfg, d.vendor.ID), d.r.observerBin)
	if v := sandboxkey.HomeKey(d.homeKeyFacts()); !v.OK {
		f.homeKey = &v
	}
	if static, ok := d.consentFactsStatic(); ok {
		if rec := hostedLoadConsent(d.r.observerDir, d.vendor.ID); rec != nil {
			if v := hostedStaticConsentVerdict(*rec, static, d.vendor, d.cfg); v == sandboxremote.ConsentOK {
				f.consentFacts = &rec.Facts
			} else {
				f.consentChange = v
			}
		}
	}
	return hostedProbeLadder(d.vendor, d.cfg, f)
}

// hostedStaticConsentVerdict is the consent verdict against the
// launch-independent facts: ConsentOK, or the one naming what changed. The
// private-range deny depends on the tier, so it is judged on the recorded
// tier under the settings now (a changed allow_private_ranges reopens it).
func hostedStaticConsentVerdict(rec sandboxremote.ConsentRecord, static sandboxremote.ConsentFacts, v sandboxremote.Vendor, cfg config.TerminalSandboxHostedConfig) string {
	static.Tier, static.Capture, static.ScopeKey = rec.Facts.Tier, rec.Facts.Capture, rec.Facts.ScopeKey
	static.PrivateRanges = hostedPrivateRangesFact(v, cfg, vocab.Tier(rec.Facts.Tier))
	return sandboxremote.CheckConsent(&rec, static)
}

// version is the row's version: the authenticated one its driver read, else
// the client contract version.
func (d *hostedDriver) version() string {
	v, _ := d.probeVersion()
	return v
}

// probeVersion is the version a probe reports and whether it is
// authenticated (FX1 item 1, live finding F-L3-5): the row's own
// authenticated source when it registers one and that source answers, else
// the client contract version, unauthenticated. Only a source that read the
// version from an authenticated identity may answer true.
func (d *hostedDriver) probeVersion() (string, bool) {
	if d.reg.authVersion != nil {
		if v, ok := d.reg.authVersion(d); ok && v != "" {
			return v, true
		}
	}
	row, _ := sandboxbackend.Get(d.vendor.ID)
	return row.Control.Pins.RequiredMin, false
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

// hostedFillProbeRow adds to a hosted row's probe entry what the New
// Terminal dialog must say before Start (lane UX): the workspace sources the
// row takes and how each reaches the box (items H5 and H8), the tools that
// cannot reach the box at the configured tier (H4), and the box's own
// network on that tier (H10). A row that is not a hosted vendor's is left
// as it is.
func hostedFillProbeRow(e *dashapi.SandboxBackendAvail, row sandboxbackend.Capability, cfg config.TerminalSandboxConfig, tier vocab.Tier) {
	v, ok := sandboxremote.VendorFor(row.ID)
	if !ok || row.Iso.Location != vocab.LocationRemote {
		return
	}
	e.WorkspaceSources, e.WorkspaceSourceNotes, _ = hostedAcceptedSources(row.ID, tier, cfg)
	e.SourceDeliveries, _ = hostedSourceDeliveries(row.ID)
	e.CloneWhere = hostedCloneWhereView(row.ID, tier, cfg)
	e.ToolNotices = hostedToolNotices(row.ID, cfg, tier)
	e.NetworkNotes = sandboxremote.TierNetworkNotes(v, tier, hostedPrivateRangesAllowed(v, cfg.Hosted))
	hostedFillHookNotices(e, cfg)
}
