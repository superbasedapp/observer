//go:build !sbo_omit_isolation && !sbo_omit_isolation_seal

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/execevidence"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/machineid"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// evidence_seal.go is component isolation.seal (ledger SHR-6, lane
// GATES-SEC): the node signs each terminal run's execution evidence digest
// with an Ed25519 key kept in internal/keystore (service
// sbo-exec-evidence-v1, the OS keychain first, a reported 0600 file
// fallback), through the sealer the terminal_run insert calls
// (internal/store/termrun_seal.go). A managed node registers the key with
// its org, which verifies and countersigns the seal at ingest; an
// individual node's seal is self-attested. Opt-in: off with no
// [components] block selecting it, and then no key is made and the run
// rows are exactly what they were.

const (
	evidenceSealComponent       = "isolation.seal"
	evidenceSealKeystoreService = "sbo-exec-evidence-v1"
	evidenceSealKeyName         = "exec-evidence-seal-key"
	evidenceSealRegisterRetry   = 6 * time.Hour
	// evidenceSealNotSupportedMin and Max bound the back-off after the org
	// answered 404 (an older org server, or its org.security.ci off): the
	// node keeps asking, doubling, so an org that turns the route on later
	// gets the key without a node restart (audit finding F6).
	evidenceSealNotSupportedMin = time.Hour
	evidenceSealNotSupportedMax = 24 * time.Hour
)

// evidenceSealNextWait is the registration loop's rule, a table walked
// top-down: registered, individual or revoked by the org, stop; the org has no route (404),
// or does not serve this switched node as managed (403 managed_only, an older
// org server), back off doubling from evidenceSealNotSupportedMin to
// evidenceSealNotSupportedMax; anything else, the fixed retry.
func evidenceSealNextWait(err error, prev time.Duration) (wait time.Duration, stop bool) {
	switch {
	case err == nil, errors.Is(err, orgclient.ErrExecSealIndividual), errors.Is(err, orgclient.ErrExecSealKeyRevoked):
		return 0, true
	case errors.Is(err, orgclient.ErrExecSealNotSupported), errors.Is(err, orgclient.ErrExecSealNotManagedHere):
		if prev < evidenceSealNotSupportedMin {
			return evidenceSealNotSupportedMin, false
		}
		return min(2*prev, evidenceSealNotSupportedMax), false
	}
	return evidenceSealRegisterRetry, false
}

func init() {
	componentOptInRules = append(componentOptInRules, evidenceSealOptIn)
}

// evidenceSealOptIn governs isolation.seal: active only when a
// [components] block selects it.
func evidenceSealOptIn(snap componentstate.Snapshot, id string) (governs, active bool) {
	if id != evidenceSealComponent {
		return false, false
	}
	return true, evidenceSealSelected(snap)
}

// evidenceSealSelected is the component's one switch.
func evidenceSealSelected(snap componentstate.Snapshot) bool {
	return snap.BlockSelects(evidenceSealComponent) && snap.ModuleActive(evidenceSealComponent)
}

// evidenceSealKeyDir is the file fallback's directory.
func evidenceSealKeyDir(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "exec-evidence-key")
}

// evidenceSealKey loads the seal key from ks, or makes and stores one.
func evidenceSealKey(ks keystore.Store) (ed25519.PrivateKey, error) {
	if s, err := ks.Get(evidenceSealKeyName); err == nil {
		seed, derr := base64.StdEncoding.DecodeString(s)
		if derr != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("isolation.seal: the stored seal key is not an Ed25519 seed")
		}
		return ed25519.NewKeyFromSeed(seed), nil
	} else if !errors.Is(err, keystore.ErrNotFound) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := ks.Set(evidenceSealKeyName, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		return nil, err
	}
	return priv, nil
}

// evidenceSealer is the store seam's sealer over one key.
func evidenceSealer(priv ed25519.PrivateKey) store.TerminalRunSealer {
	return func(_ context.Context, digest string) (store.TerminalRunSeal, bool) {
		s, err := execevidence.SignSeal(priv, digest)
		if err != nil {
			return store.TerminalRunSeal{}, false
		}
		return store.TerminalRunSeal{KeyID: s.KeyID, PublicKey: s.PublicKey, Sig: s.Sig}, true
	}
}

// evidenceSealInstalled guards one install per database handle.
var evidenceSealInstalled sync.Map // *sql.DB -> bool

// evidenceSealOpenStore opens the seal key's keystore (tests replace it).
var evidenceSealOpenStore = func(cfg config.Config, logger *slog.Logger) keystore.Store {
	opened := keystore.OpenReport(evidenceSealKeystoreService, evidenceSealKeyDir(cfg), logger)
	if opened.Reason != "" {
		logger.Warn("isolation.seal: the OS keychain is not in use for the seal key", "fallback", opened.Reason)
	}
	return opened.Store
}

// sealEvidenceOnHandle installs the sealer on one short-lived database
// handle, with no key registration (the daemon registers the key): the
// sandboxed CLI launch's own write (terminal_sandbox_cli.go), which the
// daemon's sealer does not see because it opens its own handle. It returns
// the uninstall, run before the handle closes; a no-op when isolation.seal
// is not selected or the key cannot be read (the run is then unsealed).
func sealEvidenceOnHandle(cfg config.Config, database *sql.DB, logger *slog.Logger) func() {
	if logger == nil {
		logger = slog.Default()
	}
	if database == nil || !evidenceSealSelected(componentSnapshotForConfig(cfg)) {
		return func() {}
	}
	priv, err := evidenceSealKey(evidenceSealOpenStore(cfg, logger))
	if err != nil {
		logger.Warn("isolation.seal: no seal key; the run stays unsealed", "err", err)
		return func() {}
	}
	st := store.New(database)
	st.SetTerminalRunSealer(evidenceSealer(priv))
	return func() { st.SetTerminalRunSealer(nil) }
}

// installEvidenceSealer installs the sealer on database's terminal_run
// seam when isolation.seal is selected (a no-op otherwise: no key is made),
// and starts the managed node's key registration.
func installEvidenceSealer(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	if !evidenceSealSelected(componentSnapshotForConfig(cfg)) {
		return
	}
	if _, done := evidenceSealInstalled.LoadOrStore(database, true); done {
		return
	}
	priv, err := evidenceSealKey(evidenceSealOpenStore(cfg, logger))
	if err != nil {
		logger.Warn("isolation.seal: no seal key; runs stay unsealed", "err", err)
		return
	}
	st := store.New(database)
	st.SetTerminalRunSealer(evidenceSealer(priv))
	go evidenceSealRegister(ctx, cfg, st, priv, logger)
}

// evidenceSealRegister registers the key with a managed enrolment's org
// until the org has it (or says it never will).
func evidenceSealRegister(ctx context.Context, cfg config.Config, st *store.Store, priv ed25519.PrivateKey, logger *slog.Logger) {
	wait := time.Duration(0)
	for {
		enr, err := st.LoadEnrolment(ctx)
		next := evidenceSealRegisterRetry
		managed := false
		if err == nil && enr != nil {
			// A managed enrolment, or one whose org switched it to
			// enterprise (P-205).
			managed, err = orgclient.NodeManagedFor(ctx, st, enr)
		}
		if err == nil && managed {
			machine, _ := machineid.ForOrg(enr.OrgID)
			bs := orgclient.OpenBearerStoreQuiet(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath))
			_, err = orgclient.New(cfg.OrgClient, st, bs, version, nil, nil).RegisterExecSealKey(ctx, priv, machine, time.Now())
			var stop bool
			next, stop = evidenceSealNextWait(err, wait)
			switch {
			case err == nil:
				logger.Info("isolation.seal: seal key registered with the org")
				return
			case stop:
				if errors.Is(err, orgclient.ErrExecSealKeyRevoked) {
					logger.Warn("isolation.seal: the org revoked this machine's seal key; its seals read key_revoked there")
				}
				return
			case errors.Is(err, orgclient.ErrExecSealNotSupported):
				logger.Debug("isolation.seal: the org has no seal key route yet; asked again later", "after", next)
			default:
				logger.Debug("isolation.seal: seal key not registered yet; retried later", "err", err)
			}
			wait = next
		} else if err == nil {
			return // individual or not enrolled: self-attested
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}
