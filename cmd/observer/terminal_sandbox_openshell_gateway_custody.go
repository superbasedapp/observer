//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"log/slog"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// terminal_sandbox_openshell_gateway_custody.go is the managed gateway's
// one keystore seam (lane O2 M2, risk RK-20): the private gateway's PKI
// and its credential-store key-encryption key are held in internal/
// keystore under the service openShellGatewayKeystoreService. The OS
// keychain is the custody where one is usable (CustodyKeychain). Where
// none is (a headless Linux host without a Secret Service, the only host
// class measured), the keystore's hardened owner-only file store under
// <state dir>/gateway/keys holds them instead (CustodyOwnerFile): 0600
// files in a 0700 dir, NOT encrypted, so the PKI (the CA key included)
// and the key-encryption key are on disk beside the database that key
// protects, and against the local user they are no stronger than the
// user's own OpenShell install. The probe hint, the run's posture note
// and the operator doc say so (audit finding O2-A1, decision OB-050). A
// fail-closed keystore refuses managed mode (lifecycle row G6). The
// keystore is opened once per process through keystore.OpenReport, whose
// keychain probe is bounded (audit finding O2-A5).

// openShellGatewayKeystoreService is the keystore service of the managed
// gateway's custody.
const openShellGatewayKeystoreService = sandboxopenshell.GatewayKeystoreService

// openShellGatewayKeystore opens the custody store for a state dir and
// names the keychain fallback reason ("" when the keychain is in use); a
// variable so a test hands a keystore.MemStore.
var openShellGatewayKeystore = func(stateDir string) (keystore.Store, string) {
	o := keystore.OpenReport(openShellGatewayKeystoreService, filepath.Join(stateDir, "gateway", "keys"), slog.Default())
	return o.Store, o.Reason
}

// openShellCustody adapts a keystore.Store to the planner's CustodyStore.
type openShellCustody struct{ s keystore.Store }

// Load reads one record; a missing record is ok false, never an error.
func (c openShellCustody) Load(name string) (string, bool, error) {
	v, err := c.s.Get(name)
	if errors.Is(err, keystore.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// Save stores one record.
func (c openShellCustody) Save(name, value string) error { return c.s.Set(name, value) }

// Remove deletes one record.
func (c openShellCustody) Remove(name string) error { return c.s.Delete(name) }

var _ sandboxopenshell.CustodyStore = openShellCustody{}
