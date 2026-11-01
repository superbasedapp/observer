package kics

import (
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// The driver's ids.
const (
	// DriverID is the registry id and the findings' driver name.
	DriverID = string(seciac.KICS)
	// ComponentID is the catalog row that owns the driver.
	ComponentID = "security.scan.kics"
)

// Row is the registry row.
func Row() secscan.DriverRow { return seciac.Row(seciac.KICS) }

// New returns the driver over env (its Engine is set to KICS).
func New(env seciac.Env) *seciac.Driver {
	env.Engine = seciac.KICS
	return seciac.NewDriver(env)
}

// Parse maps KICS's SARIF onto iac findings (seciac.ReadSARIF).
func Parse(b []byte, t secscan.Target, dir string, ident secscan.EngineIdentity, selfTestPassed bool, rootHash func(string) string) (secscan.Result, string) {
	return seciac.ReadSARIF(seciac.KICS, b, t, dir, ident, selfTestPassed, rootHash)
}
