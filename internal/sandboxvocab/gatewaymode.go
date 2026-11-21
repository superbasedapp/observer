package sandboxvocab

// GatewayMode is which sandbox gateway runs a row's boxes, for a row that
// runs its boxes through a gateway (the openshell row today; OpenShell
// build lanes O2 and O4, decision D2 OB-039). A driver reports it on its
// probe; the terminals.isolation floor gateway_modes judges it. The zero
// value means the row has no gateway, so the floor does not apply to it.
type GatewayMode string

// The closed GatewayMode vocabulary.
const (
	// GatewayManagedLocal: Observer's own private gateway on this machine
	// (loopback only, its config, certificates and state Observer's own).
	GatewayManagedLocal GatewayMode = "managed_local"
	// GatewayExternal: a gateway the user installs, starts and signs in to
	// themselves; Observer never writes its config (decision D3).
	GatewayExternal GatewayMode = "external"
)

// GatewayModes returns the vocabulary in the order the admin form lists it.
func GatewayModes() []GatewayMode { return []GatewayMode{GatewayManagedLocal, GatewayExternal} }

// Valid reports whether m is in the closed vocabulary.
func (m GatewayMode) Valid() bool {
	switch m {
	case GatewayManagedLocal, GatewayExternal:
		return true
	}
	return false
}
