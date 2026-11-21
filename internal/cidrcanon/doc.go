// Package cidrcanon is the one CIDR spelling rule shared by the org server's
// [openshell] config, its settings route and the org_openshell body
// validator (lane FX1, live finding F-B1). It is a leaf: it imports only the
// standard library, so a config package can use it without pulling a wire
// contract package into every build (FX1-A7).
package cidrcanon
