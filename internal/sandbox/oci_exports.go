package sandbox

import "fmt"

// oci_exports.go exposes, unchanged, the two helper argv halves the bwrap
// plan composes internally, so the oci-runc driver (lane SBX-P3A) runs the
// SAME host and guest helpers around a container that it runs around bwrap:
// one owner for the per-run sockets, the relay, the proxy forward and the
// egress gateway, whatever the isolation layer. The bwrap argv does not
// change (its golden test is untouched).

// RelayHostArgv is the host helper prefix of a relayed run for an isolation
// layer other than bwrap: [observerBin, HostVerb, --sock-dir, the relay
// flags, the tier's forwards, the placeholders, "--"]. Unlike HostArgv it is
// never nil: a relayed run always runs the helper.
func RelayHostArgv(observerBin string, n NetRequest, placeholders []Overlay, relay RelayRequest) ([]string, error) {
	if !relay.Enabled() {
		return nil, fmt.Errorf("sandbox.RelayHostArgv: a relay run id is required")
	}
	if err := validateSockDir(n.HostSocketDir); err != nil {
		return nil, fmt.Errorf("sandbox.RelayHostArgv: %w", err)
	}
	return hostArgvRelay(observerBin, n, placeholders, relay)
}

// GuestArgv is the in-box guest helper prefix for a network request (the
// part bwrap's plan puts between its "--" and the inner argv), or nil for a
// tier that forwards nothing. The socket paths are under GuestSocketDir, so
// the layer must bind the host socket dir there read-only.
func GuestArgv(observerBin string, n NetRequest) ([]string, error) {
	prof, err := resolveNet(n)
	if err != nil {
		return nil, fmt.Errorf("sandbox.GuestArgv: %w", err)
	}
	if (prof.ForwardProxy || prof.Gateway) && validateAbs(observerBin, false) != nil {
		return nil, fmt.Errorf("sandbox.GuestArgv: observer bin %q is not absolute", observerBin)
	}
	return guestArgv(observerBin, prof, n), nil
}
