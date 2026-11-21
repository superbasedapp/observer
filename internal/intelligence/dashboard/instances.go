package dashboard

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// instances.go serves the INSTANCE SWITCHER: connecting this dashboard's
// operator to a remote developer machine that runs its OWN Observer install
// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md §12 D2, partially lifted).
//
// DIRECTION MATTERS, twice over.
//
//   - Like ssh.go and unlike remote.go, this is OUTBOUND: Observer acts as an
//     SSH client. It shares no state with the inbound [remote]/Tailscale
//     pairing feature.
//   - Unlike ssh.go, it opens no shell. The child is `ssh -N -L`, carrying one
//     loopback-to-loopback port forward and nothing else.
//
// WHAT THIS DOES NOT DO: it does not proxy the remote dashboard's API. Connect
// returns a LOCAL port, and the browser opens the remote dashboard directly
// through the forward. That means the REMOTE install's own auth posture governs
// what happens there — this node lends it no capability class, no session, and
// no confirm token. (Swapping the running SPA's API base in place is a
// materially bigger arc; see the plan's §12 follow-up row.)
//
// AUTHORIZATION SHAPE (identical to ssh.go, deliberately): the client sends a
// profile NAME in the PATH and an empty body. The host, the key, the jump host
// and the remote dashboard port are all resolved from the daemon's own
// operator-authored [[terminal.ssh.profiles]] config. There is no create verb,
// no port parameter, and no way for a request to nominate a destination the
// operator did not write down.

// instanceManager is the OPTIONAL seam this surface asserts on the dashboard's
// LaunchManager, following sshLauncher's precedent exactly: the cmd adapter
// supplies it, a bare test fake does not, and a failed assertion degrades
// HONESTLY (enabled:false on the list, 501 on a verb) rather than panicking.
type instanceManager interface {
	// Instances lists every configured remote instance with its live forward
	// state, plus whether the feature is enabled at all.
	Instances() (enabled bool, instances []InstanceInfo)
	// ConnectInstance opens (or re-uses) the forward for a named profile.
	// Idempotent: a second call for a live forward returns the same port.
	ConnectInstance(name string) (InstanceInfo, error)
	// DisconnectInstance closes a named forward. Idempotent.
	DisconnectInstance(name string) (InstanceInfo, error)
	// TestInstance runs the bounded, non-interactive connectivity probe
	// (known_hosts + auth) for a named profile without opening a forward.
	// Like ConnectInstance it re-validates the profile first, so a request
	// can never probe a machine the operator did not write down.
	TestInstance(name string) (InstanceTestResult, error)
}

// instancesResponse is the list payload. Fail-soft like sshProfilesResponse: an
// unwired seam or a disabled feature both return 200 with enabled=false, so the
// header can simply omit the switcher rather than render an error.
type instancesResponse struct {
	Enabled   bool           `json:"enabled"`
	Instances []InstanceInfo `json:"instances"`
}

// instanceSeam resolves the optional manager, or ok=false when unwired.
func (s *Server) instanceSeam() (instanceManager, bool) {
	if s.opts.LaunchManager == nil {
		return nil, false
	}
	m, ok := s.opts.LaunchManager.(instanceManager)
	return m, ok
}

// handleInstances serves GET /api/instances. Fail-soft: always 200.
func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	seam, ok := s.instanceSeam()
	if !ok {
		writeJSON(w, instancesResponse{Instances: []InstanceInfo{}})
		return
	}
	enabled, instances := seam.Instances()
	if instances == nil {
		// [] rather than null, so the client iterates without a nil guard.
		instances = []InstanceInfo{}
	}
	writeJSON(w, instancesResponse{Enabled: enabled, Instances: instances})
}

// handleInstanceVerb serves POST /api/instances/{name}/connect|disconnect|test.
//
// Fail-CLOSED, exactly like handleSSHLaunch: there is no degraded path. A
// caller named a specific machine, and reporting a port that reaches a
// different one — or reaches nothing — would be worse than refusing.
func (s *Server) handleInstanceVerb(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name, verb, ok := parseInstancePath(r.URL.Path)
	if !ok {
		http.Error(w, "expected /api/instances/{name}/connect, /disconnect or /test", http.StatusNotFound)
		return
	}
	seam, seamOK := s.instanceSeam()
	if !seamOK {
		http.Error(w, "remote instances are not available on this daemon (run via `observer start`)", http.StatusNotImplemented)
		return
	}

	switch verb {
	case "connect":
		// W5.1 org-governed feature gate: node.features.terminals, the SAME gate
		// handleSSHLaunch applies. Connect is a sibling surface over the SAME
		// resource ([[terminal.ssh.profiles]]), and the 2026-08-25 review's P1
		// finding was precisely a family of such siblings that mutated a gated
		// resource without the gate. There is no sandbox lane here, so it
		// presents requestedSandbox=false. Fail-open on a nil gate.
		//
		// DISCONNECT and TEST are deliberately NOT gated, following the same
		// review's rule for the set-allow pair: an org that disabled a
		// capability must never be able to stop a node from turning it OFF
		// (disconnect), and a probe that opens no forward and changes no state
		// is not the capability the gate protects (test).
		if s.opts.TerminalFeatureGate != nil {
			if allowed, reason := s.opts.TerminalFeatureGate(false); !allowed {
				http.Error(w, reason, http.StatusForbidden)
				return
			}
		}
		info, err := seam.ConnectInstance(name)
		if err != nil {
			writeInstanceErr(w, err)
			return
		}
		writeJSON(w, info)
	case "disconnect":
		info, err := seam.DisconnectInstance(name)
		if err != nil {
			writeInstanceErr(w, err)
			return
		}
		writeJSON(w, info)
	case "test":
		result, err := seam.TestInstance(name)
		if err != nil {
			writeInstanceErr(w, err)
			return
		}
		writeJSON(w, result)
	default:
		http.Error(w, "expected /api/instances/{name}/connect, /disconnect or /test", http.StatusNotFound)
	}
}

// writeInstanceErr maps the sentinel class onto a status. Every branch keeps
// the daemon's own message, which is where the honest, actionable reason lives
// (notably the known_hosts guidance).
func writeInstanceErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInstancesDisabled):
		writeSettingRefusal(w, err, http.StatusForbidden)
	case errors.Is(err, ErrInstanceUnknown):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, ErrInstanceInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, ErrInstanceHostKeyUnknown):
		// 409, not 400: the request is well-formed and the profile is valid —
		// the machine's trust state is what is not ready yet, and the operator
		// fixes it outside this request.
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, ErrInstanceForwardFailed):
		http.Error(w, err.Error(), http.StatusBadGateway)
	default:
		http.Error(w, "instance request failed: "+err.Error(), http.StatusInternalServerError)
	}
}

// parseInstancePath splits /api/instances/{name}/{verb}.
//
// The name is URL-decoded here and then matched EXACTLY against the operator's
// profile list downstream, so decoding cannot widen what is reachable: a
// decoded string that is not already a configured name resolves to nothing.
// Exactly two segments are required — no deeper path is a valid verb.
func parseInstancePath(path string) (name, verb string, ok bool) {
	rest := strings.TrimPrefix(path, "/api/instances/")
	if rest == path {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	decoded, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", "", false
	}
	return decoded, parts[1], true
}
