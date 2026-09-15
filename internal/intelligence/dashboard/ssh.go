package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// ssh.go serves the SSH remote-system terminal surface
// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md).
//
// DIRECTION MATTERS. This file is about Observer acting as an SSH CLIENT,
// spawning a shell on a machine the operator has configured. It has nothing to
// do with remote.go / remote_manage.go / remote_tailscale.go, which are about
// exposing THIS dashboard to a paired device. The two share no state.
//
// AUTHORIZATION SHAPE. The client sends a profile NAME. Every connection
// parameter — host, user, port, key path, jump host — is resolved from the
// daemon's own operator-authored config by the application service. There is
// deliberately no create/update/delete verb here: the dashboard SELECTS among
// destinations the operator wrote in config.toml, and can never nominate one.
// Both routes are registered LOCAL-only (see registerRoutes).

// sshLauncher is the OPTIONAL seam this surface asserts on the dashboard's
// LaunchManager, following terminalLimitsSetter's precedent: the cmd adapter
// (launchManagerAdapter) supplies it, a bare test fake does not, and a failed
// assertion degrades HONESTLY — the picker reports enabled:false and a launch
// returns 501 — rather than panicking. Keeping it out of LaunchManager means a
// new launch kind does not force a change on every existing fake.
//
// Note the shape: CreateSSH takes a profile NAME, and there is no writer
// counterpart to SSHProfiles. The dashboard SELECTS among destinations the
// operator authored in config.toml; it can never create one.
type sshLauncher interface {
	// CreateSSH spawns an OUTBOUND SSH remote-system shell. The application
	// service resolves host/user/port/key/jump from the daemon's own config and
	// composes the OpenSSH argv server-side — no connection parameter ever
	// crosses this seam from a client.
	CreateSSH(spec SSHLaunchSpec) (handle string, err error)
	// SSHProfiles lists the operator-configured remote systems for the picker,
	// plus whether the feature is enabled at all. KeyHint is a BASENAME, never
	// the full key path.
	SSHProfiles() (enabled bool, profiles []SSHProfileInfo)
}

// sshSeam resolves the optional launcher, or ok=false when this daemon has no
// SSH surface wired.
func (s *Server) sshSeam() (sshLauncher, bool) {
	if s.opts.LaunchManager == nil {
		return nil, false
	}
	l, ok := s.opts.LaunchManager.(sshLauncher)
	return l, ok
}

// sshProfilesResponse is the picker payload. It is fail-soft: an unwired seam
// or a disabled feature both return 200 with enabled=false, so the New Terminal
// dialog can simply omit the system selector rather than render an error. This
// mirrors GET /api/terminal/sandbox's posture.
type sshProfilesResponse struct {
	Enabled  bool             `json:"enabled"`
	Profiles []SSHProfileInfo `json:"profiles"`
}

// sshLaunchRequest is the launch body. One field, by design — see the
// AUTHORIZATION SHAPE note above.
type sshLaunchRequest struct {
	Profile string `json:"profile"`
}

// sshLaunchResponse mirrors terminalLaunchResponse so the front-end can reuse
// its existing launch plumbing verbatim. HasProjectRoot is always false: an SSH
// session's cwd is on another machine, so the local Files/Git project panels
// have nothing to browse (plan §8). This survived the 2026-08-28 ruling that
// enabled those panels by default for every OTHER launch: the token→root seam
// excludes termrun.KindSSH on run shape, so the daemon-local directory the ssh
// client happens to run in is never presented as this terminal's directory.
type sshLaunchResponse struct {
	Token   string `json:"token"`
	Tool    string `json:"tool"`
	Profile string `json:"profile"`
	Label   string `json:"label"`
}

// handleTerminalSSH serves GET (list profiles) and POST (launch) on
// /api/terminal/ssh.
func (s *Server) handleTerminalSSH(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleSSHProfiles(w, r)
	case http.MethodPost:
		s.handleSSHLaunch(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSSHProfiles lists the operator's configured remote systems. Fail-soft:
// always 200.
func (s *Server) handleSSHProfiles(w http.ResponseWriter, _ *http.Request) {
	seam, ok := s.sshSeam()
	if !ok {
		// Feature absent on this daemon build/wiring. Honest enabled:false, so
		// the New Terminal dialog simply omits the system selector. Profiles
		// marshals as [] (not null) here too, so the client never needs a nil
		// guard on either branch.
		writeJSON(w, sshProfilesResponse{Profiles: []SSHProfileInfo{}})
		return
	}
	enabled, profiles := seam.SSHProfiles()
	if profiles == nil {
		// Marshal as [] rather than null so the client can iterate without a
		// nil guard.
		profiles = []SSHProfileInfo{}
	}
	writeJSON(w, sshProfilesResponse{Enabled: enabled, Profiles: profiles})
}

// handleSSHLaunch spawns the SSH shell.
//
// Unlike handleTerminalLaunch's model picker (fail-OPEN — an unusable model is
// dropped and the launch proceeds with the tool's default), every failure here
// is fail-CLOSED. There is no "connect anyway" degradation for an unknown or
// invalid profile: the caller named a specific machine, and silently reaching a
// different one, or none, would be worse than refusing.
func (s *Server) handleSSHLaunch(w http.ResponseWriter, r *http.Request) {
	seam, ok := s.sshSeam()
	if !ok {
		http.Error(w, "SSH remote-system terminals are not available on this daemon (run via `observer start`)", http.StatusNotImplemented)
		return
	}
	var body sshLaunchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	profile := strings.TrimSpace(body.Profile)
	if profile == "" {
		http.Error(w, "missing profile", http.StatusBadRequest)
		return
	}
	// W5.1 org-governed feature gate: node.features.terminals. An SSH launch
	// has no sandbox lane, so it presents requestedSandbox=false (an org
	// sandbox_required policy therefore denies it) — the same shape
	// handleSessionLaunch uses. Fail-open on a nil gate.
	if s.opts.TerminalFeatureGate != nil {
		if allowed, reason := s.opts.TerminalFeatureGate(false); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	handle, err := seam.CreateSSH(SSHLaunchSpec{Profile: profile})
	if err != nil {
		switch {
		case errors.Is(err, ErrLaunchSSHDisabled):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrLaunchSSHProfileUnknown):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrLaunchSSHProfileInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrLaunchTooMany):
			http.Error(w, err.Error(), http.StatusTooManyRequests)
		case errors.Is(err, ErrLaunchUnsupported):
			http.Error(w, err.Error(), http.StatusNotImplemented)
		default:
			http.Error(w, "launch failed: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, sshLaunchResponse{
		Token: handle, Tool: sshPseudoTool, Profile: profile,
		Label: s.sshProfileLabel(profile),
	})
}

// sshPseudoTool is the reserved tool NAME an SSH session is labelled with in
// the dock and the run history. It mirrors the "shell" pseudo-tool and is never
// a member of the launchable capability set, so it cannot collide with a real
// adapter name. Kept as a local constant so the dashboard package does not
// import termsvc (which owns the authoritative termsvc.SSHTool).
const sshPseudoTool = "ssh"

// sshProfileLabel resolves a profile name to its display label for the terminal
// tab header, so a live SSH tab is never mistaken for a local shell. Falls back
// to the name — never empty, never an error.
func (s *Server) sshProfileLabel(name string) string {
	seam, ok := s.sshSeam()
	if !ok {
		return name
	}
	_, profiles := seam.SSHProfiles()
	for _, p := range profiles {
		if p.Name == name {
			if p.Label != "" {
				return p.Label
			}
			return p.Name
		}
	}
	return name
}
