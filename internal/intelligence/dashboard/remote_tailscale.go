package dashboard

import (
	"errors"
	"net/http"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/remotecfg"
	"github.com/marmutapp/superbased-observer/internal/tailnet"
)

// writeSetupSpawnErr maps a CreateSetup failure to an honest status: the setup
// single-flight refusal is 409 (a privileged PTY of this kind is already
// starting — POST-spam is bounded to one live setup op per kind); anything else
// degrades to 500.
func writeSetupSpawnErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrLaunchSetupInFlight) {
		writeErrStatus(w, err, http.StatusConflict)
		return
	}
	writeErr(w, err)
}

// remote_tailscale.go is the read-only tailnet detection + guidance surface
// (dashboard-management-surface plan §D). It runs `tailscale status --json` via
// internal/tailnet (the ONE owner of the exec, shared with the CLI's
// detectTailnetHost — never reimplemented) and GENERATES the exact
// `tailscale serve` command for the operator to run. Observer NEVER executes
// `tailscale up` or `tailscale serve` itself: the daemon running a privileged
// CLI has real platform variance (on WSL2 the tailnet often runs under Windows
// tailscaled, not the Linux daemon Observer lives in), so guidance + copy is
// the honest cross-platform path. This is stated plainly in the UI.
//
// It is CapabilityView: a paired remote owner may READ detection state, but
// there is nothing to mutate here (the serve command is a string).

// handleRemoteTailscaleStatus serves GET /api/remote/tailscale/status (View).
func (s *Server) handleRemoteTailscaleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := tailnet.Detect(r.Context())

	resp := map[string]any{
		"present":   st.Present,
		"logged_in": st.LoggedIn,
		"host":      st.Host,
		"state":     st.State,
		// Honest guidance the UI surfaces when tailscale is absent.
		"install_url": "https://tailscale.com/download",
		// Observer never runs these — the UI says so (plan §D honesty rule).
		"daemon_runs_serve": false,
	}

	// Resolve the pinned backend port from the armed [remote] config so the
	// serve command targets the real loopback backend. When not armed yet, the
	// backend addr is empty and the UI instructs the operator to arm first.
	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		backendAddr := cfg.Remote.TailscaleBackendAddr
		resp["armed"] = cfg.Remote.Enabled
		resp["backend_addr"] = backendAddr
		if backendAddr != "" {
			port := remotecfg.BackendPortOnly(backendAddr)
			resp["serve_command"] = tailnet.ServeCommand(port)
			if st.Present {
				configured, detectable := tailnet.ServeStatus(r.Context(), port)
				resp["serve_configured"] = configured
				resp["serve_detectable"] = detectable
			}
		}
	}
	writeJSON(w, resp)
}

// tailscaleServeRunner runs `tailscale serve` for the operator. A package var so
// a test can stub it deterministically (the real one execs the tailscale CLI).
var tailscaleServeRunner = tailnet.RunServe

// handleRemoteTailscaleServe serves POST /api/remote/tailscale/serve (Local).
// It runs `tailscale serve --bg <backend-port>` ON THE OPERATOR'S BEHALF
// (operator direction 2026-07-13: automate the copy-and-run step). It is a
// machine-reaching mutation, so it is CapabilityLocal (owner-loopback-only,
// refused on any remote listener) AND confirm-token-gated, exactly like the arm
// verbs. Remote access must be armed first (the backend port is minted at arm);
// if Serve is not yet enabled on the tailnet, the response carries enable_url —
// the one control-plane consent Observer cannot perform — for a one-click link.
func (s *Server) handleRemoteTailscaleServe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	backendAddr := cfg.Remote.TailscaleBackendAddr
	if backendAddr == "" {
		http.Error(w, `{"error":"arm remote access first — the tailscale serve target is the backend port minted at arm time"}`, http.StatusBadRequest)
		return
	}
	res := tailscaleServeRunner(r.Context(), remotecfg.BackendPortOnly(backendAddr))
	writeJSON(w, map[string]any{
		"ok":              res.OK,
		"enable_url":      res.EnableURL,
		"needs_privilege": res.NeedsPrivilege,
		"output":          res.Output,
		"error":           res.Err,
	})
}

// handleRemoteTailscaleOperatorGrant serves POST /api/remote/tailscale/operator-grant
// (Local + confirm-gated). It spawns the one-time Tailscale operator grant
// (`sudo tailscale set --operator=<daemon-user>`) in the in-dashboard PTY so the
// user types their sudo password ONCE — after which the non-root daemon's own
// `tailscale serve` (handleRemoteTailscaleServe) works with no sudo forever.
// The daemon username is resolved server-side (tailnet.CurrentDaemonUser — never
// request input); a root daemon is refused (the grant is moot). The spawned
// session is SpecSetup → local-writer-only, so a paired remote principal can
// never drive it. Returns the PTY handle the frontend opens /ws/launch/<handle>
// against.
func (s *Server) handleRemoteTailscaleOperatorGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.LaunchManager == nil {
		// Q16: the setup PTY here is exactly as ConPTY-capable as the New
		// Terminal launch path since 2026-07-04 — reuse errTerminalUnavailable
		// (audit DI-16) instead of the stale "run under WSL/Linux" claim.
		http.Error(w, `{"error":"`+errTerminalUnavailable+`, or run `+"`sudo tailscale set --operator=<you>`"+` manually"}`, http.StatusServiceUnavailable)
		return
	}
	user, isRoot, err := tailnet.CurrentDaemonUser()
	if err != nil {
		writeErr(w, err)
		return
	}
	if isRoot {
		http.Error(w, `{"error":"the daemon already runs as root — tailscale serve needs no grant; click \"Set up serve for me\""}`, http.StatusBadRequest)
		return
	}
	argv := tailnet.OperatorGrantArgv(user)
	handle, err := s.opts.LaunchManager.CreateSetup(SetupSpec{
		Argv:  argv,
		Label: "tailscale-operator-grant",
	})
	if err != nil {
		writeSetupSpawnErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"handle":  handle,
		"user":    user,
		"command": strings.Join(argv, " "),
	})
}

// handleRemoteTailscaleLogin serves POST /api/remote/tailscale/login
// (Local + confirm-gated). It spawns the interactive Tailscale login
// (`tailscale up`, sudo-prefixed unless the daemon is root) in the in-dashboard
// PTY so the auth URL `tailscale up` prints is shown right there — the user
// opens it on their phone/browser to complete login. The argv is fully
// server-derived from tailnet.LoginArgv (the ONLY decision, sudo-vs-not, is
// resolved from the daemon identity, never request input); the spawned session
// is SpecSetup → local-writer-only, so a paired remote principal can never
// drive it. Unlike the operator grant it is valid for BOTH a root and a
// non-root daemon (login is not moot as root), so there is no root refusal.
// Returns the PTY handle the frontend opens /ws/launch/<handle> against.
func (s *Server) handleRemoteTailscaleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.LaunchManager == nil {
		// Q16: same reasoning as handleRemoteTailscaleOperatorGrant above.
		http.Error(w, `{"error":"`+errTerminalUnavailable+`, or run `+"`tailscale up`"+` manually"}`, http.StatusServiceUnavailable)
		return
	}
	_, isRoot, err := tailnet.CurrentDaemonUser()
	if err != nil {
		writeErr(w, err)
		return
	}
	argv := tailnet.LoginArgv(isRoot)
	handle, err := s.opts.LaunchManager.CreateSetup(SetupSpec{
		Argv:  argv,
		Label: "tailscale-login",
	})
	if err != nil {
		writeSetupSpawnErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"handle":  handle,
		"command": strings.Join(argv, " "),
	})
}

// handleRemoteTailscaleInstall serves POST /api/remote/tailscale/install
// (Local + confirm-gated). It spawns the official Tailscale Linux install
// script (`sudo sh -c 'curl -fsSL --proto '=https' --tlsv1.2 https://tailscale.com/install.sh | sh'`) in
// the in-dashboard PTY so the sudo password is typed once, right there. The
// argv is a FIXED closed enum (tailnet.InstallArgv) — no request input reaches
// it; the spawned session is SpecSetup → local-writer-only. It is refused
// unless the daemon runs on Linux (the script is Linux-only) AND tailscale is
// not already present (installing over an existing binary is pointless). On
// WSL the tailnet may be owned by a Windows-side Tailscale, but Observer needs
// the Linux binary the daemon itself lives beside, so a Linux install is still
// the right target here. Returns the PTY handle for /ws/launch/<handle>.
func (s *Server) handleRemoteTailscaleInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	if runtime.GOOS != "linux" {
		http.Error(w, `{"error":"the guided install runs the Linux install script — install Tailscale on the machine that owns your tailnet, or use the download link"}`, http.StatusBadRequest)
		return
	}
	if tailnet.Detect(r.Context()).Present {
		http.Error(w, `{"error":"tailscale is already installed — no install needed"}`, http.StatusBadRequest)
		return
	}
	if s.opts.LaunchManager == nil {
		// Q16: same reasoning as handleRemoteTailscaleOperatorGrant above.
		http.Error(w, `{"error":"`+errTerminalUnavailable+`, or install Tailscale manually"}`, http.StatusServiceUnavailable)
		return
	}
	// Re-check presence at the FINAL spawn boundary (not just the early advisory
	// check above) to close the check-vs-spawn TOCTOU: a tailscale that appeared
	// between the two checks (a concurrent install, a package landing) means the
	// install PTY is pointless — refuse rather than run curl|sh over an existing
	// binary. The setup single-flight (Label below) closes the concurrent-POST
	// race; this closes the slower "installed out-of-band" race.
	if tailnet.Detect(r.Context()).Present {
		http.Error(w, `{"error":"tailscale is already installed — no install needed"}`, http.StatusBadRequest)
		return
	}
	argv := tailnet.InstallArgv()
	handle, err := s.opts.LaunchManager.CreateSetup(SetupSpec{
		Argv:  argv,
		Label: "tailscale-install",
	})
	if err != nil {
		writeSetupSpawnErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"handle":  handle,
		"command": strings.Join(argv, " "),
	})
}
