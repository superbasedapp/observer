//go:build !sbo_omit_remote

package dashboard

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/remotecfg"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/tailnet"
)

// handleRemoteConfig — GET /api/remote/config (View). Reports the armed/disarmed
// [remote] state + backend addr + a MASKED secret fingerprint (never the
// secret, §11), mints a fresh double-submit confirm token (§10), and reports
// whether management is possible (config path writable) and whether a live
// controller is bound (sessions manageable without a restart). NEVER returns the
// pairing secret or URL.
func (s *Server) handleRemoteConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := setConfirmCookie(w, r)

	resp := map[string]any{
		"confirm_token":   token,
		"config_writable": s.opts.ConfigPath != "",
		// live controller ⇒ sessions can be revoked instantly (no restart, §C).
		"controller_live":                s.opts.Remote != nil,
		"enabled":                        false,
		"mode":                           "off",
		"require_tls":                    true,
		"allow_terminal":                 false,
		"allow_terminal_view":            false,
		"allow_remote_terminal_takeover": true,
		"revoke_standing_on_takeover":    false,
		"trusted_hosts":                  []string{},
		"secret_present":                 false,
		"secret_fingerprint":             "",
		"ready":                          s.opts.Remote != nil && s.opts.Remote.Ready(),
	}

	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		rc := cfg.Remote
		resp["enabled"] = rc.Enabled
		resp["mode"] = rc.Mode
		resp["require_tls"] = rc.RequireTLS
		resp["allow_terminal"] = rc.AllowTerminal
		resp["allow_terminal_view"] = rc.AllowTerminalView
		resp["allow_remote_terminal_takeover"] = rc.AllowRemoteTerminalTakeover
		resp["revoke_standing_on_takeover"] = rc.RevokeStandingOnTakeover
		resp["backend_addr"] = rc.TailscaleBackendAddr
		if rc.TrustedHosts != nil {
			resp["trusted_hosts"] = rc.TrustedHosts
		}
		resp["rate_limit_per_min"] = rc.RateLimitPerMin
		// Device cap ([remote] max_sessions, default 5) so the panel can tell
		// the operator how many devices "Add a device" can pair before the cap.
		resp["max_sessions"] = rc.MaxSessions
		// Masked fingerprint of the secret hash-at-rest (NEVER the secret): a
		// short prefix of the argon2id hash so the operator can confirm a secret
		// is provisioned + tell two apart, with no credential value.
		if fp := readSecretFingerprint(cfg); fp != "" {
			resp["secret_present"] = true
			resp["secret_fingerprint"] = fp
		}
	}
	writeJSON(w, resp)
}

// readSecretFingerprint returns a short non-sensitive fingerprint of the pairing
// secret hash-at-rest (the argon2id hash's last 8 hex chars of its own SHA is
// overkill — we simply take a short middle slice of the stored hash string,
// which is itself a one-way hash, never the secret). Empty when no secret file.
func readSecretFingerprint(cfg config.Config) string {
	path := remotecfg.SecretPath(cfg)
	b, err := readFileTrimmed(path)
	if err != nil || b == "" {
		return ""
	}
	// The stored value is an argon2id hash ($argon2id$...$hash). Show the last 8
	// chars of the encoded hash — a stable, non-reversible display token.
	if len(b) <= 8 {
		return "…"
	}
	return "…" + b[len(b)-8:]
}

// handleRemoteEnable — POST /api/remote/enable (Local). Arms remote access via
// the shared remotecfg seam and returns the pairing URL + secret in the RESPONSE
// ONLY (§11). The confirm token is checked FIRST (§10).
// enableHostDetector resolves the tailnet HTTPS host when the enable request
// carries none — the CLI-parity auto-detect (internal/tailnet is the one owner
// of the `tailscale` exec). A package var so a test can force the no-host
// precondition deterministically regardless of whether the runner has Tailscale.
var enableHostDetector = func(ctx context.Context) string { return tailnet.Detect(ctx).Host }

// reloadLiveSecret re-reads the freshly-written pairing-secret hash from disk
// and swaps it into the running controller, so a dashboard rotate/enable takes
// effect without a daemon restart. Best-effort: a read failure leaves the old
// secret in place (the operator can still restart).
func (s *Server) reloadLiveSecret(cfg config.Config) {
	if s.opts.Remote == nil {
		return
	}
	b, err := os.ReadFile(remotecfg.SecretPath(cfg))
	if err != nil {
		return
	}
	s.opts.Remote.ReloadSecret(strings.TrimSpace(string(b)))
}

func (s *Server) handleRemoteEnable(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	// W5.1 org-governed feature gate: node.features.remote. Fail-open (nil
	// FeatureGate, or no accepted policy) — see dashboard.Options.FeatureGate.
	if s.opts.FeatureGate != nil {
		if allowed, reason := s.opts.FeatureGate(nodeFeatureRemote); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	var body struct {
		Host          string `json:"host"`
		AllowTerminal bool   `json:"allow_terminal"`
		// Pointer so an OMITTED field inherits the loaded/seed default (now
		// true) instead of clobbering it to false. The Arm form omits it; the
		// dedicated /api/remote/allow-terminal-view toggle owns explicit flips.
		AllowTerminalView *bool `json:"allow_terminal_view"`
	}
	_ = decodeJSONBody(r, &body)
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	// Fix 2: the config read-modify-write below joins the configWriteMu domain
	// (lock order remoteManageMu → configWriteMu; see remoteManageMu decl).
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()
	cfg, cfgPath, err := s.loadConfigForManage()
	if err != nil {
		writeErr(w, err)
		return
	}
	host := strings.TrimSpace(body.Host)
	if host == "" {
		host = firstNonEmpty(cfg.Remote.TrustedHosts)
	}
	if host == "" {
		// No explicit host and none previously trusted — auto-detect the tailnet
		// HTTPS host the same way the CLI does (the ONE owner of the exec). This
		// is what makes "Arm" just work when Tailscale is up: the Tailscale card
		// already shows this host; the form should not force a re-type.
		host = strings.TrimSpace(enableHostDetector(r.Context()))
	}
	if host == "" {
		// Still nothing: this is a precondition, not a server fault — 400 with a
		// friendly message the panel renders, never a raw 500.
		http.Error(w, `{"error":"no tailnet host: run 'tailscale up' (the Tailscale card shows the detected host), or type the HTTPS host tailscale serve exposes"}`, http.StatusBadRequest)
		return
	}
	info, err := remotecfg.Enable(cfg, cfgPath, remotecfg.EnableOptions{Host: host, AllowTerminal: body.AllowTerminal, AllowTerminalView: body.AllowTerminalView})
	if err != nil {
		writeErr(w, err)
		return
	}
	// LIVE-STATE TRANSITIONS FIRST, AUDIT AFTER (F3, mirroring handleRemoteDisable
	// / handleRemoteSetAllowTerminalView): the best-effort recordManageAudit can
	// block up to 3s on SQLite, so a re-arm that disables terminal write / view
	// must tear the writers + viewers down BEFORE that insert — never leave
	// sensitive PTY output streaming for the duration of a blocked audit write.
	//
	// If a controller is already live (re-arm without a prior disable), hot-reload
	// the new secret so a fresh QR pairs immediately. A first arm from disabled
	// has no live controller yet — the backend listener binds on the restart.
	if s.opts.Remote != nil {
		s.reloadLiveSecret(cfg)
	}
	// A re-arm that sets allow_terminal=false is an allow_terminal→false
	// transition: any live remote writer must be revoked NOW (§8.1 item 8), not
	// left driving the PTY until the next acquire. The local writer is untouched.
	// The STANDING verifier follows allow_terminal (finding 3): hot-disable it
	// first (generation fence), or restore it from the persisted config when the
	// re-arm keeps terminal access on.
	s.reloadLiveAllowTerminal(info.AllowTerminal)
	if !info.AllowTerminal {
		s.reloadLiveStandingSecret(cfg, false)
		s.revokeRemoteWriters("allow_terminal disabled")
	} else {
		s.reloadLiveStandingSecret(cfg, cfg.Remote.AllowStandingTerminalControl)
	}
	// The remote-VIEW opt-in follows the same posture: hot-swap the live gate,
	// and on a re-arm that leaves it off, close any already-open remote-sensitive
	// viewer NOW (§3.2 read-side revoke) — BEFORE the audit write.
	s.reloadLiveAllowTerminalView(info.AllowTerminalView)
	if !info.AllowTerminalView {
		s.closeRemoteSensitiveViewers()
	}
	// Audit LAST, once the live state is already safe (F3).
	s.recordManageAudit(r, "enable", host)
	writeJSON(w, map[string]any{
		"ok":                  true,
		"restart_required":    true, // §C: arm needs a daemon restart to bind the backend
		"host":                info.Host,
		"backend_addr":        info.BackendAddr,
		"allow_terminal":      info.AllowTerminal,
		"allow_terminal_view": info.AllowTerminalView,
		"tailscale_serve":     "tailscale serve --bg " + remotecfg.BackendPortOnly(info.BackendAddr),
		// The secret + pairing URL cross the wire ONLY here (§11).
		"pairing_url":    info.PairingURL,
		"pairing_secret": info.EncodedSecret,
	})
}

// handleRemoteSetAllowTerminal — POST /api/remote/allow-terminal (Local).
// Flips ONLY [remote].allow_terminal on an already-armed controller, WITHOUT
// touching the pairing secret, backend port, trusted hosts, or paired-device
// sessions. This is deliberately NOT the re-arm path (handleRemoteEnable):
// remotecfg.Enable unconditionally mints a FRESH pairing secret (invalidating
// the current one-time QR), which is the wrong side effect for a plain policy
// toggle. Here we mutate exactly one config field, re-validate, and persist.
//
// allow_terminal now HOT-RELOADS with no daemon restart: reloadLiveAllowTerminal
// swaps the live gate (remoteController.ReloadAllowTerminal) that BOTH the
// HTTP terminal-launch gate (remote.go rc.AllowTerminal()) and the acquire-path
// authorizer (the cmd adapter's allowTerminal() closure — read at gate time AND
// re-fenced in the post-install recheck) consult, and the standing verifier is
// hot-flipped in lockstep. No authorization consumer reads a construction-time
// snapshot anymore, so restart_required is FALSE on success. The security-
// critical allow_terminal→false transition takes effect immediately: any live
// remote terminal writer is revoked NOW (§8.1 item 8), the live gate refuses new
// acquires, and an in-flight acquire that read allow_terminal=true at gate time
// is torn down by the recheck. The owner-local writer is untouched.
func (s *Server) handleRemoteSetAllowTerminal(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	// Strict decode: this endpoint has exactly ONE required decision field, and
	// a silently-defaulted zero value would mean "disable + revoke live writers"
	// on a malformed/empty body. Pointer + presence check → 400, never a default.
	var body struct {
		AllowTerminal *bool `json:"allow_terminal"`
	}
	if err := decodeJSONBody(r, &body); err != nil || body.AllowTerminal == nil {
		http.Error(w, `{"error":"body must be JSON with a boolean allow_terminal field"}`, http.StatusBadRequest)
		return
	}
	next := *body.AllowTerminal
	// W5.1 org-governed feature gate: node.features.remote — gates only the
	// ENABLE direction (an org that disabled remote must never block a node
	// from turning a remote capability OFF). Fail-open on nil gate.
	if next && s.opts.FeatureGate != nil {
		if allowed, reason := s.opts.FeatureGate(nodeFeatureRemote); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	// Fix 2: the config read-modify-write below joins the configWriteMu domain
	// (lock order remoteManageMu → configWriteMu; see remoteManageMu decl).
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()
	cfg, cfgPath, err := s.loadConfigForManage()
	if err != nil {
		writeErr(w, err)
		return
	}
	if !cfg.Remote.Enabled {
		// Terminal policy is meaningless while remote is off — the arm form
		// carries the allow_terminal checkbox for the disabled case. 400 (a
		// precondition, not a server fault) with a panel-renderable message.
		writeNeedsSetting(w, http.StatusBadRequest, "remote access is off - arm remote access first (the arm form has the terminal option)", msgRemoteOffTerminal, settingslink.RemoteAccess)
		return
	}
	cfg.Remote.AllowTerminal = next
	if err := config.Validate(cfg); err != nil {
		writeErr(w, err)
		return
	}
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		writeErr(w, err)
		return
	}
	// allow_terminal→false: revoke every live remote writer IMMEDIATELY after
	// the persist (§8.1 item 8) — BEFORE the best-effort audit write, which can
	// block up to 3s on SQLite; a device driving a PTY must not keep control for
	// the duration of a slow audit insert. Same ordering as handleRemoteRotate.
	//
	// The STANDING verifier is hot-flipped too (finding 3): the running
	// controller's allowTerminal snapshot is construction-bound, so without
	// this a paired device holding the reusable standing secret would simply
	// reopen a socket and REACQUIRE control after the kill. Hot-disabling the
	// verifier (which also bumps the standing generation — fencing in-flight
	// verifies) makes allow_terminal→false actually stop standing acquisition
	// NOW; flipping back on restores it from the persisted config + hash file.
	// Hot-swap the LIVE allow_terminal gate so BOTH the single-use and standing
	// acquire paths honour the flip immediately (finding 3 residual).
	s.reloadLiveAllowTerminal(next)
	if !next {
		s.reloadLiveStandingSecret(cfg, false)
		s.revokeRemoteWriters("allow_terminal disabled")
	} else {
		s.reloadLiveStandingSecret(cfg, cfg.Remote.AllowStandingTerminalControl)
	}
	detail := "disabled"
	if next {
		detail = "enabled"
	}
	s.recordManageAudit(r, "allow-terminal", detail)
	writeJSON(w, map[string]any{
		"ok":               true,
		"restart_required": false, // allow_terminal hot-reloads onto the live gate + standing verifier (no restart)
		"allow_terminal":   next,
	})
}

// handleRemoteSetAllowTerminalView — POST /api/remote/allow-terminal-view
// (Local). Flips ONLY [remote].allow_terminal_view on an already-armed
// controller, WITHOUT touching the pairing secret, backend port, trusted hosts,
// paired-device sessions, or allow_terminal (write). It mirrors
// handleRemoteSetAllowTerminal exactly, one config field narrower: this is the
// independent READ opt-in that lets a remote paired device SEE / read-only-
// subscribe to a remote-sensitive (attach/resume) terminal (session-attach
// design §3.2). It is STRICTLY WEAKER than allow_terminal — turning it on grants
// no write authority; driving such a session still requires allow_terminal AND
// the execute-tier writer-acquire conjunction.
//
// allow_terminal_view HOT-RELOADS with no daemon restart: reloadLiveAllowTerminalView
// swaps the live VIEW gate the dashboard boundary reads on every request
// (visibleSnapshot + the /ws/launch subscribe gate). The security-critical
// →false transition takes effect immediately: the live gate refuses NEW
// remote-sensitive views AND every ALREADY-OPEN remote-sensitive viewer is torn
// down NOW (closeRemoteSensitiveViewers) — the READ analogue of the
// revoke-kills-open-writers invariant. The owner-local (loopback) viewers are
// never registered, so they are untouched.
func (s *Server) handleRemoteSetAllowTerminalView(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	// Strict decode: exactly ONE required decision field; a silently-defaulted
	// zero value would mean "disable + close live viewers" on a malformed/empty
	// body. Pointer + presence check → 400, never a default.
	var body struct {
		AllowTerminalView *bool `json:"allow_terminal_view"`
	}
	if err := decodeJSONBody(r, &body); err != nil || body.AllowTerminalView == nil {
		http.Error(w, `{"error":"body must be JSON with a boolean allow_terminal_view field"}`, http.StatusBadRequest)
		return
	}
	next := *body.AllowTerminalView
	// W5.1 enable-only remote feature gate — same rationale as
	// handleRemoteSetAllowTerminal above.
	if next && s.opts.FeatureGate != nil {
		if allowed, reason := s.opts.FeatureGate(nodeFeatureRemote); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	// Fix 2: the config read-modify-write below joins the configWriteMu domain
	// (lock order remoteManageMu → configWriteMu; see remoteManageMu decl).
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()
	cfg, cfgPath, err := s.loadConfigForManage()
	if err != nil {
		writeErr(w, err)
		return
	}
	if !cfg.Remote.Enabled {
		// Terminal-view policy is meaningless while remote is off. 400 (a
		// precondition, not a server fault) with a panel-renderable message.
		writeNeedsSetting(w, http.StatusBadRequest, "remote access is off - arm remote access first", msgRemoteOff, settingslink.RemoteAccess)
		return
	}
	cfg.Remote.AllowTerminalView = next
	if err := config.Validate(cfg); err != nil {
		writeErr(w, err)
		return
	}
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		writeErr(w, err)
		return
	}
	// Hot-swap the LIVE VIEW gate so BOTH the snapshot redaction and the
	// /ws/launch subscribe gate honour the flip immediately. On →false, close
	// every already-open remote-sensitive viewer NOW (before the best-effort
	// audit write, which can block up to 3s on SQLite) so a device reading a
	// secret-bearing attach/resume TUI loses the stream immediately.
	s.reloadLiveAllowTerminalView(next)
	if !next {
		s.closeRemoteSensitiveViewers()
	}
	detail := "disabled"
	if next {
		detail = "enabled"
	}
	s.recordManageAudit(r, "allow-terminal-view", detail)
	writeJSON(w, map[string]any{
		"ok":                  true,
		"restart_required":    false, // allow_terminal_view hot-reloads onto the live VIEW gate (no restart)
		"allow_terminal_view": next,
	})
}

// reloadLiveAllowTerminalView hot-swaps the LIVE allow_terminal_view gate on the
// running controller so a dashboard flip immediately relaxes/refuses the remote
// VIEW gate without a daemon restart (mirrors reloadLiveAllowTerminal).
// Best-effort: a nil/non-implementing controller is a no-op.
func (s *Server) reloadLiveAllowTerminalView(allow bool) {
	if rl, ok := s.opts.Remote.(allowTerminalViewReloader); ok {
		rl.ReloadAllowTerminalView(allow)
	}
}

// handleRemoteDisable — POST /api/remote/disable (Local).
func (s *Server) handleRemoteDisable(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	// Fix 2: the config read-modify-write below joins the configWriteMu domain
	// (lock order remoteManageMu → configWriteMu; see remoteManageMu decl).
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()
	cfg, cfgPath, err := s.loadConfigForManage()
	if err != nil {
		writeErr(w, err)
		return
	}
	// KILL LIVE ACCESS FIRST, unconditionally (finding 2 residual): hot-disable
	// the standing verifier + the LIVE allow_terminal gate (so both acquire
	// paths refuse) and kill every live remote writer BEFORE the durable
	// Disable. Previously Disable (config persist + secret unlink) ran first and
	// returned early on error, leaving the running verifier + writers alive on
	// any persist/unlink failure — a fail-open 500. The standing reload also
	// bumps the generation, fencing any in-flight verify. The owner-local writer
	// survives.
	s.reloadLiveAllowTerminal(false)
	s.reloadLiveStandingSecret(cfg, false)
	s.revokeRemoteWriters("remote disabled")
	// The remote-VIEW gate dies with remote access too: refuse new sensitive
	// views and tear down any already-open one (§3.2 read-side revoke).
	s.reloadLiveAllowTerminalView(false)
	s.closeRemoteSensitiveViewers()
	removed, err := remotecfg.Disable(cfg, cfgPath)
	if err != nil {
		// Live access is already dead; report only the durable-half failure so
		// the operator retries (config still says enabled=true on disk, so a
		// restart WOULD resurrect — the 500 makes that loud).
		s.recordManageAudit(r, "disable", "live-off (persist failed)")
		writeErr(w, err)
		return
	}
	s.recordManageAudit(r, "disable", "")
	writeJSON(w, map[string]any{
		"ok":               true,
		"restart_required": true, // §C
		"secret_removed":   removed,
	})
}

// handleRemoteRotate — POST /api/remote/rotate (Local). Returns a fresh pairing
// URL + secret in the response ONLY (§11); no rotate-on-view.
func (s *Server) handleRemoteRotate(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	// Fix 2: the config read-modify-write below joins the configWriteMu domain
	// (lock order remoteManageMu → configWriteMu; see remoteManageMu decl).
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()
	cfg, cfgPath, err := s.loadConfigForManage()
	if err != nil {
		writeErr(w, err)
		return
	}
	info, err := remotecfg.Rotate(cfg, cfgPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	// Hot-reload the LIVE controller so the fresh secret takes effect without a
	// restart, and invalidate every already-paired device (the old secret is
	// gone → re-pair). This makes "rotate → scan QR → pair" work in one shot: the
	// running controller now verifies against the new secret, so no restart is
	// needed and the one-time QR no longer has to survive one.
	restartRequired := true
	if s.opts.Remote != nil {
		_ = s.opts.Remote.RotateSessions()
		s.reloadLiveSecret(cfg)
		restartRequired = false
	}
	// RotateSessions invalidates the device SESSIONS; ALSO revoke every live
	// remote writer LEASE so a device currently driving a PTY loses control at
	// rotate time (§8.1 item 8), not only on its next acquire. Local untouched.
	s.revokeRemoteWriters("remote rotated")
	// Secret rotation invalidates every paired device, so close every already-
	// open read-only sensitive viewer too (F2): a device whose session was just
	// invalidated must not keep reading attach/resume PTY output.
	s.closeRemoteSensitiveViewers()
	s.recordManageAudit(r, "rotate", "")
	writeJSON(w, map[string]any{
		"ok":               true,
		"restart_required": restartRequired,
		"host":             info.Host,
		"pairing_url":      info.PairingURL,
		"pairing_secret":   info.EncodedSecret,
	})
}

// handleRemoteAddDevice — POST /api/remote/add-device (Local). Mints a FRESH
// pairing secret + QR so an ADDITIONAL device can pair, WITHOUT unpairing the
// devices already connected. It is the same mint-and-hot-reload path as rotate
// (§11: the raw secret rides ONLY this POST response) MINUS the RotateSessions
// kill — already-paired devices authenticate by their persisted session cookie
// (remoteauth.SessionStore.Validate), which is independent of the pairing
// secret, so swapping the secret leaves their sessions valid. The previous
// one-time QR simply stops working (its device already holds a cookie). The new
// device is bounded by [remote] max_sessions (default 5). Distinct from
// handleRemoteRotate, which is the DESTRUCTIVE "unpair everyone" control.
func (s *Server) handleRemoteAddDevice(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	// W5.1 org-governed feature gate: node.features.remote. Fail-open (nil
	// FeatureGate, or no accepted policy) — see dashboard.Options.FeatureGate.
	if s.opts.FeatureGate != nil {
		if allowed, reason := s.opts.FeatureGate(nodeFeatureRemote); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	// Fix 2: the config read-modify-write below joins the configWriteMu domain
	// (lock order remoteManageMu → configWriteMu; see remoteManageMu decl).
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()
	cfg, cfgPath, err := s.loadConfigForManage()
	if err != nil {
		writeErr(w, err)
		return
	}
	info, err := remotecfg.Rotate(cfg, cfgPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	// Hot-reload the live controller to the fresh secret so the new QR pairs
	// immediately, but DELIBERATELY do not RotateSessions() — the whole point is
	// to keep existing devices connected.
	restartRequired := true
	if s.opts.Remote != nil {
		s.reloadLiveSecret(cfg)
		restartRequired = false
	}
	s.recordManageAudit(r, "pair-device", "")
	writeJSON(w, map[string]any{
		"ok":               true,
		"restart_required": restartRequired,
		"host":             info.Host,
		"pairing_url":      info.PairingURL,
		"pairing_secret":   info.EncodedSecret,
	})
}

// approveExecuteRequest is the POST /api/remote/approve-execute body: the LOCAL
// operator names the target device (by the truncated fingerprint the sessions
// list surfaces) + the terminal handle to approve control of. No secret is ever
// accepted here — the capability + confirm are MINTED and returned.
type approveExecuteRequest struct {
	Device string `json:"device"` // device-session fingerprint (from /api/remote/sessions)
	Handle string `json:"handle"` // terminal session handle to grant control of
}

// handleRemoteApproveExecute — POST /api/remote/approve-execute (Local, §4.γ/§6).
// The LOCAL approval step of the execute tier: it mints a SINGLE-USE terminal-
// control capability + a bound confirm nonce (memory-only, restart-invalidated)
// for (target device session, terminal handle) and returns BOTH in the RESPONSE
// BODY ONLY — never a URL, header, log, GET, or side channel (§8.1 #5). It is
// owner-loopback-only (CapabilityLocal): a remote principal is refused before
// its principal is even resolved, so it can never self-approve. The operator
// then conveys the capability + confirm to the remote device (the SPA writer
// dialog / §6), which supplies them on the /ws/launch acquire-writer frame; the
// §4.δ conjunction (termlease.Authorize) consumes them at lease-acquire time.
func (s *Server) handleRemoteApproveExecute(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	// W5.1 org-governed feature gate: node.features.remote. Checked before
	// any side effect. Fail-open on nil gate / no accepted policy.
	if s.opts.FeatureGate != nil {
		if allowed, reason := s.opts.FeatureGate(nodeFeatureRemote); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	if s.opts.Remote == nil {
		writeNeedsSetting(w, http.StatusServiceUnavailable, "remote access is not configured", msgRemoteNotSetUp, settingslink.RemoteAccess)
		return
	}
	authz, ok := s.opts.Remote.(TerminalControlAuthorizer)
	if !ok {
		// Fail closed: no mint surface without the concrete substrate.
		http.Error(w, "execute-tier approval is unavailable", http.StatusServiceUnavailable)
		return
	}
	var body approveExecuteRequest
	_ = decodeJSONBody(r, &body)
	handle := strings.TrimSpace(body.Handle)
	fp := strings.TrimSpace(body.Device)
	if handle == "" || fp == "" {
		http.Error(w, "device (fingerprint) and handle are required", http.StatusBadRequest)
		return
	}
	// Resolve the fingerprint → the device-session HASH server-side (never trust a
	// client-supplied full/raw id). The hash is exactly what MintTerminalControl
	// stores and what ConsumeTerminalControl (raw cookie → hash) compares against.
	var hashID string
	for _, si := range s.opts.Remote.Sessions() {
		if si.Fingerprint == fp {
			hashID = si.ID
			break
		}
	}
	if hashID == "" {
		http.Error(w, "no such device session", http.StatusNotFound)
		return
	}
	tok, confirm, err := authz.MintTerminalControl(hashID, handle)
	if err != nil {
		http.Error(w, "could not mint execute capability", http.StatusInternalServerError)
		return
	}
	// Typed execute-tier audit: the LOCAL operator approved an execute
	// capability for (device fingerprint, terminal handle). The minted
	// capability + confirm are DELIBERATELY absent — only the correlation
	// metadata is recorded (plan §8.1).
	s.recordRemoteAuditRow(store.RemoteAuditEvent{
		Kind:       "terminal_control_local_approval",
		SessionID:  fp,      // device fingerprint (hash[:8]) — correlates with the acquire events
		Principal:  "local", // owner-loopback approval
		RemoteAddr: hostnameOnly(r.RemoteAddr),
		Route:      handle, // the opaque terminal session handle
		Decision:   "ok",
		Detail:     "approved",
	})
	// The capability + confirm cross the wire ONLY in this local response body.
	writeJSON(w, map[string]any{
		"ok":         true,
		"device":     fp,
		"handle":     handle,
		"capability": tok,
		"confirm":    confirm,
	})
}

// standingTerminalWarning is the FIRM security warning shown at mint AND on the
// standing-access section (standing-terminal-access §B). It is the canonical
// copy the dashboard renders verbatim.
const standingTerminalWarning = "Standing access means ANYONE who has this secret AND a paired remote session can take control of EVERY live terminal - including one currently controlled by the native/local seat or another remote when remote takeover is enabled - across page refreshes, until you revoke it. It is stored hashed on this machine, but a device may keep the raw secret in its browser localStorage so control survives a refresh - treat it like a password. Per-terminal single-use approvals (the default above) are safer: they grant one device control of one terminal until its socket closes. Revoke standing access below to kill the secret and drop every writer holding control through it right now."

// readStandingSecretFingerprint returns a short, non-sensitive fingerprint of
// the standing terminal-control secret hash-at-rest (never the secret), mirroring
// readSecretFingerprint. Empty when no standing secret file exists.
func readStandingSecretFingerprint(cfg config.Config) string {
	b, err := readFileTrimmed(remotecfg.StandingTerminalSecretPath(cfg))
	if err != nil || b == "" {
		return ""
	}
	if len(b) <= 8 {
		return "…"
	}
	return "…" + b[len(b)-8:]
}

// reloadLiveStandingSecret re-reads the standing secret hash from disk and swaps
// it (with the enabled gate) into the running controller so a dashboard
// mint/revoke takes effect without a restart. On revoke pass enabled=false; the
// caller ensures the file is already gone so the reload clears the live hash.
func (s *Server) reloadLiveStandingSecret(cfg config.Config, enabled bool) {
	rl, ok := s.opts.Remote.(standingTerminalReloader)
	if !ok {
		return
	}
	hash := ""
	if enabled {
		if b, err := readFileTrimmed(remotecfg.StandingTerminalSecretPath(cfg)); err == nil {
			hash = b
		}
	}
	rl.ReloadStandingTerminalSecret(hash, enabled)
}

// reloadLiveAllowTerminal hot-swaps the LIVE allow_terminal gate on the running
// controller so an allow_terminal→false / remote-disable immediately refuses
// BOTH the single-use and standing acquire paths without a daemon restart
// (finding 3 residual). Best-effort: a nil/fake controller is a no-op.
func (s *Server) reloadLiveAllowTerminal(allow bool) {
	if rl, ok := s.opts.Remote.(allowTerminalReloader); ok {
		rl.ReloadAllowTerminal(allow)
	}
}

// handleStandingTerminalStatus — GET /api/remote/standing-terminal (View).
// Reports whether the OPT-IN standing terminal-control secret is enabled +
// present (masked fingerprint only, NEVER the secret), whether the panel can
// manage it (writable config), and the canonical warning copy. Read-only.
func (s *Server) handleStandingTerminalStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]any{
		"enabled":                        false,
		"secret_present":                 false,
		"secret_fingerprint":             "",
		"allow_terminal":                 false,
		"allow_remote_terminal_takeover": true,
		"remote_enabled":                 false,
		"config_writable":                s.opts.ConfigPath != "",
		"warning":                        standingTerminalWarning,
		"revoke_on_takeover":             false,
	}
	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		resp["enabled"] = cfg.Remote.AllowStandingTerminalControl
		resp["allow_terminal"] = cfg.Remote.AllowTerminal
		resp["allow_remote_terminal_takeover"] = cfg.Remote.AllowRemoteTerminalTakeover
		resp["remote_enabled"] = cfg.Remote.Enabled
		resp["revoke_on_takeover"] = cfg.Remote.RevokeStandingOnTakeover
		if fp := readStandingSecretFingerprint(cfg); fp != "" {
			resp["secret_present"] = true
			resp["secret_fingerprint"] = fp
		}
	}
	writeJSON(w, resp)
}

// handleStandingTerminalMint — POST /api/remote/standing-terminal/mint (Local).
// Enables (or ROTATES) the standing terminal-control secret: mints a fresh
// secret, writes its hash at rest, flips [remote].allow_standing_terminal_control
// on, hot-reloads the live controller, and returns the encoded secret in the
// RESPONSE BODY ONLY (shown once — never a GET, log, or side channel). On a
// ROTATE (standing access already on) it ALSO revokes every live remote writer
// so a device holding control via the OLD secret loses it immediately. Confirm
// token checked FIRST (§10); owner-loopback-only (Local).
func (s *Server) handleStandingTerminalMint(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	// W5.1 org-governed feature gate: node.features.remote. Checked before
	// any side effect. Fail-open on nil gate / no accepted policy.
	if s.opts.FeatureGate != nil {
		if allowed, reason := s.opts.FeatureGate(nodeFeatureRemote); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	// Fix 2: the config read-modify-write below joins the configWriteMu domain
	// (lock order remoteManageMu → configWriteMu; see remoteManageMu decl).
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()
	cfg, cfgPath, err := s.loadConfigForManage()
	if err != nil {
		writeErr(w, err)
		return
	}
	info, err := remotecfg.StandingTerminalEnable(cfg, cfgPath)
	if err != nil {
		// Preconditions (remote off / allow_terminal off) surface as a friendly
		// 400 the panel renders, not a raw 500.
		writeErrStatus(w, err, http.StatusBadRequest)
		return
	}
	// ORDER (finding 1): reload FIRST — swapping the live hash bumps the
	// standing GENERATION, which fences any in-flight old-secret verify (the
	// install-time recheck rejects it) — THEN kill live writers. Reversing this
	// would let a verify that started pre-rotate install a surviving writer
	// after the kill sweep ran.
	cfg.Remote.AllowStandingTerminalControl = true
	s.reloadLiveStandingSecret(cfg, true)
	// A ROTATE (standing was already enabled) must kill writers acquired via the
	// OLD secret NOW — BEFORE the best-effort audit write, which can block on
	// SQLite. A first enable has no prior standing writers, so nothing is
	// dropped.
	if info.Rotated {
		s.revokeRemoteWriters("standing terminal secret rotated")
	}
	detail := "enabled"
	if info.Rotated {
		detail = "rotated"
	}
	s.recordManageAudit(r, "standing-terminal", detail)
	writeJSON(w, map[string]any{
		"ok":               true,
		"restart_required": false, // hot-reloaded onto the live controller
		"rotated":          info.Rotated,
		"warning":          standingTerminalWarning,
		// The raw secret crosses the wire ONLY in this local response body.
		"secret": info.EncodedSecret,
	})
}

// handleStandingTerminalRevoke — POST /api/remote/standing-terminal/revoke
// (Local). Revokes standing terminal-control access: flips the config off,
// REMOVES the standing secret file (true revocation), and IMMEDIATELY kills
// every live remote writer — a device holding control through the standing
// secret loses input the instant this returns (the Phase-4 revoke-kills-open-
// writers invariant). Confirm token checked FIRST (§10); owner-loopback-only.
func (s *Server) handleStandingTerminalRevoke(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	// Fix 2: the config read-modify-write below joins the configWriteMu domain
	// (lock order remoteManageMu → configWriteMu; see remoteManageMu decl).
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()
	cfg, cfgPath, err := s.loadConfigForManage()
	if err != nil {
		writeErr(w, err)
		return
	}
	// KILL LIVE ACCESS FIRST, unconditionally (findings 1 + 2): hot-disable the
	// verifier (clears the live hash + bumps the standing GENERATION, fencing
	// any in-flight old-secret verify at install time), then kill every live
	// remote writer. Only THEN attempt the persist + secret-file unlink — a
	// config-write or unlink failure must degrade SAFE (access already dead on
	// the live controller; the persisted enabled=false gate covers a restart),
	// never fail-open with writers left driving PTYs behind an HTTP 500. The
	// owner-local writer is untouched; over-revoking all remote writers is the
	// safe direction.
	cfg.Remote.AllowStandingTerminalControl = false
	s.reloadLiveStandingSecret(cfg, false)
	s.revokeRemoteWriters("standing terminal access revoked")
	removed, err := remotecfg.StandingTerminalDisable(cfg, cfgPath)
	if err != nil {
		// Live access is already dead (verifier disabled + writers killed) —
		// the error reports only the durable half so the operator can retry.
		s.recordManageAudit(r, "standing-terminal", "revoked (persist failed)")
		writeErr(w, err)
		return
	}
	s.recordManageAudit(r, "standing-terminal", "revoked")
	writeJSON(w, map[string]any{
		"ok":             true,
		"secret_removed": removed,
	})
}

// handleRemoteAudit — GET /api/remote/audit (View). The remote_audit tail
// (metadata only, node-local). Honest label: not compliance-immutable (a local
// owner can mutate SQLite — the panel says so).
func (s *Server) handleRemoteAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.remoteManageStore()
	if st == nil {
		writeJSON(w, map[string]any{"events": []any{}})
		return
	}
	limit := intArg(r, "limit", 50, 1, 500)
	events, err := st.RecentRemoteAudit(r.Context(), limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	type row struct {
		TS         string `json:"ts"`
		Kind       string `json:"kind"`
		Principal  string `json:"principal"`
		RemoteAddr string `json:"remote_addr"`
		Route      string `json:"route"`
		Decision   string `json:"decision"`
		Detail     string `json:"detail"`
	}
	out := make([]row, 0, len(events))
	for _, e := range events {
		out = append(out, row{
			TS: e.TS.Format(time.RFC3339), Kind: e.Kind, Principal: e.Principal,
			RemoteAddr: e.RemoteAddr, Route: e.Route, Decision: e.Decision, Detail: e.Detail,
		})
	}
	writeJSON(w, map[string]any{"events": out, "immutable": false})
}

// handleRemoteSessions — GET /api/remote/sessions (View). Lists live device
// sessions as TRUNCATED fingerprints (never the full session id, §2F).
func (s *Server) handleRemoteSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type sess struct {
		Fingerprint string `json:"fingerprint"`
		CreatedAt   string `json:"created_at"`
		LastSeen    string `json:"last_seen"`
		AgeSeconds  int64  `json:"age_seconds"`
	}
	out := []sess{}
	live := s.opts.Remote != nil
	if live {
		for _, si := range s.opts.Remote.Sessions() {
			out = append(out, sess{
				Fingerprint: si.Fingerprint,
				CreatedAt:   si.CreatedAt.Format(time.RFC3339),
				LastSeen:    si.LastSeen.Format(time.RFC3339),
				AgeSeconds:  si.AgeSeconds,
			})
		}
	}
	writeJSON(w, map[string]any{"sessions": out, "controller_live": live})
}

// handleRemoteSessionRevoke — DELETE /api/remote/sessions/<fingerprint> (Local).
// Resolves the fingerprint to a full id server-side and revokes that ONE session
// (instant, no restart, §C).
func (s *Server) handleRemoteSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fp := strings.TrimPrefix(r.URL.Path, "/api/remote/sessions/")
	fp = strings.TrimSpace(strings.Trim(fp, "/"))
	if fp == "" || s.opts.Remote == nil {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	// Resolve the fingerprint → full id (never trust a client-supplied full id).
	var id string
	for _, si := range s.opts.Remote.Sessions() {
		if si.Fingerprint == fp {
			id = si.ID
			break
		}
	}
	if id == "" || !s.opts.Remote.RevokeSession(id) {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	// Revoking the device session also kills any terminal writer lease HELD BY
	// that device, so a device driving a PTY loses control the instant it is
	// de-authorized (§8.1 item 8). Matched on the FULL session hash (id, =
	// grant.HolderKey() / deviceSessionKey / SessionInfo.ID) — never the 32-bit
	// display fingerprint (fp) — so a fingerprint collision can never over-revoke
	// a different device's writer lease (F2b parity for the write side). The
	// owner-local writer is never matched.
	if s.opts.LaunchManager != nil {
		s.opts.LaunchManager.RevokeRemoteWriterByHolder(id, "device session revoked")
	}
	// Revoking the device also closes any read-only SENSITIVE viewer it left
	// open (F2): a revoked device must stop receiving attach/resume PTY output
	// NOW, not merely lose its writer lease. Scoped by the FULL session hash
	// (id, the value the viewer registry is keyed on) — never the 32-bit display
	// fingerprint (fp) — so a fingerprint collision can never disconnect a
	// different device's still-authorized view.
	s.closeRemoteSensitiveViewersForDevice(id)
	s.recordManageAudit(r, "session_revoke", fp)
	writeJSON(w, map[string]any{"ok": true, "revoked": fp})
}

// handleRemoteSessionsRevokeAll — POST /api/remote/sessions/revoke-all (Local).
// Terminate-all (instant, no restart, §C).
func (s *Server) handleRemoteSessionsRevokeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.Remote != nil {
		if err := s.opts.Remote.RotateSessions(); err != nil {
			http.Error(w, "could not revoke sessions", http.StatusInternalServerError)
			return
		}
	}
	// Terminate-all also kills every live remote writer lease (§8.1 item 8) AND
	// closes every already-open read-only sensitive viewer (F2): after a
	// revoke-all no device is trusted, so none may keep reading attach/resume
	// PTY output.
	s.revokeRemoteWriters("all device sessions revoked")
	s.closeRemoteSensitiveViewers()
	s.recordManageAudit(r, "session_revoke_all", "")
	writeJSON(w, map[string]any{"ok": true})
}

// handleRemoteSelfcheck — GET /api/remote/selfcheck (View). In-process truth:
// whether the remote backend listener is bound + Ready() (never an outbound
// probe, never the secret).
func (s *Server) handleRemoteSelfcheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ready := s.opts.Remote != nil && s.opts.Remote.Ready()
	writeJSON(w, map[string]any{
		"controller_live": s.opts.Remote != nil,
		"ready":           ready,
	})
}
