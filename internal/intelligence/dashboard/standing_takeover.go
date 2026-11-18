//go:build !sbo_omit_remote

package dashboard

// standing_takeover.go — the OPT-IN revoke-standing-on-takeover policy
// ([remote].revoke_standing_on_takeover, default false) and its manage verb.
//
// Default posture is SEAMLESS: a local (desktop) takeover of a remote writer
// revokes only the live lease; the paired device's standing credential stays
// valid and it may re-acquire when the desktop lets go. This file adds the
// opt-in hardening for operators who want a takeover to ALSO kill standing
// access — the same teardown as the explicit dashboard revoke, triggered by
// the termsession provenance hook (Manager.SetOnStandingLocalTakeover).
//
// The policy gate is the PERSISTED config value read at fire time (under
// remoteManageMu, via loadConfigForManage) — the config file is the single
// source of truth, so the manage verb below needs no live-gate hot-swap and
// the flip takes effect on the next takeover with no restart.

import (
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/remotecfg"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// OnStandingLocalTakeover is the termsession standing-takeover hook (fired
// async by the manager after a LOCAL writer acquisition superseded a remote
// lease minted through the standing credential). When the operator opted in
// ([remote].revoke_standing_on_takeover), it runs the SAME teardown sequence
// as handleStandingTerminalRevoke — live verifier disabled first, remote
// writers dropped, then the durable persist + credential-file removal — and
// writes a request-free manage audit row. A persist failure degrades SAFE
// (live access already dead) exactly like the handler.
func (s *Server) OnStandingLocalTakeover(handle, revokedHolder string) {
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	// Fix 2: the config read-modify-write below joins the configWriteMu domain
	// (lock order remoteManageMu → configWriteMu; see remoteManageMu decl).
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()
	cfg, cfgPath, err := s.loadConfigForManage()
	if err != nil {
		return
	}
	if !cfg.Remote.RevokeStandingOnTakeover || !cfg.Remote.AllowStandingTerminalControl {
		return
	}
	cfg.Remote.AllowStandingTerminalControl = false
	s.reloadLiveStandingSecret(cfg, false)
	s.revokeRemoteWriters("standing access revoked by local takeover")
	detail := "revoked (local takeover, device " + holderFingerprint8(revokedHolder) + ")"
	if _, err := remotecfg.StandingTerminalDisable(cfg, cfgPath); err != nil {
		detail = "revoked by local takeover (persist failed)"
	}
	s.recordRemoteAuditRow(store.RemoteAuditEvent{
		Kind:      "manage",
		Principal: "local",
		Route:     "standing-takeover",
		Decision:  "ok",
		Detail:    "standing-terminal " + detail,
	})
}

// holderFingerprint8 truncates a full holder key (sha256 hex) to the 8-char
// display fingerprint every audit/UI surface uses; short/empty inputs pass
// through unchanged.
func holderFingerprint8(holderKey string) string {
	if len(holderKey) > 8 {
		return holderKey[:8]
	}
	return holderKey
}

// handleRemoteSetRevokeStandingOnTakeover — POST
// /api/remote/standing-revoke-on-takeover (Local). Flips ONLY
// [remote].revoke_standing_on_takeover, mirroring
// handleRemoteSetAllowTerminalView one field narrower. No live gate to swap:
// the takeover hook reads the persisted value at fire time, so the flip is
// effective immediately with no restart. Strict pointer decode — a
// silently-defaulted zero value must never flip the policy.
func (s *Server) handleRemoteSetRevokeStandingOnTakeover(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var body struct {
		RevokeStandingOnTakeover *bool `json:"revoke_standing_on_takeover"`
	}
	if err := decodeJSONBody(r, &body); err != nil || body.RevokeStandingOnTakeover == nil {
		http.Error(w, `{"error":"body must be JSON with a boolean revoke_standing_on_takeover field"}`, http.StatusBadRequest)
		return
	}
	next := *body.RevokeStandingOnTakeover
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
		writeNeedsSetting(w, http.StatusBadRequest, "remote access is off - arm remote access first", msgRemoteOff, settingslink.RemoteAccess)
		return
	}
	cfg.Remote.RevokeStandingOnTakeover = next
	if err := config.Validate(cfg); err != nil {
		writeErr(w, err)
		return
	}
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		writeErr(w, err)
		return
	}
	detail := "disabled"
	if next {
		detail = "enabled"
	}
	s.recordManageAudit(r, "standing-revoke-on-takeover", detail)
	writeJSON(w, map[string]any{
		"ok":                          true,
		"restart_required":            false,
		"revoke_standing_on_takeover": next,
	})
}

// handleRemoteSetAllowRemoteTakeover — POST
// /api/remote/allow-remote-takeover (Local). Flips only
// [remote].allow_remote_terminal_takeover, persists it, and hot-swaps the live
// controller before returning. The credential gates are untouched and remain
// upstream. Strict pointer decode prevents a malformed body from silently
// selecting false.
func (s *Server) handleRemoteSetAllowRemoteTakeover(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var body struct {
		AllowRemoteTerminalTakeover *bool `json:"allow_remote_terminal_takeover"`
	}
	if err := decodeJSONBody(r, &body); err != nil || body.AllowRemoteTerminalTakeover == nil {
		http.Error(w, `{"error":"body must be JSON with a boolean allow_remote_terminal_takeover field"}`, http.StatusBadRequest)
		return
	}
	next := *body.AllowRemoteTerminalTakeover
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
		writeNeedsSetting(w, http.StatusBadRequest, "remote access is off - arm remote access first", msgRemoteOff, settingslink.RemoteAccess)
		return
	}
	cfg.Remote.AllowRemoteTerminalTakeover = next
	if err := config.Validate(cfg); err != nil {
		writeErr(w, err)
		return
	}
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		writeErr(w, err)
		return
	}
	if rl, ok := s.opts.Remote.(allowRemoteTerminalTakeoverReloader); ok {
		rl.ReloadAllowRemoteTerminalTakeover(next)
	}
	detail := "disabled"
	if next {
		detail = "enabled"
	}
	s.recordManageAudit(r, "allow-remote-takeover", detail)
	writeJSON(w, map[string]any{
		"ok":                             true,
		"restart_required":               false,
		"allow_remote_terminal_takeover": next,
	})
}
