// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// updateposture.go is the org-wire seam for enterprise update management
// (W3 of docs/plans/enterprise-update-management-plan-2026-09-07.md §2.1,
// ruling R10). It is a SEPARATE FILE from internal/store/orgpush.go on
// purpose: orgpush.go composes the wire by CALLING SelectUpdatePosture below,
// so the node-local `update_state` / `update_events` table names never appear
// in the push seam and tests/invariant/privacy_test.go can keep forbidding
// them there BY NAME — the arrangement routingsummary.go / locsummary.go use
// for router_decisions / file_changes.
//
// WHAT LEAVES: one row, every field a version string, a coarse platform
// token, a closed enum or a boolean. No hostname, no username, no path, no
// progress bytes, no free-text error. `update_state` holds three local paths
// (the rollback binary, the staged download, the DB snapshot) and
// `update_events.detail` is prose; none of them has a field to travel in,
// which is the point of composing here rather than SELECTing there.
//
// The row only ever NARROWS what an admin believes and never widens access:
// ring health gates are advisory over self-reports, so a lying node can at
// worst halt a rollout — the fail-safe direction (docs/security.md UPD-4).

// UpdatePostureEnv is the static half of the posture: the facts the DATABASE
// cannot know because they describe the running process, not its state.
//
// It is injected rather than discovered because internal/store must not call
// os.Executable, probe a package manager or read a config file — those are
// cmd/observer's job (the install-method table's PathProbe seam), and doing
// them here would make the composer untestable without a real installation.
type UpdatePostureEnv struct {
	// Version is the running binary's main.version.
	Version string
	// OS and Arch are the coarse platform, already inferable from the
	// adapter mix and needed to pick an artifact.
	OS, Arch string
	// InstallMethod is update.Method as a string. It tells the admin why a
	// node reports blocked and which nodes a `refuse` skew policy would
	// strand with no automatic remediation (§6 O5).
	InstallMethod string
	// AutoApply reports whether this node will apply without a human. The
	// server cannot otherwise know it: [update].auto_apply is node-owned
	// and there is deliberately no remote toggle.
	AutoApply bool
	// ExtensionVersion is the VS Code extension's version when one is
	// running and has told the daemon. EMPTY means "no extension
	// reported", never "0" (ruling R6's honest narrowing).
	ExtensionVersion string
	// Channel overrides the state row's channel when the node pinned one
	// locally ([update].channel). Empty defers to whatever the org assigned.
	Channel string
}

// updatePostureEnv is the process-wide injected environment. It is a value
// behind a mutex rather than a Store field so a Store built by a struct
// literal — every test that does not care about updates — composes nothing
// and behaves exactly as before this file existed.
var updatePostureEnv struct {
	mu  sync.RWMutex
	set bool
	env UpdatePostureEnv
}

// SetUpdatePostureEnv wires the static half of the posture. cmd/observer
// calls it once at daemon start, after it has resolved the executable and run
// the install-method table. Idempotent; a later call replaces the value (the
// VS Code extension reporting its version mid-session is exactly that case).
//
// Until it is called, SelectUpdatePosture returns nil and the push envelope
// carries no `update_posture` key at all — byte-identical to a pre-feature
// agent, which is the compat shape acceptance 4 requires.
func SetUpdatePostureEnv(env UpdatePostureEnv) {
	updatePostureEnv.mu.Lock()
	defer updatePostureEnv.mu.Unlock()
	updatePostureEnv.env = env
	updatePostureEnv.set = true
}

// ClearUpdatePostureEnv unwires the environment. Tests use it to prove the
// zero-value path; a node uses it on unenrol.
func ClearUpdatePostureEnv() {
	updatePostureEnv.mu.Lock()
	defer updatePostureEnv.mu.Unlock()
	updatePostureEnv.env = UpdatePostureEnv{}
	updatePostureEnv.set = false
}

// loadUpdatePostureEnv reads the injected environment.
func loadUpdatePostureEnv() (UpdatePostureEnv, bool) {
	updatePostureEnv.mu.RLock()
	defer updatePostureEnv.mu.RUnlock()
	return updatePostureEnv.env, updatePostureEnv.set
}

// SelectUpdatePosture composes the one row a node discloses about updating
// itself, or nil when the feature is not wired.
//
// Every value it returns is either injected (the env above) or read from the
// four ENUM columns of update_state. The path columns are not selected — not
// stripped afterwards, not selected — so there is no ordering of the code in
// which they could reach the wire.
func (s *Store) SelectUpdatePosture(ctx context.Context) (*orgcontract.UpdatePostureRow, error) {
	env, ok := loadUpdatePostureEnv()
	if !ok {
		return nil, nil
	}
	st, err := s.LoadUpdateState(ctx)
	if err != nil {
		return nil, err
	}
	channel := strings.TrimSpace(env.Channel)
	if channel == "" {
		channel = strings.TrimSpace(string(st.Channel))
	}
	state := st.State
	if !update.KnownState(state) {
		state = update.StateIdle
	}
	row := &orgcontract.UpdatePostureRow{
		Version:          strings.TrimSpace(env.Version),
		Channel:          channel,
		OS:               strings.TrimSpace(env.OS),
		Arch:             strings.TrimSpace(env.Arch),
		State:            string(state),
		Reason:           string(st.Reason),
		TargetVersion:    strings.TrimSpace(st.TargetVersion),
		ManifestVersion:  st.LastManifestVersion,
		ErrorClass:       string(st.ErrorClass),
		InstallMethod:    strings.TrimSpace(env.InstallMethod),
		AutoApply:        env.AutoApply,
		ExtensionVersion: strings.TrimSpace(env.ExtensionVersion),
	}
	return row, nil
}
