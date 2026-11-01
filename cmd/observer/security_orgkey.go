//go:build !sbo_omit_security

package main

import (
	"context"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_orgkey.go is the node's half of the org finding dedupe key
// (security plan 4.5.1, lane LEFT-SHARED).
//
//   - The security managed pull serves a MANAGED member's node holding
//     enforce.security the org's dedupe key with its version (orgcontract
//     org_dedupe, only to a node that advertised security.org_dedupe, which
//     internal/orgclient/security_pullcaps.go does). After every applied
//     outcome the daemon writes it to an owner-only file beside the posture
//     key (security dir, org_dedupe.key, 0600) or removes the file when no
//     pull carrying a key is in force. An individual node never pulls the
//     rail, so it never holds a key and nothing changes there.
//   - A secret's value exists only at detection, so its org_key
//     (secfinding.OrgSecretKey) is computed there: the detector's Identify
//     notes the digest beside the node-keyed identity
//     (securityNoteOrgIdentity) and securitySecretFinding stamps it,
//     version-tagged, on the finding (secfinding.StoredOrgKey). The key
//     file, the memo and the stamping live in internal/secsvc (orgkey.go)
//     since the merge, so the history scans share them (audit finding 5).
//   - The managed pull cache keeps the signed body with the key blanked and
//     restores it from the key file on load (orgclient
//     SecurityOrgDedupeKeySource, set here; audit finding 4).
//   - The push composition ships the digest only while the node holds that
//     same version (securityFindingsWithOrgKey, secfinding.WireOrgKey); the
//     key itself never reaches the push wire.

// securityOrgDedupeKeyName is the key file in the security directory.
const securityOrgDedupeKeyName = secsvc.OrgDedupeKeyName

func init() {
	securityManagedFollowers = append(securityManagedFollowers, followSecurityOrgDedupe)
	orgclient.SecurityOrgDedupeKeySource = func() (orgcontract.SecurityOrgDedupe, bool) {
		return secsvc.ReadOrgDedupe(securityOrgDedupeDir())
	}
}

// securityOrgDedupeDir is the daemon's security directory ("" when the base
// config is not known in this process).
var securityOrgDedupeDir = func() string {
	base, ok := secScanning.baseNow()
	if !ok || base.ConfigPath == "" {
		return ""
	}
	return secposture.LayoutFor(base.ConfigPath).Dir
}

// securityOrgDedupeFor is the key an applied state carries (nil clears).
func securityOrgDedupeFor(st securityManagedState) *orgcontract.SecurityOrgDedupe {
	return secsvc.OrgDedupeFor(st.Outcome.InForce, st.Policy)
}

// followSecurityOrgDedupe keeps the key file in step with the applied pull.
func followSecurityOrgDedupe(st securityManagedState) {
	dir := securityOrgDedupeDir()
	if dir == "" {
		return
	}
	if err := writeSecurityOrgDedupe(dir, securityOrgDedupeFor(st)); err != nil {
		slog.Default().Warn("security: the org dedupe key file was not updated", "err", err)
	}
}

// writeSecurityOrgDedupe writes (or, with nil, removes) the key file.
func writeSecurityOrgDedupe(dir string, d *orgcontract.SecurityOrgDedupe) error {
	return secsvc.WriteOrgDedupeKey(dir, d)
}

// secOrgIdentities is the daemon's detection-time org_key memo, filled by
// Identify and read by securitySecretFinding in the same daemon pass (the
// post-write and commit scans run both in one process).
var secOrgIdentities secsvc.OrgKeyMemo

// securityNoteOrgIdentity records the org_key of one secret under the key
// the node holds now (nothing without a key file).
func securityNoteOrgIdentity(dir, nodeIdentity, secretType, value string) {
	secOrgIdentities.Note(dir, nodeIdentity, secretType, value)
}

// securityOrgIdentityFor is the stored org_key noted for a node identity
// ("" when none).
func securityOrgIdentityFor(nodeIdentity string) string {
	return secOrgIdentities.For(nodeIdentity)
}

// securityHeldDedupeVersion is the dedupe key version the in-force pull
// carries (0 when none).
func securityHeldDedupeVersion() int64 {
	if p := securityManagedCurrent().Policy; p != nil && p.OrgDedupe != nil {
		return p.OrgDedupe.Version
	}
	return 0
}

// securityFindingsWithOrgKey wraps the store's finding read for the push:
// each stored, version-tagged org_key becomes the bare digest while the
// node holds that version, else nothing.
func securityFindingsWithOrgKey(read func(context.Context, int, store.SecurityScope) ([]orgcontract.SecurityFindingRow, error), held func() int64) func(context.Context, int, store.SecurityScope) ([]orgcontract.SecurityFindingRow, error) {
	return func(ctx context.Context, max int, scope store.SecurityScope) ([]orgcontract.SecurityFindingRow, error) {
		rows, err := read(ctx, max, scope)
		version := held()
		for i := range rows {
			rows[i].OrgKey = secfinding.WireOrgKey(rows[i].OrgKey, version)
		}
		return rows, err
	}
}

// securityOrgDedupeState is the status row of a served key.
func securityOrgDedupeState(p *orgcontract.SecurityManagedPolicyV1) string {
	if p.FindingShare != orgcontract.SecurityShareFindings {
		return "applied (kept in an owner-only file; no finding rows ship at this share level, so no org_key)"
	}
	return "applied (kept in an owner-only file; a secret finding sighted from now on carries org_key, the key itself never leaves this machine)"
}
