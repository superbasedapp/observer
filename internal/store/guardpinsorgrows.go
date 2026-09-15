package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// guardpinsorgrows.go is the W5.2 org-wire seam for guard MCP pins and
// exception approvals (docs/plans/org-parity-full-depth-plan-2026-08-24.md
// §4 "W5.2"). It OWNS the guard_pins / guard_approvals / guard_policy_state
// references for the org-push path — internal/store/guard.go already owns
// the node dashboard/CLI read/write seam (`observer guard mcp`,
// `observer guard approve`); this file reuses those same accessors and
// reshapes their rows into wire rows, so orgpush.go never names
// guard_pins/guard_approvals/guard_policy_state directly (module-boundary
// discipline, CLAUDE.md #1/#4).
//
// guard_policy_state (the third G13/G14-deferred table) is deliberately NOT
// wired here. It is a policy-SOURCE load log (which policy file/hash the
// node last loaded and when), not a per-dev pin or approval the admin
// audits against a developer's own choices — and under the enterprise
// posture (§0.3) guard policy is authored on the org policy rail, never
// mirrored back from the node. A future wave that wants the node's local
// policy-load history for drift diagnosis should give it its own row
// type/file rather than overload this one.
//
// SNAPSHOT, NOT EVENTS: unlike guard_events (an append-only audit log,
// already wired at row granularity), pins and approvals are CURRENT-STATE
// tables on the node — a pin is upserted in place on every re-sighting
// (UNIQUE(kind, name, client)), and an approval simply stops existing once
// it expires or is explicitly revoked and later gets pruned
// (store.PruneGuardTables). So both Select functions below ship the node's
// CURRENT set on every push; the server ingest upserts by natural key
// (guard_pin_rows / guard_approval_rows, migration 098), making a re-push
// idempotent exactly like the verbosity/cache summary wires.
//
// STALENESS HANDLING (documented per the W5.2 task): if a pin or approval
// disappears node-side between two pushes (an MCP server config removed, an
// approval expires/is revoked), NO deletion/tombstone message is sent on
// this wire — the server simply stops receiving refreshes for that natural
// key, and its row goes stale. This is a deliberate, honest design choice
// (§0.2 "no silent metadata-only degrade"): the server never guesses at a
// revoke, it just stops seeing "last verified" advance. The org rollup
// (internal/orgserver/rollup/guardpins.go) surfaces this via each pin's
// LastVerified age rather than treating an old row as still-live, and never
// silently drops a stale row from the audit view — a stale pin/approval IS
// part of the audit trail, not noise to hide. A full tombstone/diff protocol
// (actively signaling "this pin was removed") is out of scope for this wire
// and would need its own design if a future wave wants it.
func (s *Store) SelectGuardPinRows(ctx context.Context) ([]orgcontract.GuardPinRow, error) {
	pins, err := s.LoadGuardPins(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("store.SelectGuardPinRows: %w", err)
	}
	out := make([]orgcontract.GuardPinRow, 0, len(pins))
	for _, p := range pins {
		out = append(out, orgcontract.GuardPinRow{
			PinKey:       guardPinKey(p.Kind, p.Name, p.Client),
			Kind:         p.Kind,
			Name:         p.Name,
			Client:       p.Client,
			PinHash:      p.PinHash,
			FirstSeen:    timestamp(p.FirstSeen),
			LastVerified: timestamp(p.LastVerified),
			Status:       p.Status,
		})
	}
	return out, nil
}

// SelectGuardApprovalRows returns the node's currently-active guard
// approvals — the same "reviewable exception register" the node's own
// guard surfaces read via ActiveGuardApprovals(ctx, "", now) — as W5.2 wire
// rows. See the file doc comment above for the staleness-handling design:
// an approval that expires or is revoked between two pushes simply stops
// being re-shipped.
func (s *Store) SelectGuardApprovalRows(ctx context.Context) ([]orgcontract.GuardApprovalRow, error) {
	now := time.Now().UTC()
	approvals, err := s.ActiveGuardApprovals(ctx, "", now)
	if err != nil {
		return nil, fmt.Errorf("store.SelectGuardApprovalRows: %w", err)
	}
	out := make([]orgcontract.GuardApprovalRow, 0, len(approvals))
	for _, a := range approvals {
		row := orgcontract.GuardApprovalRow{
			ApprovalKey:     fmt.Sprintf("%d", a.ID),
			RuleID:          a.RuleID,
			Scope:           a.Scope,
			SessionID:       a.SessionID,
			ProjectRootHash: a.ProjectRootHash,
			GrantedBy:       a.GrantedBy,
			GrantedAt:       timestamp(a.TS),
			// ActiveGuardApprovals already filtered to expires_at = '' OR
			// expires_at > now, so every row this function ships is active
			// as of this push by construction.
			Active: true,
		}
		if !a.ExpiresAt.IsZero() {
			row.ExpiresAt = timestamp(a.ExpiresAt)
		}
		out = append(out, row)
	}
	return out, nil
}

// guardPinKey derives the server's per-dev natural key for a guard pin from
// the node's own UNIQUE(kind, name, client) triple
// (internal/db/migrations/040_guard_layer.sql) — client is empty for
// client-agnostic pins, kept in the key so a client-scoped and a
// client-agnostic pin sharing (kind, name) never collide.
func guardPinKey(kind, name, client string) string {
	return kind + ":" + name + ":" + client
}

// probeGuardPins is the Track R2 change-detection probe for the guard_pins
// wire. It lives here — with the wire's own read — so orgsnapgate.go and
// orgpush.go stay free of the table name.
//
// PROBE: (MAX(id), COUNT(*), MAX(last_verified), COUNT(DISTINCT status)) over
// guard_pins. The table holds one row per pinned MCP server / client binding —
// a handful of rows — so a full scan costs nothing.
//
// WHY last_verified AND status ARE IN THE PROBE: guard_pins is UPDATED in place
// (`SET status = ?, last_verified = ?`) on every verification, and status is
// exactly the column an admin watches (a pin flipping to a drift state is the
// signal this wire exists to carry). Because the two columns are always written
// together, MAX(last_verified) moves whenever the newest-verified pin changes,
// and the distinct-status count moves whenever a pin enters or leaves a state
// no other pin is in.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: a status flip on a pin whose
// last_verified is NOT the table maximum, into a state another pin already
// occupies, moves neither component. snapGate's maxSkipAge recomputes within
// the hour.
func (s *Store) probeGuardPins(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'gp' || COALESCE(MAX(id), 0) || '/' || COUNT(*) ||
		       '/' || COALESCE(MAX(last_verified), '') || '/' || COUNT(DISTINCT status)
		  FROM guard_pins`)
}

// probeGuardApprovals is the Track R2 change-detection probe for the
// guard_approvals wire. It lives here — with the wire's own read — so
// orgsnapgate.go and orgpush.go stay free of the table name.
//
// PROBE: (MAX(id), COUNT(*)) over guard_approvals — a small "reviewable
// exception register", not an event log, so the count is free.
//
// WHY THE COUNT IS NEEDED: an approval is granted by INSERT and REVOKED by
// DELETE, so revocation is a pure row disappearance that MAX(id) cannot see.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: this wire's output is also
// TIME-dependent — SelectGuardApprovalRows ships only approvals still active at
// the moment of the push, so an approval simply expiring changes the wire with
// no write at all. That was already the wire's documented model (an expired
// approval "stops being re-shipped"; the server never deletes what it has), and
// snapGate's maxSkipAge bounds the lag to an hour.
func (s *Store) probeGuardApprovals(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'ga' || COALESCE(MAX(id), 0) || '/' || COUNT(*) FROM guard_approvals`)
}
