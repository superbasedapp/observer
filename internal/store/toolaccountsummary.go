// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// toolaccountsummary.go composes the W3 vendor-login observation wire (see
// docs/plans/node-session-detail-trickle-up-to-org-plan-2026-09-10.md §2
// "W3"). This file — NOT orgpush.go — owns the tool_account_observations READ,
// exactly as taskflowsummary.go owns the task_* read and
// cachesessionorgrows.go the cache_events read: the privacy sentinel forbids
// that table name from ever appearing in orgpush.go, so the push path composes
// this through a FUNCTION CALL.
//
// internal/store/toolaccount.go stays the table's one WRITER (CLAUDE.md module
// boundary #4) and its one node-side reader. This file only reads, for the
// wire.
//
// THE IDENTITY GATE LIVES HERE, ONCE. SelectSessionToolAccounts takes a
// shipsContent bool that the ONE call site in orgpush.go supplies as
// share.shipsRawContent(). When it is false the three identity columns
// (email, name, account_id) are not in the SELECT LIST at all — the values
// never enter the process, so there is no window in which a developer's vendor
// e-mail sits in a wire row awaiting a strip step someone could forget. This
// is operator decision D2 made structural.
//
// THE KEY IS PART OF THAT GATE WHEN IT HAS NO OPAQUE PREIMAGE (PRIV-1,
// codebase audit 2026-09-16). account_key is an unsalted
// sha256(tool || 0x00 || identity) where identity is the first non-empty of
// AccountID, Email, Name (internal/toolaccount.Normalize). When the preimage is
// a vendor ACCOUNT ID the key is opaque in both directions and ships under
// tool_account_detail alone, as designed. When it is an EMAIL or a NAME the key
// is not opaque at all: the preimage space is small and enumerable — an org
// admin holds the member roster the D2 split is meant to withhold this from —
// so a dictionary of sha256(tool||0x00||email) recovers it offline in
// milliseconds. Shipping it under the metadata tier would hand over the
// identity half through the binding half's door.
//
// So the metadata-posture SELECT ships account_key only for rows that HAVE an
// account_id, and blanks it otherwise; the raw-content posture ships it
// unconditionally, exactly like the identity columns beside it. HMAC was
// considered and rejected: a per-node secret would make the key incomparable
// ACROSS nodes, which is the one question ("did two developers use the same
// vendor account?") the key exists to answer.
//
// WHAT AN EMPTY KEY MEANS ON THE WIRE. "not disclosed", never "no account" —
// the same honesty rule the empty Email already carries. A surface that sees a
// blank key for a binding must render the account as unknown; it must not infer
// that two blank-keyed observations are the same account, or different ones.
// The blank also collapses two differing email-derived observations for one
// binding onto the same natural key, so a CONFLICT between them is not
// distinguishable under the metadata tier. That is the disclosure cost of the
// D2 split and it is the correct direction: an org that wants per-account
// resolution turns on the node's raw-content posture and gets the identity
// itself, rather than a hash it would have to crack to use.
//
// WINDOW + IDEMPOTENCY. The recompute is bounded to observations made in the
// trailing sessionToolAccountWindowDays window, and the server upserts on the
// same natural key the node's PRIMARY KEY uses, so re-pushing a window is
// idempotent — the SelectSessionCacheSummaries posture.

// sessionToolAccountWindowDays bounds the recompute to observations made in
// the trailing window. Seven days, matching sessionCacheWindowDays and
// sessionTaskWindowDays: login evidence is captured at session time and an
// observation older than a week has already shipped.
const sessionToolAccountWindowDays = 7

// SelectSessionToolAccounts returns every login observation recorded in the
// trailing sessionToolAccountWindowDays window.
//
// CONFLICTS ARE PRESERVED. The node retains a second, differing observation
// for the same binding as its own row (INSERT OR IGNORE on the full composite
// key), and so does this Select — nothing here picks a winner. A surface that
// sees two account_keys for one binding must render "conflict", never one of
// them.
func (s *Store) SelectSessionToolAccounts(ctx context.Context, shipsContent bool) ([]orgcontract.SessionToolAccountRow, error) {
	since := timestamp(time.Now().UTC().AddDate(0, 0, -sessionToolAccountWindowDays))

	// Two query texts rather than one with conditional binds — the identity
	// columns are structurally absent from the metadata-posture SELECT list,
	// the same discipline SelectSessionTaskItems uses for the plan prose.
	// The CASE is the PRIV-1 key gate (see the file comment): a key derived
	// from an email or a name is an offline-recoverable preimage, so it rides
	// the identity gate with the columns it was derived from. A key derived
	// from a vendor account_id is opaque and ships under the binding tier.
	// Expressed in the SELECT LIST, not stripped in Go afterwards, for the
	// same reason the identity columns are: there is then no window in which
	// the value exists in a wire row awaiting a strip step.
	query := `
		SELECT session_id, tool, binding_kind, binding_id, role,
		       CASE WHEN COALESCE(account_id,'') <> '' THEN account_key ELSE '' END,
		       '', '', '',
		       source, scope, stage, observed_at
		  FROM tool_account_observations
		 WHERE observed_at >= ?
		 ORDER BY session_id, observed_at, account_key, source, scope, stage`
	if shipsContent {
		query = `
		SELECT session_id, tool, binding_kind, binding_id, role, account_key,
		       email, name, account_id,
		       source, scope, stage, observed_at
		  FROM tool_account_observations
		 WHERE observed_at >= ?
		 ORDER BY session_id, observed_at, account_key, source, scope, stage`
	}

	rows, err := s.db.QueryContext(ctx, query, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionToolAccounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.SessionToolAccountRow{}
	for rows.Next() {
		var r orgcontract.SessionToolAccountRow
		if err := rows.Scan(&r.SessionID, &r.Tool, &r.BindingKind, &r.BindingID,
			&r.Role, &r.AccountKey,
			&r.Email, &r.Name, &r.AccountID,
			&r.Source, &r.Scope, &r.Stage, &r.ObservedAt); err != nil {
			return nil, fmt.Errorf("store.SelectSessionToolAccounts: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionToolAccounts: %w", err)
	}
	return out, nil
}

// probeToolAccounts is the Track R2 change-detection probe for the
// session_tool_accounts wire family (internal/store/orgsnapgate.go). It lives
// HERE, with the table's other reader, so orgsnapgate.go and orgpush.go stay
// free of the tool_account_observations name the privacy sentinel forbids
// there.
//
// PROBE: COALESCE(MAX(rowid),0) — one index-endpoint seek, O(1). The table has
// a composite PRIMARY KEY and no surrogate id column, so rowid IS its insert
// order.
//
// WHY THAT REFLECTS MUTATION: every writer is an INSERT OR IGNORE
// (Store.RecordToolAccounts) — an observation is never updated in place, and a
// replay deliberately keeps the first one — so any genuinely new evidence
// advances MAX(rowid).
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: a retention DELETE inside the
// window is invisible to MAX(rowid); snapGate's maxSkipAge recomputes within
// the hour, exactly like probeCacheEvents' identical residual.
func (s *Store) probeToolAccounts(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `SELECT 'ta' || COALESCE(MAX(rowid), 0) FROM tool_account_observations`)
}
