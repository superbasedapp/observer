// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"fmt"
	"log/slog"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// orgpushsections.go owns the envelope-level SECTIONS of a push: the single
// rows and reports that ride on PushEnvelope beside the row families (budget
// posture, component posture, the org AI tool policy state, the AI tool
// configuration inventory), and the byte accounting that keeps them inside the
// envelope budget.
//
// Before this file they were attached after the cursor lanes had filled the
// envelope and were never counted, so a managed node's ~200 KiB inventory
// pushed every serialized envelope over [org_client] max_push_bytes (the
// 2026-11-10 live wedge: "push batch too large", every cycle, the overflow a
// constant ~200-240 KiB whatever the row count). Because a failed push never
// commits the inventory's digest, the next cycle attached it again and failed
// again: nothing reached the org. Sections are now composed FIRST, measured,
// and bounded to a share of the envelope, so the cursor lanes fit into what is
// left.

// pushEnvelopeSectionDivisor bounds the envelope-level sections to
// max/pushEnvelopeSectionDivisor of the envelope. Half the envelope leaves the
// cursor lanes room to make progress on the (at most hourly) push that carries
// the inventory, and every other push carries only the tiny posture rows.
const pushEnvelopeSectionDivisor = 2

// Oversize report families for the envelope sections and for a cursor row
// that cannot fit an envelope on its own (orgsnapoversize.go renders them).
const (
	snapFamEnvelopeAgentConfigInventory snapFamily = "envelope_agent_config_inventory"
	snapFamEnvelopeAgentConfigState     snapFamily = "envelope_agent_config_state"
	snapFamCursorPrefix                 snapFamily = "cursor_"
)

// composeEnvelopeSections attaches every envelope-level section to batch and
// charges its exact JSON size to budget. Reports with rows (AI tool policy
// state, AI tool configuration inventory) are cut to the leading rows that fit
// the section allowance, with the report's Truncated flag set and the cut
// recorded in the oversized-row report, so nothing is dropped without a
// recorded reason.
func (s *Store) composeEnvelopeSections(ctx context.Context, batch *PushBatch, budget *envelopeBudget, share ShareOptions) {
	allowance := budget.max / pushEnvelopeSectionDivisor

	// Org BUDGET posture (org-budget plan §3.3d): one enum-only row saying
	// whether the org's budget is actually holding on this node, composed
	// through the func seam in budgetposture.go. A posture the admin cannot
	// see is the failure the row exists to prevent, so it is attached before
	// any row family competes for the envelope. nil = nothing to report.
	batch.BudgetPosture = s.composeBudgetPosture()
	// The component posture (modular packaging plan 6.4): composed through
	// the func seam in componentposture.go; metadata about the binary, so it
	// ships in every share mode. A change forces a push until delivered.
	batch.ComponentPosture, batch.componentPostureChanged = s.composeComponentPosture(ctx)
	if batch.BudgetPosture != nil {
		budget.est += jsonSize(batch.BudgetPosture)
	}
	if batch.ComponentPosture != nil {
		budget.est += jsonSize(batch.ComponentPosture)
	}

	// The org AI tool policy state (adapter config P7): a managed node's
	// applied state, composed through the func seam in agentconfigorg.go so
	// orgpush.go names no node table. Observed values ride only under
	// shipsRawContent(). A changed report forces a push (an admin must see
	// drift without waiting for unrelated telemetry); an unchanged one only
	// rides along.
	state := s.composeAgentConfigState(ctx, share.shipsRawContent())
	batch.agentConfigChanged = s.noteAgentConfigDigest(state)
	if state != nil {
		var dropped, full int64
		state.Rows, dropped, full = fitSectionRows(state.Rows, jsonSize(orgcontract.AgentConfigStateReport{
			PolicyVersion: state.PolicyVersion, Digest: state.Digest, Truncated: true,
		}), allowance-budget.est)
		if dropped > 0 {
			state.Truncated = true
		}
		s.snap.noteSection(snapFamEnvelopeAgentConfigState, dropped, full, allowance)
		batch.AgentConfigState = state
		budget.est += jsonSize(state)
	}

	// The AI tool configuration inventory (D-112, T-427): same func-seam
	// posture, value-bearing, so raw content only; attached only when it
	// changed since the last accepted push (a change forces a push).
	inv := s.composeAgentConfigInventory(ctx, share.shipsRawContent())
	if inv != nil {
		var dropped, full int64
		inv.Rows, dropped, full = fitSectionRows(inv.Rows, jsonSize(orgcontract.AgentConfigInventoryReport{
			Digest: inv.Digest, Truncated: true,
		}), allowance-budget.est)
		if dropped > 0 {
			inv.Truncated = true
		}
		s.snap.noteSection(snapFamEnvelopeAgentConfigInventory, dropped, full, allowance)
		batch.AgentConfigInventory = inv
		budget.est += jsonSize(inv)
	}
}

// fitSectionRows returns the leading rows of a section report whose JSON
// (overhead for the report's own fields, plus each row and the comma between
// rows) fits limit, how many rows were dropped, and the size the whole report
// would have had. A limit too small for even the overhead keeps no row.
func fitSectionRows[T any](rows []T, overhead, limit int64) (kept []T, dropped, full int64) {
	used := overhead
	cut := -1
	for i := range rows {
		sz := jsonSize(rows[i])
		if i > 0 {
			sz++ // the comma before this row
		}
		if cut < 0 && used+sz > limit {
			cut = i
		}
		used += sz
	}
	if cut < 0 {
		return rows, 0, used
	}
	return rows[:cut], int64(len(rows) - cut), used
}

// noteSection records one envelope section's (or one cursor lane's) outcome
// for this compose in the oversized-row report: dropped > 0 writes the entry
// (rows that did not fit, the size they needed, the budget they had), zero
// drops a stale entry. Unlike a snapshot family the section is always looked
// at whole, so every compose that reaches it is complete.
func (g *snapGate) noteSection(fam snapFamily, dropped, needed, limit int64) {
	if dropped > 0 {
		slog.Default().Warn("org push: an envelope section or row is larger than the push budget; the part that did not fit was cut",
			"family", string(fam), "rows_cut", dropped, "needed_bytes", needed, "budget_bytes", limit,
			"hint", "raise [org_client] max_push_bytes to ship it whole")
	}
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entryLocked(fam)
	e.obs.ticked, e.obs.complete = true, true
	if dropped > 0 {
		e.obs.cut = true
		e.obs.rows += dropped
		e.obs.largest = max(e.obs.largest, needed)
		e.obs.budget = limit
	}
}

// pushCutMarkerFormat ends a body the push cut to fit the envelope, so a
// reader on the org side sees that (and by how much) the text was shortened,
// never a silently shorter body.
const pushCutMarkerFormat = "\n[observer: %d bytes cut to fit the org push limit]"

// fitLoneCursorRow handles a cursor-lane row that would be the FIRST row of
// the envelope (admitted unconditionally for forward progress) but is larger
// than the room left in the whole envelope. Admitting it as-is would make
// every envelope oversized, forever: the cursor could never move past it.
// shrink, when non-nil, cuts the row's free-text bodies down to room (with a
// marker naming the cut); a row that still does not fit is skipped. Either way
// the outcome is recorded in the oversized-row report under fam and logged.
// keep=false means skip the row but advance the cursor past it.
func fitLoneCursorRow[T any](s *Store, budget *envelopeBudget, fam snapFamily, row T, sz int64, shrink func(T, int64) T) (out T, outSz int64, keep bool) {
	room := budget.max - pushEnvelopeCursorSlack - budget.est
	if sz <= room {
		return row, sz, true
	}
	out, outSz = row, sz
	if shrink != nil && room > 0 {
		out = shrink(row, room)
		outSz = jsonSize(out)
	}
	keep = outSz <= room
	s.snap.noteCursorCut(fam, sz, room)
	return out, outSz, keep
}

// shrinkActionRow cuts an action row's free-text fields, longest first, until
// its JSON fits room. Each cut field ends with the cut marker.
func shrinkActionRow(r orgcontract.ActionRow, room int64) orgcontract.ActionRow {
	fields := []*string{&r.RawToolOutput, &r.RawToolInput, &r.PrecedingReasoning, &r.ErrorMessage, &r.Target}
	shrinkFieldsToFit(func() int64 { return jsonSize(r) }, fields, room)
	return r
}

// shrinkOTelContentRow cuts an OTel content row's body until its JSON fits.
func shrinkOTelContentRow(r orgcontract.OTelContentRow, room int64) orgcontract.OTelContentRow {
	shrinkFieldsToFit(func() int64 { return jsonSize(r) }, []*string{&r.Content}, room)
	return r
}

// shrinkFieldsToFit repeatedly cuts the longest still-uncut of fields by the
// current excess (size() - room), UTF-8 safely, ending it with the cut marker,
// until size() fits room or every field has been cut. A field cut as far as
// it can go is not picked again. Bounded passes: JSON escaping can make one
// string byte cost several JSON bytes, so one cut may not be enough.
func shrinkFieldsToFit(size func() int64, fields []*string, room int64) {
	done := make([]bool, len(fields))
	for pass := 0; pass < 4*len(fields)+4; pass++ {
		sz := size()
		if sz <= room {
			return
		}
		pick, pickLen := -1, 0
		for i, c := range fields {
			if !done[i] && len(*c) > pickLen {
				pick, pickLen = i, len(*c)
			}
		}
		if pick < 0 {
			return
		}
		f := fields[pick]
		orig := *f
		// Reserve room for the marker the cut appends (its digits are
		// bounded by the original length).
		markerLen := int64(len(fmt.Sprintf(pushCutMarkerFormat, len(orig))))
		keep := int64(len(orig)) - (sz - room) - markerLen
		if keep <= 0 {
			keep, done[pick] = 0, true
		}
		cut := truncateUTF8(orig, int(keep))
		*f = cut + fmt.Sprintf(pushCutMarkerFormat, len(orig)-len(cut))
		if len(*f) >= len(orig) {
			// The marker is no shorter than what it replaced: keep the
			// original and stop picking this field.
			*f, done[pick] = orig, true
		}
	}
}

// truncateUTF8 returns the longest prefix of s of at most n bytes that does
// not split a UTF-8 sequence.
func truncateUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	if n <= 0 {
		return ""
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// noteCursorCut records one cursor row that could not ship whole in the
// oversized-row report (the largest such row and the room it had; a cursor
// lane is never looked at whole, so the persisted count only ever grows to the
// largest per-compose count) and logs it.
func (g *snapGate) noteCursorCut(fam snapFamily, rowBytes, room int64) {
	slog.Default().Warn("org push: a row is larger than the whole push envelope; its text was cut (or the row skipped) so the queue can move",
		"family", string(fam), "row_bytes", rowBytes, "room_bytes", room,
		"hint", "raise [org_client] max_push_bytes to ship such rows whole")
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entryLocked(fam)
	e.obs.ticked, e.obs.cut = true, true
	e.obs.rows++
	e.obs.largest = max(e.obs.largest, rowBytes)
	e.obs.budget = room
}
