package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// portalinsights.go serves the two W2 portal reads: the account-day
// materialization behind Overview v2, and the standing-grant registrations
// behind the Privacy page (D19). Both sit behind portalAuth exactly like the
// existing portal endpoints — session cookie, per-account cap, CSRF enforced on
// mutating methods (these are GETs, which are exempt by design) — and both
// return ONLY data this account's own devices uploaded under this account's own
// grant.

const (
	// defaultInsightsDays is the Overview's default window.
	defaultInsightsDays = 30
	// maxInsightsDays bounds it: the rail's own source-window rule is a trailing
	// 30 completed days, so a wider request cannot surface more evidence — it
	// can only make an unbounded query.
	maxInsightsDays = 90
)

// structuralDisclosure is the honesty line every structural card carries. It
// says what the numbers ARE (the devices that synced, the days they covered)
// rather than letting a partial corpus read as a complete one.
const structuralDisclosure = "These figures come from the devices that have synced structural windows under your standing grant. " +
	"A day with no synced window has no row at all: it is shown as missing, never as a zero."

// structuralRetentionDetail states, in one sentence, what the service actually
// does with this data. It is derived from the deletion path's behaviour, not
// from an aspiration.
const structuralRetentionDetail = "Structural snapshots and the account-day rollup derived from them are kept while this account exists, " +
	"and are deleted outright (not tombstoned) when the account is deleted. No shorter retention window is configured for them in this release."

// handlePortalInsights serves Overview v2: the account-day materialization for
// a bounded window, its whole-window summary, the corpus coverage facts every
// card must state, and the enrichment coverage counters collapsed into one
// block.
func (s *Server) handlePortalInsights(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := portalPrincipalFrom(ctx)

	days := defaultInsightsDays
	if raw := r.URL.Query().Get("days"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxInsightsDays {
			writeErr(w, http.StatusBadRequest, "bad_request",
				"days must be an integer between 1 and "+strconv.Itoa(maxInsightsDays))
			return
		}
		days = n
	}

	// Periods are calendar days in each account's DECLARED timezone, which the
	// server does not resolve here — so the range is deliberately generous at
	// BOTH ends by one day: a device in UTC+13 can legitimately have already
	// completed a day whose label is ahead of the server's UTC date, and one in
	// UTC-11 can still be finishing a day whose label is behind. Filtering
	// tighter would silently drop a real window for a traveller.
	today := s.now().UTC()
	from := today.AddDate(0, 0, -days).Format(cloudcontract.StructuralPeriodLayout)
	to := today.AddDate(0, 0, 1).Format(cloudcontract.StructuralPeriodLayout)

	rows, err := s.store.ListStructuralAccountDays(ctx, p.AccountID, from, to)
	if err != nil {
		s.log.Error("cloudserver/api: portal insights days", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read structural insights")
		return
	}
	coverage, err := s.store.StructuralCoverageFor(ctx, p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: portal insights coverage", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read coverage")
		return
	}
	// F13: the cards summarize [from, to], so the device count they are labelled
	// with must be measured over [from, to] too. coverage.Devices is the
	// whole-CORPUS figure — it counts a machine that synced once a year ago and
	// has been offline since — and rendering it inside a line that names the
	// window overstated the window. Both figures are published, each named for
	// what it is.
	windowDevices, err := s.store.StructuralWindowDeviceCount(ctx, p.AccountID, from, to)
	if err != nil {
		s.log.Error("cloudserver/api: portal insights window devices", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read coverage")
		return
	}
	ov, err := s.store.OverviewStats(ctx, p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: portal insights enrichment", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read enrichment coverage")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window": map[string]any{
			"from": from,
			"to":   to,
			"days": days,
			// Devices that contributed a current snapshot INSIDE this window —
			// the honest qualifier for every card on the page.
			"devices": windowDevices,
		},
		"days":    rows,
		"summary": store.SummarizeStructuralDays(rows),
		"coverage": map[string]any{
			// All-history, deliberately: how many machines have ever contributed.
			// Distinct from window.devices; never used to label a windowed card.
			"devices":   coverage.Devices,
			"snapshots": coverage.Snapshots,
			"first_day": coverage.FirstDay,
			"last_day":  coverage.LastDay,
			"days":      coverage.TotalDays,
		},
		// The four enrichment coverage counters, collapsed into ONE block: they
		// are one card on Overview v2, not four.
		"enrichment": map[string]any{
			"jobs_by_state":  ov.JobsByState,
			"jobs_total":     ov.JobsTotal,
			"results_total":  ov.ResultsTotal,
			"last_result_at": ov.LastResultAt,
			"disclosure":     coverageDisclosure,
		},
		"structural_disclosure": structuralDisclosure,
	})
}

// handlePortalGrants serves the Privacy page's standing-grant detail (D19):
// per-grant field classes, the schema + policy versions, the consent generation
// the terms were agreed at, and the retention state.
func (s *Server) handlePortalGrants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := portalPrincipalFrom(ctx)

	grants, err := s.store.ListStructuralGrants(ctx, p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: portal grants", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read standing grants")
		return
	}
	coverage, err := s.store.StructuralCoverageFor(ctx, p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: portal grants coverage", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read coverage")
		return
	}

	type grantView struct {
		Purpose              string   `json:"purpose"`
		FieldClasses         []string `json:"field_classes"`
		SchemaVersion        string   `json:"schema_version"`
		DataDictionaryDigest string   `json:"data_dictionary_digest"`
		// DictionaryCurrent reports whether the digest the grant was agreed
		// against is still the one this service serves. False means the schema
		// moved and the grant needs re-confirming — stated, never hidden.
		DictionaryCurrent bool   `json:"dictionary_current"`
		ConsentGeneration int64  `json:"consent_generation"`
		DeclaredTimezone  string `json:"declared_timezone"`
		SourceWindowRule  string `json:"source_window_rule"`
		FirstSeenAt       string `json:"first_seen_at"`
		UpdatedAt         string `json:"updated_at"`
		RevokedAt         string `json:"revoked_at"`
		State             string `json:"state"`
	}

	current := cloudcontract.StructuralDataDictionaryDigest()
	out := make([]grantView, 0, len(grants))
	for _, g := range grants {
		v := grantView{
			Purpose:              g.Purpose,
			FieldClasses:         structuralFieldClasses(g.Purpose),
			SchemaVersion:        g.SchemaVersion,
			DataDictionaryDigest: g.DataDictionaryDigest,
			DictionaryCurrent:    g.DataDictionaryDigest == current,
			ConsentGeneration:    g.ConsentGeneration,
			DeclaredTimezone:     g.DeclaredTimezone,
			SourceWindowRule:     g.SourceWindowRule,
			FirstSeenAt:          g.FirstSeenAt.UTC().Format(time.RFC3339),
			UpdatedAt:            g.UpdatedAt.UTC().Format(time.RFC3339),
			State:                "active",
		}
		if g.RevokedAt != nil {
			v.RevokedAt = g.RevokedAt.UTC().Format(time.RFC3339)
			v.State = "revoked"
		}
		out = append(out, v)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"grants":                    out,
		"current_schema_version":    cloudcontract.StructuralSnapshotSchemaVersion,
		"current_data_dictionary":   current,
		"retention_state":           "retained_until_account_deletion",
		"retention_detail":          structuralRetentionDetail,
		"stored_snapshots":          coverage.Snapshots,
		"stored_account_days":       coverage.TotalDays,
		"contributing_device_count": coverage.Devices,
	})
}

// structuralFieldClasses names the field classes a purpose's standing grant
// binds. For the structural rail that is EXACTLY structural_metrics: the
// snapshot TYPE has no field in which a path, an excerpt or user feedback could
// be expressed, so claiming any other class would overstate the disclosure.
// (The node prints the same list at grant time — this is the portal restating
// what the developer agreed to, from the server's own record.)
func structuralFieldClasses(purpose string) []string {
	if purpose == string(cloudcontract.PurposeStructuralInsights) {
		return []string{string(cloudcontract.FieldClassStructuralMetrics)}
	}
	// No other purpose is standing-grantable in this release; a row for one
	// could only arrive from a future change that must decide its own classes
	// deliberately rather than inherit these.
	return []string{}
}
